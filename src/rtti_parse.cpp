#include "vtcheck.h"
#include <Psapi.h>
#include <DbgHelp.h>
#include <cstring>
#include <cstdio>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

// ============================================================================
// MSVC x64 RTTI structures (undocumented but stable since VS2015)
//
// In x64, RTTI uses RVAs (relative to module base) instead of raw pointers.
// vtable[-1] -> CompleteObjectLocator
// ============================================================================

#pragma pack(push, 4)

struct TypeDescriptor {
    uintptr_t   pVFTable;       // always points to ??_7type_info@@6B@
    uintptr_t   spare;          // internal runtime use
    char        name[];         // mangled name, e.g. ".?AVMyClass@@"
};

struct PMD {
    int32_t     mdisp;          // member displacement
    int32_t     pdisp;          // vbtable displacement (-1 if not virtual)
    int32_t     vdisp;          // displacement inside vbtable
};

struct BaseClassDescriptor {
    uint32_t    pTypeDescriptor;    // RVA to TypeDescriptor
    uint32_t    numContainedBases;
    PMD         where;
    uint32_t    attributes;
};

struct BaseClassArray {
    uint32_t    arrayOfBaseClassDescriptors[1]; // RVAs to BaseClassDescriptor
};

struct ClassHierarchyDescriptor {
    uint32_t    signature;          // 0 = x86, 1 = x64
    uint32_t    attributes;         // bit 0: multiple inheritance, bit 1: virtual inheritance
    uint32_t    numBaseClasses;
    uint32_t    pBaseClassArray;    // RVA to BaseClassArray
};

struct CompleteObjectLocator {
    uint32_t    signature;          // 1 for x64
    uint32_t    offset;             // offset of this vtable in the complete object
    uint32_t    cdOffset;           // constructor displacement offset
    uint32_t    pTypeDescriptor;    // RVA to TypeDescriptor
    uint32_t    pClassDescriptor;   // RVA to ClassHierarchyDescriptor
    uint32_t    pSelf;              // RVA to this CompleteObjectLocator (for base addr calc)
};

#pragma pack(pop)

// ============================================================================
// Helpers
// ============================================================================

static BOOL get_module_bounds(HMODULE hmod, uintptr_t* base, uintptr_t* end)
{
    MODULEINFO mi = {};
    if (!GetModuleInformation(GetCurrentProcess(), hmod, &mi, sizeof(mi)))
        return FALSE;

    *base = (uintptr_t)mi.lpBaseOfDll;
    *end  = *base + mi.SizeOfImage;
    return TRUE;
}

// Resolve an RVA relative to module base. Returns 0 if out of bounds.
static uintptr_t resolve_rva(uint32_t rva, uintptr_t mod_base, uintptr_t mod_end)
{
    if (rva == 0)
        return 0;

    uintptr_t addr = mod_base + rva;
    if (addr < mod_base || addr >= mod_end)
        return 0;

    return addr;
}

// Demangle an MSVC mangled name. Falls back to raw name on failure.
static void demangle_name(const char* mangled, char* out, size_t out_len)
{
    // MSVC RTTI names start with ".?AV" (class) or ".?AU" (struct)
    // UnDecorateSymbolName wants the name without the leading '.'
    const char* start = mangled;
    if (start[0] == '.')
        start++;

    DWORD result = UnDecorateSymbolName(start, out, (DWORD)out_len,
                                        UNDNAME_NO_ARGUMENTS |
                                        UNDNAME_NO_ACCESS_SPECIFIERS |
                                        UNDNAME_NO_MEMBER_TYPE);
    if (result == 0) {
        // Fallback: just copy raw name, strip the ".?AV" / ".?AU" prefix
        if (mangled[0] == '.' && mangled[1] == '?' && mangled[2] == 'A') {
            const char* clean = mangled + 4; // skip .?AV or .?AU
            size_t len = strlen(clean);
            // Strip trailing "@@"
            if (len > 2 && clean[len-1] == '@' && clean[len-2] == '@')
                len -= 2;
            if (len >= out_len) len = out_len - 1;
            memcpy(out, clean, len);
            out[len] = '\0';
        } else {
            strncpy_s(out, out_len, mangled, _TRUNCATE);
        }
    }
}

// ============================================================================
// Public API
// ============================================================================

uintptr_t read_complete_object_locator(uintptr_t vtable_addr)
{
    if (!vtable_addr)
        return 0;

    // In MSVC ABI, vtable[-1] holds pointer to CompleteObjectLocator
    uintptr_t* vtable = (uintptr_t*)vtable_addr;
    uintptr_t col_ptr = vtable[-1];

    // Basic sanity: should be a valid readable address
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery((LPCVOID)col_ptr, &mbi, sizeof(mbi)) == 0)
        return 0;
    if (mbi.State != MEM_COMMIT)
        return 0;

    // Verify signature field (should be 1 for x64)
    auto col = (CompleteObjectLocator*)col_ptr;

    __try {
        if (col->signature != 1)
            return 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }

    return col_ptr;
}

BOOL parse_type_descriptor(uintptr_t type_desc_rva, HMODULE hmod,
                           char* out_name, size_t name_len)
{
    if (!hmod || !out_name || name_len == 0)
        return FALSE;

    uintptr_t mod_base = 0, mod_end = 0;
    if (!get_module_bounds(hmod, &mod_base, &mod_end))
        return FALSE;

    uintptr_t td_addr = resolve_rva((uint32_t)type_desc_rva, mod_base, mod_end);
    if (!td_addr)
        return FALSE;

    auto td = (TypeDescriptor*)td_addr;

    __try {
        demangle_name(td->name, out_name, name_len);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return TRUE;
}

BOOL walk_class_hierarchy(uintptr_t col_addr, HMODULE hmod, RTTI_INFO* out)
{
    if (!col_addr || !hmod || !out)
        return FALSE;

    uintptr_t mod_base = 0, mod_end = 0;
    if (!get_module_bounds(hmod, &mod_base, &mod_end))
        return FALSE;

    auto col = (CompleteObjectLocator*)col_addr;

    // Resolve ClassHierarchyDescriptor
    uintptr_t chd_addr = resolve_rva(col->pClassDescriptor, mod_base, mod_end);
    if (!chd_addr)
        return FALSE;

    auto chd = (ClassHierarchyDescriptor*)chd_addr;

    __try {
        if (chd->numBaseClasses == 0 || chd->numBaseClasses > VTCHECK_MAX_BASES)
            return FALSE;

        // Resolve BaseClassArray
        uintptr_t bca_addr = resolve_rva(chd->pBaseClassArray, mod_base, mod_end);
        if (!bca_addr)
            return FALSE;

        auto bca = (BaseClassArray*)bca_addr;

        out->base_count = 0;

        for (uint32_t i = 0; i < chd->numBaseClasses && i < VTCHECK_MAX_BASES; i++) {
            uintptr_t bcd_addr = resolve_rva(bca->arrayOfBaseClassDescriptors[i],
                                              mod_base, mod_end);
            if (!bcd_addr)
                continue;

            auto bcd = (BaseClassDescriptor*)bcd_addr;

            // Parse the TypeDescriptor for this base class
            char name[VTCHECK_MAX_NAME_LEN] = {};
            if (parse_type_descriptor(bcd->pTypeDescriptor, hmod,
                                      name, sizeof(name))) {
                strncpy_s(out->base_classes[out->base_count].name, name, _TRUNCATE);
                out->base_classes[out->base_count].mdisp = bcd->where.mdisp;
                out->base_classes[out->base_count].pdisp = bcd->where.pdisp;
                out->base_classes[out->base_count].vdisp = bcd->where.vdisp;
                out->base_count++;
            }
        }

        // First entry in hierarchy is the class itself
        if (out->base_count > 0) {
            strncpy_s(out->class_name, out->base_classes[0].name, _TRUNCATE);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return (out->base_count > 0);
}

BOOL validate_rtti_chain(void* object, const wchar_t* module_name, RTTI_INFO* out)
{
    if (!object || !module_name || !out)
        return FALSE;

    memset(out, 0, sizeof(RTTI_INFO));

    HMODULE hmod = GetModuleHandleW(module_name);
    if (!hmod)
        return FALSE;

    uintptr_t mod_base = 0, mod_end = 0;
    if (!get_module_bounds(hmod, &mod_base, &mod_end))
        return FALSE;

    // Get vtable pointer from the object
    uintptr_t vtable_addr = *(uintptr_t*)object;
    if (!vtable_addr)
        return FALSE;

    // Read COL from vtable[-1]
    uintptr_t col_addr = read_complete_object_locator(vtable_addr);
    if (!col_addr)
        return FALSE;

    // Verify COL is within module bounds
    if (col_addr < mod_base || col_addr >= mod_end)
        return FALSE;

    auto col = (CompleteObjectLocator*)col_addr;

    // Verify self-reference: pSelf RVA should resolve back to col_addr
    // This is a good integrity check -- hooks usually don't bother faking this
    uintptr_t self_addr = resolve_rva(col->pSelf, mod_base, mod_end);
    if (self_addr != col_addr)
        return FALSE;

    // Verify TypeDescriptor is within module
    uintptr_t td_addr = resolve_rva(col->pTypeDescriptor, mod_base, mod_end);
    if (!td_addr)
        return FALSE;

    // Walk the hierarchy
    if (!walk_class_hierarchy(col_addr, hmod, out))
        return FALSE;

    return TRUE;
}
