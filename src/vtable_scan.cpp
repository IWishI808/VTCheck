#include "vtcheck.h"
#include <Psapi.h>
#include <cstring>

#pragma comment(lib, "psapi.lib")

// ============================================================================
// Internal helpers
// ============================================================================

// Find a PE section by name. Returns FALSE if not found.
static BOOL find_section(HMODULE hmod, const char* name,
                         uintptr_t* out_start, uintptr_t* out_end)
{
    auto dos = (PIMAGE_DOS_HEADER)hmod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    auto nt = (PIMAGE_NT_HEADERS64)((uint8_t*)hmod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    auto section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        if (strncmp((const char*)section->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            *out_start = (uintptr_t)hmod + section->VirtualAddress;
            *out_end   = *out_start + section->Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

// Check if addr falls within [start, end).
static inline BOOL in_range(uintptr_t addr, uintptr_t start, uintptr_t end)
{
    return (addr >= start && addr < end);
}

// Quick probe: can we read sizeof(void*) at this address?
static BOOL is_readable(uintptr_t addr)
{
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0)
        return FALSE;

    // Must be committed and have some read access
    if (mbi.State != MEM_COMMIT)
        return FALSE;

    DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                     PAGE_EXECUTE_READWRITE;
    return (mbi.Protect & readable) != 0;
}

// ============================================================================
// Public API
// ============================================================================

BOOL validate_vtable_pointer(uintptr_t vtable_addr, HMODULE hmod)
{
    if (!vtable_addr || !hmod)
        return FALSE;

    uintptr_t rdata_start = 0, rdata_end = 0;
    if (!find_section(hmod, ".rdata", &rdata_start, &rdata_end))
        return FALSE;

    return in_range(vtable_addr, rdata_start, rdata_end);
}

BOOL validate_vtable_entries(uintptr_t vtable_addr, HMODULE hmod,
                             VTABLE_INFO* out, uint32_t max_entries)
{
    if (!out || !hmod || !vtable_addr)
        return FALSE;

    uintptr_t text_start = 0, text_end = 0;
    if (!find_section(hmod, ".text", &text_start, &text_end))
        return FALSE;

    MODULEINFO modinfo = {};
    if (!GetModuleInformation(GetCurrentProcess(), hmod, &modinfo, sizeof(modinfo)))
        return FALSE;

    uintptr_t mod_start = (uintptr_t)modinfo.lpBaseOfDll;
    uintptr_t mod_end   = mod_start + modinfo.SizeOfImage;

    BOOL all_valid = TRUE;
    uintptr_t* vtable = (uintptr_t*)vtable_addr;
    uint32_t count = 0;

    for (uint32_t i = 0; i < max_entries; i++) {
        if (!is_readable((uintptr_t)&vtable[i]))
            break;

        uintptr_t entry = vtable[i];

        // Heuristic: if the entry is 0 or clearly not a code pointer, stop.
        // This isn't perfect -- vtables don't have an explicit terminator.
        // TODO: use RTTI entry count or COM interface size to bound this properly
        if (entry == 0)
            break;

        // Some entries might be in a different section (thunks, etc)
        // but they should at least be in the module
        if (!is_readable(entry))
            break;

        out->entries[i].addr       = entry;
        out->entries[i].in_module  = in_range(entry, mod_start, mod_end);
        out->entries[i].in_text    = in_range(entry, text_start, text_end);

        // Grab page protection for this entry's target
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery((LPCVOID)entry, &mbi, sizeof(mbi))) {
            out->entries[i].page_protect = mbi.Protect;
        }

        if (!out->entries[i].in_module) {
            all_valid = FALSE;
        }

        count++;
    }

    out->entry_count = count;
    return all_valid;
}

BOOL check_memory_protection(uintptr_t vtable_addr)
{
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery((LPCVOID)vtable_addr, &mbi, sizeof(mbi)) == 0)
        return FALSE;

    // vtable data should be in a read-only page.
    // PAGE_READONLY or PAGE_EXECUTE_READ are acceptable.
    // If someone VirtualProtect'd it to RW/RWX, that's suspicious.
    if (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_EXECUTE_READ)
        return TRUE;

    // PAGE_WRITECOPY is also fine -- that's the default for shared sections
    if (mbi.Protect == PAGE_WRITECOPY)
        return TRUE;

    return FALSE;
}

VTABLE_INFO scan_object(void* object, const wchar_t* expected_module)
{
    VTABLE_INFO info = {};
    info.object_addr = object;

    if (!object || !expected_module) {
        info.is_valid = FALSE;
        return info;
    }

    wcsncpy_s(info.module_name, expected_module, VTCHECK_MAX_MODULE_LEN - 1);

    HMODULE hmod = GetModuleHandleW(expected_module);
    if (!hmod) {
        info.is_valid = FALSE;
        return info;
    }

    // First qword at the object address is the vtable pointer
    uintptr_t vtable_ptr = *(uintptr_t*)object;
    info.vtable_addr = vtable_ptr;

    // Step 1: vtable pointer must be in .rdata
    if (!validate_vtable_pointer(vtable_ptr, hmod)) {
        info.is_valid = FALSE;
        return info;
    }

    // Step 2: memory protection on the vtable region
    if (!check_memory_protection(vtable_ptr)) {
        // Not fatal but worth flagging
        // TODO: separate warning field instead of hard fail
        info.is_valid = FALSE;
        return info;
    }

    // Step 3: validate individual entries
    BOOL entries_ok = validate_vtable_entries(vtable_ptr, hmod, &info, VTCHECK_MAX_ENTRIES);

    info.is_valid = entries_ok;
    return info;
}
