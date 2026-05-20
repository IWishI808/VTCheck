#pragma once

#include <Windows.h>
#include <cstdint>

#define VTCHECK_MAX_ENTRIES     256
#define VTCHECK_MAX_BASES       32
#define VTCHECK_MAX_NAME_LEN    256
#define VTCHECK_MAX_MODULE_LEN  260

typedef struct _VTABLE_INFO {
    void*       object_addr;
    uintptr_t   vtable_addr;
    uint32_t    entry_count;
    wchar_t     module_name[VTCHECK_MAX_MODULE_LEN];
    BOOL        is_valid;
    // per-entry results
    struct {
        uintptr_t   addr;
        BOOL        in_module;       // entry points within expected module
        BOOL        in_text;         // entry points to .text section specifically
        DWORD       page_protect;    // actual protection flags on this page
    } entries[VTCHECK_MAX_ENTRIES];
} VTABLE_INFO;

typedef struct _RTTI_INFO {
    char        class_name[VTCHECK_MAX_NAME_LEN];
    uint32_t    base_count;
    struct {
        char    name[VTCHECK_MAX_NAME_LEN];
        int32_t mdisp;  // member displacement
        int32_t pdisp;  // vbtable displacement
        int32_t vdisp;  // displacement inside vbtable
    } base_classes[VTCHECK_MAX_BASES];
} RTTI_INFO;

// --- vtable_scan.cpp ---

// Check if a vtable pointer lands in .rdata of the given module.
BOOL validate_vtable_pointer(uintptr_t vtable_addr, HMODULE hmod);

// Validate that each vtable entry points within the expected module's .text.
// Populates entry_count with number of entries found.
BOOL validate_vtable_entries(uintptr_t vtable_addr, HMODULE hmod,
                             VTABLE_INFO* out, uint32_t max_entries);

// VirtualQuery the vtable region and check PAGE_READONLY.
BOOL check_memory_protection(uintptr_t vtable_addr);

// Full scan: combines pointer validation, entry checks, and protection check.
VTABLE_INFO scan_object(void* object, const wchar_t* expected_module);

// --- rtti_parse.cpp ---

// Read MSVC CompleteObjectLocator from vtable[-1].
// Returns the COL address, or 0 on failure.
uintptr_t read_complete_object_locator(uintptr_t vtable_addr);

// Extract demangled class name from TypeDescriptor.
BOOL parse_type_descriptor(uintptr_t type_desc_rva, HMODULE hmod,
                           char* out_name, size_t name_len);

// Walk ClassHierarchyDescriptor and fill base class info.
BOOL walk_class_hierarchy(uintptr_t col_addr, HMODULE hmod,
                          RTTI_INFO* out);

// Validate entire RTTI chain: COL -> CHD -> BCD[] -> TypeDescriptors.
// All pointers must resolve within module bounds.
BOOL validate_rtti_chain(void* object, const wchar_t* module_name,
                         RTTI_INFO* out);

// --- dxgi_monitor.cpp ---

// Locate the vtable of an IDXGISwapChain instance.
uintptr_t get_swapchain_vtable(void* swapchain);

// Validate Present (vtable index 8) against on-disk image.
// Returns TRUE if the entry matches the original.
BOOL monitor_present(void* swapchain, const wchar_t* dxgi_module);

// TODO: continuous monitoring thread
// DWORD WINAPI vtable_monitor_thread(LPVOID param);
