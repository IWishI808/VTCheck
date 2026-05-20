#include "vtcheck.h"
#include <Psapi.h>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "psapi.lib")

// ============================================================================
// DXGI-specific vtable monitoring
//
// IDXGISwapChain vtable layout (indices):
//   0  QueryInterface
//   1  AddRef
//   2  Release
//   3  SetPrivateData
//   4  SetPrivateDataInterface
//   5  GetPrivateData
//   6  GetParent
//   7  GetDevice
//   8  Present              <-- primary hook target
//   9  GetBuffer
//   10 SetFullscreenState
//   11 GetFullscreenState
//   12 GetDesc
//   13 ResizeBuffers        <-- also commonly hooked
//   14 ResizeTarget
//   ...
// ============================================================================

#define DXGI_PRESENT_INDEX      8
#define DXGI_RESIZEBUFFERS_INDEX 13

// ============================================================================
// Internal: read original vtable entry from the on-disk PE image
// ============================================================================

// Find a section's raw (file) offset and virtual address from the PE headers.
static BOOL get_section_mapping(HMODULE hmod, const char* section_name,
                                uint32_t* out_va, uint32_t* out_raw_offset,
                                uint32_t* out_raw_size)
{
    auto dos = (PIMAGE_DOS_HEADER)hmod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    auto nt = (PIMAGE_NT_HEADERS64)((uint8_t*)hmod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (strncmp((const char*)sec->Name, section_name, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            *out_va         = sec->VirtualAddress;
            *out_raw_offset = sec->PointerToRawData;
            *out_raw_size   = sec->SizeOfRawData;
            return TRUE;
        }
    }
    return FALSE;
}

// Read the original value of a vtable entry from the on-disk module file.
// This bypasses any in-memory patches.
//
// TODO: this is slow -- reads from disk every time. Should cache the .rdata
// section on first call and compare against that. Also doesn't handle
// relocations properly yet (assumes preferred base).
static BOOL read_original_vtable_entry(const wchar_t* module_path, HMODULE hmod,
                                       uintptr_t vtable_addr, uint32_t index,
                                       uintptr_t* out_original)
{
    if (!module_path || !hmod || !out_original)
        return FALSE;

    uintptr_t mod_base = (uintptr_t)hmod;

    // Figure out which section the vtable is in and its file offset
    uint32_t rdata_va = 0, rdata_raw = 0, rdata_size = 0;
    if (!get_section_mapping(hmod, ".rdata", &rdata_va, &rdata_raw, &rdata_size))
        return FALSE;

    // Calculate the file offset of the vtable entry
    uintptr_t vtable_rva = vtable_addr - mod_base;
    if (vtable_rva < rdata_va || vtable_rva >= rdata_va + rdata_size)
        return FALSE; // vtable not in .rdata?

    uint32_t offset_in_section = (uint32_t)(vtable_rva - rdata_va);
    uint32_t file_offset = rdata_raw + offset_in_section + (index * sizeof(uintptr_t));

    // Read from the file
    HANDLE hFile = CreateFileW(module_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    LARGE_INTEGER li;
    li.QuadPart = file_offset;
    if (!SetFilePointerEx(hFile, li, NULL, FILE_BEGIN)) {
        CloseHandle(hFile);
        return FALSE;
    }

    uintptr_t raw_value = 0;
    DWORD bytes_read = 0;
    BOOL ok = ReadFile(hFile, &raw_value, sizeof(raw_value), &bytes_read, NULL);
    CloseHandle(hFile);

    if (!ok || bytes_read != sizeof(raw_value))
        return FALSE;

    // The on-disk value is a VA assuming preferred image base.
    // Need to adjust if the module was rebased.
    // TODO: handle ASLR rebasing properly. For now, use the delta between
    // preferred base and actual base.
    auto nt = (PIMAGE_NT_HEADERS64)((uint8_t*)hmod +
              ((PIMAGE_DOS_HEADER)hmod)->e_lfanew);
    uintptr_t preferred_base = nt->OptionalHeader.ImageBase;
    intptr_t rebase_delta = (intptr_t)(mod_base - preferred_base);

    *out_original = raw_value + rebase_delta;
    return TRUE;
}

// ============================================================================
// Get module file path from handle
// ============================================================================

static BOOL get_module_path(HMODULE hmod, wchar_t* path, DWORD path_len)
{
    return GetModuleFileNameExW(GetCurrentProcess(), hmod, path, path_len) > 0;
}

// ============================================================================
// Public API
// ============================================================================

uintptr_t get_swapchain_vtable(void* swapchain)
{
    if (!swapchain)
        return 0;

    // COM objects: first pointer-sized value at the object address is the vtable
    uintptr_t vtable = *(uintptr_t*)swapchain;
    return vtable;
}

BOOL monitor_present(void* swapchain, const wchar_t* dxgi_module)
{
    if (!swapchain || !dxgi_module)
        return FALSE;

    HMODULE hmod = GetModuleHandleW(dxgi_module);
    if (!hmod)
        return FALSE;

    uintptr_t vtable = get_swapchain_vtable(swapchain);
    if (!vtable)
        return FALSE;

    // Read the current in-memory value of Present
    uintptr_t* vtable_entries = (uintptr_t*)vtable;
    uintptr_t current_present = vtable_entries[DXGI_PRESENT_INDEX];

    // Read the original from disk
    wchar_t mod_path[MAX_PATH] = {};
    if (!get_module_path(hmod, mod_path, MAX_PATH))
        return FALSE;

    uintptr_t original_present = 0;
    if (!read_original_vtable_entry(mod_path, hmod, vtable,
                                    DXGI_PRESENT_INDEX, &original_present)) {
        // Can't read original -- assume compromised
        // TODO: this fails on first call if dxgi.dll hasn't been cached yet.
        // Need a better fallback.
        return FALSE;
    }

    if (current_present != original_present) {
        // Present has been hooked
        // TODO: log the hook target address, try to identify which module
        // owns the hook (GetMappedFileName on the target page).
        return FALSE;
    }

    // Also check ResizeBuffers while we're at it
    uintptr_t current_resize = vtable_entries[DXGI_RESIZEBUFFERS_INDEX];
    uintptr_t original_resize = 0;
    if (read_original_vtable_entry(mod_path, hmod, vtable,
                                   DXGI_RESIZEBUFFERS_INDEX, &original_resize)) {
        if (current_resize != original_resize)
            return FALSE;
    }

    return TRUE;
}

// TODO: monitoring thread that calls monitor_present() on a timer.
// Rough idea:
//
// struct MonitorContext {
//     void*       swapchain;
//     wchar_t     module[MAX_PATH];
//     DWORD       interval_ms;
//     volatile BOOL running;
// };
//
// DWORD WINAPI vtable_monitor_thread(LPVOID param) {
//     auto ctx = (MonitorContext*)param;
//     while (ctx->running) {
//         if (!monitor_present(ctx->swapchain, ctx->module)) {
//             // hook detected -- notify via callback? event? OutputDebugString?
//         }
//         Sleep(ctx->interval_ms);
//     }
//     return 0;
// }
//
// Problems to solve:
// - swapchain pointer might become invalid (device lost, resize)
// - need to re-acquire after device recreation
// - thread safety around the swapchain pointer
// - what to do when a hook is detected (just log? block? restore?)
