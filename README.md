# VTCheck

Runtime vtable integrity checker for Windows x64 binaries. Validates that vtable pointers and their entries haven't been tampered with by comparing against the on-disk module image.

Currently focused on DXGI/D3D vtables but the core validation logic is generic.

## What it does

- Validates vtable pointers land in `.rdata` of the expected module
- Checks each vtable entry points to code within the expected module's `.text` section
- Verifies memory protection on vtable regions (should be PAGE_READONLY)
- Parses MSVC RTTI structures to validate the class hierarchy chain
- Monitors IDXGISwapChain::Present for hooks

## Building

Visual Studio 2022, x64. No external dependencies.

```
msbuild VTCheck.sln /p:Configuration=Release /p:Platform=x64
```

Or just open the sln and hit build.

## Usage

```cpp
#include "vtcheck.h"

// Validate any COM object's vtable
IUnknown* obj = /* ... */;
VTABLE_INFO info = scan_object(obj, L"d3d11.dll");
if (!info.is_valid) {
    // vtable has been modified
}

// RTTI validation
RTTI_INFO rtti = {};
if (validate_rtti_chain(obj, L"dxgi.dll", &rtti)) {
    printf("class: %s\n", rtti.class_name);
}
```

## Status

WIP. Core validation works but needs more testing against real hooks. DXGI monitoring loop is rough.

## Notes

- Only supports x64 MSVC binaries (RTTI layout is compiler-specific)
- vtable[-1] points to CompleteObjectLocator in MSVC ABI
- Module base address caching needs work for modules that get rebased
