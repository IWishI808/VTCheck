# VTCheck

VTCheck is a Windows x64 research prototype for validating COM and C++ virtual
method table integrity. It focuses on detecting vtable pointer replacement,
vtable entry redirection, suspicious memory protections, and MSVC RTTI chain
inconsistencies.

The project is defensive tooling: it helps analysts reason about hook detection
and object-layout integrity in authorized applications and lab binaries.

## What is implemented

- validation that a vtable pointer lands inside the expected module's `.rdata`
  section
- validation that vtable entries point back into the expected module image
- `.text` section checks for individual virtual function entries
- `VirtualQuery` checks for suspicious writable vtable memory
- MSVC x64 RTTI parsing through `CompleteObjectLocator`
- class hierarchy walking through RTTI descriptors
- DXGI `IDXGISwapChain::Present` and `ResizeBuffers` comparison helpers

## Defensive use cases

- detect direct vtable entry patching
- detect full vtable replacement with heap-backed copies
- validate RTTI metadata during reverse engineering
- inspect COM interfaces commonly targeted by overlays and hooks
- compare in-memory vtable entries against the expected module boundary

## Build notes

This repository exposes library-style source files rather than a standalone CLI.
Compile the source into your own Visual Studio project or object files:

```bat
cl /EHsc /W4 /O2 /DWIN32_LEAN_AND_MEAN /std:c++17 /c src\vtable_scan.cpp src\rtti_parse.cpp src\dxgi_monitor.cpp
```

Link with:

```bat
psapi.lib dbghelp.lib
```

## Example

```cpp
#include "vtcheck.h"

IUnknown* object = /* object to inspect */;
VTABLE_INFO info = scan_object(object, L"dxgi.dll");

if (!info.is_valid) {
    // vtable pointer, entries, or memory protections are suspicious
}

RTTI_INFO rtti = {};
if (validate_rtti_chain(object, L"dxgi.dll", &rtti)) {
    printf("class: %s\n", rtti.class_name);
}
```

## Current status

Core validation logic is present, but this is still research code. It needs more
testing against benign overlays, legitimate hooks, rebased modules, and multiple
compiler/RTTI configurations. The DXGI monitor is a helper, not a full
continuous monitoring agent.

## Responsible use

VTCheck is intended for defensive analysis, reverse engineering, and authorized
hook-detection labs. It does not include hook installation or bypass code.

## Related writeup

- [VMT Hooking Detection](https://iwishi808.github.io/2026/05/12/vmt-hooking-detection/)

## License

MIT
