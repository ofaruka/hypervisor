# Hypervisor

A Windows x64 hypervisor written in C++ with Intel VT-x/EPT and AMD SVM/NPT support.

Tested on both Intel VT-x and AMD SVM.

## Features

- Intel VT-x with Extended Page Tables (EPT).
- AMD SVM with Nested Page Tables (NPT).
- VM-exit and hypercall handling.
- Guest memory access and page hooks.
- MMIO handling and TPM emulation.
- In-memory logging.

## Processor requirements

An x64 processor with Intel VT-x and EPT, or AMD SVM and NPT. Hardware virtualization must be enabled in the system firmware.

## Build

Requirements:

- Windows x64.
- Visual Studio 2022 or 2026 with C++ build tools and MASM.
- Windows Driver Kit with the `WindowsKernelModeDriver10.0` toolset.
- Git and CMake.

From the repository root:

```powershell
.\scripts\build.ps1 -Configuration Release
```

The script fetches pinned Zydis and Zycore revisions and builds them under `artifacts/deps`. An internet connection is required for the first build.

Use `-Configuration Debug` for a debug build. After preparing the dependencies, `hypervisor.sln` can also be built in Visual Studio.

Output: `artifacts/x64/Release/crybullet_p2c_hypervisor.sys`.

## Source layout

| Path | Contents |
| --- | --- |
| `src/main.cpp` | Initialization and CPU vendor dispatch |
| `src/svm/` | AMD SVM backend, NPT, and shared utilities |
| `src/vtx/` | Intel VT-x backend and EPT |
| `src/*/handlers_ctx/` | VM-exit and hypercall handlers |
| `src/svm/utilities_ctx/tpm/` | TPM emulation and related definitions |
| `scripts/` | Build and dependency preparation |

The loader entry point is `driver_entry(PVOID, SIZE_T)` in `src/main.cpp`.

## License

No project license is granted. Third-party licenses are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
