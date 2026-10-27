# Hypervisor

An experimental Windows x64 hypervisor with Intel VT-x and AMD SVM backends, written in C++20 and x64 assembly.

The implementation includes EPT/NPT management, VM-exit handling, guest memory access, page hooks, MMIO handling, TPM emulation, and an in-memory logger. The entry point selects the backend from the CPU vendor.

## Status

`v0.1.0` is the first public source snapshot. Compatibility across processor models and Windows builds has not been established for this release. TPM emulation is part of the implementation; full TPM specification compliance is not claimed.

This repository contains the hypervisor component. Its custom `driver_entry(PVOID, SIZE_T)` entry point expects integration with a separate loader, and it does not register a conventional `DriverUnload` callback. The EFI loader, companion driver, and client from the original workspace are outside this release. There is no installer or signed driver package.

Runtime work requires a dedicated test machine with kernel debugging and a recovery path. A successful build alone does not establish that a configuration is safe to load.

## Build

Use Windows x64 with Visual Studio C++ build tools and a compatible Windows Driver Kit that provides the `WindowsKernelModeDriver10.0` toolset. MASM and C++20 support are required, along with Git and CMake.

From the repository root:

```powershell
.\scripts\build.ps1 -Configuration Release
```

The first build fetches pinned Zydis and Zycore source revisions and builds their static libraries locally under `artifacts/deps`. It requires an internet connection. No NuGet restore is needed.

For a debug build, use `-Configuration Debug`. After preparing the dependencies with the script, you can also open `hypervisor.sln` in Visual Studio and select `Release | x64` or `Debug | x64`.

The release output is `artifacts/x64/Release/crybullet_p2c_hypervisor.sys`. The build script compiles the project; it does not sign or load the result.

Both x64 configurations were compiled with Visual Studio 18 Community and WDK 10.0.28000.0 for this snapshot. No hardware runtime testing was performed as part of the release checks.

## Source layout

| Path | Contents |
| --- | --- |
| `src/main.cpp` | Initialization and CPU vendor dispatch |
| `src/svm/` | AMD SVM backend, NPT, and shared utilities |
| `src/vtx/` | Intel VT-x backend and EPT |
| `src/*/handlers_ctx/` | VM-exit and hypercall handlers |
| `src/svm/utilities_ctx/tpm/` | TPM emulation and related definitions |
| `scripts/` | Build and dependency preparation |

See [CHANGELOG.md](CHANGELOG.md) for release notes and [CONTRIBUTING.md](CONTRIBUTING.md) for issue reporting.

## License

This project is published without a project license. No reuse license is granted for the project code. Third-party components retain their own license terms; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
