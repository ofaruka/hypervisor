# v0.1.0 — Initial source release

The first public snapshot of the Windows x64 hypervisor.

Included in this release:

- Intel VT-x/EPT and AMD SVM/NPT implementations.
- VM-exit and hypercall handlers, guest memory access, page hooks, MMIO handling, TPM emulation, and logging.
- A standalone x64 Visual Studio solution and PowerShell build script.
- Zydis and Zycore dependencies fetched at pinned revisions and built locally from source.

This is an experimental source release. The custom loader entry point and absence of a conventional unload callback require separate integration work. There is no signed driver package or installer, and hardware compatibility has not been established for this release.

Release and Debug x64 builds passed with Visual Studio 18 Community and WDK 10.0.28000.0. These checks covered compilation and linking; no driver was loaded during release preparation.

The project is published without a project license. Third-party components retain their existing terms.
