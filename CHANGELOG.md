# Changelog

## 0.1.0 — 2026-10-27

Initial public source snapshot.

- Intel VT-x/EPT and AMD SVM/NPT backends.
- VM-exit handling, guest memory access, page hooks, MMIO handling, TPM emulation, and logging.
- Standalone x64 Visual Studio solution and PowerShell build script.
- Pinned disassembler dependencies built locally from source.
- Build instructions, source overview, and third-party notices.

This release contains the hypervisor source and dependency build scripts. It does not include prebuilt libraries, a signed hypervisor binary, installer, EFI loader, companion driver, or client. Runtime compatibility across Windows builds and processor models is unverified for this release.
