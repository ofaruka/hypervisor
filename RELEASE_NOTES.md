# v0.1.0 — Initial release

A Windows x64 hypervisor written in C++ with Intel VT-x/EPT and AMD SVM/NPT support.

Tested on both Intel VT-x and AMD SVM.

- Intel VT-x/EPT and AMD SVM/NPT implementations.
- VM-exit and hypercall handlers, guest memory access, page hooks, MMIO handling, TPM emulation, and logging.
- Visual Studio solution and PowerShell build script with pinned Zydis and Zycore dependencies.

Build instructions are in the [README](https://github.com/ofaruka/hypervisor#build).
