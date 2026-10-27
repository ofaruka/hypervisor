# Third-party notices

The project has no project-level license. The components below retain their original terms and notices.

| Component | Files or revision | Terms |
| --- | --- | --- |
| [Zydis 4.0.0](https://github.com/zyantific/zydis/tree/1ba75aeefae37094c7be8eba07ff81d4fe0f1f20) | `1ba75aeefae37094c7be8eba07ff81d4fe0f1f20` | [MIT](licenses/Zydis-MIT.txt) |
| [Zycore](https://github.com/zyantific/zycore-c/tree/1401fb85ac313f6605ec795c52bf99ea3f292a69) | `1401fb85ac313f6605ec795c52bf99ea3f292a69` | [MIT](licenses/Zycore-MIT.txt) |
| Intel TPM definitions, from [EDK II](https://github.com/tianocore/edk2) | `src/svm/utilities_ctx/tpm/includes/tpm12.h`, `tpm20.h` | BSD; see the preserved file headers and [license text](licenses/EDK-II-BSD.txt) |

The build script fetches these exact revisions into `artifacts/deps` and builds them locally. The Zycore revision is the dependency recorded by Zydis 4.0.0. No prebuilt disassembler libraries are included in the repository.

The TPM headers retain Intel's copyright notices: 2006–2010 for the TPM 1.2 definitions and 2013 for the TPM 2.0 definitions. The EDK II BSD license text is included separately; it does not license the surrounding hypervisor implementation.
