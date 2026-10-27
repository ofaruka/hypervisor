#pragma once
/* ------------------ */

// Windows 11 25H2 (build 26200) layout — regenerated from ntkrnlmp.pdb
// (2A6E73CB5CCE9CCDA64E151FAC38D45C1). Only the fields the hypervisor reads
// are modeled explicitly; everything else is padding.
//   Pcb                0x0   (sizeof 0x1c8)
//   UniqueProcessId    0x1d0
//   ActiveProcessLinks 0x1d8
//   SectionBaseAddress 0x2b0
//0x840 bytes (sizeof)
struct _EPROCESS
{
    struct _KPROCESS Pcb;                                                   //0x0
    UCHAR _pad_1c8[0x1d0 - 0x1c8];                                          //0x1c8
    VOID* UniqueProcessId;                                                  //0x1d0
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x1d8
    UCHAR _pad_1e8[0x2b0 - 0x1e8];                                          //0x1e8
    VOID* SectionBaseAddress;                                               //0x2b0
    UCHAR _pad_2b8[0x840 - 0x2b8];                                          //0x2b8
};
