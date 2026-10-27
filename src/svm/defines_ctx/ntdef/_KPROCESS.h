#pragma once
/* ------------------ */

// Windows 11 25H2 (build 26200) layout — regenerated from ntkrnlmp.pdb
// (2A6E73CB5CCE9CCDA64E151FAC38D45C1). Only the fields the hypervisor reads
// are modeled explicitly; everything else is padding.
//0x1c8 bytes (sizeof)
struct _KPROCESS
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    UCHAR _pad_30[0x1c8 - 0x30];                                            //0x30
};
