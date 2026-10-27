#pragma once
#include "../includes.h"

namespace svm {

#pragma pack(push, 1)
struct gdt_entry_t {
    u16 limit_low;
    u16 base_low;
    u8 base_mid;
    u8 access;
    u8 granularity;
    u8 base_high;
};
#pragma pack(pop)
static_assert(sizeof(gdt_entry_t) == 8, "GDT entry size mismatch");
#pragma pack(push, 1)
struct gdt_descriptor_t {
    u16 limit;
    u64 base;
};
#pragma pack(pop)
#pragma pack(push, 1)
struct tss64_t {
    u32 reserved0;
    u64 rsp0;
    u64 rsp1;
    u64 rsp2;
    u64 reserved1;
    u64 ist1;
    u64 ist2;
    u64 ist3;
    u64 ist4;
    u64 ist5;
    u64 ist6;
    u64 ist7;
    u64 reserved2;
    u16 reserved3;
    u16 iopb_offset;
};
#pragma pack(pop)
static_assert(sizeof(tss64_t) == 104, "TSS64 size mismatch");
}
