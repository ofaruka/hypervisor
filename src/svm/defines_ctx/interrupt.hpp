#pragma once
#include "../includes.h"

namespace svm {

#pragma pack(push, 1)
struct idt_entry_t {
    u16 offset_low;
    u16 selector;
    u8 ist : 3;
    u8 reserved0 : 5;
    u8 type : 4;
    u8 zero : 1;
    u8 dpl : 2;
    u8 present : 1;
    u16 offset_mid;
    u32 offset_high;
    u32 reserved1;
};
#pragma pack(pop)
static_assert(sizeof(idt_entry_t) == 16, "IDT entry size mismatch");
#pragma pack(push, 1)
struct idt_descriptor_t {
    u16 limit;
    u64 base;
};
#pragma pack(pop)
struct interrupt_frame_t {
    uint64_t return_rip;
    uint64_t return_cs;
    uint64_t return_rflags;
    uint64_t return_rsp;
    uint64_t return_ss;
};
using pinterrupt_frame_t = interrupt_frame_t*;
struct interrupt_frame_with_error_t {
    uint64_t error_code;
    uint64_t return_rip;
    uint64_t return_cs;
    uint64_t return_rflags;
    uint64_t return_rsp;
    uint64_t return_ss;
};
using pinterrupt_frame_with_error_t = interrupt_frame_with_error_t*;
struct gpr_state_t {
    uint64_t r15;
    uint64_t r14;
    uint64_t r13;
    uint64_t r12;
    uint64_t r11;
    uint64_t r10;
    uint64_t r9;
    uint64_t r8;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t rbx;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t rax;
};
using pgpr_state_t = gpr_state_t*;
}
