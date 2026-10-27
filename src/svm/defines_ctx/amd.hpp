#pragma once
#include "../includes.h"

namespace svm {

typedef struct _processor_number {
    u16 group;
    u8 number;
    u8 reserved;
    ULONG get_processor_index() {
        PROCESSOR_NUMBER processor_num;
        KeGetCurrentProcessorNumberEx(&processor_num);
        return KeGetProcessorIndexFromNumber(&processor_num);
    }
} processor_number, *pprocessor_number;
typedef struct DECLSPEC_ALIGN(16) DECLSPEC_NOINITALL _context_t {
    u64 p1_home;
    u64 p2_home;
    u64 p3_home;
    u64 p4_home;
    u64 p5_home;
    u64 p6_home;
    u32 context_flags;
    u32 mx_csr;
    u16 seg_cs;
    u16 seg_ds;
    u16 seg_es;
    u16 seg_fs;
    u16 seg_gs;
    u16 seg_ss;
    u32 e_flags;
    u64 dr0;
    u64 dr1;
    u64 dr2;
    u64 dr3;
    u64 dr6;
    u64 dr7;
    u64 rax;
    u64 rcx;
    u64 rdx;
    u64 rbx;
    u64 rsp;
    u64 rbp;
    u64 rsi;
    u64 rdi;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
    u64 rip;
    union {
        XMM_SAVE_AREA32 flt_save;
        struct {
            M128A header[2];
            M128A legacy[8];
            M128A xmm0;
            M128A xmm1;
            M128A xmm2;
            M128A xmm3;
            M128A xmm4;
            M128A xmm5;
            M128A xmm6;
            M128A xmm7;
            M128A xmm8;
            M128A xmm9;
            M128A xmm10;
            M128A xmm11;
            M128A xmm12;
            M128A xmm13;
            M128A xmm14;
            M128A xmm15;
        } dummy_struct_name;
    } dummy_union_name;
    M128A vector_register[26];
    u64 vector_control;
    u64 debug_control;
    u64 last_branch_to_rip;
    u64 last_branch_from_rip;
    u64 last_exception_to_rip;
    u64 last_exception_from_rip;
    void* get_current_context() {
        pcontext_t current_ctx =
            reinterpret_cast<pcontext_t>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(svm::context_t), 'vmm'));
        if (current_ctx) {
            RtlZeroMemory(current_ctx, sizeof(svm::context_t));
            RtlCaptureContext(reinterpret_cast<PCONTEXT>(current_ctx));
            return current_ctx;
        }

        return nullptr;
    }
} context_t, *pcontext_t;
}
