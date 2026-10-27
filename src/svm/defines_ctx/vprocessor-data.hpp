#pragma once
#include "../includes.h"

namespace svm {

struct os_version_t {
    u32 build_number;
    u16 major_version;
    u16 minor_version;
    u32 service_version;
};
struct alignas(16) shadow {
    struct {
        bool should_exit : 1;
        bool intercept_rdtsc_pending : 1;
        bool timing_window_open : 1;
    };
    svm::efer_msr efer;
    svm::hsave_pa_msr hsave_pa;
};
struct debug_state_t {
    struct {
        u64 dr0, dr1, dr2, dr3, dr6, dr7;
    } guest;
    struct {
        u64 dr0, dr1, dr2, dr3, dr6, dr7;
    } host;
};
struct leave_state_t {
    u64 guest_pat;
    descriptor_table_register_t* original_idtr;
    descriptor_table_register_t* original_gdtr;
};
struct alignas(0x1000) shared_vcpu {
    os_version_t os_type;
    debug_state_t debug_state;
    cr3_t system_cr3;
    _EPROCESS* system_eprocess;
};
using pshared_vcpu_t = shared_vcpu*;
// Guest-observed cost of an intercepted CPUID is hidden by returning a
// synthetic TSC for the timestamp read that follows it. The subtracted
// overhead is calculated at runtime from measured exit round-trips;
// these are the seeds/bounds for that calculation.
inline constexpr u64 default_cpuid_exit_adjustment = 1000;
inline constexpr u64 vmexit_reentry_overhead = 400;
inline constexpr u64 exit_overhead_sample_min = 300;
inline constexpr u64 exit_overhead_sample_max = 15000;
// Max instruction-stream distance (bytes) between the arming cpuid and
// the intercepted timestamp read for the read to close the pair.
inline constexpr u64 armed_cpuid_max_distance = 32;
// Max age of the guest's last rdtsc for it to anchor a following pair.
inline constexpr u64 t1_anchor_max_window = 1000000;
// Max instruction-stream distance (bytes) between two adjacent rdtsc
// reads for the second to be treated as a back-to-back granularity probe.
inline constexpr u64 sequential_rdtsc_max_distance = 32;
// Last intercepted timestamp read, tracked separately for kernel and
// user mode and keyed by process, so unrelated readers never clobber a
// detector's own t1.
struct rdtsc_track_t {
    u64 entry_tsc;
    u64 value;
    u64 rip;
    u64 cr3;
};
struct alignas(0x1000) vprocessor_data {
    union {
        u8 host_stack_limit[0x6000];
        struct {
            u8 stack_contents[0x6000 - (sizeof(u64) * 7) - sizeof(leave_state_t) - sizeof(KTRAP_FRAME) - sizeof(shadow) -
                              sizeof(msrpm_t*)];
            msrpm_t* active_msrpm;
            u64 guest_vmcb_pa;
            u64 host_vmcb_pa;
            vprocessor_data* self;
            pshared_vcpu_t shared_vcpu;
            u64 pending_tlb_flush;
            leave_state_t leave_state;
            KTRAP_FRAME trap_frame;
            shadow shadow_data;
            u64 vmexit_entry_tsc; // written by the vmexit asm entry (first instructions, pre-prologue)
        } host_stack_layout;
    };
    vmcb_t guest_vmcb;
    vmcb_t host_vmcb;
    npt_data_t npt[2];
    idt_entry_t host_idt_entries[256];
    descriptor_table_register_t original_idtr;
    segment_descriptor_t host_gdt_entries[256];
    descriptor_table_register_t original_gdtr;
    tss64_t host_tss;
    u16 host_tr_selector;
    u16 host_gdtr_limit;
    void* ist1_stack;
    void* ist2_stack;
    u64 cpuid_exit_tsc;
    u64 measured_rdtsc_delta;
    u64 vmexit_leave_tsc;
    u64 measured_cpuid_delta;
    u64 measured_exit_overhead;
    u64 last_timing_window;
    u64 armed_cpuid_rip;
    rdtsc_track_t last_rdtsc[2];
    alignas(0x1000) u8 host_state_area[0x1000];
};
using pvcpu_t = vprocessor_data*;
static_assert(sizeof(vprocessor_data) ==
                  0x9000 + (sizeof(vmcb_t) * 2) + (sizeof(npt_data_t) * 2),
              "vprocessor_data size mismatch");
// host_vmexit_entry_tsc (svm_x64.asm) is rsp-relative to guest_vmcb_pa.
static_assert(offsetof(vprocessor_data, host_stack_layout.vmexit_entry_tsc) -
                  offsetof(vprocessor_data, host_stack_layout.guest_vmcb_pa) ==
                  0x1f0,
              "vmexit_entry_tsc offset must match host_vmexit_entry_tsc in svm_x64.asm");
}
