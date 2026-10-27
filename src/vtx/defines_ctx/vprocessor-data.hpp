#pragma once
#include "../../includes.h"

namespace vtx {
    struct ept_hook_node;

    struct guest_gprs {
        u64 r15, r14, r13, r12, r11, r10, r9, r8;
        u64 rdi, rsi, rbp, _rsp_placeholder, rbx, rdx, rcx, rax;
    };
    static_assert(sizeof(guest_gprs) == 128, "guest_gprs must be 16 qwords");

    struct debug_register_state {
        u64 dr0;
        u64 dr1;
        u64 dr2;
        u64 dr3;
        u64 dr6;
        u64 dr7;
    };

    struct vmx_msr_entry {
        u32 index;
        u32 reserved;
        u64 value;
    };
    static_assert(sizeof(vmx_msr_entry) == 16, "vmx_msr_entry size");

    constexpr u32 managed_msr_count_max = 8;
    constexpr u32 host_stack_size = 0x6000;
    // Legacy seed for the CPUID-exit TSC adjustment, used until the runtime
    // round-trip calibration produces its first measured sample.
    constexpr u64 cpuid_tsc_entry_adjustment = 1112;
    // Share of a measured round-trip (leave -> re-enter -> exit) attributed to
    // the re-entry path (vmresume + one guest instruction); the remainder is
    // the exit-side overhead the guest would have observed.
    constexpr u64 vmexit_reentry_overhead = 700;
    constexpr u64 exit_overhead_sample_min = 300;
    constexpr u64 exit_overhead_sample_max = 15000;
    // Round-trip window beyond which a pending anchor is considered stale
    // (unrelated guest code ran since the arming cpuid) and the native
    // clock is returned instead of a synthetic value.
    constexpr u64 exit_window_stale_threshold = 25000;

    enum timing_source : u8 {
        timing_source_none = 0,
        timing_source_tsc = 1,
        timing_source_aperf = 2,
        timing_source_mperf = 3,
        timing_source_rdpmc_fixed1 = 4,
        timing_source_rdpmc_fixed2 = 5,
        timing_source_rdtscp = 6,
    };

    struct alignas(0x1000) vprocessor_data {
        alignas(0x1000) u8 vmxon_region[0x1000];
        alignas(0x1000) u8 vmcs_region[0x1000];
        alignas(0x1000) u8 msr_bitmap[0x1000];
        alignas(0x10) u8 host_stack[host_stack_size];

        vprocessor_data* self;

        u64 devirt_rip;
        u64 devirt_rsp;
        u64 devirt_rflags;

        ept_hook_node* pending_mtf_unhide;
        volatile u8 launched;

        u64 guest_cr0;
        u64 guest_cr3;
        u64 guest_cr4;
        u64 devirt_cr0;
        u64 devirt_cr3;
        u64 devirt_cr4;
        u64 vmexit_entry_tsc;
        u64 cpuid_exit_tsc;
        u64 measured_rdtsc_delta;
        volatile u8 intercept_rdtsc_pending;
        u64 tsc_offset;
        u64 tsc_adjust;
        u64 last_timing_read_value;
        u64 last_timing_read_host_tsc;
        u64 synthetic_timing_value;
        u8 last_timing_source;
        u8 synthetic_timing_source;
        u64 guest_xcr0;
        u64 lbr_shadow[5];
        u64 fixed_ctr_exit[3];

        debug_register_state guest_debug;
        debug_register_state host_debug;
        volatile u8 pending_external_interrupt;
        u8 pending_external_vector;
        volatile u8 pending_nmi;
        volatile u8 nmi_active;
        u32 managed_msr_count;
        alignas(0x10) vmx_msr_entry managed_msrs[managed_msr_count_max];
        alignas(0x10) vmx_msr_entry host_msrs[managed_msr_count_max];
        host_pt_t* host_pt;
        u64 host_cr3;
        svm::descriptor_table_register_t host_gdtr;
        svm::descriptor_table_register_t host_idtr;
        u8 timing_record_next;

        // Runtime exit-overhead calibration (cpuid/rdtsc timing spoof).
        u64 vmexit_leave_tsc;
        u64 measured_cpuid_delta;
        u64 measured_exit_overhead;
        u8 timing_window_open;
    };
    using pvcpu_t = vprocessor_data*;

    static_assert(offsetof(vprocessor_data, self) == 0x9000, "self offset");
    static_assert(offsetof(vprocessor_data, devirt_rip) == 0x9008, "devirt_rip offset");
    static_assert(offsetof(vprocessor_data, devirt_rsp) == 0x9010, "devirt_rsp offset");
    static_assert(offsetof(vprocessor_data, devirt_rflags) == 0x9018, "devirt_rflags offset");
    static_assert(offsetof(vprocessor_data, pending_mtf_unhide) == 0x9020, "pending_mtf_unhide offset");
    static_assert(offsetof(vprocessor_data, launched) == 0x9028, "launched offset");
    static_assert(offsetof(vprocessor_data, guest_cr0) == 0x9030, "guest_cr0 offset");
    static_assert(offsetof(vprocessor_data, guest_cr3) == 0x9038, "guest_cr3 offset");
    static_assert(offsetof(vprocessor_data, guest_cr4) == 0x9040, "guest_cr4 offset");
    static_assert(offsetof(vprocessor_data, devirt_cr0) == 0x9048, "devirt_cr0 offset");
    static_assert(offsetof(vprocessor_data, devirt_cr3) == 0x9050, "devirt_cr3 offset");
    static_assert(offsetof(vprocessor_data, devirt_cr4) == 0x9058, "devirt_cr4 offset");
    static_assert(offsetof(vprocessor_data, vmexit_entry_tsc) == 0x9060, "vmexit_entry_tsc offset");
    static_assert(offsetof(vprocessor_data, host_gdtr) == 0x9270, "host_gdtr offset");
    static_assert(offsetof(vprocessor_data, host_idtr) == 0x927a, "host_idtr offset");
    static_assert((sizeof(vprocessor_data) % PAGE_SIZE) == 0,
        "vprocessor_data must remain page-rounded for EPT hiding");
    constexpr u32 vprocessor_data_page_count =
        static_cast<u32>(sizeof(vprocessor_data) / PAGE_SIZE);
}
