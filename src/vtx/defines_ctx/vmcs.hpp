#pragma once
#include "../../includes.h"

namespace vtx {
    // VMCS field encodings (Intel SDM Vol 3, Appendix B). Only fields actually
    // touched by setup_vmcs / exit handlers are listed; add more as needed.
    enum class vmcs_field : u32 {
        // 16-bit control
        virtual_processor_id = 0x0000,

        // 16-bit guest selectors
        guest_es_sel       = 0x0800,
        guest_cs_sel       = 0x0802,
        guest_ss_sel       = 0x0804,
        guest_ds_sel       = 0x0806,
        guest_fs_sel       = 0x0808,
        guest_gs_sel       = 0x080a,
        guest_ldtr_sel     = 0x080c,
        guest_tr_sel       = 0x080e,

        // 16-bit host selectors
        host_es_sel        = 0x0c00,
        host_cs_sel        = 0x0c02,
        host_ss_sel        = 0x0c04,
        host_ds_sel        = 0x0c06,
        host_fs_sel        = 0x0c08,
        host_gs_sel        = 0x0c0a,
        host_tr_sel        = 0x0c0c,

        // 64-bit control
        msr_bitmap         = 0x2004,
        vm_exit_msr_store_addr = 0x2006,
        vm_exit_msr_load_addr  = 0x2008,
        vm_entry_msr_load_addr = 0x200a,
        tsc_offset         = 0x2010,
        ept_pointer        = 0x201a,

        // 64-bit read-only — set on EPT_VIOLATION exit
        guest_physical_address = 0x2400,

        // 64-bit guest
        vmcs_link_pointer  = 0x2800,
        guest_ia32_debugctl= 0x2802,
        guest_ia32_pat     = 0x2804,
        guest_ia32_efer    = 0x2806,

        // 64-bit host
        host_ia32_pat      = 0x2c00,
        host_ia32_efer     = 0x2c02,

        // 32-bit control
        pin_based_ctls            = 0x4000,
        procbased_ctls            = 0x4002,
        exception_bitmap          = 0x4004,
        page_fault_error_code_mask  = 0x4006,
        page_fault_error_code_match = 0x4008,
        cr3_target_count          = 0x400a,
        vm_exit_ctls              = 0x400c,
        vm_exit_msr_store_count   = 0x400e,
        vm_exit_msr_load_count    = 0x4010,
        vm_entry_ctls             = 0x4012,
        vm_entry_msr_load_count   = 0x4014,
        vm_entry_intr_info        = 0x4016,
        vm_entry_exception_err    = 0x4018,
        vm_entry_instr_len        = 0x401a,
        procbased_ctls2           = 0x401e,

        // 32-bit read-only
        vm_instruction_error = 0x4400,
        vm_exit_reason       = 0x4402,
        vm_exit_intr_info    = 0x4404,
        vm_exit_intr_err     = 0x4406,
        idt_vectoring_info   = 0x4408,
        idt_vectoring_err    = 0x440a,
        vm_exit_instr_len    = 0x440c,
        vm_exit_instr_info   = 0x440e,

        // 32-bit guest state
        guest_es_limit     = 0x4800,
        guest_cs_limit     = 0x4802,
        guest_ss_limit     = 0x4804,
        guest_ds_limit     = 0x4806,
        guest_fs_limit     = 0x4808,
        guest_gs_limit     = 0x480a,
        guest_ldtr_limit   = 0x480c,
        guest_tr_limit     = 0x480e,
        guest_gdtr_limit   = 0x4810,
        guest_idtr_limit   = 0x4812,
        guest_es_ar        = 0x4814,
        guest_cs_ar        = 0x4816,
        guest_ss_ar        = 0x4818,
        guest_ds_ar        = 0x481a,
        guest_fs_ar        = 0x481c,
        guest_gs_ar        = 0x481e,
        guest_ldtr_ar      = 0x4820,
        guest_tr_ar        = 0x4822,
        guest_interruptibility_state = 0x4824,
        guest_activity_state         = 0x4826,
        guest_sysenter_cs  = 0x482a,

        // 32-bit host state
        host_sysenter_cs   = 0x4c00,

        // Natural-width control
        cr0_guest_host_mask = 0x6000,
        cr4_guest_host_mask = 0x6002,
        cr0_read_shadow     = 0x6004,
        cr4_read_shadow     = 0x6006,

        // Natural-width read-only
        exit_qualification  = 0x6400,
        guest_linear_addr   = 0x640a,

        // Natural-width guest state
        guest_cr0          = 0x6800,
        guest_cr3          = 0x6802,
        guest_cr4          = 0x6804,
        guest_es_base      = 0x6806,
        guest_cs_base      = 0x6808,
        guest_ss_base      = 0x680a,
        guest_ds_base      = 0x680c,
        guest_fs_base      = 0x680e,
        guest_gs_base      = 0x6810,
        guest_ldtr_base    = 0x6812,
        guest_tr_base      = 0x6814,
        guest_gdtr_base    = 0x6816,
        guest_idtr_base    = 0x6818,
        guest_dr7          = 0x681a,
        guest_rsp          = 0x681c,
        guest_rip          = 0x681e,
        guest_rflags       = 0x6820,
        guest_pending_dbg_exceptions = 0x6822,
        guest_sysenter_esp = 0x6824,
        guest_sysenter_eip = 0x6826,

        // Natural-width host state
        host_cr0           = 0x6c00,
        host_cr3           = 0x6c02,
        host_cr4           = 0x6c04,
        host_fs_base       = 0x6c06,
        host_gs_base       = 0x6c08,
        host_tr_base       = 0x6c0a,
        host_gdtr_base     = 0x6c0c,
        host_idtr_base     = 0x6c0e,
        host_sysenter_esp  = 0x6c10,
        host_sysenter_eip  = 0x6c12,
        host_rsp           = 0x6c14,
        host_rip           = 0x6c16,
    };

    constexpr u32 pinbased_external_interrupt_exiting = 1u << 0;
    constexpr u32 pinbased_nmi_exiting             = 1u << 3;
    constexpr u32 pinbased_virtual_nmis            = 1u << 5;
    constexpr u32 procbased_interrupt_window_exiting = 1u << 2;
    constexpr u32 procbased_use_tsc_offsetting      = 1u << 3;
    constexpr u32 procbased_rdpmc_exiting           = 1u << 11;
    constexpr u32 procbased_rdtsc_exiting           = 1u << 12;
    constexpr u32 procbased_use_tpr_shadow          = 1u << 21;
    constexpr u32 procbased_nmi_window_exiting     = 1u << 22;
    constexpr u32 procbased_mov_dr_exiting         = 1u << 23;
    constexpr u32 procbased_monitor_trap_flag       = 1u << 27;  // single-step VM-exit after one guest insn
    constexpr u32 procbased_use_msr_bitmap          = 1u << 28;
    constexpr u32 procbased_activate_secondary      = 1u << 31;
    constexpr u32 procbased2_enable_ept             = 1u << 1;
    constexpr u32 procbased2_descriptor_table_exiting = 1u << 2;
    constexpr u32 procbased2_enable_rdtscp          = 1u << 3;
    constexpr u32 procbased2_enable_vpid            = 1u << 5;
    constexpr u32 procbased2_unrestricted_guest     = 1u << 7;
    constexpr u32 procbased2_enable_invpcid         = 1u << 12;
    constexpr u32 procbased2_enable_xsaves_xrstors  = 1u << 20;
    constexpr u32 vm_exit_host_addr_space_size      = 1u << 9;
    constexpr u32 vm_exit_ack_interrupt_on_exit     = 1u << 15;
    constexpr u32 vm_exit_load_ia32_pat             = 1u << 19;
    constexpr u32 vm_exit_load_ia32_efer            = 1u << 21;
    constexpr u32 vm_entry_ia32e_mode_guest         = 1u << 9;
    constexpr u32 vm_entry_load_debug_controls      = 1u << 2;
    constexpr u32 vm_entry_load_ia32_pat            = 1u << 14;
    constexpr u32 vm_entry_load_ia32_efer           = 1u << 15;
    constexpr u32 vm_exit_save_debug_controls       = 1u << 2;

    constexpr u32 vmx_event_valid                   = 1u << 31;
    constexpr u32 vmx_event_error_code_valid        = 1u << 11;
    constexpr u32 vmx_event_type_external_interrupt = 0u;
    constexpr u32 vmx_event_type_nmi                = 2u;
    constexpr u32 vmx_event_type_hw_exception       = 3u;
    constexpr u32 vmx_event_type_sw_interrupt       = 4u;
    constexpr u32 vmx_event_type_priv_sw_exception  = 5u;
    constexpr u32 vmx_event_type_sw_exception       = 6u;
    constexpr u32 vmx_event_type_other              = 7u;

    constexpr u8 exception_vector_debug             = 1;
    constexpr u8 exception_vector_nmi               = 2;
    constexpr u8 exception_vector_breakpoint        = 3;
    constexpr u8 exception_vector_invalid_opcode    = 6;
    constexpr u8 exception_vector_general_protection= 13;
    constexpr u8 exception_vector_double_fault      = 8;
    constexpr u8 exception_vector_invalid_tss       = 10;
    constexpr u8 exception_vector_segment_not_present = 11;
    constexpr u8 exception_vector_stack_segment     = 12;
    constexpr u8 exception_vector_page_fault        = 14;
    constexpr u8 exception_vector_alignment_check   = 17;
    constexpr u8 exception_vector_control_protection = 21;
    constexpr u8 exception_vector_security          = 30;

    constexpr u32 guest_intr_state_blocking_by_sti    = 1u << 0;
    constexpr u32 guest_intr_state_blocking_by_mov_ss = 1u << 1;
    constexpr u32 guest_intr_state_blocking_by_nmi    = 1u << 3;

    constexpr u32 guest_rflags_interrupt_enable = 1u << 9;
    constexpr u32 vm_exit_reason_entry_failure = 1u << 31;

    enum class exit_reason : u16 {
        exception_or_nmi  = 0,
        external_interrupt= 1,
        triple_fault      = 2,
        init_signal       = 3,
        sipi              = 4,
        interrupt_window  = 7,
        nmi_window        = 8,
        task_switch       = 9,
        cpuid             = 10,
        getsec            = 11,
        monitor_trap_flag = 37,
        wbinvd            = 54,
        hlt               = 12,
        invd              = 13,
        invlpg            = 14,
        rdpmc             = 15,
        rdtsc             = 16,
        vmcall            = 18,
        vmclear           = 19,
        vmlaunch          = 20,
        vmptrld           = 21,
        vmptrst           = 22,
        vmread            = 23,
        vmresume          = 24,
        vmwrite           = 25,
        vmxoff            = 26,
        vmxon             = 27,
        cr_access         = 28,
        dr_access         = 29,
        io_instruction    = 30,
        rdmsr             = 31,
        wrmsr             = 32,
        ept_violation     = 48,
        ept_misconfig     = 49,
        invept            = 50,
        rdtscp            = 51,
        invvpid           = 53,
        xsetbv            = 55,
        access_gdtr_or_idtr = 46,
        access_ldtr_or_tr = 47,
        invpcid           = 58,
        vmfunc            = 59,
    };

    // VMCALL magic codes
    constexpr u64 vmcall_magic_devirtualize = 0xCAFE0000;
    constexpr u64 vmcall_magic_invept       = 0xCAFE0001;
}
