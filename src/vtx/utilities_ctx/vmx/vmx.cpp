#include "vmx.hpp"
#include "../ept/ept.hpp"
#include "../../handlers_ctx/debug_registers/dr_vtx.hpp"
#include "../../handlers_ctx/msr/msr_vtx.hpp"
#include "../utilities.hpp"

namespace vtx {

u32 vmx::get_vmcs_revision_id() {
    return static_cast<u32>(__readmsr(vtx::msr::ia32_vmx_basic) & 0x7fffffff);
}

u64 vmx::adjust_cr0_for_vmx(u64 cr0) {
    return (cr0 | __readmsr(vtx::msr::ia32_vmx_cr0_fixed0))
         & __readmsr(vtx::msr::ia32_vmx_cr0_fixed1);
}

u64 vmx::adjust_cr4_for_vmx(u64 cr4) {
    return (cr4 | __readmsr(vtx::msr::ia32_vmx_cr4_fixed0))
         & __readmsr(vtx::msr::ia32_vmx_cr4_fixed1);
}

bool vmx::enter_vmx_root(pvcpu_t vcpu) {
    if (!vcpu) return false;
    if (!utilities::get()->ensure_feature_control()) return false;

    __sgdt(&vcpu->host_gdtr);
    __sidt(&vcpu->host_idtr);

    auto orig_cr0 = __readcr0();
    auto orig_cr3 = __readcr3();
    auto orig_cr4 = __readcr4();
    auto cr0 = adjust_cr0_for_vmx(orig_cr0);
    auto cr4 = adjust_cr4_for_vmx(orig_cr4 | cr4_vmxe_bit);

    vcpu->guest_cr0 = orig_cr0;
    vcpu->guest_cr3 = orig_cr3;
    vcpu->guest_cr4 = orig_cr4 & ~cr4_vmxe_bit;

    __writecr0(cr0);
    __writecr4(cr4);

    *reinterpret_cast<u32*>(vcpu->vmxon_region) = get_vmcs_revision_id();

    auto pa = static_cast<u64>(MmGetPhysicalAddress(vcpu->vmxon_region).QuadPart);
    if (__vmx_on(&pa) == 0) {
        return true;
    }

    __writecr4(orig_cr4);
    __writecr0(orig_cr0);
    return false;
}

void vmx::leave_vmx_root(pvcpu_t vcpu) {
    __vmx_off();

    if (vcpu) {
        __lgdt(&vcpu->host_gdtr);
        __lidt(&vcpu->host_idtr);
        __writecr4(vcpu->guest_cr4);
        __writecr0(vcpu->guest_cr0);
        return;
    }

    __writecr4(__readcr4() & ~cr4_vmxe_bit);
}

bool vmx::vmcs_init(pvcpu_t vcpu) {
    if (!vcpu) return false;

    *reinterpret_cast<u32*>(vcpu->vmcs_region) = get_vmcs_revision_id();

    auto pa = static_cast<u64>(MmGetPhysicalAddress(vcpu->vmcs_region).QuadPart);
    if (__vmx_vmclear(&pa) != 0) return false;
    if (__vmx_vmptrld(&pa) != 0) return false;
    return true;
}

u32 vmx::adjust_ctls(u32 wanted, u32 capability_msr_id) {
    u64 cap = __readmsr(capability_msr_id);
    u32 must_be_1 = static_cast<u32>(cap & 0xffffffff);
    u32 allowed_1 = static_cast<u32>(cap >> 32);
    return (wanted | must_be_1) & allowed_1;
}

vmx::segment_info vmx::read_segment(u64 gdt_base, u16 sel) {
    segment_info out{ 0, 0, segment_unusable_bit };
    if ((sel & ~7u) == 0) return out;

    auto* desc = reinterpret_cast<u8*>(gdt_base + (sel & ~7u));

    out.base = static_cast<u64>(*reinterpret_cast<u16*>(desc + 2))
             | (static_cast<u64>(desc[4]) << 16)
             | (static_cast<u64>(desc[7]) << 24);
    out.limit = static_cast<u32>(*reinterpret_cast<u16*>(desc))
              | (static_cast<u32>(desc[6] & 0x0f) << 16);

    if ((desc[6] & 0x80) != 0) {
        out.limit = (out.limit << 12) | 0xfff;
    }

    out.ar = static_cast<u32>(desc[5]) | ((static_cast<u32>(desc[6]) & 0xf0) << 8);

    if ((desc[5] & 0x10) == 0) {
        out.base |= static_cast<u64>(*reinterpret_cast<u32*>(desc + 8)) << 32;
    }

    return out;
}

bool vmx::setup_vmcs(pvcpu_t vcpu) {
    if (!vcpu) return false;

    struct vmcs_write {
        vmcs_field field;
        u64 value;
    };

    auto vmw = [](vmcs_field field, u64 value) -> bool {
        return __vmx_vmwrite(static_cast<size_t>(field), static_cast<size_t>(value)) == 0;
    };

    auto write_fields = [&](const vmcs_write* fields, size_t count) -> bool {
        for (size_t i = 0; i < count; ++i) {
            if (!vmw(fields[i].field, fields[i].value)) return false;
        }
        return true;
    };

    auto write_guest_segment = [&](u16 selector,
                                   const segment_info& segment,
                                   vmcs_field selector_field,
                                   vmcs_field base_field,
                                   vmcs_field limit_field,
                                   vmcs_field ar_field) -> bool {
        const vmcs_write fields[] = {
            { selector_field, selector },
            { base_field, segment.base },
            { limit_field, segment.limit },
            { ar_field, segment.ar },
        };
        return write_fields(fields, sizeof(fields) / sizeof(fields[0]));
    };

    auto gdtr = vcpu->host_gdtr;
    auto idtr = vcpu->host_idtr;

    auto cs_sel = __read_cs();
    auto ss_sel = __read_ss();
    auto ds_sel = __read_ds();
    auto es_sel = __read_es();
    auto fs_sel = __read_fs();
    auto gs_sel = __read_gs();
    auto tr_sel = __read_tr();
    auto ldtr_sel = __read_ldtr();

    auto cs = read_segment(gdtr.base, cs_sel);
    auto ss = read_segment(gdtr.base, ss_sel);
    auto ds = read_segment(gdtr.base, ds_sel);
    auto es = read_segment(gdtr.base, es_sel);
    auto fs = read_segment(gdtr.base, fs_sel);
    auto gs = read_segment(gdtr.base, gs_sel);
    auto tr = read_segment(gdtr.base, tr_sel);
    auto ldtr = read_segment(gdtr.base, ldtr_sel);

    fs.base = __readmsr(MSR_FS_BASE);
    gs.base = __readmsr(MSR_GS_BASE);

    auto mark_accessed = [](u32 ar) -> u32 {
        return (ar & segment_unusable_bit) ? ar : (ar | 1u);
    };

    cs.ar = mark_accessed(cs.ar);
    ss.ar = mark_accessed(ss.ar);
    ds.ar = mark_accessed(ds.ar);
    es.ar = mark_accessed(es.ar);
    fs.ar = mark_accessed(fs.ar);
    gs.ar = mark_accessed(gs.ar);

    if ((tr.ar & segment_unusable_bit) == 0) {
        tr.ar = (tr.ar & ~0xfu) | 11u;
    }

    auto basic = __readmsr(vtx::msr::ia32_vmx_basic);
    auto has_true_ctls = ((basic >> 55) & 1) != 0;
    auto pin_msr = has_true_ctls ? vtx::msr::ia32_vmx_true_pinbased_ctls
                                 : vtx::msr::ia32_vmx_pinbased_ctls;
    auto proc_msr = has_true_ctls ? vtx::msr::ia32_vmx_true_procbased_ctls
                                  : vtx::msr::ia32_vmx_procbased_ctls;
    auto exit_msr = has_true_ctls ? vtx::msr::ia32_vmx_true_exit_ctls
                                  : vtx::msr::ia32_vmx_exit_ctls;
    auto entry_msr = has_true_ctls ? vtx::msr::ia32_vmx_true_entry_ctls
                                   : vtx::msr::ia32_vmx_entry_ctls;

    auto ctls2_cap = __readmsr(vtx::msr::ia32_vmx_procbased_ctls2);
    auto ctls2_allowed1 = static_cast<u32>(ctls2_cap >> 32);
    auto secondary_wanted = procbased2_enable_ept | procbased2_enable_vpid;

    if ((ctls2_allowed1 & procbased2_enable_rdtscp) != 0) secondary_wanted |= procbased2_enable_rdtscp;
    if ((ctls2_allowed1 & procbased2_enable_invpcid) != 0) secondary_wanted |= procbased2_enable_invpcid;
    if ((ctls2_allowed1 & procbased2_enable_xsaves_xrstors) != 0) secondary_wanted |= procbased2_enable_xsaves_xrstors;

    auto secondary_ctls = adjust_ctls(secondary_wanted, vtx::msr::ia32_vmx_procbased_ctls2);
    if ((secondary_ctls & procbased2_enable_ept) == 0) return false;
    if ((secondary_ctls & procbased2_enable_vpid) == 0) return false;

    auto msr_ctx = msr_handler::get();
    msr_ctx->prepare_bitmap(vcpu->msr_bitmap);
    if (!msr_ctx->setup_managed_msrs(vcpu)) return false;
    dr_handler::get()->prepare_debug_state(vcpu);
    vcpu->guest_xcr0 = _xgetbv(0);
    RtlZeroMemory(vcpu->lbr_shadow, sizeof(vcpu->lbr_shadow));
    RtlZeroMemory(vcpu->fixed_ctr_exit, sizeof(vcpu->fixed_ctr_exit));

    auto vpid = static_cast<u16>(KeGetCurrentProcessorIndex() + 1);
    auto guest_cr0 = adjust_cr0_for_vmx(vcpu->guest_cr0);
    auto guest_cr4_shadow = vcpu->guest_cr4 & ~cr4_vmxe_bit;
    auto guest_cr4 = adjust_cr4_for_vmx(guest_cr4_shadow | cr4_vmxe_bit);
    auto pin_wanted = pinbased_nmi_exiting | pinbased_virtual_nmis;
    auto proc_wanted = procbased_activate_secondary |
                       procbased_use_tsc_offsetting |
                       procbased_use_msr_bitmap |
                       procbased_mov_dr_exiting;
    auto pin_ctls = adjust_ctls(pin_wanted, pin_msr);
    auto proc_ctls = adjust_ctls(proc_wanted, proc_msr);
    auto proc_ctls_with_interrupt_window = adjust_ctls(proc_wanted | procbased_interrupt_window_exiting, proc_msr);
    auto proc_ctls_with_nmi_window = adjust_ctls(proc_wanted | procbased_nmi_window_exiting, proc_msr);
    auto proc_ctls_with_rdtsc = adjust_ctls(proc_wanted | procbased_rdtsc_exiting, proc_msr);
    auto proc_ctls_with_rdpmc = adjust_ctls(proc_wanted | procbased_rdpmc_exiting, proc_msr);

    if ((pin_ctls & pin_wanted) != pin_wanted) return false;
    if ((proc_ctls & proc_wanted) != proc_wanted) return false;
    if ((proc_ctls_with_interrupt_window & procbased_interrupt_window_exiting) == 0) return false;
    if ((proc_ctls_with_nmi_window & procbased_nmi_window_exiting) == 0) return false;
    if ((proc_ctls_with_rdtsc & procbased_rdtsc_exiting) == 0) return false;
    if ((proc_ctls_with_rdpmc & procbased_rdpmc_exiting) == 0) return false;

    const vmcs_write control_fields[] = {
        { vmcs_field::pin_based_ctls, pin_ctls },
        { vmcs_field::procbased_ctls, proc_ctls },
        { vmcs_field::procbased_ctls2, secondary_ctls },
        { vmcs_field::tsc_offset, vcpu->tsc_offset },
        { vmcs_field::ept_pointer, ept::get()->ept_pointer() },
        { vmcs_field::msr_bitmap, static_cast<u64>(MmGetPhysicalAddress(vcpu->msr_bitmap).QuadPart) },
        { vmcs_field::virtual_processor_id, vpid },
        { vmcs_field::vm_exit_ctls,
          adjust_ctls(vm_exit_host_addr_space_size |
                      vm_exit_save_debug_controls |
                      ((pin_ctls & pinbased_external_interrupt_exiting)
                          ? vm_exit_ack_interrupt_on_exit
                          : 0) |
                      vm_exit_load_ia32_pat |
                      vm_exit_load_ia32_efer,
                      exit_msr) },
        { vmcs_field::vm_entry_ctls,
          adjust_ctls(vm_entry_ia32e_mode_guest |
                      vm_entry_load_debug_controls |
                      vm_entry_load_ia32_pat |
                      vm_entry_load_ia32_efer,
                      entry_msr) },
        { vmcs_field::exception_bitmap, 0 },
        { vmcs_field::page_fault_error_code_mask, 0 },
        { vmcs_field::page_fault_error_code_match, 0 },
        { vmcs_field::cr3_target_count, 0 },
        { vmcs_field::vm_exit_msr_store_count, vcpu->managed_msr_count },
        { vmcs_field::vm_exit_msr_store_addr, static_cast<u64>(MmGetPhysicalAddress(vcpu->managed_msrs).QuadPart) },
        { vmcs_field::vm_exit_msr_load_count, vcpu->managed_msr_count },
        { vmcs_field::vm_exit_msr_load_addr, static_cast<u64>(MmGetPhysicalAddress(vcpu->host_msrs).QuadPart) },
        { vmcs_field::vm_entry_msr_load_count, vcpu->managed_msr_count },
        { vmcs_field::vm_entry_msr_load_addr, static_cast<u64>(MmGetPhysicalAddress(vcpu->managed_msrs).QuadPart) },
        { vmcs_field::vm_entry_intr_info, 0 },
        { vmcs_field::vm_entry_exception_err, 0 },
        { vmcs_field::vm_entry_instr_len, 0 },
        { vmcs_field::cr0_guest_host_mask, 0 },
        { vmcs_field::cr4_guest_host_mask, cr4_vmxe_bit },
        { vmcs_field::cr0_read_shadow, guest_cr0 },
        { vmcs_field::cr4_read_shadow, guest_cr4_shadow },
    };
    if (!write_fields(control_fields, sizeof(control_fields) / sizeof(control_fields[0]))) {
        return false;
    }

    const vmcs_write guest_fields[] = {
        { vmcs_field::guest_cr0, guest_cr0 },
        { vmcs_field::guest_cr3, vcpu->guest_cr3 },
        { vmcs_field::guest_cr4, guest_cr4 },
        { vmcs_field::guest_dr7, vcpu->guest_debug.dr7 },
        { vmcs_field::guest_rflags, __readeflags() },
        { vmcs_field::guest_gdtr_base, gdtr.base },
        { vmcs_field::guest_gdtr_limit, gdtr.limit },
        { vmcs_field::guest_idtr_base, idtr.base },
        { vmcs_field::guest_idtr_limit, idtr.limit },
        { vmcs_field::guest_sysenter_cs, __readmsr(MSR_SYSENTER_CS) },
        { vmcs_field::guest_sysenter_esp, __readmsr(MSR_SYSENTER_ESP) },
        { vmcs_field::guest_sysenter_eip, __readmsr(MSR_SYSENTER_EIP) },
        { vmcs_field::guest_ia32_debugctl, __readmsr(MSR_DEBUG_CTL) },
        { vmcs_field::guest_ia32_pat, __readmsr(MSR_PAT) },
        { vmcs_field::guest_ia32_efer, __readmsr(MSR_EFER) },
        { vmcs_field::vmcs_link_pointer, ~0ULL },
        { vmcs_field::guest_activity_state, 0 },
        { vmcs_field::guest_interruptibility_state, 0 },
        { vmcs_field::guest_pending_dbg_exceptions, 0 },
    };
    if (!write_fields(guest_fields, sizeof(guest_fields) / sizeof(guest_fields[0]))) {
        return false;
    }

    if (!write_guest_segment(cs_sel, cs, vmcs_field::guest_cs_sel, vmcs_field::guest_cs_base,
                             vmcs_field::guest_cs_limit, vmcs_field::guest_cs_ar)) return false;
    if (!write_guest_segment(ss_sel, ss, vmcs_field::guest_ss_sel, vmcs_field::guest_ss_base,
                             vmcs_field::guest_ss_limit, vmcs_field::guest_ss_ar)) return false;
    if (!write_guest_segment(ds_sel, ds, vmcs_field::guest_ds_sel, vmcs_field::guest_ds_base,
                             vmcs_field::guest_ds_limit, vmcs_field::guest_ds_ar)) return false;
    if (!write_guest_segment(es_sel, es, vmcs_field::guest_es_sel, vmcs_field::guest_es_base,
                             vmcs_field::guest_es_limit, vmcs_field::guest_es_ar)) return false;
    if (!write_guest_segment(fs_sel, fs, vmcs_field::guest_fs_sel, vmcs_field::guest_fs_base,
                             vmcs_field::guest_fs_limit, vmcs_field::guest_fs_ar)) return false;
    if (!write_guest_segment(gs_sel, gs, vmcs_field::guest_gs_sel, vmcs_field::guest_gs_base,
                             vmcs_field::guest_gs_limit, vmcs_field::guest_gs_ar)) return false;
    if (!write_guest_segment(tr_sel, tr, vmcs_field::guest_tr_sel, vmcs_field::guest_tr_base,
                             vmcs_field::guest_tr_limit, vmcs_field::guest_tr_ar)) return false;
    if (!write_guest_segment(ldtr_sel, ldtr, vmcs_field::guest_ldtr_sel, vmcs_field::guest_ldtr_base,
                             vmcs_field::guest_ldtr_limit, vmcs_field::guest_ldtr_ar)) return false;

    const vmcs_write host_fields[] = {
        { vmcs_field::host_cr0, __readcr0() },
        { vmcs_field::host_cr3, vcpu->host_cr3 },
        { vmcs_field::host_cr4, __readcr4() },
        { vmcs_field::host_cs_sel, cs_sel & ~7u },
        { vmcs_field::host_ss_sel, ss_sel & ~7u },
        { vmcs_field::host_ds_sel, ds_sel & ~7u },
        { vmcs_field::host_es_sel, es_sel & ~7u },
        { vmcs_field::host_fs_sel, fs_sel & ~7u },
        { vmcs_field::host_gs_sel, gs_sel & ~7u },
        { vmcs_field::host_tr_sel, tr_sel & ~7u },
        { vmcs_field::host_fs_base, fs.base },
        { vmcs_field::host_gs_base, gs.base },
        { vmcs_field::host_tr_base, tr.base },
        { vmcs_field::host_gdtr_base, gdtr.base },
        { vmcs_field::host_idtr_base, idtr.base },
        { vmcs_field::host_sysenter_cs, __readmsr(MSR_SYSENTER_CS) },
        { vmcs_field::host_sysenter_esp, __readmsr(MSR_SYSENTER_ESP) },
        { vmcs_field::host_sysenter_eip, __readmsr(MSR_SYSENTER_EIP) },
        { vmcs_field::host_ia32_pat, __readmsr(MSR_PAT) },
        { vmcs_field::host_ia32_efer, __readmsr(MSR_EFER) },
    };
    return write_fields(host_fields, sizeof(host_fields) / sizeof(host_fields[0]));
}

vmx* vmx::get() {
    static vmx instance;
    return &instance;
}

}
