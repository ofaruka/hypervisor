#include "vmm_handlers.hpp"
#include "../utilities_ctx/memory/memory_access_vtx.hpp"

namespace vtx {

auto vmm_dispatcher::guest_code_is_64_bit() -> bool {
    constexpr size_t efer_lma = 1ULL << 10;
    constexpr size_t code_long_bit = 1ULL << 13;

    size_t efer = 0;
    size_t cs_ar = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_ia32_efer), &efer);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cs_ar), &cs_ar);
    return (efer & efer_lma) != 0 && (cs_ar & code_long_bit) != 0;
}

auto vmm_dispatcher::canonical_address(size_t value) -> bool {
    auto sign = static_cast<i64>(value) >> 47;
    return sign == 0 || sign == -1;
}

auto vmm_dispatcher::advanced_guest_rip(size_t rip, size_t length) -> size_t {
    auto next = rip + length;
    return guest_code_is_64_bit()
        ? next
        : static_cast<size_t>(static_cast<u32>(next));
}

auto vmm_dispatcher::get() -> vmm_dispatcher* {
    static vmm_dispatcher instance;
    return &instance;
}

auto vmm_dispatcher::advance_rip(bool complete_emulation) -> void {
    size_t rip = 0, len = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rip),         &rip);
    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_exit_instr_len), &len);
    if (len == 0 || len > 15) {
        event_handler::get()->inject_ud();
        return;
    }

    auto next = advanced_guest_rip(rip, len);
    if (guest_code_is_64_bit() && !canonical_address(next)) {
        event_handler::get()->inject_gp(0);
        return;
    }

    __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_rip), next);
    if (complete_emulation) {
        event_handler::get()->complete_emulated_instruction();
    }
}

auto vmm_dispatcher::prepare_devirtualize_current(pvcpu_t vcpu) -> bool {
    if (!vcpu) return false;

    size_t rip = 0, rsp = 0, rflags = 0, cr0 = 0, cr3 = 0, cr4 = 0;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::guest_rip), &rip) != 0) return false;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::guest_rsp), &rsp) != 0) return false;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::guest_rflags), &rflags) != 0) return false;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::guest_cr0), &cr0) != 0) return false;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::guest_cr3), &cr3) != 0) return false;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::guest_cr4), &cr4) != 0) return false;

    vcpu->devirt_rip = rip;
    vcpu->devirt_rsp = rsp;
    vcpu->devirt_rflags = rflags;
    vcpu->devirt_cr0 = cr0;
    vcpu->devirt_cr3 = cr3;
    vcpu->devirt_cr4 = cr4 & ~(1ULL << 13);
    return true;
}

auto vmm_dispatcher::fatal_exit(exit_reason reason) -> void {
    size_t reason_raw = 0, rip = 0, qual = 0, gpa = 0, vm_error = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_exit_reason),          &reason_raw);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rip),              &rip);
    __vmx_vmread(static_cast<size_t>(vmcs_field::exit_qualification),     &qual);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_physical_address), &gpa);
    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_instruction_error),    &vm_error);

    if ((reason_raw & vm_exit_reason_entry_failure) != 0) {
        size_t intr_info = 0, instr_len = 0, intr_error = 0;
        size_t cs_ar = 0, interruptibility = 0, activity = 0, pending_dbg = 0;
        __vmx_vmread(static_cast<size_t>(vmcs_field::vm_entry_intr_info), &intr_info);
        __vmx_vmread(static_cast<size_t>(vmcs_field::vm_entry_instr_len), &instr_len);
        __vmx_vmread(static_cast<size_t>(vmcs_field::vm_entry_exception_err), &intr_error);
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cs_ar), &cs_ar);
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_interruptibility_state),
                     &interruptibility);
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_activity_state), &activity);
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_pending_dbg_exceptions),
                     &pending_dbg);

        KeBugCheckEx(0xB16B00B5UL,
                     static_cast<ULONG_PTR>(reason_raw),
                     static_cast<ULONG_PTR>(rip),
                     static_cast<ULONG_PTR>(((intr_info & 0xffffffffULL) << 32) |
                         ((instr_len & 0xffffULL) << 16) |
                         (intr_error & 0xffffULL)),
                     static_cast<ULONG_PTR>(((pending_dbg & 0xffffffffULL) << 32) |
                         ((activity & 0xffULL) << 24) |
                         ((interruptibility & 0xffULL) << 16) |
                         (cs_ar & 0xffffULL)));
    }

    auto detail = (reason_raw & vm_exit_reason_entry_failure)
        ? ((reason_raw & 0xffffffffULL) << 32) | (vm_error & 0xffffffffULL)
        : gpa;

    KeBugCheckEx(0xB16B00B5UL,
                 static_cast<ULONG_PTR>(reason),
                 static_cast<ULONG_PTR>(rip),
                 static_cast<ULONG_PTR>(qual),
                 static_cast<ULONG_PTR>(detail));
}

auto vmm_dispatcher::vmresume_failure(pvcpu_t vcpu) -> void {
    size_t vm_error = 0, reason_raw = 0, rip = 0, rflags = 0;
    size_t intr_info = 0, interruptibility = 0, pending_dbg = 0;

    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_instruction_error), &vm_error);
    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_exit_reason), &reason_raw);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rip), &rip);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rflags), &rflags);
    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_entry_intr_info), &intr_info);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_interruptibility_state), &interruptibility);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_pending_dbg_exceptions), &pending_dbg);

    debug::panicf("[vtx] VMRESUME failed cpu=%lu vcpu=%p error=%llx exit_raw=%llx rip=%llx rflags=%llx intr_info=%llx interruptibility=%llx pending_dbg=%llx\n",
        KeGetCurrentProcessorIndex(),
        vcpu,
        static_cast<unsigned long long>(vm_error),
        static_cast<unsigned long long>(reason_raw),
        static_cast<unsigned long long>(rip),
        static_cast<unsigned long long>(rflags),
        static_cast<unsigned long long>(intr_info),
        static_cast<unsigned long long>(interruptibility),
        static_cast<unsigned long long>(pending_dbg));

    KeBugCheckEx(0x0000001E,
                 static_cast<ULONG_PTR>(vm_error),
                 static_cast<ULONG_PTR>(rip),
                 static_cast<ULONG_PTR>(intr_info),
                 static_cast<ULONG_PTR>(interruptibility));
}

extern "C" void vtx_handle_vmresume_failure(pvcpu_t vcpu) {
    vmm_dispatcher::get()->vmresume_failure(vcpu);
}

extern "C" u8 vtx_handle_vmexit(pvcpu_t vcpu, guest_gprs* gprs) {
    auto disp = vmm_dispatcher::get();
    auto dr = dr_handler::get();
    auto events = event_handler::get();

    size_t reason_raw = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_exit_reason), &reason_raw);
    auto reason = static_cast<exit_reason>(reason_raw & 0xffff);
    if ((reason_raw & vm_exit_reason_entry_failure) != 0) {
        disp->fatal_exit(reason);
    }

    // The calibration window only survives when the very next exit is the
    // armed timestamp read; any other exit in between voids the round-trip.
    if (vcpu->timing_window_open && reason != exit_reason::rdtsc && reason != exit_reason::rdtscp) {
        vcpu->timing_window_open = 0;
    }

    events->clear_injection();

    switch (reason) {
    case exit_reason::exception_or_nmi:
        if (!events->exception_or_nmi_exit_handler(vcpu, gprs)) {
            disp->fatal_exit(reason);
        }
        break;

    case exit_reason::external_interrupt:
        events->reinject_idt_vectoring(vcpu);
        events->reinject_exit_interrupt(vcpu);
        break;

    case exit_reason::nmi_window:
        events->nmi_window_exit_handler(vcpu);
        break;

    case exit_reason::interrupt_window:
        events->interrupt_window_exit_handler(vcpu);
        break;

    case exit_reason::cpuid:
    {
        if (events->pending_debug_exception_ready()) {
            timing_handler::get()->clear_timing_exiting(vcpu);
            events->inject_db_single_step(vcpu);
            break;
        }

        cpuid_handler::get()->cpuid_exit_handler(vcpu, gprs);
        disp->advance_rip(true);
        break;
    }

    case exit_reason::vmcall: {
        auto result = vmcall_handler::get()->vmcall_exit_handler(vcpu, gprs);
        if (result == vmcall_handler::result::devirtualize) {
            msr_handler::get()->load_managed_msrs(vcpu);
            dr->load_guest_debug_state(vcpu, true);
            return 1;
        }
        if (result == vmcall_handler::result::advance_rip) disp->advance_rip();
        break;
    }

    case exit_reason::dr_access:
        if (dr->dr_exit_handler(vcpu, gprs)) {
            disp->advance_rip();
        }
        break;

    case exit_reason::cr_access:
        if (cr_handler::get()->cr_exit_handler(vcpu, gprs)) {
            disp->advance_rip();
        }
        break;

    case exit_reason::getsec:
    case exit_reason::vmclear:
    case exit_reason::vmlaunch:
    case exit_reason::vmptrld:
    case exit_reason::vmptrst:
    case exit_reason::vmread:
    case exit_reason::vmresume:
    case exit_reason::vmwrite:
    case exit_reason::vmxoff:
    case exit_reason::vmxon:
    case exit_reason::invept:
    case exit_reason::invvpid:
    case exit_reason::vmfunc:
        events->inject_ud();
        break;

    case exit_reason::xsetbv:
        if (xcr_handler::get()->xsetbv_exit_handler(vcpu, gprs)) {
            disp->advance_rip();
        }
        break;

    case exit_reason::rdpmc:
        if (timing_handler::get()->rdpmc_exit_handler(vcpu, gprs)) {
            disp->advance_rip();
        }
        break;

    case exit_reason::rdtsc:
        if (timing_handler::get()->rdtsc_exit_handler(vcpu, gprs)) {
            disp->advance_rip();
        }
        break;

    case exit_reason::rdtscp:
        if (timing_handler::get()->rdtscp_exit_handler(vcpu, gprs)) {
            disp->advance_rip();
        }
        break;

    case exit_reason::hlt:
        disp->advance_rip();
        break;

    case exit_reason::invd:
        if (cache_handler::get()->invd_exit_handler()) {
            disp->advance_rip();
        }
        break;

    case exit_reason::wbinvd:
        if (cache_handler::get()->wbinvd_exit_handler()) {
            disp->advance_rip();
        }
        break;

    case exit_reason::rdmsr:
    {
        auto handled = msr_handler::get()->msr_exit_handler(vcpu, gprs, false);
        if (handled) {
            disp->advance_rip();
        }
        break;
    }

    case exit_reason::wrmsr:
    {
        auto handled = msr_handler::get()->msr_exit_handler(vcpu, gprs, true);
        if (handled) {
            disp->advance_rip();
        }
        break;
    }

    case exit_reason::ept_violation:
        if (!epv_handler::get()->epv_exit_handler(vcpu, gprs)) {
            disp->fatal_exit(reason);
        }
        break;

    case exit_reason::monitor_trap_flag:
        mtf_handler::get()->mtf_exit_handler(vcpu);
        break;

    case exit_reason::access_gdtr_or_idtr:
    case exit_reason::access_ldtr_or_tr:
        if (descriptor_handler::get()->descriptor_exit_handler(gprs)) {
            disp->advance_rip();
        }
        break;

    case exit_reason::invpcid:
        vtx_invvpid_all_contexts();
        disp->advance_rip();
        break;

    case exit_reason::task_switch: {
        size_t qualification = 0;
        __vmx_vmread(static_cast<size_t>(vmcs_field::exit_qualification), &qualification);
        events->inject_gp(static_cast<u32>(qualification & 0xffff));
        break;
    }

    case exit_reason::ept_misconfig:
        disp->fatal_exit(reason);
        break;

    case exit_reason::triple_fault:
        if (disp->prepare_devirtualize_current(vcpu)) {
            msr_handler::get()->load_managed_msrs(vcpu);
            dr->load_guest_debug_state(vcpu, true);
            return 1;
        }
        disp->fatal_exit(reason);
        break;

    case exit_reason::init_signal:
    case exit_reason::sipi:
        break;

    default:
        disp->fatal_exit(reason);
        break;
    }

    if (reason != exit_reason::ept_violation) {
        memory_access::get()->try_consume_pending(vcpu);
    }

    if (vcpu->timing_window_open && reason == exit_reason::cpuid) {
        vcpu->vmexit_leave_tsc = __rdtsc();
    }

    events->reinject_idt_vectoring(vcpu);
    events->sanitize_pending_injection(vcpu);
    return 0;
}

}
