#include "vmm_handlers.hpp"

namespace svm {

vmm_dispatcher* vmm_dispatcher::get() {
    static vmm_dispatcher instance;
    return &instance;
}

void vmm_dispatcher::begin_exit(pvcpu_t vcpu, pguest_registers_t registers, guest_ctx_t& guest_ctx) {
    dr_handler::get()->restore_host_debug_state(vcpu);

    registers->rax = vcpu->guest_vmcb.state_save_area.rax;
    guest_ctx.vprocessor_registers = registers;
    guest_ctx.should_exit = false;

    vcpu->guest_vmcb.control_area.tlb_control = static_cast<u32>(flush_tlb_t::tlb_control_id::do_nothing);
    vcpu->host_stack_layout.trap_frame.Rsp = vcpu->guest_vmcb.state_save_area.rsp;
    vcpu->host_stack_layout.trap_frame.Rip = advance_rip_or_next(vcpu, 0);
}

void vmm_dispatcher::dispatch_exit(pvcpu_t vcpu, guest_ctx_t& guest_ctx) {
    const auto exit_code = static_cast<vmexit>(vcpu->guest_vmcb.control_area.exit_code);

    // The calibration window only survives when the very next exit is the
    // armed timestamp read; any other exit in between voids the round-trip.
    if (vcpu->host_stack_layout.shadow_data.timing_window_open &&
        exit_code != vmexit::rdtsc && exit_code != vmexit::rdtscp) {
        vcpu->host_stack_layout.shadow_data.timing_window_open = false;
    }

    switch (exit_code) {
    case vmexit::cr0_read:
    case vmexit::cr0_write:
    case vmexit::cr3_read:
    case vmexit::cr3_write:
    case vmexit::cr4_read:
    case vmexit::cr4_write:
        cr_handler::get()->cr_exit_handler(vcpu, &guest_ctx);
        break;
    case vmexit::dr0_read:
    case vmexit::dr1_read:
    case vmexit::dr2_read:
    case vmexit::dr3_read:
    case vmexit::dr4_read:
    case vmexit::dr5_read:
    case vmexit::dr6_read:
    case vmexit::dr7_read:
    case vmexit::dr8_read:
    case vmexit::dr9_read:
    case vmexit::dr10_read:
    case vmexit::dr11_read:
    case vmexit::dr12_read:
    case vmexit::dr13_read:
    case vmexit::dr14_read:
    case vmexit::dr15_read:
    case vmexit::dr0_write:
    case vmexit::dr1_write:
    case vmexit::dr2_write:
    case vmexit::dr3_write:
    case vmexit::dr4_write:
    case vmexit::dr5_write:
    case vmexit::dr6_write:
    case vmexit::dr7_write:
    case vmexit::dr8_write:
    case vmexit::dr9_write:
    case vmexit::dr10_write:
    case vmexit::dr11_write:
    case vmexit::dr12_write:
    case vmexit::dr13_write:
    case vmexit::dr14_write:
    case vmexit::dr15_write:
        dr_handler::get()->dr_exit_handler(vcpu, &guest_ctx);
        break;
    case vmexit::cpuid:
        cpuid_handler::get()->cpuid_exit_handler(vcpu, &guest_ctx);
        break;
    case vmexit::msr:
        msr_handler::get()->msr_exit_handler(vcpu, &guest_ctx);
        break;
    case vmexit::efer_write_trap:
        efer_handler::get()->efer_write_trap_handler(vcpu, &guest_ctx);
        break;
    case vmexit::vmcall:
        vmmcall_handler::get()->vmmcall_exit_handler(vcpu, &guest_ctx);
        break;
    case vmexit::npf:
        npf_handler::get()->npf_exit_handler(vcpu, &guest_ctx);
        break;
    case vmexit::nmi:
        nmi_handler::get()->nmi_exit_handler(vcpu, &guest_ctx);
        break;
    case vmexit::excp1_write:
        event_handler::get()->debug_exception_exit_handler(vcpu);
        break;
    case vmexit::excp13_write:
        event_handler::get()->general_protection_exit_handler(vcpu);
        break;
    case vmexit::pause:
        vcpu->guest_vmcb.state_save_area.rip = advance_rip_or_next(vcpu, 2);
        break;
    case vmexit::clgi:
    case vmexit::stgi:
        gif_handler::get()->gif_exit_handler(vcpu);
        break;
    case vmexit::rdtsc:
        timing_handler::get()->rdtsc_exit_handler(vcpu, &guest_ctx);
        break;
    case vmexit::rdtscp:
        timing_handler::get()->rdtscp_exit_handler(vcpu, &guest_ctx);
        break;
    case vmexit::mwait:
    case vmexit::mwait_conditional:
    case vmexit::monitor:
    case vmexit::vmrun:
    case vmexit::vmload:
    case vmexit::vmsave:
    case vmexit::skinit:
    case vmexit::icebp:
    case vmexit::invlpga:
        event_handler::get()->invalid_opcode_exit_handler(vcpu);
        break;
    case vmexit::invalid:
    default:
        fatal_exit(vcpu);
        break;
    }
}

bool vmm_dispatcher::leave_svm(pvcpu_t vcpu, guest_ctx_t& guest_ctx) {
    const auto guest_cr0 = vcpu->guest_vmcb.state_save_area.cr0.value;
    const auto guest_cr3 = vcpu->guest_vmcb.state_save_area.cr3.value;
    const auto guest_cr4 = vcpu->guest_vmcb.state_save_area.cr4.value;
    auto& leave_state = vcpu->host_stack_layout.leave_state;

    dr_handler::get()->save_host_debug_state(vcpu);
    dr_handler::get()->load_guest_debug_state(vcpu);

    leave_state.guest_pat = vcpu->guest_vmcb.state_save_area.gpat;
    leave_state.original_idtr = &vcpu->original_idtr;
    leave_state.original_gdtr = &vcpu->original_gdtr;

    guest_ctx.vprocessor_registers->rax.value = reinterpret_cast<uint64_t>(vcpu) & MAXUINT;
    guest_ctx.vprocessor_registers->rbx.value = vcpu->guest_vmcb.state_save_area.rip;
    guest_ctx.vprocessor_registers->rcx.value = vcpu->guest_vmcb.state_save_area.rsp;
    guest_ctx.vprocessor_registers->rdx.value = reinterpret_cast<uint64_t>(vcpu) >> 32;
    guest_ctx.vprocessor_registers->r8.value = guest_cr0;
    guest_ctx.vprocessor_registers->r9.value = guest_cr4;
    guest_ctx.vprocessor_registers->r10.value = guest_cr3;
    guest_ctx.vprocessor_registers->r11.value = vcpu->guest_vmcb.state_save_area.rflags;

    _disable();
    return true;
}

bool vmm_dispatcher::finish_exit(pvcpu_t vcpu, guest_ctx_t& guest_ctx) {
    if (vcpu->host_stack_layout.shadow_data.timing_window_open &&
        vcpu->guest_vmcb.control_area.exit_code == static_cast<u64>(vmexit::cpuid)) {
        vcpu->vmexit_leave_tsc = __rdtsc();
    }

    if (vcpu->guest_vmcb.control_area.exit_code != vmexit::npf) {
        memory_access::get()->try_consume_pending(vcpu);
    }

    if (guest_ctx.should_exit) {
        return leave_svm(vcpu, guest_ctx);
    }

    vcpu->guest_vmcb.state_save_area.rax = guest_ctx.vprocessor_registers->rax.value;
    flush_tlb_t{}.apply_pending(vcpu);
    return false;
}

void vmm_dispatcher::fatal_exit(pvcpu_t vcpu) {
    debug::panicf("SVM fatal exit vcpu=%p code=0x%llx rip=0x%llx rsp=0x%llx info1=0x%llx info2=0x%llx\n", vcpu,
                  vcpu->guest_vmcb.control_area.exit_code, vcpu->guest_vmcb.state_save_area.rip,
                  vcpu->guest_vmcb.state_save_area.rsp, vcpu->guest_vmcb.control_area.exit_info1,
                  vcpu->guest_vmcb.control_area.exit_info2);

    KeBugCheckEx(0xB16B00B5UL, static_cast<ULONG_PTR>(vcpu->guest_vmcb.control_area.exit_code),
                 static_cast<ULONG_PTR>(vcpu->guest_vmcb.control_area.exit_info1),
                 static_cast<ULONG_PTR>(vcpu->guest_vmcb.control_area.exit_info2),
                 static_cast<ULONG_PTR>(vcpu->guest_vmcb.state_save_area.rip));
}

bool vmm_dispatcher::handle_vmexit(pvcpu_t vcpu, pguest_registers_t registers) {
    if (!vcpu || !registers) {
        KeBugCheck(0xB16B00B5UL);
    }

    // vcpu->host_stack_layout.vmexit_entry_tsc is captured in the vmexit asm
    // entry (svm_x64.asm) before the prologue runs.

    guest_ctx_t guest_ctx{};
    begin_exit(vcpu, registers, guest_ctx);
    dispatch_exit(vcpu, guest_ctx);
    return finish_exit(vcpu, guest_ctx);
}

extern "C" bool vmexit_handler(pvcpu_t vcpu, pguest_registers_t registers) {
    return vmm_dispatcher::get()->handle_vmexit(vcpu, registers);
}

}
