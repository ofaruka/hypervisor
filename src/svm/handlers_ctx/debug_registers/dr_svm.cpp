#include "dr_svm.hpp"

namespace svm {

void dr_handler::mark_dbg_regs_dirty(svm::pvcpu_t vcpu) {
    vcpu->guest_vmcb.control_area.vmcb_clean &= ~static_cast<u32>(svm::vmcb_clean_bits::dbg_regs);
}

u64* dr_handler::get_register_for_dr_exit(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    if (!vcpu || !guest_ctx || !guest_ctx->vprocessor_registers) {
        return nullptr;
    }

    const u64 gpr_num = vcpu->guest_vmcb.control_area.exit_info1 & 0xF;
    auto regs = guest_ctx->vprocessor_registers;

    switch (gpr_num) {
    case 0:
        return &regs->rax.value;
    case 1:
        return &regs->rcx.value;
    case 2:
        return &regs->rdx.value;
    case 3:
        return &regs->rbx.value;
    case 4:
        return &vcpu->guest_vmcb.state_save_area.rsp;
    case 5:
        return &regs->rbp.value;
    case 6:
        return &regs->rsi.value;
    case 7:
        return &regs->rdi.value;
    case 8:
        return &regs->r8.value;
    case 9:
        return &regs->r9.value;
    case 10:
        return &regs->r10.value;
    case 11:
        return &regs->r11.value;
    case 12:
        return &regs->r12.value;
    case 13:
        return &regs->r13.value;
    case 14:
        return &regs->r14.value;
    case 15:
        return &regs->r15.value;
    default:
        return nullptr;
    }
}

void dr_handler::prepare_debug_state(svm::pvcpu_t vcpu) {
    if (!vcpu->host_stack_layout.shared_vcpu) {
        return;
    }

    debug_state* state = reinterpret_cast<debug_state*>(&vcpu->host_stack_layout.shared_vcpu->debug_state.guest);
    state->dr0 = __readdr(0);
    state->dr1 = __readdr(1);
    state->dr2 = __readdr(2);
    state->dr3 = __readdr(3);
    u64 host_dr6 = __readdr(6);
    u64 host_dr7 = __readdr(7);
    state->dr6 = host_dr6;
    state->dr7 = host_dr7;
    vcpu->guest_vmcb.state_save_area.dr6 = host_dr6;
    vcpu->guest_vmcb.state_save_area.dr7 = host_dr7 & ~(1ULL << 13);
    mark_dbg_regs_dirty(vcpu);
}

void dr_handler::save_host_debug_state(svm::pvcpu_t vcpu) {
    if (!vcpu || !vcpu->host_stack_layout.shared_vcpu) {
        return;
    }

    debug_state* state = reinterpret_cast<debug_state*>(&vcpu->host_stack_layout.shared_vcpu->debug_state.host);
    state->dr0 = __readdr(0);
    state->dr1 = __readdr(1);
    state->dr2 = __readdr(2);
    state->dr3 = __readdr(3);
}

void dr_handler::restore_host_debug_state(svm::pvcpu_t vcpu) {
    if (!vcpu || !vcpu->host_stack_layout.shared_vcpu) {
        return;
    }

    debug_state* state = reinterpret_cast<debug_state*>(&vcpu->host_stack_layout.shared_vcpu->debug_state.host);
    __writedr(0, state->dr0);
    __writedr(1, state->dr1);
    __writedr(2, state->dr2);
    __writedr(3, state->dr3);
}

void dr_handler::load_guest_debug_state(svm::pvcpu_t vcpu) {
    if (!vcpu || !vcpu->host_stack_layout.shared_vcpu) {
        return;
    }

    debug_state* state = reinterpret_cast<debug_state*>(&vcpu->host_stack_layout.shared_vcpu->debug_state.guest);
    __writedr(0, state->dr0);
    __writedr(1, state->dr1);
    __writedr(2, state->dr2);
    __writedr(3, state->dr3);
}

void dr_handler::dr_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    u16 exit_code = static_cast<u16>(vcpu->guest_vmcb.control_area.exit_code);
    bool is_write;
    u32 dr_index;

    if (exit_code >= static_cast<u16>(vmexit::dr0_read) && exit_code <= static_cast<u16>(vmexit::dr15_read)) {
        is_write = false;
        dr_index = exit_code - static_cast<u16>(vmexit::dr0_read);
    } else if (exit_code >= static_cast<u16>(vmexit::dr0_write) && exit_code <= static_cast<u16>(vmexit::dr15_write)) {
        is_write = true;
        dr_index = exit_code - static_cast<u16>(vmexit::dr0_write);
    } else {
        event_inj_t{}.general_protection_exception(vcpu);
        return;
    }

    if (dr_index > 7) {
        event_inj_t{}.invalid_opcode_exception(vcpu);
        return;
    }

    if (dr_index == 4 || dr_index == 5) {
        if (vcpu->guest_vmcb.state_save_area.cr4.de == 1) {
            event_inj_t{}.invalid_opcode_exception(vcpu);
            return;
        }

        dr_index = (dr_index == 4) ? 6 : 7;
    }

    if (!vcpu->host_stack_layout.shared_vcpu) {
        event_inj_t{}.general_protection_exception(vcpu);
        return;
    }

    debug_state* state = reinterpret_cast<debug_state*>(&vcpu->host_stack_layout.shared_vcpu->debug_state.guest);
    u64* reg = get_register_for_dr_exit(vcpu, guest_ctx);

    if (!reg) {
        event_inj_t{}.general_protection_exception(vcpu);
        return;
    }

    if (is_write) {
        u64 new_value = *reg;

        switch (dr_index) {
        case 0:
            state->dr0 = new_value;
            break;
        case 1:
            state->dr1 = new_value;
            break;
        case 2:
            state->dr2 = new_value;
            break;
        case 3:
            state->dr3 = new_value;
            break;
        case 6:
            new_value = (new_value & 0x000000000000E00FULL) | 0x00000000FFFF0FF0ULL;
            state->dr6 = new_value;
            vcpu->guest_vmcb.state_save_area.dr6 = new_value;
            mark_dbg_regs_dirty(vcpu);
            break;
        case 7:
            new_value = (new_value & 0x00000000FFFF23FFULL) | 0x0000000000000400ULL;
            state->dr7 = new_value;
            vcpu->guest_vmcb.state_save_area.dr7 = new_value & ~(1ULL << 13);
            mark_dbg_regs_dirty(vcpu);
            break;
        }
    } else {
        switch (dr_index) {
        case 0:
            *reg = state->dr0;
            break;
        case 1:
            *reg = state->dr1;
            break;
        case 2:
            *reg = state->dr2;
            break;
        case 3:
            *reg = state->dr3;
            break;
        case 6:
            *reg = vcpu->guest_vmcb.state_save_area.dr6;
            break;
        case 7:
            *reg = state->dr7;
            break;
        }
    }

    if (!(vcpu->guest_vmcb.control_area.event_inj & (1ULL << 31))) {
        vcpu->guest_vmcb.state_save_area.rip = vcpu->guest_vmcb.control_area.next_rip;
    }
}

dr_handler* dr_handler::get() {
    static dr_handler instance;
    return &instance;
}
}
