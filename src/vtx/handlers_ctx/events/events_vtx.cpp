#include "events_vtx.hpp"
#include "../debug_registers/dr_vtx.hpp"

namespace vtx {

auto event_handler::guest_code_is_64_bit() -> bool {
    constexpr size_t efer_lma = 1ULL << 10;
    constexpr size_t code_long_bit = 1ULL << 13;

    size_t efer = 0;
    size_t cs_ar = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_ia32_efer), &efer);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cs_ar), &cs_ar);
    return (efer & efer_lma) != 0 && (cs_ar & code_long_bit) != 0;
}

auto event_handler::canonical_address(size_t value) -> bool {
    auto sign = static_cast<i64>(value) >> 47;
    return sign == 0 || sign == -1;
}

auto event_handler::advanced_guest_rip(size_t rip, size_t length) -> size_t {
    auto next = rip + length;
    return guest_code_is_64_bit()
        ? next
        : static_cast<size_t>(static_cast<u32>(next));
}

auto event_handler::get() -> event_handler* {
    static event_handler instance;
    return &instance;
}

auto event_handler::injection_pending() -> bool {
    size_t info = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_entry_intr_info), &info);
    return (info & vmx_event_valid) != 0;
}

auto event_handler::exception_uses_error_code(u32 vector) -> bool {
    switch (vector) {
    case exception_vector_double_fault:
    case exception_vector_invalid_tss:
    case exception_vector_segment_not_present:
    case exception_vector_stack_segment:
    case exception_vector_general_protection:
    case exception_vector_page_fault:
    case exception_vector_alignment_check:
    case exception_vector_control_protection:
    case exception_vector_security:
        return true;
    default:
        return false;
    }
}

auto event_handler::software_event_type(u32 type) -> bool {
    return type == vmx_event_type_sw_interrupt ||
           type == vmx_event_type_priv_sw_exception ||
           type == vmx_event_type_sw_exception;
}

auto event_handler::guest_blocks_external_interrupts() -> bool {
    size_t rflags = 0;
    size_t interruptibility = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rflags), &rflags);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_interruptibility_state), &interruptibility);

    return (rflags & guest_rflags_interrupt_enable) == 0 ||
           (interruptibility & (guest_intr_state_blocking_by_sti |
                                guest_intr_state_blocking_by_mov_ss)) != 0;
}

auto event_handler::can_inject_nmi() -> bool {
    size_t interruptibility = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_interruptibility_state), &interruptibility);
    return (interruptibility & (guest_intr_state_blocking_by_sti |
                                guest_intr_state_blocking_by_mov_ss |
                                guest_intr_state_blocking_by_nmi)) == 0;
}

auto event_handler::set_interrupt_window(bool enabled) -> void {
    size_t controls = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::procbased_ctls), &controls);

    if (enabled) {
        controls |= procbased_interrupt_window_exiting;
    }
    else {
        controls &= ~static_cast<size_t>(procbased_interrupt_window_exiting);
    }

    __vmx_vmwrite(static_cast<size_t>(vmcs_field::procbased_ctls), controls);
}

auto event_handler::set_nmi_window(bool enabled) -> void {
    size_t controls = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::procbased_ctls), &controls);

    if (enabled) {
        controls |= procbased_nmi_window_exiting;
    }
    else {
        controls &= ~static_cast<size_t>(procbased_nmi_window_exiting);
    }

    __vmx_vmwrite(static_cast<size_t>(vmcs_field::procbased_ctls), controls);
}

auto event_handler::clear_virtual_nmi_blocking() -> void {
    size_t interruptibility = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_interruptibility_state), &interruptibility);
    interruptibility &= ~static_cast<size_t>(guest_intr_state_blocking_by_nmi);
    __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_interruptibility_state), interruptibility);
}

auto event_handler::advance_guest_rip() -> void {
    size_t rip = 0;
    size_t instr_len = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rip), &rip);
    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_exit_instr_len), &instr_len);

    if (instr_len == 0 || instr_len > 15) {
        inject_ud();
        return;
    }

    auto next = advanced_guest_rip(rip, instr_len);
    if (guest_code_is_64_bit() && !canonical_address(next)) {
        inject_gp(0);
        return;
    }

    __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_rip), next);
}

auto event_handler::guest_trap_flag_enabled() -> bool {
    size_t rflags = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rflags), &rflags);
    return (rflags & 0x100ULL) != 0;
}

auto event_handler::guest_single_step_enabled() -> bool {
    size_t debugctl = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_ia32_debugctl), &debugctl);

    constexpr size_t debugctl_btf = 1ULL << 1;
    return guest_trap_flag_enabled() && (debugctl & debugctl_btf) == 0;
}

auto event_handler::pending_debug_exception_ready() -> bool {
    constexpr size_t pending_debug_enabled_breakpoint = 1ULL << 12;
    constexpr size_t pending_debug_bs = 1ULL << 14;

    size_t pending = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_pending_dbg_exceptions), &pending);
    return (pending & (pending_debug_enabled_breakpoint | pending_debug_bs)) != 0;
}

auto event_handler::arm_pending_debug_exception(pvcpu_t vcpu) -> void {
    constexpr size_t pending_debug_breakpoints = 0xfULL;
    constexpr size_t pending_debug_enabled_breakpoint = 1ULL << 12;
    constexpr size_t pending_debug_bs = 1ULL << 14;
    constexpr size_t pending_debug_rtm = 1ULL << 16;

    size_t pending = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_pending_dbg_exceptions), &pending);
    __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_pending_dbg_exceptions),
                  (pending & (pending_debug_breakpoints |
                              pending_debug_enabled_breakpoint |
                              pending_debug_bs |
                              pending_debug_rtm)) | pending_debug_bs);
    dr_handler::get()->set_single_step_status(vcpu);
}

auto event_handler::inject_db_single_step(pvcpu_t vcpu) -> void {
    arm_pending_debug_exception(vcpu);
}

auto event_handler::inject_db_after_emulated_instruction(pvcpu_t vcpu) -> void {
    arm_pending_debug_exception(vcpu);
}

auto event_handler::consume_debug_prompt_exception(pvcpu_t vcpu, u32 vector, u32 type) -> bool {
    if (type == vmx_event_type_hw_exception && vector == exception_vector_debug) {
        size_t qualification = 0;
        __vmx_vmread(static_cast<size_t>(vmcs_field::exit_qualification), &qualification);
        dr_handler::get()->sync_debug_exception(vcpu, qualification);
    }

    return false;
}

auto event_handler::inject_event(u32 vector,
                                 u32 type,
                                 bool has_error,
                                 u32 error_code,
                                 u32 instr_len) -> bool {
    if (type > vmx_event_type_other) return false;
    if (type == vmx_event_type_external_interrupt && has_error) return false;
    if (type == vmx_event_type_nmi && (vector != exception_vector_nmi || has_error)) return false;
    if (type == vmx_event_type_hw_exception &&
        (vector > 31 || has_error != exception_uses_error_code(vector))) return false;
    if (software_event_type(type) &&
        (has_error || instr_len == 0 || instr_len > 15)) return false;

    auto info = vmx_event_valid | (type << 8) | vector;

    if (has_error) {
        info |= vmx_event_error_code_valid;
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::vm_entry_exception_err), error_code);
    }
    else {
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::vm_entry_exception_err), 0);
    }

    __vmx_vmwrite(static_cast<size_t>(vmcs_field::vm_entry_instr_len),
                  software_event_type(type) ? instr_len : 0);
    __vmx_vmwrite(static_cast<size_t>(vmcs_field::vm_entry_intr_info), info);
    return true;
}

auto event_handler::queue_external_interrupt(pvcpu_t vcpu, u8 vector) -> void {
    if (!vcpu) return;

    if (!injection_pending() && !guest_blocks_external_interrupts()) {
        if (inject_event(vector, vmx_event_type_external_interrupt, false, 0, 0)) {
            vcpu->pending_external_interrupt = 0;
            set_interrupt_window(false);
            return;
        }
    }

    vcpu->pending_external_interrupt = 1;
    vcpu->pending_external_vector = vector;
    set_interrupt_window(true);
}

auto event_handler::reinject_info(vmcs_field info_field, vmcs_field err_field, pvcpu_t vcpu) -> bool {
    if (injection_pending()) return false;

    size_t info = 0;
    __vmx_vmread(static_cast<size_t>(info_field), &info);
    if ((info & vmx_event_valid) == 0) return false;

    auto vector = static_cast<u32>(info & 0xff);
    auto type = static_cast<u32>((info >> 8) & 7);
    auto has_error = (info & vmx_event_error_code_valid) != 0;

    size_t error_code = 0;
    size_t instr_len = 0;

    if (has_error) {
        __vmx_vmread(static_cast<size_t>(err_field), &error_code);
    }

    if (software_event_type(type)) {
        __vmx_vmread(static_cast<size_t>(vmcs_field::vm_exit_instr_len), &instr_len);
    }

    if (type == vmx_event_type_external_interrupt && guest_blocks_external_interrupts()) {
        queue_external_interrupt(vcpu, static_cast<u8>(vector));
        return true;
    }

    if (type == vmx_event_type_nmi) {
        if (!can_inject_nmi()) {
            if (vcpu) vcpu->pending_nmi = 1;
            set_nmi_window(true);
            return true;
        }

        if (inject_event(vector, type, has_error, static_cast<u32>(error_code), 0)) {
            if (vcpu) {
                vcpu->pending_nmi = 0;
                vcpu->nmi_active = 1;
            }
            set_nmi_window(true);
            return true;
        }

        return false;
    }

    return inject_event(vector, type, has_error, static_cast<u32>(error_code), static_cast<u32>(instr_len));
}

auto event_handler::clear_injection() -> void {
    __vmx_vmwrite(static_cast<size_t>(vmcs_field::vm_entry_intr_info), 0);
    __vmx_vmwrite(static_cast<size_t>(vmcs_field::vm_entry_exception_err), 0);
    __vmx_vmwrite(static_cast<size_t>(vmcs_field::vm_entry_instr_len), 0);
}

auto event_handler::sanitize_pending_injection(pvcpu_t vcpu) -> void {
    size_t raw_info = 0;
    size_t interruptibility = 0;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::guest_interruptibility_state),
                    &interruptibility) == 0) {
        auto sanitized = interruptibility &
            (guest_intr_state_blocking_by_sti |
             guest_intr_state_blocking_by_mov_ss |
             guest_intr_state_blocking_by_nmi);
        if ((sanitized & guest_intr_state_blocking_by_sti) != 0 &&
            (sanitized & guest_intr_state_blocking_by_mov_ss) != 0) {
            sanitized &= ~static_cast<size_t>(guest_intr_state_blocking_by_sti);
        }
        if (sanitized != interruptibility) {
            __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_interruptibility_state),
                          sanitized);
            interruptibility = sanitized;
        }
    }

    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_entry_intr_info), &raw_info);
    {
        constexpr size_t pending_debug_breakpoints = 0xfULL;
        constexpr size_t pending_debug_enabled_breakpoint = 1ULL << 12;
        constexpr size_t pending_debug_bs = 1ULL << 14;
        constexpr size_t pending_debug_rtm = 1ULL << 16;

        size_t pending = 0;
        size_t activity = 0;
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_pending_dbg_exceptions), &pending);
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_activity_state), &activity);

        auto sanitized = pending & (pending_debug_breakpoints |
                                    pending_debug_enabled_breakpoint |
                                    pending_debug_bs |
                                    pending_debug_rtm);
        if ((sanitized & pending_debug_enabled_breakpoint) == 0) {
            sanitized &= ~pending_debug_breakpoints;
        }
        if ((sanitized & pending_debug_bs) != 0 && !guest_trap_flag_enabled()) {
            sanitized &= ~pending_debug_bs;
        }
        if ((sanitized & (pending_debug_enabled_breakpoint | pending_debug_bs)) == 0) {
            sanitized = 0;
        }
        if (activity != 0 || (raw_info & vmx_event_valid) != 0) {
            sanitized = 0;
        }
        if (sanitized != pending) {
            __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_pending_dbg_exceptions),
                          sanitized);
        }
    }

    if ((raw_info & vmx_event_valid) == 0) {
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::vm_entry_exception_err), 0);
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::vm_entry_instr_len), 0);
        return;
    }

    auto vector = static_cast<u32>(raw_info & 0xff);
    auto type = static_cast<u32>((raw_info >> 8) & 7);
    auto has_error = (raw_info & vmx_event_error_code_valid) != 0;

    size_t instr_len = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_entry_instr_len), &instr_len);

    bool valid = true;
    switch (type) {
    case vmx_event_type_external_interrupt:
        if (has_error) {
            valid = false;
            break;
        }
        if (guest_blocks_external_interrupts()) {
            clear_injection();
            queue_external_interrupt(vcpu, static_cast<u8>(vector));
            return;
        }
        break;
    case vmx_event_type_nmi:
        valid = vector == exception_vector_nmi && !has_error && can_inject_nmi();
        if (!valid && vcpu) {
            vcpu->pending_nmi = 1;
            set_nmi_window(true);
        }
        break;
    case vmx_event_type_hw_exception:
        valid = vector <= 31 && has_error == exception_uses_error_code(vector);
        if (valid && vector == exception_vector_debug) {
            if ((interruptibility & guest_intr_state_blocking_by_mov_ss) != 0) {
                clear_injection();
                arm_pending_debug_exception(vcpu);
                return;
            }
        }
        break;
    case vmx_event_type_sw_interrupt:
        valid = !has_error && instr_len > 0 && instr_len <= 15;
        break;
    case vmx_event_type_priv_sw_exception:
        valid = vector == exception_vector_debug && !has_error && instr_len > 0 && instr_len <= 15;
        break;
    case vmx_event_type_sw_exception:
        valid = (vector == exception_vector_breakpoint || vector == 4) &&
                !has_error && instr_len > 0 && instr_len <= 15;
        break;
    default:
        valid = false;
        break;
    }

    if (!valid) {
        clear_injection();
        return;
    }

    auto info = vmx_event_valid | (type << 8) | vector;
    if (has_error) info |= vmx_event_error_code_valid;
    if (!software_event_type(type)) instr_len = 0;

    __vmx_vmwrite(static_cast<size_t>(vmcs_field::vm_entry_instr_len), instr_len);
    __vmx_vmwrite(static_cast<size_t>(vmcs_field::vm_entry_intr_info), info);
}

auto event_handler::arm_pending_debug_after_emulation() -> void {
    if (injection_pending()) return;

    if (!guest_single_step_enabled()) {
        return;
    }

    arm_pending_debug_exception(nullptr);
}

auto event_handler::clear_emulation_interrupt_shadow() -> void {
    size_t interruptibility = 0;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::guest_interruptibility_state),
                    &interruptibility) != 0) {
        return;
    }

    interruptibility &= ~static_cast<size_t>(guest_intr_state_blocking_by_sti |
                                            guest_intr_state_blocking_by_mov_ss);
    __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_interruptibility_state),
                  interruptibility);
}

auto event_handler::complete_emulated_instruction() -> void {
    arm_pending_debug_after_emulation();
    clear_emulation_interrupt_shadow();
}

auto event_handler::inject_exception(u8 vector, u32 error_code, bool has_error) -> void {
    inject_event(vector, vmx_event_type_hw_exception, has_error, error_code, 0);
}

auto event_handler::inject_gp(u32 error_code) -> void {
    inject_exception(exception_vector_general_protection, error_code, true);
}

auto event_handler::inject_ud() -> void {
    inject_exception(exception_vector_invalid_opcode, 0, false);
}

auto event_handler::inject_db() -> void {
    inject_exception(exception_vector_debug, 0, false);
}

auto event_handler::interrupt_window_exit_handler(pvcpu_t vcpu) -> void {
    if (!vcpu || !vcpu->pending_external_interrupt) {
        set_interrupt_window(false);
        return;
    }

    queue_external_interrupt(vcpu, vcpu->pending_external_vector);
}

auto event_handler::queue_nmi(pvcpu_t vcpu) -> void {
    if (!vcpu) return;

    if (!injection_pending() && can_inject_nmi()) {
        inject_event(exception_vector_nmi, vmx_event_type_nmi, false, 0, 0);
        vcpu->pending_nmi = 0;
        vcpu->nmi_active = 1;
        set_nmi_window(true);
        return;
    }

    vcpu->pending_nmi = 1;
    set_nmi_window(true);
}

auto event_handler::exception_or_nmi_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool {
    unref_param(gprs);

    size_t info = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::vm_exit_intr_info), &info);
    if ((info & vmx_event_valid) == 0) return false;

    auto vector = static_cast<u32>(info & 0xff);
    auto type = static_cast<u32>((info >> 8) & 7);

    if (type == vmx_event_type_nmi) {
        if (vcpu && !vcpu->nmi_active) {
            clear_virtual_nmi_blocking();
        }

        queue_nmi(vcpu);
        return true;
    }

    if (consume_debug_prompt_exception(vcpu, vector, type)) {
        return true;
    }

    return reinject_info(vmcs_field::vm_exit_intr_info, vmcs_field::vm_exit_intr_err, vcpu);
}

auto event_handler::nmi_window_exit_handler(pvcpu_t vcpu) -> void {
    if (!vcpu) {
        set_nmi_window(false);
        return;
    }

    if (vcpu->pending_nmi) {
        queue_nmi(vcpu);
        return;
    }

    vcpu->nmi_active = 0;
    set_nmi_window(false);
}

auto event_handler::reinject_exit_interrupt(pvcpu_t vcpu) -> void {
    reinject_info(vmcs_field::vm_exit_intr_info, vmcs_field::vm_exit_intr_err, vcpu);
}

auto event_handler::reinject_idt_vectoring(pvcpu_t vcpu) -> void {
    reinject_info(vmcs_field::idt_vectoring_info, vmcs_field::idt_vectoring_err, vcpu);
}

}
