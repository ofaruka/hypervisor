#pragma once
#include "../../../includes.h"

namespace vtx {

class event_handler {
private:
    event_handler() = default;

    auto injection_pending() -> bool;
    auto exception_uses_error_code(u32 vector) -> bool;
    auto software_event_type(u32 type) -> bool;
    auto guest_blocks_external_interrupts() -> bool;
    auto can_inject_nmi() -> bool;
    auto set_interrupt_window(bool enabled) -> void;
    auto set_nmi_window(bool enabled) -> void;
    auto clear_virtual_nmi_blocking() -> void;
    auto guest_code_is_64_bit() -> bool;
    auto canonical_address(size_t value) -> bool;
    auto advanced_guest_rip(size_t rip, size_t length) -> size_t;
    auto advance_guest_rip() -> void;
    auto consume_debug_prompt_exception(pvcpu_t vcpu, u32 vector, u32 type) -> bool;
    auto inject_event(u32 vector, u32 type, bool has_error, u32 error_code, u32 instr_len) -> bool;
    auto queue_external_interrupt(pvcpu_t vcpu, u8 vector) -> void;
    auto reinject_info(vmcs_field info_field, vmcs_field err_field, pvcpu_t vcpu) -> bool;
    auto clear_emulation_interrupt_shadow() -> void;

public:
    static auto get() -> event_handler*;

    auto clear_injection() -> void;
    auto guest_trap_flag_enabled() -> bool;
    auto guest_single_step_enabled() -> bool;
    auto pending_debug_exception_ready() -> bool;
    auto arm_pending_debug_exception(pvcpu_t vcpu) -> void;
    auto inject_db_single_step(pvcpu_t vcpu) -> void;
    auto inject_db_after_emulated_instruction(pvcpu_t vcpu) -> void;
    auto sanitize_pending_injection(pvcpu_t vcpu) -> void;
    auto arm_pending_debug_after_emulation() -> void;
    auto complete_emulated_instruction() -> void;
    auto inject_exception(u8 vector, u32 error_code, bool has_error) -> void;
    auto inject_gp(u32 error_code) -> void;
    auto inject_ud() -> void;
    auto inject_db() -> void;
    auto interrupt_window_exit_handler(pvcpu_t vcpu) -> void;
    auto queue_nmi(pvcpu_t vcpu) -> void;
    auto exception_or_nmi_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool;
    auto nmi_window_exit_handler(pvcpu_t vcpu) -> void;
    auto reinject_exit_interrupt(pvcpu_t vcpu) -> void;
    auto reinject_idt_vectoring(pvcpu_t vcpu) -> void;
};

}
