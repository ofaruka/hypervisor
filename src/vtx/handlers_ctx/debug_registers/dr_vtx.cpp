#include "dr_vtx.hpp"
#include "../events/events_vtx.hpp"

namespace vtx {

auto dr_handler::get() -> dr_handler* {
    static dr_handler instance;
    return &instance;
}

auto dr_handler::is_canonical_address(u64 value) -> bool {
    auto extended = (static_cast<i64>(value) << 16) >> 16;
    return static_cast<u64>(extended) == value;
}

auto dr_handler::sanitize_dr6(u64 value) -> u64 {
    return (value & dr6_writable_mask) | dr6_fixed_bits;
}

auto dr_handler::sanitize_dr7(u64 value) -> u64 {
    return (value & dr7_writable_mask) | dr7_fixed_bits;
}

auto dr_handler::get_gpr(guest_gprs* gprs, u32 index, u64& value) -> bool {
    if (!gprs) return false;

    switch (index) {
    case 0: value = gprs->rax; return true;
    case 1: value = gprs->rcx; return true;
    case 2: value = gprs->rdx; return true;
    case 3: value = gprs->rbx; return true;
    case 4: {
        size_t rsp = 0;
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rsp), &rsp);
        value = rsp;
        return true;
    }
    case 5: value = gprs->rbp; return true;
    case 6: value = gprs->rsi; return true;
    case 7: value = gprs->rdi; return true;
    case 8: value = gprs->r8; return true;
    case 9: value = gprs->r9; return true;
    case 10: value = gprs->r10; return true;
    case 11: value = gprs->r11; return true;
    case 12: value = gprs->r12; return true;
    case 13: value = gprs->r13; return true;
    case 14: value = gprs->r14; return true;
    case 15: value = gprs->r15; return true;
    default: return false;
    }
}

auto dr_handler::set_gpr(guest_gprs* gprs, u32 index, u64 value) -> bool {
    if (!gprs) return false;

    switch (index) {
    case 0: gprs->rax = value; return true;
    case 1: gprs->rcx = value; return true;
    case 2: gprs->rdx = value; return true;
    case 3: gprs->rbx = value; return true;
    case 4:
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_rsp), value);
        return true;
    case 5: gprs->rbp = value; return true;
    case 6: gprs->rsi = value; return true;
    case 7: gprs->rdi = value; return true;
    case 8: gprs->r8 = value; return true;
    case 9: gprs->r9 = value; return true;
    case 10: gprs->r10 = value; return true;
    case 11: gprs->r11 = value; return true;
    case 12: gprs->r12 = value; return true;
    case 13: gprs->r13 = value; return true;
    case 14: gprs->r14 = value; return true;
    case 15: gprs->r15 = value; return true;
    default: return false;
    }
}

auto dr_handler::read_debug_register(pvcpu_t vcpu, u32 index, u64& value) -> bool {
    if (!vcpu) return false;

    switch (index) {
    case 0: value = vcpu->guest_debug.dr0 = __readdr(0); return true;
    case 1: value = vcpu->guest_debug.dr1 = __readdr(1); return true;
    case 2: value = vcpu->guest_debug.dr2 = __readdr(2); return true;
    case 3: value = vcpu->guest_debug.dr3 = __readdr(3); return true;
    case 6: value = vcpu->guest_debug.dr6 = sanitize_dr6(__readdr(6)); return true;
    case 7: {
        size_t guest_dr7 = 0;
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_dr7), &guest_dr7);
        value = vcpu->guest_debug.dr7 = sanitize_dr7(guest_dr7);
        return true;
    }
    default: return false;
    }
}

auto dr_handler::write_debug_register(pvcpu_t vcpu, u32 index, u64 value) -> bool {
    if (!vcpu) return false;

    switch (index) {
    case 0:
        vcpu->guest_debug.dr0 = value;
        __writedr(0, value);
        return true;
    case 1:
        vcpu->guest_debug.dr1 = value;
        __writedr(1, value);
        return true;
    case 2:
        vcpu->guest_debug.dr2 = value;
        __writedr(2, value);
        return true;
    case 3:
        vcpu->guest_debug.dr3 = value;
        __writedr(3, value);
        return true;
    case 6:
        vcpu->guest_debug.dr6 = sanitize_dr6(value);
        __writedr(6, vcpu->guest_debug.dr6);
        return true;
    case 7:
        vcpu->guest_debug.dr7 = sanitize_dr7(value);
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_dr7), vcpu->guest_debug.dr7);
        return true;
    default:
        return false;
    }
}

auto dr_handler::prepare_debug_state(pvcpu_t vcpu) -> void {
    if (!vcpu) return;

    vcpu->guest_debug.dr0 = __readdr(0);
    vcpu->guest_debug.dr1 = __readdr(1);
    vcpu->guest_debug.dr2 = __readdr(2);
    vcpu->guest_debug.dr3 = __readdr(3);
    vcpu->guest_debug.dr6 = sanitize_dr6(__readdr(6));
    vcpu->guest_debug.dr7 = sanitize_dr7(__readdr(7));

    RtlZeroMemory(&vcpu->host_debug, sizeof(vcpu->host_debug));
    vcpu->host_debug.dr6 = dr6_fixed_bits;
    vcpu->host_debug.dr7 = dr7_fixed_bits;
    vcpu->pending_external_interrupt = 0;
    vcpu->pending_external_vector = 0;
    vcpu->pending_nmi = 0;
    vcpu->nmi_active = 0;
}

auto dr_handler::save_guest_debug_state(pvcpu_t vcpu) -> void {
    if (!vcpu) return;

    vcpu->guest_debug.dr0 = __readdr(0);
    vcpu->guest_debug.dr1 = __readdr(1);
    vcpu->guest_debug.dr2 = __readdr(2);
    vcpu->guest_debug.dr3 = __readdr(3);
    vcpu->guest_debug.dr6 = sanitize_dr6(__readdr(6));

    size_t guest_dr7 = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_dr7), &guest_dr7);
    vcpu->guest_debug.dr7 = sanitize_dr7(guest_dr7);
}

auto dr_handler::restore_host_debug_state(pvcpu_t vcpu) -> void {
    if (!vcpu) return;

    __writedr(7, dr7_fixed_bits);
    __writedr(0, vcpu->host_debug.dr0);
    __writedr(1, vcpu->host_debug.dr1);
    __writedr(2, vcpu->host_debug.dr2);
    __writedr(3, vcpu->host_debug.dr3);
    __writedr(6, sanitize_dr6(vcpu->host_debug.dr6));
    __writedr(7, sanitize_dr7(vcpu->host_debug.dr7));
}

auto dr_handler::load_guest_debug_state(pvcpu_t vcpu, bool load_dr7) -> void {
    if (!vcpu) return;

    __writedr(7, dr7_fixed_bits);
    __writedr(0, vcpu->guest_debug.dr0);
    __writedr(1, vcpu->guest_debug.dr1);
    __writedr(2, vcpu->guest_debug.dr2);
    __writedr(3, vcpu->guest_debug.dr3);
    __writedr(6, sanitize_dr6(vcpu->guest_debug.dr6));
    __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_dr7), sanitize_dr7(vcpu->guest_debug.dr7));

    if (load_dr7) {
        __writedr(7, sanitize_dr7(vcpu->guest_debug.dr7));
    }
}

auto dr_handler::set_single_step_status(pvcpu_t vcpu) -> void {
    if (!vcpu) return;

    constexpr u64 dr6_single_step = 1ULL << 14;
    vcpu->guest_debug.dr6 = sanitize_dr6(vcpu->guest_debug.dr6 | dr6_single_step);
    __writedr(6, vcpu->guest_debug.dr6);
}

auto dr_handler::sync_debug_exception(pvcpu_t vcpu, size_t qualification) -> void {
    if (!vcpu) return;

    vcpu->guest_debug.dr6 = sanitize_dr6(static_cast<u64>(qualification));
    __writedr(6, vcpu->guest_debug.dr6);
}

auto dr_handler::dr_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool {
    if (!vcpu || !gprs) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    size_t qualification = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::exit_qualification), &qualification);

    auto dr_index = static_cast<u32>(qualification & 7);
    auto from_dr = ((qualification >> 4) & 1) != 0;
    auto gpr_index = static_cast<u32>((qualification >> 8) & 0xf);

    size_t cs = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cs_sel), &cs);
    if ((cs & 3) != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    if (dr_index == 4 || dr_index == 5) {
        size_t cr4 = 0;
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cr4), &cr4);
        if ((cr4 & cr4_debug_extensions) != 0) {
            event_handler::get()->inject_ud();
            return false;
        }

        dr_index = (dr_index == 4) ? 6 : 7;
    }

    if ((vcpu->guest_debug.dr7 & dr7_general_detect) != 0) {
        vcpu->guest_debug.dr7 = sanitize_dr7(vcpu->guest_debug.dr7 & ~dr7_general_detect);
        vcpu->guest_debug.dr6 = sanitize_dr6(1ULL << 13);
        __writedr(6, vcpu->guest_debug.dr6);
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_dr7), vcpu->guest_debug.dr7);
        event_handler::get()->inject_db();
        return false;
    }

    if (from_dr) {
        u64 value = 0;
        if (!read_debug_register(vcpu, dr_index, value)) {
            event_handler::get()->inject_ud();
            return false;
        }

        if (!set_gpr(gprs, gpr_index, value)) {
            event_handler::get()->inject_gp(0);
            return false;
        }

        return true;
    }

    u64 value = 0;
    if (!get_gpr(gprs, gpr_index, value)) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    if ((dr_index == 6 || dr_index == 7) && (value >> 32) != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    if (dr_index <= 3 && !is_canonical_address(value)) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    if (!write_debug_register(vcpu, dr_index, value)) {
        event_handler::get()->inject_ud();
        return false;
    }

    return true;
}

}
