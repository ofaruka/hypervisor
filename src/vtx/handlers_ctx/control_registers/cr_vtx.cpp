#include "cr_vtx.hpp"

namespace vtx {

auto cr_handler::get() -> cr_handler* {
    static cr_handler instance;
    return &instance;
}

auto cr_handler::vmread_u64(vmcs_field field, u64& value) -> bool {
    size_t raw = 0;
    if (__vmx_vmread(static_cast<size_t>(field), &raw) != 0) return false;
    value = static_cast<u64>(raw);
    return true;
}

auto cr_handler::vmwrite_u64(vmcs_field field, u64 value) -> bool {
    return __vmx_vmwrite(static_cast<size_t>(field), static_cast<size_t>(value)) == 0;
}

auto cr_handler::read_gpr(guest_gprs* gprs, u32 index, u64& value) -> bool {
    if (!gprs) return false;

    switch (index) {
    case 0: value = gprs->rax; return true;
    case 1: value = gprs->rcx; return true;
    case 2: value = gprs->rdx; return true;
    case 3: value = gprs->rbx; return true;
    case 4: return vmread_u64(vmcs_field::guest_rsp, value);
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

auto cr_handler::write_gpr(guest_gprs* gprs, u32 index, u64 value, u8 size) -> bool {
    if (!gprs) return false;

    auto merge = [value, size](u64 old_value) -> u64 {
        switch (size) {
        case 2: return (old_value & ~0xffffULL) | (value & 0xffffULL);
        case 4: return value & 0xffffffffULL;
        default: return value;
        }
    };

    u64 rsp = 0;
    switch (index) {
    case 0: gprs->rax = merge(gprs->rax); return true;
    case 1: gprs->rcx = merge(gprs->rcx); return true;
    case 2: gprs->rdx = merge(gprs->rdx); return true;
    case 3: gprs->rbx = merge(gprs->rbx); return true;
    case 4:
        if (!vmread_u64(vmcs_field::guest_rsp, rsp)) return false;
        return vmwrite_u64(vmcs_field::guest_rsp, merge(rsp));
    case 5: gprs->rbp = merge(gprs->rbp); return true;
    case 6: gprs->rsi = merge(gprs->rsi); return true;
    case 7: gprs->rdi = merge(gprs->rdi); return true;
    case 8: gprs->r8 = merge(gprs->r8); return true;
    case 9: gprs->r9 = merge(gprs->r9); return true;
    case 10: gprs->r10 = merge(gprs->r10); return true;
    case 11: gprs->r11 = merge(gprs->r11); return true;
    case 12: gprs->r12 = merge(gprs->r12); return true;
    case 13: gprs->r13 = merge(gprs->r13); return true;
    case 14: gprs->r14 = merge(gprs->r14); return true;
    case 15: gprs->r15 = merge(gprs->r15); return true;
    default: return false;
    }
}

auto cr_handler::valid_cr_value(u64 value, u32 fixed0_msr, u32 fixed1_msr) -> bool {
    auto fixed0 = __readmsr(fixed0_msr);
    auto fixed1 = __readmsr(fixed1_msr);
    return (value & fixed0) == fixed0 && (value & ~fixed1) == 0;
}

auto cr_handler::guest_physical_address_mask() -> u64 {
    int regs[4] = {};
    __cpuid(regs, 0x80000000);
    if (static_cast<u32>(regs[0]) < 0x80000008) {
        return (1ULL << 36) - 1;
    }

    __cpuid(regs, 0x80000008);
    auto width = static_cast<u32>(regs[0]) & 0xff;
    if (width < 32 || width > 52) {
        width = 36;
    }

    return width == 64 ? ~0ULL : ((1ULL << width) - 1);
}

auto cr_handler::set_guest_cr3(pvcpu_t vcpu, u64 value) -> bool {
    if (!vcpu) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    constexpr u64 cr3_no_flush_bit = 1ULL << 63;
    constexpr u64 cr3_pwt_pcd_bits = (1ULL << 3) | (1ULL << 4);
    constexpr u64 cr4_pcide_bit = 1ULL << 17;

    auto pcide_enabled = (vcpu->guest_cr4 & cr4_pcide_bit) != 0;
    if (!pcide_enabled && (value & cr3_no_flush_bit) != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    auto normalized = value & ~cr3_no_flush_bit;
    auto address_mask = guest_physical_address_mask() & ~0xfffULL;
    auto low_allowed = pcide_enabled ? 0xfffULL : cr3_pwt_pcd_bits;
    auto reserved_mask = ~(address_mask | low_allowed);
    if ((normalized & reserved_mask) != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    vcpu->guest_cr3 = normalized;
    return vmwrite_u64(vmcs_field::guest_cr3, normalized);
}

auto cr_handler::set_guest_cr0(pvcpu_t vcpu, u64 value) -> bool {
    if (!vcpu || !valid_cr_value(value, vtx::msr::ia32_vmx_cr0_fixed0,
                                 vtx::msr::ia32_vmx_cr0_fixed1)) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    vcpu->guest_cr0 = value;
    vmwrite_u64(vmcs_field::guest_cr0, vmx::get()->adjust_cr0_for_vmx(value));
    vmwrite_u64(vmcs_field::cr0_read_shadow, value);
    return true;
}

auto cr_handler::set_guest_cr4(pvcpu_t vcpu, u64 value) -> bool {
    if (!vcpu || (value & cr4_vmxe_bit) != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    auto physical = value | cr4_vmxe_bit;
    if (!valid_cr_value(physical, vtx::msr::ia32_vmx_cr4_fixed0,
                        vtx::msr::ia32_vmx_cr4_fixed1)) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    constexpr u64 cr3_pwt_pcd_bits = (1ULL << 3) | (1ULL << 4);
    constexpr u64 cr4_pcide_bit = 1ULL << 17;
    auto address_mask = guest_physical_address_mask() & ~0xfffULL;
    if ((value & cr4_pcide_bit) == 0 &&
        (vcpu->guest_cr3 & ~(address_mask | cr3_pwt_pcd_bits)) != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    vcpu->guest_cr4 = value;
    vmwrite_u64(vmcs_field::guest_cr4, vmx::get()->adjust_cr4_for_vmx(physical));
    vmwrite_u64(vmcs_field::cr4_read_shadow, value);
    return true;
}

auto cr_handler::cr_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool {
    u64 qualification = 0;
    if (!vmread_u64(vmcs_field::exit_qualification, qualification)) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    auto cr = static_cast<u32>(qualification & 0xf);
    auto access = static_cast<u32>((qualification >> 4) & 3);
    auto gpr = static_cast<u32>((qualification >> 8) & 0xf);
    auto lmsw_data = static_cast<u16>((qualification >> 16) & 0xffff);

    u64 value = 0;
    switch (access) {
    case 0:
        if (!read_gpr(gprs, gpr, value)) {
            event_handler::get()->inject_gp(0);
            return false;
        }
        switch (cr) {
        case 0: return set_guest_cr0(vcpu, value);
        case 3: return set_guest_cr3(vcpu, value);
        case 4: return set_guest_cr4(vcpu, value);
        default:
            event_handler::get()->inject_gp(0);
            return false;
        }

    case 1:
        switch (cr) {
        case 0: value = vcpu ? vcpu->guest_cr0 : 0; break;
        case 3: value = vcpu ? vcpu->guest_cr3 : 0; break;
        case 4: value = vcpu ? vcpu->guest_cr4 : 0; break;
        default:
            event_handler::get()->inject_gp(0);
            return false;
        }
        if (!write_gpr(gprs, gpr, value)) {
            event_handler::get()->inject_gp(0);
            return false;
        }
        return true;

    case 2:
        if (cr != 0) {
            event_handler::get()->inject_gp(0);
            return false;
        }
        return set_guest_cr0(vcpu, (vcpu ? vcpu->guest_cr0 : 0) & ~(1ULL << 3));

    case 3: {
        auto cr0 = vcpu ? vcpu->guest_cr0 : 0;
        auto next = (cr0 & ~0xfULL) | (lmsw_data & 0xf);
        if ((cr0 & 1) != 0) next |= 1;
        return set_guest_cr0(vcpu, next);
    }

    default:
        event_handler::get()->inject_gp(0);
        return false;
    }
}

}
