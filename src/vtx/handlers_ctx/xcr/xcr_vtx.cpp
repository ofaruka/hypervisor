#include "xcr_vtx.hpp"

namespace vtx {

auto xcr_handler::get() -> xcr_handler* {
    static xcr_handler instance;
    return &instance;
}

auto xcr_handler::vmread_u64(vmcs_field field, u64& value) -> bool {
    size_t raw = 0;
    if (__vmx_vmread(static_cast<size_t>(field), &raw) != 0) return false;
    value = static_cast<u64>(raw);
    return true;
}

auto xcr_handler::guest_cpl() -> u8 {
    u64 cs = 0;
    vmread_u64(vmcs_field::guest_cs_sel, cs);
    return static_cast<u8>(cs & 3);
}

auto xcr_handler::visible_cr4() -> u64 {
    u64 guest = 0, shadow = 0, mask = 0;
    vmread_u64(vmcs_field::guest_cr4, guest);
    vmread_u64(vmcs_field::cr4_read_shadow, shadow);
    vmread_u64(vmcs_field::cr4_guest_host_mask, mask);
    return (guest & ~mask) | (shadow & mask);
}

auto xcr_handler::valid_xcr0(u64 value) -> bool {
    int regs[4] = {};
    __cpuidex(regs, 0, 0);
    if (static_cast<u32>(regs[0]) < 0x0d) return false;

    __cpuidex(regs, 0x0d, 0);
    auto supported = static_cast<u64>(static_cast<u32>(regs[0])) |
                     (static_cast<u64>(static_cast<u32>(regs[3])) << 32);

    constexpr u64 x87 = 1ULL << 0;
    constexpr u64 sse = 1ULL << 1;
    constexpr u64 ymm = 1ULL << 2;
    constexpr u64 bndregs = 1ULL << 3;
    constexpr u64 bndcsr = 1ULL << 4;
    constexpr u64 opmask = 1ULL << 5;
    constexpr u64 zmm_hi256 = 1ULL << 6;
    constexpr u64 hi16_zmm = 1ULL << 7;
    constexpr u64 tile_cfg = 1ULL << 17;
    constexpr u64 tile_data = 1ULL << 18;

    if ((value & ~supported) != 0) return false;
    if ((value & x87) == 0) return false;
    if ((value & ymm) != 0 && (value & sse) == 0) return false;
    if (((value & bndregs) == 0) != ((value & bndcsr) == 0)) return false;

    auto avx512 = value & (opmask | zmm_hi256 | hi16_zmm);
    if (avx512 != 0 && avx512 != (opmask | zmm_hi256 | hi16_zmm)) return false;
    if (avx512 != 0 && (value & (sse | ymm)) != (sse | ymm)) return false;
    if ((value & tile_data) != 0 && (value & tile_cfg) == 0) return false;
    return true;
}

auto xcr_handler::xsetbv_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool {
    if (!vcpu || !gprs) return false;
    if (guest_cpl() != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }
    if ((visible_cr4() & cr4_osxsave_bit) == 0) {
        event_handler::get()->inject_ud();
        return false;
    }
    if (static_cast<u32>(gprs->rcx) != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    auto value = (gprs->rax & 0xffffffffULL) | ((gprs->rdx & 0xffffffffULL) << 32);
    if (!valid_xcr0(value)) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    __try {
        _xsetbv(0, value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    vcpu->guest_xcr0 = value;
    return true;
}

}
