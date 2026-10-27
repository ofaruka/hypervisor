#pragma once
#include "../../../includes.h"

namespace vtx {

class xcr_handler {
private:
    xcr_handler() = default;

    static constexpr u64 cr4_osxsave_bit = 1ULL << 18;

    auto vmread_u64(vmcs_field field, u64& value) -> bool;
    auto guest_cpl() -> u8;
    auto visible_cr4() -> u64;
    auto valid_xcr0(u64 value) -> bool;

public:
    static auto get() -> xcr_handler*;
    auto xsetbv_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool;
};

}
