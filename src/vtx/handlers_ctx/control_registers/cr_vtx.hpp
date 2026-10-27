#pragma once
#include "../../../includes.h"

namespace vtx {

class cr_handler {
private:
    static constexpr u64 cr4_vmxe_bit = 1ULL << 13;

    cr_handler() = default;

    auto vmread_u64(vmcs_field field, u64& value) -> bool;
    auto vmwrite_u64(vmcs_field field, u64 value) -> bool;
    auto read_gpr(guest_gprs* gprs, u32 index, u64& value) -> bool;
    auto write_gpr(guest_gprs* gprs, u32 index, u64 value, u8 size = 8) -> bool;
    auto valid_cr_value(u64 value, u32 fixed0_msr, u32 fixed1_msr) -> bool;
    auto guest_physical_address_mask() -> u64;
    auto set_guest_cr3(pvcpu_t vcpu, u64 value) -> bool;
    auto set_guest_cr0(pvcpu_t vcpu, u64 value) -> bool;
    auto set_guest_cr4(pvcpu_t vcpu, u64 value) -> bool;

public:
    static auto get() -> cr_handler*;
    auto cr_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool;
};

}
