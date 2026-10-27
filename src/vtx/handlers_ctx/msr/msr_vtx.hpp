#pragma once
#include "../../../includes.h"

namespace vtx {

class msr_handler {
private:
    msr_handler() = default;

    static constexpr u32 perf_counter_count_max = 8;

    auto set_bitmap(u8* bitmap, u32 msr, bool read, bool write) -> void;
    auto inject_gp() -> void;
    auto read_msr(u32 msr, u64& value) -> bool;
    auto write_msr(u32 msr, u64 value) -> bool;
    auto validate_msr_write(u32 msr, u64 value) -> bool;
    auto add_managed_msr(pvcpu_t vcpu, u32 msr, bool required) -> bool;
    auto get_managed_msr(pvcpu_t vcpu, u32 msr, u64& value) -> bool;
    auto set_managed_msr(pvcpu_t vcpu, u32 msr, u64 value) -> bool;
    auto is_canonical(u64 value) -> bool;
    auto is_valid_pat(u64 value) -> bool;
    auto is_mtrr_msr(u32 msr) -> bool;
    auto is_vmx_msr(u32 msr) -> bool;
    auto is_kvm_msr(u32 msr) -> bool;
    auto is_lbr_msr(u32 msr, u32& index) -> bool;
    auto debugctl_valid_bits() -> u64;

    auto rdmsr_handler(pvcpu_t vcpu, guest_gprs* gprs, u32 msr) -> bool;
    auto wrmsr_handler(pvcpu_t vcpu, guest_gprs* gprs, u32 msr) -> bool;

public:
    static auto get() -> msr_handler*;
    auto read_raw_msr(u32 msr, u64& value) -> bool;
    auto read_guest_msr(pvcpu_t vcpu, u32 msr, u64& value) -> bool;

    auto setup_managed_msrs(pvcpu_t vcpu) -> bool;
    auto load_managed_msrs(pvcpu_t vcpu) -> void;
    auto prepare_bitmap(u8* bitmap) -> void;
    auto msr_exit_handler(pvcpu_t vcpu, guest_gprs* gprs, bool is_write) -> bool;
};

}
