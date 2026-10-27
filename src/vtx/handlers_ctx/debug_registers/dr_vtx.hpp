#pragma once
#include "../../../includes.h"

namespace vtx {

class dr_handler {
private:
    dr_handler() = default;

    static constexpr u64 dr6_writable_mask = 0x000000000000e00fULL;
    static constexpr u64 dr6_fixed_bits = 0x00000000ffff0ff0ULL;
    static constexpr u64 dr7_writable_mask = 0x00000000ffff23ffULL;
    static constexpr u64 dr7_fixed_bits = 0x0000000000000400ULL;
    static constexpr u64 dr7_general_detect = 1ULL << 13;
    static constexpr u64 cr4_debug_extensions = 1ULL << 3;

    auto is_canonical_address(u64 value) -> bool;
    auto sanitize_dr6(u64 value) -> u64;
    auto sanitize_dr7(u64 value) -> u64;
    auto get_gpr(guest_gprs* gprs, u32 index, u64& value) -> bool;
    auto set_gpr(guest_gprs* gprs, u32 index, u64 value) -> bool;
    auto read_debug_register(pvcpu_t vcpu, u32 index, u64& value) -> bool;
    auto write_debug_register(pvcpu_t vcpu, u32 index, u64 value) -> bool;

public:
    static auto get() -> dr_handler*;

    auto prepare_debug_state(pvcpu_t vcpu) -> void;
    auto save_guest_debug_state(pvcpu_t vcpu) -> void;
    auto restore_host_debug_state(pvcpu_t vcpu) -> void;
    auto load_guest_debug_state(pvcpu_t vcpu, bool load_dr7) -> void;
    auto set_single_step_status(pvcpu_t vcpu) -> void;
    auto sync_debug_exception(pvcpu_t vcpu, size_t qualification) -> void;
    auto dr_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool;
};

}
