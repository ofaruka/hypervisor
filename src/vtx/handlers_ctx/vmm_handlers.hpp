#pragma once
#include "../includes.h"

namespace vtx {

class vmm_dispatcher {
private:
    vmm_dispatcher() = default;

    auto guest_code_is_64_bit() -> bool;
    auto canonical_address(size_t value) -> bool;
    auto advanced_guest_rip(size_t rip, size_t length) -> size_t;

public:
    static auto get() -> vmm_dispatcher*;

    auto advance_rip(bool complete_emulation = true) -> void;
    auto prepare_devirtualize_current(pvcpu_t vcpu) -> bool;
    auto vmresume_failure(pvcpu_t vcpu) -> void;
    auto fatal_exit(exit_reason reason) -> void;
};

extern "C" u8 vtx_handle_vmexit(pvcpu_t vcpu, guest_gprs* gprs);
extern "C" void vtx_handle_vmresume_failure(pvcpu_t vcpu);

}
