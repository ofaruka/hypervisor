#pragma once
#include "../../../includes.h"

namespace vtx {

class mtf_handler {
private:
    mtf_handler() = default;

    auto write_procbased_mtf(bool enable) -> void;

public:
    static auto get() -> mtf_handler*;

    // Set procbased_ctls.MTF so the next instruction in the guest fires a
    // monitor_trap_flag VM-exit. Used by epv_handler to single-step past a
    // hooked page-fetch and re-arm the EPT hook.
    auto arm() -> void;
    auto disarm() -> void;

    // Restore the data PTE (orig_pfn, R/W only) and clear pending state.
    auto mtf_exit_handler(pvcpu_t vcpu) -> void;
};

}
