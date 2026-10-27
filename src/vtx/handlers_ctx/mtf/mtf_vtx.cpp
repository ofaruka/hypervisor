#include "mtf_vtx.hpp"
#include "../events/events_vtx.hpp"

namespace vtx {

auto mtf_handler::get() -> mtf_handler* {
    static mtf_handler instance;
    return &instance;
}

auto mtf_handler::write_procbased_mtf(bool enable) -> void {
    size_t pc = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::procbased_ctls), &pc);
    if (enable) pc |= static_cast<size_t>(procbased_monitor_trap_flag);
    else pc &= ~static_cast<size_t>(procbased_monitor_trap_flag);
    __vmx_vmwrite(static_cast<size_t>(vmcs_field::procbased_ctls), pc);
}

auto mtf_handler::arm() -> void {
    write_procbased_mtf(true);
}

auto mtf_handler::disarm() -> void {
    write_procbased_mtf(false);
}

auto mtf_handler::mtf_exit_handler(pvcpu_t vcpu) -> void {
    if (vcpu) {
        vcpu->pending_mtf_unhide = nullptr;
    }
    disarm();
}

}
