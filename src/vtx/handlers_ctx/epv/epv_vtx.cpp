#include "epv_vtx.hpp"
#include "../../../hv_spinlock.hpp"

namespace vtx {

auto epv_handler::get() -> epv_handler* {
    static epv_handler instance;
    return &instance;
}

auto epv_handler::epv_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool {
    hv_shared_lock_guard lock;

    size_t qual = 0, gpa = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::exit_qualification),     &qual);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_physical_address), &gpa);

    if (!ept::get()->handle_hook_violation(gpa, qual)) {
        return mmio::get()->handle_fault(vcpu, gprs, gpa, qual);
    }
    return true;
}

}
