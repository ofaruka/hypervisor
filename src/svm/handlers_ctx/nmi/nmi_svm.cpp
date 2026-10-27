#include "nmi_svm.hpp"

namespace svm {

nmi_handler* nmi_handler::get() {
    static nmi_handler instance;
    return &instance;
}

void nmi_handler::nmi_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    UNREFERENCED_PARAMETER(guest_ctx);

    event_inj_t event{};
    event.fields.vector = 2;
    event.fields.type = 2;
    event.fields.valid = 1;
    vcpu->guest_vmcb.control_area.event_inj = event.value;
}
}
