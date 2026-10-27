#include "events_svm.hpp"

namespace svm {

event_handler* event_handler::get() {
    static event_handler instance;
    return &instance;
}

void event_handler::debug_exception_exit_handler(pvcpu_t vcpu) {
    event_inj_t event{};
    event.fields.vector = 1;
    event.fields.type = 3;
    event.fields.valid = 1;
    vcpu->guest_vmcb.control_area.event_inj = event.value;
}

void event_handler::general_protection_exit_handler(pvcpu_t vcpu) {
    event_inj_t{}.general_protection_exception(vcpu);
}

void event_handler::invalid_opcode_exit_handler(pvcpu_t vcpu) {
    event_inj_t{}.invalid_opcode_exception(vcpu);
}

}
