#include "gif_svm.hpp"

namespace svm {

gif_handler* gif_handler::get() {
    static gif_handler instance;
    return &instance;
}

void gif_handler::gif_exit_handler(pvcpu_t vcpu) {
    if (vcpu->host_stack_layout.shadow_data.efer.svme) {
        vcpu->guest_vmcb.state_save_area.rip = advance_rip_or_next(vcpu, 3);
        return;
    }

    event_inj_t{}.invalid_opcode_exception(vcpu);
}

}
