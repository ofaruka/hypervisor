#include "efer_svm.hpp"

namespace svm {

efer_handler* efer_handler::get() {
    static efer_handler instance;
    return &instance;
}

bool efer_handler::write_guest_efer(svm::pvcpu_t vcpu, u64 value) {
    svm::efer_msr efer{};
    efer.value = value;

    if (vcpu->guest_vmcb.state_save_area.efer.long_mode_active && !efer.long_mode_enable) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    if (efer.long_mode_enable && !vcpu->guest_vmcb.state_save_area.cr4.pae) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    efer.long_mode_active = efer.long_mode_enable && vcpu->guest_vmcb.state_save_area.cr0.pg;
    efer.svme = 0;
    vcpu->host_stack_layout.shadow_data.efer = efer;
    efer.svme = 1;
    vcpu->guest_vmcb.state_save_area.efer = efer;
    return true;
}

void efer_handler::efer_write_trap_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    ULARGE_INTEGER value{};
    value.LowPart = guest_ctx->vprocessor_registers->rax.value & MAXUINT;
    value.HighPart = guest_ctx->vprocessor_registers->rdx.value & MAXUINT;

    if (write_guest_efer(vcpu, value.QuadPart)) {
        vcpu->guest_vmcb.state_save_area.rip = advance_rip_or_next(vcpu, 2);
    }
}
}
