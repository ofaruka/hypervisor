#pragma once
#include "../../includes.h"

namespace svm {

class vmm_dispatcher {
  private:
    vmm_dispatcher() = default;

    void begin_exit(pvcpu_t vcpu, pguest_registers_t registers, guest_ctx_t& guest_ctx);
    void dispatch_exit(pvcpu_t vcpu, guest_ctx_t& guest_ctx);
    bool finish_exit(pvcpu_t vcpu, guest_ctx_t& guest_ctx);

    bool leave_svm(pvcpu_t vcpu, guest_ctx_t& guest_ctx);
    void fatal_exit(pvcpu_t vcpu);

  public:
    static vmm_dispatcher* get();
    bool handle_vmexit(pvcpu_t vcpu, pguest_registers_t registers);
};

extern "C" bool vmexit_handler(pvcpu_t vcpu, pguest_registers_t registers);

}
