#pragma once
#include "../../../includes.h"

namespace svm {

class efer_handler {
  private:
    efer_handler() = default;

  public:
    static efer_handler* get();
    bool write_guest_efer(svm::pvcpu_t vcpu, u64 value);
    void efer_write_trap_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
};
}
