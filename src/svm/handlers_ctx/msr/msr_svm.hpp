#pragma once
#include "../../../includes.h"

namespace svm {

class msr_handler {
  private:
    bool read_msr(u32 msr, u64& value);
    bool write_msr(u32 msr, u64 value);
    void rdmsr_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u32 msr);
    void wrmsr_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u32 msr);

  public:
    static msr_handler* get();
    void msr_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
};
}
