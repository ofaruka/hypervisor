#pragma once
#include "../includes.h"

namespace svm {

class dr_handler {
  private:
    struct debug_state {
        u64 dr0;
        u64 dr1;
        u64 dr2;
        u64 dr3;
        u64 dr6;
        u64 dr7;
    };
    void mark_dbg_regs_dirty(svm::pvcpu_t vcpu);
    u64* get_register_for_dr_exit(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);

  public:
    static dr_handler* get();
    void dr_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
    void prepare_debug_state(svm::pvcpu_t vcpu);
    void save_host_debug_state(svm::pvcpu_t vcpu);
    void restore_host_debug_state(svm::pvcpu_t vcpu);
    void load_guest_debug_state(svm::pvcpu_t vcpu);
};
}
