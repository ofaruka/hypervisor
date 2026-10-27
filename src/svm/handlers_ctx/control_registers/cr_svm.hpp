#pragma once
#include "../includes.h"

namespace svm {

class cr_handler {
  private:
    bool handle_cr0_read(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
    bool handle_cr0_write(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
    bool handle_lmsw(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
    bool handle_smsw(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
    bool handle_clts(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
    bool apply_mov_to_cr0(svm::pvcpu_t vcpu, svm::cr0_t new_cr0);
    bool handle_cr3_read(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
    bool handle_cr3_write(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
    bool validate_pae_pdpes(svm::pvcpu_t vcpu, u64 cr3_value);
    bool handle_cr4_read(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
    bool handle_cr4_write(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
    bool validate_cr4_bits(svm::pvcpu_t vcpu, svm::cr4_t new_cr4, svm::cr4_t old_cr4, svm::cr0_t cr0);
    u64* get_register_for_cr_exit(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
    bool is_long_mode_active(svm::pvcpu_t vcpu);
    void mark_ctrl_regs_dirty(svm::pvcpu_t vcpu);

  public:
    static cr_handler* get();
    bool cr_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
};
}
