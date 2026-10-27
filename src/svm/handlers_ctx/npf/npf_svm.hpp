#pragma once
#include "../includes.h"

namespace svm {

class npf_handler {
  private:
    bool handle_not_present_fault(svm::pvcpu_t vcpu, const page_context& ctx);
    bool handle_execute_fault(svm::pvcpu_t vcpu, const page_context& ctx);
    bool handle_write_fault(svm::pvcpu_t vcpu, const page_context& ctx);
    bool is_shadow_npt_active(svm::pvcpu_t vcpu);
    bool is_crossing_boundary_instruction(svm::pvcpu_t vcpu);
    bool is_page_active_in_shadow(svm::pvcpu_t vcpu, u64 virtual_address);
    bool enable_shadow_execute(svm::pvcpu_t vcpu, u64 virtual_address);
    bool handle_instruction_splitting(svm::pvcpu_t vcpu);
    void setup_pte(pte_64* pte, u64 pfn, bool allow_exec, bool allow_write);
    bool setup_new_page_in_primary(svm::pvcpu_t vcpu, u64 page_pfn);
    bool setup_new_page_in_shadow(svm::pvcpu_t vcpu, u64 page_pfn);

  public:
    static npf_handler* get();
    void npf_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
};
}
