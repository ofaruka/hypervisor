#pragma once
#include "../../../includes.h"

namespace svm {

class exception_dispatcher {
  private:
    exception_dispatcher() = default;

    void fatal_no_error(const char* name, pinterrupt_frame_t frame, pgpr_state_t gpr_state);
    void fatal_with_error(const char* name, pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state);

  public:
    static exception_dispatcher* get();

    void clear_trap_flag(pinterrupt_frame_t frame);
    void general_protection(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state);
    void page_fault(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state);

    void divide_error(pinterrupt_frame_t frame, pgpr_state_t gpr_state);
    void overflow(pinterrupt_frame_t frame, pgpr_state_t gpr_state);
    void bound_range(pinterrupt_frame_t frame, pgpr_state_t gpr_state);
    void invalid_opcode(pinterrupt_frame_t frame, pgpr_state_t gpr_state);
    void device_not_available(pinterrupt_frame_t frame, pgpr_state_t gpr_state);
    void x87_floating_point(pinterrupt_frame_t frame, pgpr_state_t gpr_state);
    void machine_check(pinterrupt_frame_t frame, pgpr_state_t gpr_state);
    void simd_floating_point(pinterrupt_frame_t frame, pgpr_state_t gpr_state);

    void double_fault(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state);
    void invalid_tss(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state);
    void segment_not_present(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state);
    void stack_fault(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state);
    void alignment_check(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state);
    void control_protection(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state);
};

}
