#pragma once
#include "../includes.h"

namespace svm {

class idt {
  private:
    struct exception_handler_info {
        void* handler;
        bool has_error_code;
        uint8_t ist_index;
        bool forward_to_guest;
    };
    static constexpr exception_handler_info handler_table[] = {
        {(void*)divide_error_fault_handler_a, false, 0, true},
        {(void*)debug_fault_trap_handler_a, false, 0, true},
        {nullptr, false, 2, false},
        {(void*)breakpoint_trap_handler_a, false, 0, true},
        {(void*)overflow_trap_handler_a, false, 0, true},
        {(void*)bound_range_fault_handler_a, false, 0, true},
        {(void*)invalid_opcode_fault_handler_a, false, 0, true},
        {(void*)device_not_available_fault_handler_a, false, 0, true},
        {(void*)double_fault_abort_handler_a, true, 1, false},
        {nullptr, false, 0, false},
        {(void*)invalid_tss_fault_handler_a, true, 0, true},
        {(void*)segment_not_present_fault_handler_a, true, 0, true},
        {(void*)stack_fault_handler_a, true, 0, true},
        {(void*)general_protection_fault_handler_a, true, 0, true},
        {(void*)page_fault_handler_a, true, 0, true},
        {nullptr, false, 0, false},
        {(void*)x87_floating_point_fault_handler_a, false, 0, true},
        {(void*)alignment_check_fault_handler_a, true, 0, true},
        {(void*)machine_check_abort_handler_a, false, 1, false},
        {(void*)simd_floating_point_fault_handler_a, false, 0, true},
        {nullptr, false, 0, false},
        {(void*)control_protection_fault_handler_a, true, 0, true},
    };
    void set_idt_entry(svm::idt_entry_t* idt_table, uint8_t vector, void* handler, uint16_t selector, uint8_t type,
                       uint8_t dpl, uint8_t ist = 0);

  public:
    void prepare_host_idt(svm::pvcpu_t vcpu);
    void restore_guest_idt(svm::pvcpu_t vcpu);
    static idt* get();
};
}
