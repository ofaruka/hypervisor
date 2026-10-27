#pragma once
#include "../includes.h"
extern "C" void divide_error_fault_handler_a(void);
extern "C" void non_maskable_interrupt_handler_a(void);
extern "C" void debug_fault_trap_handler_a(void);
extern "C" void breakpoint_trap_handler_a(void);
extern "C" void overflow_trap_handler_a(void);
extern "C" void bound_range_fault_handler_a(void);
extern "C" void invalid_opcode_fault_handler_a(void);
extern "C" void device_not_available_fault_handler_a(void);
extern "C" void x87_floating_point_fault_handler_a(void);
extern "C" void machine_check_abort_handler_a(void);
extern "C" void simd_floating_point_fault_handler_a(void);
extern "C" void double_fault_abort_handler_a(void);
extern "C" void invalid_tss_fault_handler_a(void);
extern "C" void segment_not_present_fault_handler_a(void);
extern "C" void stack_fault_handler_a(void);
extern "C" void general_protection_fault_handler_a(void);
extern "C" void page_fault_handler_a(void);
extern "C" void alignment_check_fault_handler_a(void);
extern "C" void control_protection_fault_handler_a(void);
extern "C" void non_maskable_interrupt_ready_a(void);
