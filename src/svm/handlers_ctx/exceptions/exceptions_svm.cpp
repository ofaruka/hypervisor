#include "exceptions_svm.hpp"

namespace svm {

exception_dispatcher* exception_dispatcher::get() {
    static exception_dispatcher instance;
    return &instance;
}

void exception_dispatcher::fatal_no_error(const char* name, pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    debug::panicf("%s at rip=0x%llx frame=%p gpr=%p\n", name, frame->return_rip, frame, gpr_state);
    deadloop();
}

void exception_dispatcher::fatal_with_error(const char* name, pinterrupt_frame_with_error_t frame,
                                            pgpr_state_t gpr_state) {
    debug::panicf("%s at rip=0x%llx error=0x%llx frame=%p gpr=%p\n", name, frame->return_rip, frame->error_code, frame,
                  gpr_state);
    deadloop();
}

void exception_dispatcher::clear_trap_flag(pinterrupt_frame_t frame) {
    frame->return_rflags &= ~0x100ULL;
}

void exception_dispatcher::general_protection(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    debug::panicf("#GP rip=0x%llx rsp=0x%llx cs=0x%llx rflags=0x%llx error=0x%llx\n", frame->return_rip,
                  frame->return_rsp, frame->return_cs, frame->return_rflags, frame->error_code);
    debug::panicf("#GP rax=0x%llx rcx=0x%llx rdx=0x%llx rbx=0x%llx\n", gpr_state->rax, gpr_state->rcx,
                  gpr_state->rdx, gpr_state->rbx);
    debug::panicf("#GP rsi=0x%llx rdi=0x%llx rbp=0x%llx\n", gpr_state->rsi, gpr_state->rdi, gpr_state->rbp);
    debug::panicf("#GP r8=0x%llx r9=0x%llx r10=0x%llx r11=0x%llx\n", gpr_state->r8, gpr_state->r9, gpr_state->r10,
                  gpr_state->r11);
    deadloop();
}

void exception_dispatcher::page_fault(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    UNREFERENCED_PARAMETER(gpr_state);
    debug::panicf("#PF rip=0x%llx cr2=0x%llx error=0x%llx\n", frame->return_rip, __readcr2(), frame->error_code);
    deadloop();
}

void exception_dispatcher::divide_error(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    fatal_no_error("#DE", frame, gpr_state);
}

void exception_dispatcher::overflow(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    fatal_no_error("#OF", frame, gpr_state);
}

void exception_dispatcher::bound_range(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    fatal_no_error("#BR", frame, gpr_state);
}

void exception_dispatcher::invalid_opcode(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    fatal_no_error("#UD", frame, gpr_state);
}

void exception_dispatcher::device_not_available(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    fatal_no_error("#NM", frame, gpr_state);
}

void exception_dispatcher::x87_floating_point(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    fatal_no_error("#MF", frame, gpr_state);
}

void exception_dispatcher::machine_check(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    fatal_no_error("#MC", frame, gpr_state);
}

void exception_dispatcher::simd_floating_point(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    fatal_no_error("#XM", frame, gpr_state);
}

void exception_dispatcher::double_fault(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    fatal_with_error("#DF", frame, gpr_state);
}

void exception_dispatcher::invalid_tss(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    fatal_with_error("#TS", frame, gpr_state);
}

void exception_dispatcher::segment_not_present(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    fatal_with_error("#NP", frame, gpr_state);
}

void exception_dispatcher::stack_fault(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    fatal_with_error("#SS", frame, gpr_state);
}

void exception_dispatcher::alignment_check(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    fatal_with_error("#AC", frame, gpr_state);
}

void exception_dispatcher::control_protection(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    fatal_with_error("#CP", frame, gpr_state);
}

extern "C" void divide_error_fault_handler(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->divide_error(frame, gpr_state);
}

extern "C" void debug_fault_trap_handler(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    UNREFERENCED_PARAMETER(gpr_state);
    exception_dispatcher::get()->clear_trap_flag(frame);
}

extern "C" void breakpoint_trap_handler(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    UNREFERENCED_PARAMETER(gpr_state);
    exception_dispatcher::get()->clear_trap_flag(frame);
}

extern "C" void overflow_trap_handler(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->overflow(frame, gpr_state);
}

extern "C" void bound_range_fault_handler(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->bound_range(frame, gpr_state);
}

extern "C" void invalid_opcode_fault_handler(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->invalid_opcode(frame, gpr_state);
}

extern "C" void device_not_available_fault_handler(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->device_not_available(frame, gpr_state);
}

extern "C" void x87_floating_point_fault_handler(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->x87_floating_point(frame, gpr_state);
}

extern "C" void machine_check_abort_handler(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->machine_check(frame, gpr_state);
}

extern "C" void simd_floating_point_fault_handler(pinterrupt_frame_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->simd_floating_point(frame, gpr_state);
}

extern "C" void double_fault_abort_handler(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->double_fault(frame, gpr_state);
}

extern "C" void invalid_tss_fault_handler(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->invalid_tss(frame, gpr_state);
}

extern "C" void segment_not_present_fault_handler(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->segment_not_present(frame, gpr_state);
}

extern "C" void stack_fault_handler(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->stack_fault(frame, gpr_state);
}

extern "C" void general_protection_fault_handler(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->general_protection(frame, gpr_state);
}

extern "C" void page_fault_handler(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->page_fault(frame, gpr_state);
}

extern "C" void alignment_check_fault_handler(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->alignment_check(frame, gpr_state);
}

extern "C" void control_protection_fault_handler(pinterrupt_frame_with_error_t frame, pgpr_state_t gpr_state) {
    exception_dispatcher::get()->control_protection(frame, gpr_state);
}

}
