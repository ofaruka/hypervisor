include svm_macro.inc

.code _text

extern divide_error_fault_handler:proc
extern debug_fault_trap_handler:proc
extern breakpoint_trap_handler:proc
extern overflow_trap_handler:proc
extern bound_range_fault_handler:proc
extern invalid_opcode_fault_handler:proc
extern device_not_available_fault_handler:proc
extern double_fault_abort_handler:proc
extern invalid_tss_fault_handler:proc
extern segment_not_present_fault_handler:proc
extern stack_fault_handler:proc
extern general_protection_fault_handler:proc
extern page_fault_handler:proc
extern x87_floating_point_fault_handler:proc
extern alignment_check_fault_handler:proc
extern machine_check_abort_handler:proc
extern simd_floating_point_fault_handler:proc
extern control_protection_fault_handler:proc

non_maskable_interrupt_handler_a proc

	; We do not handle NMI on ourself. NMI should be forwarded.
	; First of all, immediately disable interrupts globally.
	clgi
	; Use a special macro to return from NMI but do not unblock NMIs.
	nmiret
	; The arriving NMI is kept pending even if GIF is set later.

non_maskable_interrupt_handler_a endp

non_maskable_interrupt_ready_a proc

	; Set the GIF to unblock the NMI due to GIF.
	stgi
	; NMI should occur immediately after this instruction.
	; NMI has completed without unblocking NMIs here.
	; The return value is the stack.
	; Hypervisor must inject NMI to the guest once the
	; nested hypervisor enters vGIF=1 state.
	ret

non_maskable_interrupt_ready_a endp

divide_error_fault_handler_a proc

	pushaq
	; Construct parameters for the exception handler.
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler.
	sub rsp,20h
	call divide_error_fault_handler
	add rsp,20h
	popaq
	iretq

divide_error_fault_handler_a endp

debug_fault_trap_handler_a proc

	pushaq
	; Construct parameters for the exception handler.
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call debug_fault_trap_handler
	add rsp,20h
	popaq
	iretq

debug_fault_trap_handler_a endp

breakpoint_trap_handler_a proc

	pushaq
	; Construct parameters for the exception handler.
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call breakpoint_trap_handler
	add rsp,20h
	popaq
	iretq

breakpoint_trap_handler_a endp

overflow_trap_handler_a proc

	pushaq
	; Construct parameters for the exception handler.
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call overflow_trap_handler
	add rsp,20h
	popaq
	iretq

overflow_trap_handler_a endp

bound_range_fault_handler_a proc

	pushaq
	; Construct parameters for the exception handler.
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call bound_range_fault_handler
	add rsp,20h
	popaq
	iretq

bound_range_fault_handler_a endp

invalid_opcode_fault_handler_a proc

	pushaq
	; Construct parameters for the exception handler.
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call invalid_opcode_fault_handler
	add rsp,20h
	popaq
	iretq

invalid_opcode_fault_handler_a endp

device_not_available_fault_handler_a proc

	pushaq
	; Construct parameters for the exception handler.
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call device_not_available_fault_handler
	add rsp,20h
	popaq
	iretq

device_not_available_fault_handler_a endp

double_fault_abort_handler_a proc

	pushaq
	; Construct parameters for the exception handler.
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call double_fault_abort_handler
	add rsp,20h
	popaq
	; #DF has an error code. It must be popped out before the exception returns.
	add rsp,8
	iretq

double_fault_abort_handler_a endp

invalid_tss_fault_handler_a proc

	pushaq
	; Construct parameters for the exception handler
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call invalid_tss_fault_handler
	add rsp,20h
	popaq
	; #TS has an error code. It must be popped out before the exception returns.
	add rsp,8
	iretq

invalid_tss_fault_handler_a endp

segment_not_present_fault_handler_a proc

	pushaq
	; Construct parameters for the exception handler
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call segment_not_present_fault_handler
	add rsp,20h
	popaq
	; #NP has an error code. It must be popped out before the exception returns.
	add rsp,8
	iretq

segment_not_present_fault_handler_a endp

stack_fault_handler_a proc

	pushaq
	; Construct parameters for the exception handler
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call stack_fault_handler
	add rsp,20h
	popaq
	; #SS has an error code. It must be popped out before the exception returns.
	add rsp,8
	iretq

stack_fault_handler_a endp

general_protection_fault_handler_a proc

	; #GP might occur when switching to invalid Guest state.
	pushaq
	; Construct parameters for the exception handler.
	lea rcx,[rsp+gpr_stack_size]	; The first parameter stores the exception frame.
	mov rdx,rsp						; The second parameter stores the GPR state.
	; Call the handler.
	sub rsp,20h
	call general_protection_fault_handler
	add rsp,20h
	popaq
	; #GP has an error code. It must be popped out before the exception returns.
	add rsp,8
	iretq

general_protection_fault_handler_a endp

page_fault_handler_a proc

	; #PF might occur when attempting to access guest memory.
	pushaq	; Save Registers.
	; Construct parameters for the exception handler.
	lea rcx,[rsp+gpr_stack_size]	; The first parameter stores the exception frame.
	mov rdx,rsp						; The second parameter stores the GPR state.
	; Call the handler.
	sub rsp,20h
	call page_fault_handler
	add rsp,20h
	popaq	; Restore Registers.
	; #PF has an error code. It must be popped out before the exception returns.
	add rsp,8
	iretq

page_fault_handler_a endp

x87_floating_point_fault_handler_a proc

	pushaq
	; Construct parameters for the exception handler
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call x87_floating_point_fault_handler
	add rsp,20h
	popaq
	iretq

x87_floating_point_fault_handler_a endp

alignment_check_fault_handler_a proc

	pushaq
	; Construct parameters for the exception handler
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call alignment_check_fault_handler
	add rsp,20h
	popaq
	; #AC has an error code. It must be popped out before the exception returns.
	add rsp,8
	iretq

alignment_check_fault_handler_a endp

machine_check_abort_handler_a proc

	pushaq
	; Construct parameters for the exception handler
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call machine_check_abort_handler
	add rsp,20h
	popaq
	iretq

machine_check_abort_handler_a endp

simd_floating_point_fault_handler_a proc

	pushaq
	; Construct parameters for the exception handler
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call simd_floating_point_fault_handler
	add rsp,20h
	popaq
	iretq

simd_floating_point_fault_handler_a endp

control_protection_fault_handler_a proc

	pushaq
	; Construct parameters for the exception handler
	lea rcx,[rsp+gpr_stack_size]
	mov rdx,rsp
	; Call the handler
	sub rsp,20h
	call control_protection_fault_handler
	add rsp,20h
	popaq
	; #CP has an error code. It must be popped out before the exception returns.
	add rsp,8
	iretq

control_protection_fault_handler_a endp

end