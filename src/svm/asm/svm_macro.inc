;===============================================================================
; SVM Macro Definitions
;===============================================================================

; Constants
ktrap_frame_size        equ 190h
mach_frame_size         equ 28h
gpr_stack_size          equ 80h
volatile_gpr_stack_size equ 40h
ctx_rcx                 equ 80h
ctx_rdx                 equ 88h
ctx_rbx                 equ 90h
ctx_rbp                 equ 0a0h
ctx_rsi                 equ 0a8h
ctx_rdi                 equ 0b0h
ctx_r8                  equ 0b8h
ctx_r9                  equ 0c0h
ctx_r10                 equ 0c8h
ctx_r11                 equ 0d0h
ctx_r12                 equ 0d8h
ctx_r13                 equ 0e0h
ctx_r14                 equ 0e8h
ctx_r15                 equ 0f0h

guest_r15               equ 00h
guest_r14               equ 08h
guest_r13               equ 10h
guest_r12               equ 18h
guest_r11               equ 20h
guest_r10               equ 28h
guest_r9                equ 30h
guest_r8                equ 38h
guest_rdi               equ 40h
guest_rsi               equ 48h
guest_rbp               equ 50h
guest_rsp               equ 58h
guest_rbx               equ 60h
guest_rdx               equ 68h
guest_rcx               equ 70h
guest_rax               equ 78h

; Macro for NMI-blocking iret
nmiret macro
    ; Emulate the iret instruction in order not to unblock NMIs.
    push rax                    ; Save the rax
    ; Now the stack layout would be like:
    ; qword ptr [rsp+8*0]   rax
    ; qword ptr [rsp+8*1]   rip
    ; word ptr [rsp+8*2]    cs
    ; qword ptr [rsp+8*3]   rflags
    ; qword ptr [rsp+8*4]   rsp
    ; qword ptr [rsp+8*5]   ss
    mov rax,rsp                 ; Save the NMI stack pointer.
    lss rsp,[rax+8*4]           ; Restore ss and rsp
    ; Note that rsp is switched to pre-NMI stack, so use rax for memory addressing.
    push qword ptr [rax+18h]    ; Store rflags to pre-NMI stack.
    popf                        ; Restore rflags
    push qword ptr [rax+10h]    ; Store cs to pre-NMI stack.
    push qword ptr [rax+8h]     ; Store rip to pre-NMI stack.
    mov rax,qword ptr [rax]     ; Restore rax
    retf                        ; Restore cs and rip
endm

; Macro for pushing all GPRs to stack
pushaq macro
    push rax
    push rcx
    push rdx
    push rbx
    push -1
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
endm

; Macro for popping all GPRs from stack
popaq macro
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rbx
    pop rdx
    pop rcx
    pop rax
endm

; Macro for pushing all XMM registers onto stack
pushax macro
    sub rsp, 80h
    movaps xmmword ptr [rsp + 20h], xmm0
    movaps xmmword ptr [rsp + 30h], xmm1
    movaps xmmword ptr [rsp + 40h], xmm2
    movaps xmmword ptr [rsp + 50h], xmm3
    movaps xmmword ptr [rsp + 60h], xmm4
    movaps xmmword ptr [rsp + 70h], xmm5
endm

; Macro for popping all XMM registers from stack
popax macro
    movaps xmm5, xmmword ptr [rsp + 70h]
    movaps xmm4, xmmword ptr [rsp + 60h]
    movaps xmm3, xmmword ptr [rsp + 50h]
    movaps xmm2, xmmword ptr [rsp + 40h]
    movaps xmm1, xmmword ptr [rsp + 30h]
    movaps xmm0, xmmword ptr [rsp + 20h]
    add rsp, 80h
endm
