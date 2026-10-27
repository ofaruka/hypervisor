include svm_macro.inc

host_self_from_saved_gprs equ ktrap_frame_size + gpr_stack_size + 10h
host_guest_vmcb_pa        equ ktrap_frame_size
host_leave_guest_pat      equ ktrap_frame_size + 28h
host_leave_idtr           equ ktrap_frame_size + 30h
host_leave_gdtr           equ ktrap_frame_size + 38h
; vprocessor_data::host_stack_layout.vmexit_entry_tsc, relative to the
; exit-time stack pointer (which points at host_stack_layout.guest_vmcb_pa).
host_vmexit_entry_tsc     equ 1f0h
msr_efer                  equ 0c0000080h
msr_pat                   equ 277h
efer_svme_clear_mask      equ 0ffffefffh

.code

extern vmexit_handler:proc

vmenter proc frame
    mov     rax, rdx
    mov     rsp, rcx
    mov     rbx, [rax + ctx_rbx]
    mov     rbp, [rax + ctx_rbp]
    mov     rsi, [rax + ctx_rsi]
    mov     rdi, [rax + ctx_rdi]
    mov     r8,  [rax + ctx_r8]
    mov     r9,  [rax + ctx_r9]
    mov     r10, [rax + ctx_r10]
    mov     r11, [rax + ctx_r11]
    mov     r12, [rax + ctx_r12]
    mov     r13, [rax + ctx_r13]
    mov     r14, [rax + ctx_r14]
    mov     r15, [rax + ctx_r15]
    mov     rcx, [rax + ctx_rcx]
    mov     rdx, [rax + ctx_rdx]

enter_guest:
    mov     rax, [rsp]
    clgi
    vmload  rax
    vmrun   rax
    vmsave  rax
    mov     rax, [rsp + 8]
    vmload  rax

dispatch_vmexit:
    ; Capture the entry TSC before anything else: keeping the prologue out of
    ; the measurement makes the exit latency stable across cold/warm caches,
    ; which the timing spoof's overhead calibration relies on.
    mov     qword ptr [rsp - 8], rdx
    rdtsc
    shl     rdx, 20h
    or      rax, rdx
    mov     qword ptr [rsp + host_vmexit_entry_tsc], rax
    mov     rdx, qword ptr [rsp - 8]

    .pushframe
    sub     rsp, ktrap_frame_size
    .allocstack ktrap_frame_size - mach_frame_size + 100h

    pushaq

    mov     rdx, rsp
    mov     rcx, [rsp + host_self_from_saved_gprs]

    pushax
    .endprolog

    call    vmexit_handler

    popax
    test    al, al
    popaq
    jnz     leave_svm

    add     rsp, ktrap_frame_size
    jmp     enter_guest

leave_svm:
    mov     cr4, r9
    mov     cr3, r10
    mov     cr0, r8
    mov     r8, rsp
    mov     r9, [r8 + host_guest_vmcb_pa]
    mov     r10, [r8 + host_leave_guest_pat]
    mov     rsp, rcx
    push    rax
    push    rcx
    push    rdx
    mov     rax, r9
    vmload  rax
    mov     ecx, msr_pat
    mov     rax, r10
    mov     rdx, r10
    shr     rdx, 20h
    wrmsr
    mov     rdx, [r8 + host_leave_idtr]
    lidt    fword ptr [rdx]
    mov     rdx, [r8 + host_leave_gdtr]
    lgdt    fword ptr [rdx]
    stgi
    mov     ecx, msr_efer
    rdmsr
    and     eax, efer_svme_clear_mask
    wrmsr
    pop     rdx
    pop     rcx
    pop     rax
    push    r11
    popfq
    mov     ecx, 'svm'
    jmp     rbx

vmenter endp

svm_vmmcall proc
    pushaq
    vmmcall
    popaq
    ret
svm_vmmcall endp

svm_passthrough_vmmcall proc
    push    rbx
    push    rbp
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 20h
    mov     [rsp], rcx

    mov     rax, [rcx + guest_rax]
    mov     rbx, [rcx + guest_rbx]
    mov     rbp, [rcx + guest_rbp]
    mov     rsi, [rcx + guest_rsi]
    mov     rdi, [rcx + guest_rdi]
    mov     r8,  [rcx + guest_r8]
    mov     r9,  [rcx + guest_r9]
    mov     r10, [rcx + guest_r10]
    mov     r11, [rcx + guest_r11]
    mov     r12, [rcx + guest_r12]
    mov     r13, [rcx + guest_r13]
    mov     r14, [rcx + guest_r14]
    mov     r15, [rcx + guest_r15]
    mov     rdx, [rcx + guest_rdx]
    mov     rcx, [rcx + guest_rcx]

    vmmcall

    mov     [rsp + 8], r10
    mov     r10, [rsp]
    mov     [r10 + guest_rax], rax
    mov     [r10 + guest_rbx], rbx
    mov     [r10 + guest_rbp], rbp
    mov     [r10 + guest_rsi], rsi
    mov     [r10 + guest_rdi], rdi
    mov     [r10 + guest_r8],  r8
    mov     [r10 + guest_r9],  r9
    mov     rax, [rsp + 8]
    mov     [r10 + guest_r10], rax
    mov     [r10 + guest_r11], r11
    mov     [r10 + guest_r12], r12
    mov     [r10 + guest_r13], r13
    mov     [r10 + guest_r14], r14
    mov     [r10 + guest_r15], r15
    mov     [r10 + guest_rcx], rcx
    mov     [r10 + guest_rdx], rdx

    add     rsp, 20h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbp
    pop     rbx
    ret
svm_passthrough_vmmcall endp

end
