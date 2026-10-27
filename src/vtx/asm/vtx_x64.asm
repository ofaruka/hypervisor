include vtx_macro.inc

.code

extern vtx_handle_vmexit:proc
extern vtx_handle_vmresume_failure:proc

vtx_vmlaunch_entry proc
    pushfq
    pop r9
    cli

    mov rax, vmcs_guest_rsp
    vmwrite rax, rsp
    jbe vmwrite_failed

    mov rax, vmcs_guest_rip
    lea r8, after_vmlaunch
    vmwrite rax, r8
    jbe vmwrite_failed

    vmlaunch

vmwrite_failed:
    push r9
    popfq
    xor eax, eax
    ret

after_vmlaunch:
    push r9
    popfq
    mov eax, 1
    ret
vtx_vmlaunch_entry endp

vtx_vmexit_entry proc
    vtx_pushaq

    mov rcx, qword ptr [rsp + 80h]
    rdtsc
    shl rdx, 20h
    or rax, rdx
    mov qword ptr [rcx + vtx_vmexit_entry_tsc_ofs], rax

    mov rax, 400h
    mov dr7, rax

    mov rcx, qword ptr [rsp + 80h]
    mov rdx, rsp

    cld
    vtx_pushax
    call vtx_handle_vmexit
    vtx_popax

    mov r10b, al
    test r10b, r10b
    jnz devirt_path

    vtx_popaq
    vmresume
    mov rcx, qword ptr [rsp]
    sub rsp, 20h
    call vtx_handle_vmresume_failure
    add rsp, 20h
vmresume_failure_halt:
    hlt
    jmp vmresume_failure_halt

devirt_path:
    mov rcx, qword ptr [rsp + 80h]

    mov rax, qword ptr [rcx + vtx_devirt_cr4_ofs]
    mov rdx, qword ptr [rcx + vtx_devirt_cr3_ofs]
    mov r11, qword ptr [rcx + vtx_devirt_cr0_ofs]

    vmxoff

    lgdt fword ptr [rcx + vtx_host_gdtr_ofs]
    lidt fword ptr [rcx + vtx_host_idtr_ofs]

    mov cr4, rax
    mov cr3, rdx
    mov cr0, r11

    mov rax, qword ptr [rcx + vtx_devirt_rip_ofs]
    mov rdx, qword ptr [rcx + vtx_devirt_rsp_ofs]
    sub rdx, 10h
    mov qword ptr [rdx + 8], rax
    mov rax, qword ptr [rcx + vtx_devirt_rflags_ofs]
    mov qword ptr [rdx], rax
    mov qword ptr [rsp + 58h], rdx

    mov r15, qword ptr [rsp]
    mov r14, qword ptr [rsp + 08h]
    mov r13, qword ptr [rsp + 10h]
    mov r12, qword ptr [rsp + 18h]
    mov r11, qword ptr [rsp + 20h]
    mov r10, qword ptr [rsp + 28h]
    mov r9,  qword ptr [rsp + 30h]
    mov r8,  qword ptr [rsp + 38h]
    mov rdi, qword ptr [rsp + 40h]
    mov rsi, qword ptr [rsp + 48h]
    mov rbp, qword ptr [rsp + 50h]
    mov rbx, qword ptr [rsp + 60h]
    mov rdx, qword ptr [rsp + 68h]
    mov rcx, qword ptr [rsp + 70h]
    mov rax, qword ptr [rsp + 78h]

    mov rsp, qword ptr [rsp + 58h]
    popfq
    ret
vtx_vmexit_entry endp

vtx_devirtualize_via_vmcall proc
    mov ecx, 0CAFE0000h
    vmcall
    ret
vtx_devirtualize_via_vmcall endp

vtx_invept_via_vmcall proc
    mov ecx, 0CAFE0001h
    vmcall
    ret
vtx_invept_via_vmcall endp

vtx_invept_all proc
    sub rsp, 28h
    mov qword ptr [rsp], rcx
    mov qword ptr [rsp+8], 0
    mov rax, 1
    db 66h, 0Fh, 38h, 80h, 04h, 24h
    add rsp, 28h
    ret
vtx_invept_all endp

vtx_invvpid_all_contexts proc
    sub rsp, 28h
    mov qword ptr [rsp], 0
    mov qword ptr [rsp+8], 0
    mov rax, 3
    db 66h, 0Fh, 38h, 81h, 04h, 24h
    add rsp, 28h
    ret
vtx_invvpid_all_contexts endp

vtx_invd proc
    invd
    ret
vtx_invd endp

vtx_write_cr2 proc
    mov cr2, rcx
    ret
vtx_write_cr2 endp

end
