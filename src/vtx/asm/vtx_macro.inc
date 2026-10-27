vtx_self_ofs           equ 9000h
vtx_devirt_rip_ofs     equ 9008h
vtx_devirt_rsp_ofs     equ 9010h
vtx_devirt_rflags_ofs  equ 9018h
vtx_devirt_cr0_ofs     equ 9048h
vtx_devirt_cr3_ofs     equ 9050h
vtx_devirt_cr4_ofs     equ 9058h
vtx_vmexit_entry_tsc_ofs equ 9060h
vtx_host_gdtr_ofs      equ 9270h
vtx_host_idtr_ofs      equ 927ah

vmcs_host_rsp          equ 6c14h
vmcs_host_rip          equ 6c16h
vmcs_guest_rsp         equ 681ch
vmcs_guest_rip         equ 681eh

vtx_pushaq macro
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

vtx_popaq macro
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

vtx_pushax macro
    sub rsp, 80h
    movaps xmmword ptr [rsp + 20h], xmm0
    movaps xmmword ptr [rsp + 30h], xmm1
    movaps xmmword ptr [rsp + 40h], xmm2
    movaps xmmword ptr [rsp + 50h], xmm3
    movaps xmmword ptr [rsp + 60h], xmm4
    movaps xmmword ptr [rsp + 70h], xmm5
endm

vtx_popax macro
    movaps xmm5, xmmword ptr [rsp + 70h]
    movaps xmm4, xmmword ptr [rsp + 60h]
    movaps xmm3, xmmword ptr [rsp + 50h]
    movaps xmm2, xmmword ptr [rsp + 40h]
    movaps xmm1, xmmword ptr [rsp + 30h]
    movaps xmm0, xmmword ptr [rsp + 20h]
    add rsp, 80h
endm
