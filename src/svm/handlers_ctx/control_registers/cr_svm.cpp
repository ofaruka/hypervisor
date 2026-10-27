#include "cr_svm.hpp"

namespace svm {

u64* cr_handler::get_register_for_cr_exit(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    if (!vcpu || !guest_ctx || !guest_ctx->vprocessor_registers) {
        return nullptr;
    }

    const u64 gpr_num = vcpu->guest_vmcb.control_area.exit_info1 & 0xF;

    switch (gpr_num) {
    case 0:
        return &guest_ctx->vprocessor_registers->rax.value;
    case 1:
        return &guest_ctx->vprocessor_registers->rcx.value;
    case 2:
        return &guest_ctx->vprocessor_registers->rdx.value;
    case 3:
        return &guest_ctx->vprocessor_registers->rbx.value;
    case 4:
        return &vcpu->guest_vmcb.state_save_area.rsp;
    case 5:
        return &guest_ctx->vprocessor_registers->rbp.value;
    case 6:
        return &guest_ctx->vprocessor_registers->rsi.value;
    case 7:
        return &guest_ctx->vprocessor_registers->rdi.value;
    case 8:
        return &guest_ctx->vprocessor_registers->r8.value;
    case 9:
        return &guest_ctx->vprocessor_registers->r9.value;
    case 10:
        return &guest_ctx->vprocessor_registers->r10.value;
    case 11:
        return &guest_ctx->vprocessor_registers->r11.value;
    case 12:
        return &guest_ctx->vprocessor_registers->r12.value;
    case 13:
        return &guest_ctx->vprocessor_registers->r13.value;
    case 14:
        return &guest_ctx->vprocessor_registers->r14.value;
    case 15:
        return &guest_ctx->vprocessor_registers->r15.value;
    default:
        return nullptr;
    }
}

bool cr_handler::is_long_mode_active(svm::pvcpu_t vcpu) {
    return (vcpu->guest_vmcb.state_save_area.efer.long_mode_enable == 1) &&
           (vcpu->guest_vmcb.state_save_area.cr0.pg == 1);
}

void cr_handler::mark_ctrl_regs_dirty(svm::pvcpu_t vcpu) {
    vcpu->guest_vmcb.control_area.vmcb_clean &= ~static_cast<u32>(svm::vmcb_clean_bits::ctrl_regs);
}

bool cr_handler::handle_cr0_read(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    u8 instruction_bytes[3] = {0};
    auto status = memory_access::get()->read_virtual_memory(
        vcpu, vcpu->guest_vmcb.state_save_area.cr3, reinterpret_cast<u64>(instruction_bytes),
        vcpu->guest_vmcb.state_save_area.rip, sizeof(instruction_bytes));

    if (status == svm::svmroot_error_t::error_success && instruction_bytes[0] == 0x0F && instruction_bytes[1] == 0x01) {
        u8 reg_field = (instruction_bytes[2] >> 3) & 0x7;

        if (reg_field == 4) {
            return handle_smsw(vcpu, guest_ctx);
        }
    }

    u64* reg = get_register_for_cr_exit(vcpu, guest_ctx);

    if (!reg) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    *reg = vcpu->guest_vmcb.state_save_area.cr0.value;
    return true;
}

bool cr_handler::apply_mov_to_cr0(svm::pvcpu_t vcpu, svm::cr0_t new_cr0) {
    svm::cr0_t old_cr0 = vcpu->guest_vmcb.state_save_area.cr0;

    if (new_cr0.pe == 0 && new_cr0.pg == 1) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    if (new_cr0.cd == 0 && new_cr0.nw == 1) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    if (is_long_mode_active(vcpu) && (new_cr0.pg == 0 || new_cr0.pe == 0)) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    bool flush = (old_cr0.pg != new_cr0.pg) || (old_cr0.cd != new_cr0.cd) || (old_cr0.nw != new_cr0.nw);
    vcpu->guest_vmcb.state_save_area.cr0 = new_cr0;
    mark_ctrl_regs_dirty(vcpu);

    if (flush) {
        flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
    }

    return true;
}

bool cr_handler::handle_cr0_write(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    u8 instruction_bytes[3] = {0};
    auto status = memory_access::get()->read_virtual_memory(
        vcpu, vcpu->guest_vmcb.state_save_area.cr3, reinterpret_cast<u64>(instruction_bytes),
        vcpu->guest_vmcb.state_save_area.rip, sizeof(instruction_bytes));

    if (status == svm::svmroot_error_t::error_success) {
        if (instruction_bytes[0] == 0x0F && instruction_bytes[1] == 0x06) {
            return handle_clts(vcpu, guest_ctx);
        }

        if (instruction_bytes[0] == 0x0F && instruction_bytes[1] == 0x01) {
            u8 reg_field = (instruction_bytes[2] >> 3) & 0x7;

            if (reg_field == 6) {
                return handle_lmsw(vcpu, guest_ctx);
            }
        }
    }

    u64* reg = get_register_for_cr_exit(vcpu, guest_ctx);

    if (!reg) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    svm::cr0_t new_cr0{};
    new_cr0.value = *reg;
    return apply_mov_to_cr0(vcpu, new_cr0);
}

bool cr_handler::handle_lmsw(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    u16 source_value = static_cast<u16>(vcpu->guest_vmcb.control_area.exit_info1);
    svm::cr0_t cr0 = vcpu->guest_vmcb.state_save_area.cr0;
    u16 cr0_low = cr0.value & 0xFFFF;

    if ((source_value & 0x1) == 0 && (cr0_low & 0x1) == 1) {
        source_value |= 0x1;
    }

    cr0.value = (cr0.value & ~0xFFFFULL) | source_value;

    if (cr0.cd == 0 && cr0.nw == 1) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    vcpu->guest_vmcb.state_save_area.cr0 = cr0;
    mark_ctrl_regs_dirty(vcpu);
    return true;
}

bool cr_handler::handle_smsw(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    u64* reg = get_register_for_cr_exit(vcpu, guest_ctx);

    if (!reg) {
        return false;
    }

    u64 cr0 = vcpu->guest_vmcb.state_save_area.cr0.value;
    bool is_32bit = (vcpu->guest_vmcb.control_area.exit_info1 >> 32) & 1;

    if (is_32bit) {
        *reg = (*reg & ~0xFFFFFFFFULL) | (cr0 & 0xFFFFFFFFULL);
    } else {
        *reg = (*reg & ~0xFFFFULL) | (cr0 & 0xFFFFULL);
    }

    return true;
}

bool cr_handler::handle_clts(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    vcpu->guest_vmcb.state_save_area.cr0.ts = 0;
    mark_ctrl_regs_dirty(vcpu);
    return true;
}

bool cr_handler::validate_pae_pdpes(svm::pvcpu_t vcpu, u64 cr3_value) {
    struct pdpe_pae {
        u64 present : 1;
        u64 reserved1 : 2;
        u64 pwt : 1;
        u64 pcd : 1;
        u64 reserved2 : 4;
        u64 ignored : 3;
        u64 page_frame : 40;
        u64 reserved3 : 12;
    };
    u64 pdpt_pa = cr3_value & ~0x1FULL;
    if (!page_table::is_mapped_physical(pdpt_pa)) {
        return false;
    }
    pdpe_pae* pdpes = reinterpret_cast<pdpe_pae*>(host_physical_memory_base + pdpt_pa);

    for (int i = 0; i < 4; i++) {
        if (pdpes[i].present && (pdpes[i].reserved1 || pdpes[i].reserved2 || pdpes[i].reserved3)) {
            return false;
        }
    }

    return true;
}

bool cr_handler::handle_cr3_write(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    u64* reg = get_register_for_cr_exit(vcpu, guest_ctx);

    if (!reg) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    u64 raw_cr3 = *reg;
    bool pae_enabled =
        (vcpu->guest_vmcb.state_save_area.cr4.pae == 1) && (vcpu->guest_vmcb.state_save_area.cr0.pg == 1);
    bool pcide_enabled = (vcpu->guest_vmcb.state_save_area.cr4.pcide == 1);
    bool long_mode = is_long_mode_active(vcpu);
    bool no_flush = pcide_enabled && (raw_cr3 & (1ULL << 63));
    u64 new_cr3 = pcide_enabled ? (raw_cr3 & ~(1ULL << 63)) : raw_cr3;

    if (pcide_enabled) {
        if (!long_mode) {
            event_inj_t{}.general_protection_exception(vcpu);
            return false;
        }

        if (new_cr3 & 0x7FF0000000000000ULL) {
            event_inj_t{}.general_protection_exception(vcpu);
            return false;
        }
    } else {
        if (new_cr3 & 0xFFF0000000000000ULL) {
            event_inj_t{}.general_protection_exception(vcpu);
            return false;
        }

        if (pae_enabled && !long_mode && (new_cr3 & 0x1F)) {
            event_inj_t{}.general_protection_exception(vcpu);
            return false;
        }

        if (long_mode && (new_cr3 & 0xFFF)) {
            event_inj_t{}.general_protection_exception(vcpu);
            return false;
        }
    }

    svm::cr3_t old_cr3 = vcpu->guest_vmcb.state_save_area.cr3;
    vcpu->guest_vmcb.state_save_area.cr3.value = new_cr3;
    mark_ctrl_regs_dirty(vcpu);

    if (pae_enabled && !long_mode && !validate_pae_pdpes(vcpu, new_cr3)) {
        vcpu->guest_vmcb.state_save_area.cr3 = old_cr3;
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    if (!no_flush) {
        flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_guest_non_global_tlb);
    }

    memory_access::get()->try_consume_pending(vcpu);
    return true;
}

bool cr_handler::handle_cr3_read(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    u64* reg = get_register_for_cr_exit(vcpu, guest_ctx);

    if (!reg) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    *reg = vcpu->guest_vmcb.state_save_area.cr3.value;
    return true;
}

bool cr_handler::validate_cr4_bits(svm::pvcpu_t vcpu, svm::cr4_t new_cr4, svm::cr4_t old_cr4, svm::cr0_t cr0) {
    if (new_cr4.reserved13 || new_cr4.reserved19 || new_cr4.reserved24) {
        return false;
    }

    if (new_cr4.pcide == 1 && !is_long_mode_active(vcpu)) {
        return false;
    }

    if (new_cr4.pae == 0 && old_cr4.pae == 1) {
        svm::efer_msr efer = vcpu->guest_vmcb.state_save_area.efer;

        if (efer.long_mode_active == 1) {
            return false;
        }
    }

    if (new_cr4.pge == 1 && cr0.pg == 0) {
        return false;
    }

    return true;
}

bool cr_handler::handle_cr4_write(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    u64* reg = get_register_for_cr_exit(vcpu, guest_ctx);

    if (!reg) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    svm::cr4_t new_cr4{};
    new_cr4.value = *reg;
    svm::cr4_t old_cr4 = vcpu->guest_vmcb.state_save_area.cr4;
    svm::cr0_t cr0 = vcpu->guest_vmcb.state_save_area.cr0;

    if (!validate_cr4_bits(vcpu, new_cr4, old_cr4, cr0)) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    if (new_cr4.pcide == 1 && old_cr4.pcide == 0) {
        if (vcpu->guest_vmcb.state_save_area.cr3.value & 0xFFF) {
            event_inj_t{}.general_protection_exception(vcpu);
            return false;
        }
    }

    bool pge_change = (old_cr4.pge != new_cr4.pge);
    bool pae_change = (old_cr4.pae != new_cr4.pae);
    bool pcide_change = (old_cr4.pcide != new_cr4.pcide);
    bool smep_change = (old_cr4.smep != new_cr4.smep);
    vcpu->guest_vmcb.state_save_area.cr4 = new_cr4;
    mark_ctrl_regs_dirty(vcpu);

    if (pge_change || pae_change || pcide_change || smep_change) {
        auto kind = (pge_change && new_cr4.pge == 0) ? flush_tlb_t::tlb_control_id::flush_entire_tlb
                                                     : flush_tlb_t::tlb_control_id::flush_guest_non_global_tlb;
        flush_tlb_t{}.flush_tlb(vcpu, kind);
    }

    return true;
}

bool cr_handler::handle_cr4_read(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    u64* reg = get_register_for_cr_exit(vcpu, guest_ctx);

    if (!reg) {
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    *reg = vcpu->guest_vmcb.state_save_area.cr4.value;
    return true;
}

bool cr_handler::cr_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    bool status = false;
    auto exit_code = vcpu->guest_vmcb.control_area.exit_code;

    switch (exit_code) {
    case vmexit::cr0_read:
        status = handle_cr0_read(vcpu, guest_ctx);
        break;
    case vmexit::cr0_write:
        status = handle_cr0_write(vcpu, guest_ctx);
        break;
    case vmexit::cr3_read:
        status = handle_cr3_read(vcpu, guest_ctx);
        break;
    case vmexit::cr3_write:
        status = handle_cr3_write(vcpu, guest_ctx);
        break;
    case vmexit::cr4_read:
        status = handle_cr4_read(vcpu, guest_ctx);
        break;
    case vmexit::cr4_write:
        status = handle_cr4_write(vcpu, guest_ctx);
        break;
    default:
        event_inj_t{}.general_protection_exception(vcpu);
        return false;
    }

    if (status && !(vcpu->guest_vmcb.control_area.event_inj & (1ULL << 31))) {
        vcpu->guest_vmcb.state_save_area.rip = vcpu->guest_vmcb.control_area.next_rip;
    }

    return status;
}

cr_handler* cr_handler::get() {
    static cr_handler instance;
    return &instance;
}
}
