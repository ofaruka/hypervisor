#include "mmio_svm.hpp"

namespace svm {

mmio::mmio() : range_count_(0) {
    KeInitializeSpinLock(&lock_);
    RtlZeroMemory(ranges_, sizeof(ranges_));
}

mmio* mmio::get() {
    static mmio instance;
    return &instance;
}

bool mmio::register_range(u64 start, u64 end) {
    if (end < start) {
        return false;
    }

    start &= ~0xFFFULL;
    end |= 0xFFFULL;

    KIRQL old_irql;
    KeAcquireSpinLock(&lock_, &old_irql);
    bool result = false;

    for (size_t i = 0; i < range_count_; i++) {
        if (start <= ranges_[i].end && end >= ranges_[i].start) {
            ranges_[i].start = crt_min(ranges_[i].start, start);
            ranges_[i].end = crt_max(ranges_[i].end, end);
            result = true;
            KeReleaseSpinLock(&lock_, old_irql);
            return result;
        }
    }

    if (range_count_ < MAX_MMIO_RANGES) {
        ranges_[range_count_++] = {.start = start, .end = end, .flags = 0};
        result = true;
    }

    KeReleaseSpinLock(&lock_, old_irql);
    return result;
}

bool mmio::is_mmio_address(u64 physical_address) const {
    for (size_t i = 0; i < range_count_; i++) {
        if (physical_address >= ranges_[i].start && physical_address <= ranges_[i].end)
            return true;
    }

    return false;
}

const mmio::mmio_range_t* mmio::get_range(u64 physical_address) const {
    for (size_t i = 0; i < range_count_; i++) {
        if (physical_address >= ranges_[i].start && physical_address <= ranges_[i].end)
            return &ranges_[i];
    }

    return nullptr;
}

bool mmio::configure_pte(svm::pvcpu_t vcpu, u64 page_pa) {
    auto primary_pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::primary], page_pa, true);
    auto shadow_pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::shadow], page_pa, true);
    if (!primary_pte || !shadow_pte) {
        return false;
    }

    auto setup = [page_pa](pte_64* pte) {
        pte->flags = 0;
        pte->present = 0;
        pte->write = 0;
        pte->supervisor = 1;
        pte->page_level_write_through = 0;
        pte->page_level_cache_disable = 1;
        pte->execute_disable = 0;
        pte->page_frame_number = page_pa >> 12;
    };
    setup(primary_pte);
    setup(shadow_pte);
    return true;
}

bool mmio::setup_npt(svm::pvcpu_t vcpu) {
    if (!vcpu) {
        return false;
    }

    KIRQL old_irql;
    KeAcquireSpinLock(&lock_, &old_irql);
    bool success = true;

    for (size_t i = 0; i < range_count_ && success; i++) {
        for (u64 pa = ranges_[i].start; pa <= ranges_[i].end; pa += 0x1000) {
            if (!configure_pte(vcpu, pa)) {
                debug::log_info("[MMIO] Failed to configure PTE for 0x%llx\n", pa);
                success = false;
                break;
            }
        }
    }

    if (success) {
        vcpu->guest_vmcb.control_area.vmcb_clean &= ~(1ULL << 4);
        flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
    }

    KeReleaseSpinLock(&lock_, old_irql);
    return success;
}

u8 mmio::reg_to_index(ZydisRegister reg, bool& is_high_byte) {
    is_high_byte = false;

    switch (reg) {
    case ZYDIS_REGISTER_RAX:
    case ZYDIS_REGISTER_EAX:
    case ZYDIS_REGISTER_AX:
    case ZYDIS_REGISTER_AL:
        return 0;
    case ZYDIS_REGISTER_AH:
        is_high_byte = true;
        return 0;
    case ZYDIS_REGISTER_RCX:
    case ZYDIS_REGISTER_ECX:
    case ZYDIS_REGISTER_CX:
    case ZYDIS_REGISTER_CL:
        return 1;
    case ZYDIS_REGISTER_CH:
        is_high_byte = true;
        return 1;
    case ZYDIS_REGISTER_RDX:
    case ZYDIS_REGISTER_EDX:
    case ZYDIS_REGISTER_DX:
    case ZYDIS_REGISTER_DL:
        return 2;
    case ZYDIS_REGISTER_DH:
        is_high_byte = true;
        return 2;
    case ZYDIS_REGISTER_RBX:
    case ZYDIS_REGISTER_EBX:
    case ZYDIS_REGISTER_BX:
    case ZYDIS_REGISTER_BL:
        return 3;
    case ZYDIS_REGISTER_BH:
        is_high_byte = true;
        return 3;
    case ZYDIS_REGISTER_RSP:
    case ZYDIS_REGISTER_ESP:
    case ZYDIS_REGISTER_SP:
    case ZYDIS_REGISTER_SPL:
        return 4;
    case ZYDIS_REGISTER_RBP:
    case ZYDIS_REGISTER_EBP:
    case ZYDIS_REGISTER_BP:
    case ZYDIS_REGISTER_BPL:
        return 5;
    case ZYDIS_REGISTER_RSI:
    case ZYDIS_REGISTER_ESI:
    case ZYDIS_REGISTER_SI:
    case ZYDIS_REGISTER_SIL:
        return 6;
    case ZYDIS_REGISTER_RDI:
    case ZYDIS_REGISTER_EDI:
    case ZYDIS_REGISTER_DI:
    case ZYDIS_REGISTER_DIL:
        return 7;
    case ZYDIS_REGISTER_R8:
    case ZYDIS_REGISTER_R8D:
    case ZYDIS_REGISTER_R8W:
    case ZYDIS_REGISTER_R8B:
        return 8;
    case ZYDIS_REGISTER_R9:
    case ZYDIS_REGISTER_R9D:
    case ZYDIS_REGISTER_R9W:
    case ZYDIS_REGISTER_R9B:
        return 9;
    case ZYDIS_REGISTER_R10:
    case ZYDIS_REGISTER_R10D:
    case ZYDIS_REGISTER_R10W:
    case ZYDIS_REGISTER_R10B:
        return 10;
    case ZYDIS_REGISTER_R11:
    case ZYDIS_REGISTER_R11D:
    case ZYDIS_REGISTER_R11W:
    case ZYDIS_REGISTER_R11B:
        return 11;
    case ZYDIS_REGISTER_R12:
    case ZYDIS_REGISTER_R12D:
    case ZYDIS_REGISTER_R12W:
    case ZYDIS_REGISTER_R12B:
        return 12;
    case ZYDIS_REGISTER_R13:
    case ZYDIS_REGISTER_R13D:
    case ZYDIS_REGISTER_R13W:
    case ZYDIS_REGISTER_R13B:
        return 13;
    case ZYDIS_REGISTER_R14:
    case ZYDIS_REGISTER_R14D:
    case ZYDIS_REGISTER_R14W:
    case ZYDIS_REGISTER_R14B:
        return 14;
    case ZYDIS_REGISTER_R15:
    case ZYDIS_REGISTER_R15D:
    case ZYDIS_REGISTER_R15W:
    case ZYDIS_REGISTER_R15B:
        return 15;
    default:
        return 0xFF;
    }
}

bool mmio::read_inst_bytes(svm::pvcpu_t vcpu, u8* buffer, size_t& bytes_read) {
    if (!vcpu || !buffer) {
        return false;
    }

    u64 guest_rip = vcpu->guest_vmcb.state_save_area.rip;
    svm::cr3_t guest_cr3{vcpu->guest_vmcb.state_save_area.cr3.value};
    bytes_read = 0;

    while (bytes_read < MAX_INSTRUCTION_LENGTH) {
        u64 offset_to_next_page = 0;
        void* host_va = page_table::get()->gva_to_hva(guest_cr3, guest_rip + bytes_read, offset_to_next_page);

        if (!host_va || !offset_to_next_page) {
            break;
        }

        u64 remaining = static_cast<u64>(MAX_INSTRUCTION_LENGTH - bytes_read);
        u64 chunk = offset_to_next_page < remaining ? offset_to_next_page : remaining;
        RtlCopyMemory(buffer + bytes_read, host_va, chunk);
        bytes_read += static_cast<size_t>(chunk);
    }

    return bytes_read != 0;
}

mmio::decoded_instruction_t mmio::decode_instruction(svm::pvcpu_t vcpu, bool is_write) {
    decoded_instruction_t result = {};
    u8 inst_bytes[MAX_INSTRUCTION_LENGTH] = {};
    size_t bytes_read = 0;

    if (!read_inst_bytes(vcpu, inst_bytes, bytes_read)) {
        debug::log_info("[MMIO] Failed to read instruction at RIP 0x%llx\n", vcpu->guest_vmcb.state_save_area.rip);
        return result;
    }

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    if (!disassembler::get()->decode_full(inst_bytes, bytes_read, 64, &instruction, operands)) {
        debug::log_info("[MMIO] Failed to decode instruction\n");
        return result;
    }

    result.inst_length = (u8)instruction.length;

    if (instruction.operand_count_visible == 0 &&
        (instruction.attributes & ZYDIS_ATTRIB_HAS_REPNZ) == 0) {
        switch (instruction.mnemonic) {
        case ZYDIS_MNEMONIC_MOVSB:
            result.op = operation::string_movs;
            result.access_size = 1;
            break;
        case ZYDIS_MNEMONIC_MOVSW:
            result.op = operation::string_movs;
            result.access_size = 2;
            break;
        case ZYDIS_MNEMONIC_MOVSD:
            result.op = operation::string_movs;
            result.access_size = 4;
            break;
        case ZYDIS_MNEMONIC_MOVSQ:
            result.op = operation::string_movs;
            result.access_size = 8;
            break;
        case ZYDIS_MNEMONIC_STOSB:
            if (is_write) {
                result.op = operation::string_stos;
                result.access_size = 1;
            }
            break;
        case ZYDIS_MNEMONIC_STOSW:
            if (is_write) {
                result.op = operation::string_stos;
                result.access_size = 2;
            }
            break;
        case ZYDIS_MNEMONIC_STOSD:
            if (is_write) {
                result.op = operation::string_stos;
                result.access_size = 4;
            }
            break;
        case ZYDIS_MNEMONIC_STOSQ:
            if (is_write) {
                result.op = operation::string_stos;
                result.access_size = 8;
            }
            break;
        case ZYDIS_MNEMONIC_LODSB:
            if (!is_write) {
                result.op = operation::string_lods;
                result.access_size = 1;
            }
            break;
        case ZYDIS_MNEMONIC_LODSW:
            if (!is_write) {
                result.op = operation::string_lods;
                result.access_size = 2;
            }
            break;
        case ZYDIS_MNEMONIC_LODSD:
            if (!is_write) {
                result.op = operation::string_lods;
                result.access_size = 4;
            }
            break;
        case ZYDIS_MNEMONIC_LODSQ:
            if (!is_write) {
                result.op = operation::string_lods;
                result.access_size = 8;
            }
            break;
        default:
            break;
        }

        if (result.op != operation::none) {
            result.is_string_op = true;
            result.has_rep = (instruction.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE)) != 0;
            result.valid = true;
            return result;
        }
    }

    if (instruction.attributes & (ZYDIS_ATTRIB_HAS_LOCK | ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE |
                                  ZYDIS_ATTRIB_HAS_REPNZ)) {
        return result;
    }

    if (instruction.mnemonic != ZYDIS_MNEMONIC_MOV && instruction.mnemonic != ZYDIS_MNEMONIC_MOVZX &&
        instruction.mnemonic != ZYDIS_MNEMONIC_MOVSX && instruction.mnemonic != ZYDIS_MNEMONIC_MOVSXD) {
        return result;
    }

    const ZydisDecodedOperand* mem = nullptr;
    u32 mem_index = 0;
    u32 mem_count = 0;

    for (u32 i = 0; i < instruction.operand_count_visible; i++) {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            mem = &operands[i];
            mem_index = i;
            mem_count++;
        }
    }

    if (!mem || mem_count != 1) {
        return result;
    }

    u8 access_size = static_cast<u8>(mem->size / 8);

    if (!access_size || access_size > 8 || (mem->size % 8) != 0) {
        return result;
    }

    bool memory_read = (mem->actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
    bool memory_write = (mem->actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;

    if (memory_read == memory_write || is_write != memory_write) {
        return result;
    }

    result.access_size = access_size;

    if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
        if (is_write) {
            if (mem_index != 0 || instruction.operand_count_visible < 2) {
                return result;
            }

            const auto& src = operands[1];

            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                bool is_high = false;
                u8 idx = reg_to_index(src.reg.value, is_high);

                if (idx == 0xFF) {
                    return result;
                }

                result.op = operation::mov_mem_reg;
                result.reg_index = idx;
                result.is_high_byte = is_high;
            } else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                result.op = operation::mov_mem_imm;
                result.immediate = src.imm.is_signed ? static_cast<u64>(src.imm.value.s) : src.imm.value.u;
            } else {
                return result;
            }
        } else {
            if (mem_index != 1 || instruction.operand_count_visible < 2) {
                return result;
            }

            const auto& dst = operands[0];

            if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
                return result;
            }

            bool is_high = false;
            u8 idx = reg_to_index(dst.reg.value, is_high);

            if (idx == 0xFF) {
                return result;
            }

            result.op = operation::mov_reg_mem;
            result.reg_index = idx;
            result.reg_size = static_cast<u8>(dst.size / 8);
            result.is_high_byte = is_high;
        }

        if (!result.reg_size) {
            result.reg_size = result.access_size;
        }

        result.valid = true;
        return result;
    }

    if (is_write || mem_index != 1 || instruction.operand_count_visible < 2) {
        return result;
    }

    const auto& dst = operands[0];

    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return result;
    }

    bool is_high = false;
    u8 idx = reg_to_index(dst.reg.value, is_high);

    if (idx == 0xFF) {
        return result;
    }

    result.op = instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX ? operation::movzx_reg_mem : operation::movsx_reg_mem;
    result.reg_index = idx;
    result.reg_size = static_cast<u8>(dst.size / 8);
    result.is_high_byte = is_high;
    result.valid = result.reg_size >= result.access_size && result.reg_size >= 1 && result.reg_size <= 8;
    return result;
}

u64* mmio::get_reg_ptr(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u8 reg_index) {
    if (!vcpu || !guest_ctx || !guest_ctx->vprocessor_registers) {
        return nullptr;
    }

    auto regs = guest_ctx->vprocessor_registers;

    switch (reg_index) {
    case 0:
        return &regs->rax.value;
    case 1:
        return &regs->rcx.value;
    case 2:
        return &regs->rdx.value;
    case 3:
        return &regs->rbx.value;
    case 4:
        return &vcpu->guest_vmcb.state_save_area.rsp;
    case 5:
        return &regs->rbp.value;
    case 6:
        return &regs->rsi.value;
    case 7:
        return &regs->rdi.value;
    case 8:
        return &regs->r8.value;
    case 9:
        return &regs->r9.value;
    case 10:
        return &regs->r10.value;
    case 11:
        return &regs->r11.value;
    case 12:
        return &regs->r12.value;
    case 13:
        return &regs->r13.value;
    case 14:
        return &regs->r14.value;
    case 15:
        return &regs->r15.value;
    default:
        return nullptr;
    }
}

u64 mmio::read_reg(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u8 reg_index, u8 size, bool is_high_byte) {
    u64* reg = get_reg_ptr(vcpu, guest_ctx, reg_index);

    if (!reg) {
        return 0;
    }

    u64 value = *reg;

    if (is_high_byte) {
        return (value >> 8) & 0xFF;
    }

    switch (size) {
    case 1:
        return value & 0xFF;
    case 2:
        return value & 0xFFFF;
    case 4:
        return value & 0xFFFFFFFF;
    default:
        return value;
    }
}

void mmio::write_reg(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u8 reg_index, u64 value, u8 size,
                     bool is_high_byte) {
    u64* reg = get_reg_ptr(vcpu, guest_ctx, reg_index);

    if (!reg) {
        return;
    }

    if (is_high_byte) {
        *reg = (*reg & ~0xFF00ULL) | ((value & 0xFF) << 8);
        return;
    }

    switch (size) {
    case 1:
        *reg = (*reg & ~0xFFULL) | (value & 0xFF);
        break;
    case 2:
        *reg = (*reg & ~0xFFFFULL) | (value & 0xFFFF);
        break;
    case 4:
        *reg = value & 0xFFFFFFFF;
        break;
    case 8:
        *reg = value;
        break;
    }
}

void* mmio::translate_gva(svm::pvcpu_t vcpu, u64 guest_va) {
    u64 offset = 0;
    return page_table::get()->gva_to_hva(svm::cr3_t{vcpu->guest_vmcb.state_save_area.cr3.value}, guest_va, offset);
}

bool mmio::copy_from_guest(svm::pvcpu_t vcpu, void* dst, u64 guest_va, size_t size) {
    if (!dst || !guest_va) {
        return false;
    }

    if (!size) {
        return true;
    }

    size_t copied = 0;

    while (copied < size) {
        u64 remaining = 0;
        auto src = page_table::get()->gva_to_hva(svm::cr3_t{vcpu->guest_vmcb.state_save_area.cr3.value},
                                                 guest_va + copied, remaining);

        if (!src || !remaining) {
            return false;
        }

        auto chunk = min(remaining, size - copied);
        RtlCopyMemory(static_cast<u8*>(dst) + copied, src, chunk);
        copied += chunk;
    }

    return true;
}

bool mmio::copy_to_guest(svm::pvcpu_t vcpu, u64 guest_va, const void* src, size_t size) {
    if (!src || !guest_va) {
        return false;
    }

    if (!size) {
        return true;
    }

    size_t copied = 0;

    while (copied < size) {
        u64 remaining = 0;
        auto dst = page_table::get()->gva_to_hva(svm::cr3_t{vcpu->guest_vmcb.state_save_area.cr3.value},
                                                 guest_va + copied, remaining);

        if (!dst || !remaining) {
            return false;
        }

        auto chunk = min(remaining, size - copied);
        RtlCopyMemory(dst, static_cast<const u8*>(src) + copied, chunk);
        copied += chunk;
    }

    return true;
}

u64 mmio::sign_extend_value(u64 value, u8 size) {
    switch (size) {
    case 1:
        return static_cast<u64>(static_cast<i64>(static_cast<i8>(value)));
    case 2:
        return static_cast<u64>(static_cast<i64>(static_cast<i16>(value)));
    case 4:
        return static_cast<u64>(static_cast<i64>(static_cast<i32>(value)));
    default:
        return value;
    }
}

bool mmio::dispatch_access(const mmio_access_t& access) {
    if (tpm::get()->is_tpm_address(access.physical_address)) {
        if (access.is_write) {
            tpm::get()->handle_write(access.physical_address, access.offset, access.write_value, access.size);
        } else {
            if (!access.read_value) {
                return false;
            }

            *access.read_value = tpm::get()->handle_read(access.physical_address, access.offset, access.size);
        }

        return true;
    }

    if (!access.is_write) {
        if (!access.read_value) {
            return false;
        }

        *access.read_value = ~0ULL;
    }

    return true;
}

bool mmio::emulate_regular(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u64 guest_pa, bool is_write,
                           const decoded_instruction_t& inst) {
    const auto* range = get_range(guest_pa);
    u32 offset = range ? (u32)(guest_pa - range->start) : (u32)(guest_pa & 0xFFFF);
    u64 read_val = 0;
    mmio_access_t access = {.physical_address = guest_pa,
                            .offset = offset,
                            .size = inst.access_size,
                            .is_write = is_write,
                            .write_value = 0,
                            .read_value = &read_val};

    if (is_write) {
        switch (inst.op) {
        case operation::mov_mem_reg:
            access.write_value = read_reg(vcpu, guest_ctx, inst.reg_index, inst.access_size, inst.is_high_byte);
            break;
        case operation::mov_mem_imm:
            access.write_value = inst.immediate;
            break;
        default:
            return false;
        }

        access.read_value = nullptr;
    }

    if (!dispatch_access(access)) {
        return false;
    }

    if (!is_write) {
        switch (inst.op) {
        case operation::mov_reg_mem:
        case operation::movzx_reg_mem:
            write_reg(vcpu, guest_ctx, inst.reg_index, read_val, inst.reg_size, inst.is_high_byte);
            break;
        case operation::movsx_reg_mem:
            write_reg(vcpu, guest_ctx, inst.reg_index, sign_extend_value(read_val, inst.access_size), inst.reg_size,
                      inst.is_high_byte);
            break;
        default:
            return false;
        }
    }

    vcpu->guest_vmcb.state_save_area.rip += inst.inst_length;
    return true;
}

bool mmio::emulate_string(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u64 guest_pa, bool is_write,
                          const decoded_instruction_t& inst) {
    if (!guest_ctx->vprocessor_registers) {
        return false;
    }

    auto regs = guest_ctx->vprocessor_registers;

    if (inst.has_rep && regs->rcx.value == 0) {
        vcpu->guest_vmcb.state_save_area.rip += inst.inst_length;
        return true;
    }

    i64 increment = inst.direction_down ? -static_cast<i64>(inst.access_size) : static_cast<i64>(inst.access_size);
    const auto* range = get_range(guest_pa);
    u32 offset = range ? (u32)(guest_pa - range->start) : (u32)(guest_pa & 0xFFFF);

    if (inst.op == operation::string_movs) {
        u64 value = 0;

        if (is_write) {
            if (!copy_from_guest(vcpu, &value, regs->rsi.value, inst.access_size)) {
                return false;
            }

            mmio_access_t access = {guest_pa, offset, inst.access_size, true, value, nullptr};
            if (!dispatch_access(access)) {
                return false;
            }
        } else {
            mmio_access_t access = {guest_pa, offset, inst.access_size, false, 0, &value};
            if (!dispatch_access(access)) {
                return false;
            }

            if (!copy_to_guest(vcpu, regs->rdi.value, &value, inst.access_size)) {
                return false;
            }
        }

        regs->rsi.value = static_cast<u64>(static_cast<i64>(regs->rsi.value) + increment);
        regs->rdi.value = static_cast<u64>(static_cast<i64>(regs->rdi.value) + increment);
    } else if (inst.op == operation::string_stos && is_write) {
        mmio_access_t access = {guest_pa, offset, inst.access_size, true,
                                read_reg(vcpu, guest_ctx, 0, inst.access_size, false), nullptr};

        if (!dispatch_access(access)) {
            return false;
        }

        regs->rdi.value = static_cast<u64>(static_cast<i64>(regs->rdi.value) + increment);
    } else if (inst.op == operation::string_lods && !is_write) {
        u64 value = 0;
        mmio_access_t access = {guest_pa, offset, inst.access_size, false, 0, &value};

        if (!dispatch_access(access)) {
            return false;
        }

        write_reg(vcpu, guest_ctx, 0, value, inst.access_size, false);
        regs->rsi.value = static_cast<u64>(static_cast<i64>(regs->rsi.value) + increment);
    } else {
        return false;
    }

    if (inst.has_rep) {
        regs->rcx.value--;

        if (regs->rcx.value == 0) {
            vcpu->guest_vmcb.state_save_area.rip += inst.inst_length;
        }
    } else {
        vcpu->guest_vmcb.state_save_area.rip += inst.inst_length;
    }

    return true;
}

bool mmio::handle_fault(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, const page_context& ctx) {
    if (!vcpu || !guest_ctx || !guest_ctx->vprocessor_registers) {
        return false;
    }

    if (ctx.is_execution || !is_mmio_address(ctx.guest_pa)) {
        return false;
    }

    auto pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::primary], ctx.guest_pa, false);
    if (!pte) {
        return false;
    }

    bool is_write = (vcpu->guest_vmcb.control_area.exit_info1 & (1ULL << 1)) != 0;
    decoded_instruction_t inst = decode_instruction(vcpu, is_write);

    if (!inst.valid) {
        debug::log_info("[MMIO] Decode failed at RIP 0x%llx\n", vcpu->guest_vmcb.state_save_area.rip);
        return false;
    }

    inst.direction_down = (vcpu->guest_vmcb.state_save_area.rflags & (1ULL << 10)) != 0;

    if (inst.is_string_op)
        return emulate_string(vcpu, guest_ctx, ctx.guest_pa, is_write, inst);
    else
        return emulate_regular(vcpu, guest_ctx, ctx.guest_pa, is_write, inst);
}
}
