#include "mmio_vtx.hpp"
#include "../../memory/memory_access_vtx.hpp"

namespace vtx {

auto mmio::guest_code_is_64_bit() -> bool {
    constexpr size_t efer_lma = 1ULL << 10;
    constexpr size_t code_long_bit = 1ULL << 13;

    size_t efer = 0;
    size_t cs_ar = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_ia32_efer), &efer);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cs_ar), &cs_ar);
    return (efer & efer_lma) != 0 && (cs_ar & code_long_bit) != 0;
}

auto mmio::canonical_address(size_t value) -> bool {
    auto sign = static_cast<i64>(value) >> 47;
    return sign == 0 || sign == -1;
}

auto mmio::advanced_guest_rip(size_t rip, size_t length) -> size_t {
    auto next = rip + length;
    return guest_code_is_64_bit()
        ? next
        : static_cast<size_t>(static_cast<u32>(next));
}

mmio::mmio() : range_count_(0) {
    KeInitializeSpinLock(&lock_);
    RtlZeroMemory(ranges_, sizeof(ranges_));
}

auto mmio::get() -> mmio* {
    static mmio instance;
    return &instance;
}

auto mmio::register_range(u64 start, u64 end) -> bool {
    if (start >= end) return false;

    KIRQL old_irql;
    KeAcquireSpinLock(&lock_, &old_irql);

    bool result = false;
    if (range_count_ < max_ranges) {
        ranges_[range_count_++] = { start & ~0xfffULL, end };
        result = true;
    }

    KeReleaseSpinLock(&lock_, old_irql);
    return result;
}

auto mmio::setup_ept() -> bool {
    KIRQL old_irql;
    KeAcquireSpinLock(&lock_, &old_irql);

    bool success = true;
    for (size_t i = 0; i < range_count_ && success; i++) {
        for (u64 pa = ranges_[i].start; pa <= ranges_[i].end; pa += PAGE_SIZE) {
            if (!ept::get()->configure_mmio_page(pa)) {
                success = false;
                break;
            }
        }
    }

    KeReleaseSpinLock(&lock_, old_irql);
    return success;
}

auto mmio::is_mmio_address(u64 physical_address) const -> bool {
    for (size_t i = 0; i < range_count_; i++) {
        if (physical_address >= ranges_[i].start && physical_address <= ranges_[i].end) {
            return true;
        }
    }
    return false;
}

auto mmio::get_range(u64 physical_address) const -> const range* {
    for (size_t i = 0; i < range_count_; i++) {
        if (physical_address >= ranges_[i].start && physical_address <= ranges_[i].end) {
            return &ranges_[i];
        }
    }
    return nullptr;
}

auto mmio::reg_to_index(ZydisRegister reg, bool& is_high_byte) -> u8 {
    is_high_byte = false;

    switch (reg) {
    case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX:
    case ZYDIS_REGISTER_AX:  case ZYDIS_REGISTER_AL: return 0;
    case ZYDIS_REGISTER_AH: is_high_byte = true; return 0;
    case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX:
    case ZYDIS_REGISTER_CX:  case ZYDIS_REGISTER_CL: return 1;
    case ZYDIS_REGISTER_CH: is_high_byte = true; return 1;
    case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX:
    case ZYDIS_REGISTER_DX:  case ZYDIS_REGISTER_DL: return 2;
    case ZYDIS_REGISTER_DH: is_high_byte = true; return 2;
    case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX:
    case ZYDIS_REGISTER_BX:  case ZYDIS_REGISTER_BL: return 3;
    case ZYDIS_REGISTER_BH: is_high_byte = true; return 3;
    case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP:
    case ZYDIS_REGISTER_SP:  case ZYDIS_REGISTER_SPL: return 4;
    case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP:
    case ZYDIS_REGISTER_BP:  case ZYDIS_REGISTER_BPL: return 5;
    case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI:
    case ZYDIS_REGISTER_SI:  case ZYDIS_REGISTER_SIL: return 6;
    case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI:
    case ZYDIS_REGISTER_DI:  case ZYDIS_REGISTER_DIL: return 7;
    case ZYDIS_REGISTER_R8:  case ZYDIS_REGISTER_R8D:
    case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R8B: return 8;
    case ZYDIS_REGISTER_R9:  case ZYDIS_REGISTER_R9D:
    case ZYDIS_REGISTER_R9W: case ZYDIS_REGISTER_R9B: return 9;
    case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D:
    case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R10B: return 10;
    case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D:
    case ZYDIS_REGISTER_R11W: case ZYDIS_REGISTER_R11B: return 11;
    case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D:
    case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R12B: return 12;
    case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D:
    case ZYDIS_REGISTER_R13W: case ZYDIS_REGISTER_R13B: return 13;
    case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D:
    case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R14B: return 14;
    case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D:
    case ZYDIS_REGISTER_R15W: case ZYDIS_REGISTER_R15B: return 15;
    default: return 0xff;
    }
}

auto mmio::get_reg_ptr(guest_gprs* gprs, u8 reg_index) -> u64* {
    if (!gprs) return nullptr;

    switch (reg_index) {
    case 0: return &gprs->rax;
    case 1: return &gprs->rcx;
    case 2: return &gprs->rdx;
    case 3: return &gprs->rbx;
    case 5: return &gprs->rbp;
    case 6: return &gprs->rsi;
    case 7: return &gprs->rdi;
    case 8: return &gprs->r8;
    case 9: return &gprs->r9;
    case 10: return &gprs->r10;
    case 11: return &gprs->r11;
    case 12: return &gprs->r12;
    case 13: return &gprs->r13;
    case 14: return &gprs->r14;
    case 15: return &gprs->r15;
    default: return nullptr;
    }
}

auto mmio::sign_extend_value(u64 value, u8 size) -> u64 {
    switch (size) {
    case 1: return static_cast<u64>(static_cast<i64>(static_cast<i8>(value)));
    case 2: return static_cast<u64>(static_cast<i64>(static_cast<i16>(value)));
    case 4: return static_cast<u64>(static_cast<i64>(static_cast<i32>(value)));
    default: return value;
    }
}

auto mmio::fill_register_context(guest_gprs* gprs, u64 rip, ZydisRegisterContext& ctx) -> void {
    RtlZeroMemory(&ctx, sizeof(ctx));
    if (!gprs) return;

    u64 rsp = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rsp), reinterpret_cast<size_t*>(&rsp));

    ctx.values[ZYDIS_REGISTER_RAX] = gprs->rax;
    ctx.values[ZYDIS_REGISTER_RCX] = gprs->rcx;
    ctx.values[ZYDIS_REGISTER_RDX] = gprs->rdx;
    ctx.values[ZYDIS_REGISTER_RBX] = gprs->rbx;
    ctx.values[ZYDIS_REGISTER_RSP] = rsp;
    ctx.values[ZYDIS_REGISTER_RBP] = gprs->rbp;
    ctx.values[ZYDIS_REGISTER_RSI] = gprs->rsi;
    ctx.values[ZYDIS_REGISTER_RDI] = gprs->rdi;
    ctx.values[ZYDIS_REGISTER_R8]  = gprs->r8;
    ctx.values[ZYDIS_REGISTER_R9]  = gprs->r9;
    ctx.values[ZYDIS_REGISTER_R10] = gprs->r10;
    ctx.values[ZYDIS_REGISTER_R11] = gprs->r11;
    ctx.values[ZYDIS_REGISTER_R12] = gprs->r12;
    ctx.values[ZYDIS_REGISTER_R13] = gprs->r13;
    ctx.values[ZYDIS_REGISTER_R14] = gprs->r14;
    ctx.values[ZYDIS_REGISTER_R15] = gprs->r15;
    ctx.values[ZYDIS_REGISTER_RIP] = rip;
}

auto mmio::read_instruction_bytes(u64 rip, u8* buffer, size_t& bytes_read) -> bool {
    if (!buffer || !rip) return false;

    bytes_read = 0;
    while (bytes_read < max_instruction_length) {
        u64 physical_address = 0;
        u64 bytes_to_next_page = 0;
        if (!memory_access::get()->translate(0, rip + bytes_read,
                                             physical_address, bytes_to_next_page)) {
            break;
        }

        auto remaining = static_cast<u64>(max_instruction_length - bytes_read);
        auto chunk = bytes_to_next_page < remaining ? bytes_to_next_page : remaining;
        if (!chunk) break;

        if (!memory_access::get()->read_virtual(0, rip + bytes_read,
                                                buffer + bytes_read, chunk)) {
            break;
        }

        bytes_read += static_cast<size_t>(chunk);
    }

    return bytes_read != 0;
}

auto mmio::decode_instruction(u64 rip, bool is_write, guest_gprs* gprs, u64 gla) -> decoded_instruction {
    decoded_instruction result{};

    u8 inst_bytes[max_instruction_length] = {};
    size_t bytes_read = 0;
    if (!read_instruction_bytes(rip, inst_bytes, bytes_read)) {
        return result;
    }

    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    if (!svm::disassembler::get()->decode_full(inst_bytes, bytes_read, 64, &instruction, operands)) {
        return result;
    }

    result.inst_length = static_cast<u8>(instruction.length);
    if (instruction.address_width != 64) return result;

    auto set_string = [&](operation op, u8 size) -> void {
        result.op = op;
        result.is_string_op = true;
        result.access_size = size;
        result.valid = true;
        result.has_rep = (instruction.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE)) != 0;
    };

    if (instruction.operand_count_visible == 0 &&
        (instruction.attributes & ZYDIS_ATTRIB_HAS_REPNZ) == 0) {
        switch (instruction.mnemonic) {
        case ZYDIS_MNEMONIC_MOVSB: set_string(operation::string_movs, 1); break;
        case ZYDIS_MNEMONIC_MOVSW: set_string(operation::string_movs, 2); break;
        case ZYDIS_MNEMONIC_MOVSD: set_string(operation::string_movs, 4); break;
        case ZYDIS_MNEMONIC_MOVSQ: set_string(operation::string_movs, 8); break;
        case ZYDIS_MNEMONIC_STOSB: if (is_write) set_string(operation::string_stos, 1); break;
        case ZYDIS_MNEMONIC_STOSW: if (is_write) set_string(operation::string_stos, 2); break;
        case ZYDIS_MNEMONIC_STOSD: if (is_write) set_string(operation::string_stos, 4); break;
        case ZYDIS_MNEMONIC_STOSQ: if (is_write) set_string(operation::string_stos, 8); break;
        case ZYDIS_MNEMONIC_LODSB: if (!is_write) set_string(operation::string_lods, 1); break;
        case ZYDIS_MNEMONIC_LODSW: if (!is_write) set_string(operation::string_lods, 2); break;
        case ZYDIS_MNEMONIC_LODSD: if (!is_write) set_string(operation::string_lods, 4); break;
        case ZYDIS_MNEMONIC_LODSQ: if (!is_write) set_string(operation::string_lods, 8); break;
        default: break;
        }

        if (result.valid) return result;
    }

    if (instruction.attributes & (ZYDIS_ATTRIB_HAS_LOCK |
                                  ZYDIS_ATTRIB_HAS_REP |
                                  ZYDIS_ATTRIB_HAS_REPE |
                                  ZYDIS_ATTRIB_HAS_REPNZ)) {
        return result;
    }

    if (instruction.mnemonic != ZYDIS_MNEMONIC_MOV &&
        instruction.mnemonic != ZYDIS_MNEMONIC_MOVZX &&
        instruction.mnemonic != ZYDIS_MNEMONIC_MOVSX &&
        instruction.mnemonic != ZYDIS_MNEMONIC_MOVSXD) {
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

    if (!mem || mem_count != 1) return result;

    auto access_size = static_cast<u8>(mem->size / 8);
    if (!access_size || access_size > 8 || (mem->size % 8) != 0) return result;

    bool memory_read = (mem->actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
    bool memory_write = (mem->actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
    if (memory_read == memory_write) return result;
    if (is_write != memory_write) return result;

    ZydisRegisterContext ctx;
    fill_register_context(gprs, rip, ctx);

    ZyanU64 effective_address = 0;
    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddressEx(&instruction, mem, rip,
                                                &ctx, &effective_address)) &&
        effective_address != gla) {
        return result;
    }

    result.access_size = access_size;

    if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
        if (is_write) {
            if (mem_index != 0 || instruction.operand_count_visible < 2) return result;

            const auto& src = operands[1];
            if (src.type == ZYDIS_OPERAND_TYPE_REGISTER) {
                bool high = false;
                auto idx = reg_to_index(src.reg.value, high);
                if (idx == 0xff) return result;

                result.op = operation::mov_mem_reg;
                result.reg_index = idx;
                result.is_high_byte = high;
            }
            else if (src.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                result.op = operation::mov_mem_imm;
                result.immediate = src.imm.is_signed
                    ? static_cast<u64>(src.imm.value.s)
                    : src.imm.value.u;
            }
            else {
                return result;
            }
        }
        else {
            if (mem_index != 1 || instruction.operand_count_visible < 2) return result;

            const auto& dst = operands[0];
            if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) return result;

            bool high = false;
            auto idx = reg_to_index(dst.reg.value, high);
            if (idx == 0xff) return result;

            result.op = operation::mov_reg_mem;
            result.reg_index = idx;
            result.reg_size = static_cast<u8>(dst.size / 8);
            result.is_high_byte = high;
        }

        if (!result.reg_size) result.reg_size = result.access_size;
        result.valid = true;
        return result;
    }

    if (is_write || mem_index != 1 || instruction.operand_count_visible < 2) {
        return result;
    }

    const auto& dst = operands[0];
    if (dst.type != ZYDIS_OPERAND_TYPE_REGISTER) return result;

    bool high = false;
    auto idx = reg_to_index(dst.reg.value, high);
    if (idx == 0xff) return result;

    result.op = instruction.mnemonic == ZYDIS_MNEMONIC_MOVZX
        ? operation::movzx_reg_mem
        : operation::movsx_reg_mem;
    result.reg_index = idx;
    result.reg_size = static_cast<u8>(dst.size / 8);
    result.is_high_byte = high;
    result.valid = result.reg_size >= result.access_size &&
                   result.reg_size >= 1 &&
                   result.reg_size <= 8;
    return result;
}

auto mmio::read_reg(guest_gprs* gprs, u8 reg_index, u8 size, bool is_high_byte) -> u64 {
    u64 value = 0;
    if (reg_index == 4) {
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rsp), reinterpret_cast<size_t*>(&value));
    }
    else {
        auto reg = get_reg_ptr(gprs, reg_index);
        if (!reg) return 0;
        value = *reg;
    }

    if (is_high_byte) return (value >> 8) & 0xff;

    switch (size) {
    case 1: return value & 0xff;
    case 2: return value & 0xffff;
    case 4: return value & 0xffffffff;
    default: return value;
    }
}

auto mmio::write_reg(guest_gprs* gprs, u8 reg_index, u64 value, u8 size, bool is_high_byte) -> void {
    u64* reg = nullptr;
    u64 rsp = 0;

    if (reg_index == 4) {
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rsp), reinterpret_cast<size_t*>(&rsp));
        reg = &rsp;
    }
    else {
        reg = get_reg_ptr(gprs, reg_index);
    }

    if (!reg) return;

    if (is_high_byte) {
        *reg = (*reg & ~0xff00ULL) | ((value & 0xff) << 8);
    }
    else {
        switch (size) {
        case 1: *reg = (*reg & ~0xffULL) | (value & 0xff); break;
        case 2: *reg = (*reg & ~0xffffULL) | (value & 0xffff); break;
        case 4: *reg = value & 0xffffffff; break;
        case 8: *reg = value; break;
        }
    }

    if (reg_index == 4) {
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_rsp), static_cast<size_t>(rsp));
    }
}

auto mmio::copy_from_guest(void* dst, u64 guest_va, size_t size) -> bool {
    if (!dst || !guest_va) return false;
    if (!size) return true;

    return memory_access::get()->read_virtual(0, guest_va, dst, static_cast<u64>(size));
}

auto mmio::copy_to_guest(u64 guest_va, const void* src, size_t size) -> bool {
    if (!src || !guest_va) return false;
    if (!size) return true;

    return memory_access::get()->write_virtual(0, guest_va, src, static_cast<u64>(size));
}

auto mmio::valid_qualification(u64 qualification) const -> bool {
    auto access = qualification & (ept_qual_data_read | ept_qual_data_write | ept_qual_instr_fetch);
    if (!access || (qualification & ept_qual_instr_fetch)) return false;
    if ((qualification & ept_qual_gla_valid) == 0) return false;
    if ((qualification & ept_qual_translated) == 0) return false;
    return true;
}

auto mmio::advance_rip(u8 length) -> void {
    size_t rip = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rip), &rip);
    auto next = advanced_guest_rip(rip, length);
    if (guest_code_is_64_bit() && !canonical_address(next)) {
        event_handler::get()->inject_gp(0);
        return;
    }

    __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_rip), next);
    event_handler::get()->complete_emulated_instruction();
}

auto mmio::dispatch_access(const access_context& access) -> bool {
    if (svm::tpm::get()->is_tpm_address(access.physical_address)) {
        if (access.is_write) {
            svm::tpm::get()->handle_write(access.physical_address, access.offset,
                                     access.write_value, access.size);
        }
        else {
            if (!access.read_value) return false;
            *access.read_value = svm::tpm::get()->handle_read(access.physical_address,
                                                         access.offset, access.size);
        }
        return true;
    }

    if (!access.is_write) {
        if (!access.read_value) return false;
        *access.read_value = ~0ULL;
    }

    return true;
}

auto mmio::emulate_regular(pvcpu_t vcpu, guest_gprs* gprs, u64 gpa, bool is_write,
                           const decoded_instruction& inst) -> bool {
    UNREFERENCED_PARAMETER(vcpu);

    auto mmio_range = get_range(gpa);
    u32 offset = mmio_range ? static_cast<u32>(gpa - mmio_range->start)
                            : static_cast<u32>(gpa & 0xffff);

    u64 read_value = 0;
    access_context access{
        gpa,
        offset,
        inst.access_size,
        is_write,
        0,
        &read_value
    };

    if (is_write) {
        switch (inst.op) {
        case operation::mov_mem_reg:
            access.write_value = read_reg(gprs, inst.reg_index,
                                          inst.access_size, inst.is_high_byte);
            break;
        case operation::mov_mem_imm:
            access.write_value = inst.immediate;
            break;
        default:
            return false;
        }
        access.read_value = nullptr;
    }

    if (!dispatch_access(access)) return false;

    if (!is_write) {
        switch (inst.op) {
        case operation::mov_reg_mem:
        case operation::movzx_reg_mem:
            write_reg(gprs, inst.reg_index, read_value,
                      inst.reg_size, inst.is_high_byte);
            break;
        case operation::movsx_reg_mem:
            write_reg(gprs, inst.reg_index,
                      sign_extend_value(read_value, inst.access_size),
                      inst.reg_size, inst.is_high_byte);
            break;
        default:
            return false;
        }
    }

    advance_rip(inst.inst_length);
    return true;
}

auto mmio::emulate_string(pvcpu_t vcpu, guest_gprs* gprs, u64 gpa, bool is_write,
                          const decoded_instruction& inst) -> bool {
    UNREFERENCED_PARAMETER(vcpu);

    if (inst.has_rep && gprs->rcx == 0) {
        advance_rip(inst.inst_length);
        return true;
    }

    i64 increment = inst.direction_down ? -static_cast<i64>(inst.access_size)
                                        : static_cast<i64>(inst.access_size);
    auto mmio_range = get_range(gpa);
    u32 offset = mmio_range ? static_cast<u32>(gpa - mmio_range->start)
                            : static_cast<u32>(gpa & 0xffff);

    if (inst.op == operation::string_movs) {
        if (is_write) {
            u64 value = 0;
            if (!copy_from_guest(&value, gprs->rsi, inst.access_size)) return false;

            access_context access{ gpa, offset, inst.access_size, true, value, nullptr };
            if (!dispatch_access(access)) return false;
        }
        else {
            u64 value = 0;
            access_context access{ gpa, offset, inst.access_size, false, 0, &value };
            if (!dispatch_access(access)) return false;
            if (!copy_to_guest(gprs->rdi, &value, inst.access_size)) return false;
        }

        gprs->rsi = static_cast<u64>(static_cast<i64>(gprs->rsi) + increment);
        gprs->rdi = static_cast<u64>(static_cast<i64>(gprs->rdi) + increment);
    }
    else if (inst.op == operation::string_stos && is_write) {
        access_context access{
            gpa,
            offset,
            inst.access_size,
            true,
            read_reg(gprs, 0, inst.access_size, false),
            nullptr
        };
        if (!dispatch_access(access)) return false;
        gprs->rdi = static_cast<u64>(static_cast<i64>(gprs->rdi) + increment);
    }
    else if (inst.op == operation::string_lods && !is_write) {
        u64 value = 0;
        access_context access{ gpa, offset, inst.access_size, false, 0, &value };
        if (!dispatch_access(access)) return false;
        write_reg(gprs, 0, value, inst.access_size, false);
        gprs->rsi = static_cast<u64>(static_cast<i64>(gprs->rsi) + increment);
    }
    else {
        return false;
    }

    if (inst.has_rep) {
        gprs->rcx--;
        if (gprs->rcx == 0) {
            advance_rip(inst.inst_length);
        }
    }
    else {
        advance_rip(inst.inst_length);
    }

    return true;
}

auto mmio::handle_fault(pvcpu_t vcpu, guest_gprs* gprs, u64 gpa, u64 qualification) -> bool {
    if (!vcpu || !gprs) return false;
    if (!is_mmio_address(gpa)) return false;
    if (!valid_qualification(qualification)) return false;

    size_t rip = 0, rflags = 0, gla = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rip), &rip);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rflags), &rflags);
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_linear_addr), &gla);

    bool is_write = (qualification & ept_qual_data_write) != 0;
    auto inst = decode_instruction(rip, is_write, gprs, static_cast<u64>(gla));
    if (!inst.valid) return false;

    inst.direction_down = (rflags & (1ULL << 10)) != 0;

    return inst.is_string_op
        ? emulate_string(vcpu, gprs, gpa, is_write, inst)
        : emulate_regular(vcpu, gprs, gpa, is_write, inst);
}

}
