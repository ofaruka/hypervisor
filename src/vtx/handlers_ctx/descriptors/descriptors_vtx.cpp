#include "descriptors_vtx.hpp"

namespace vtx {

auto descriptor_handler::get() -> descriptor_handler* {
    static descriptor_handler instance;
    return &instance;
}

auto descriptor_handler::vmread_u64(vmcs_field field, u64& value) -> bool {
    size_t raw = 0;
    if (__vmx_vmread(static_cast<size_t>(field), &raw) != 0) return false;
    value = static_cast<u64>(raw);
    return true;
}

auto descriptor_handler::guest_cpl() -> u8 {
    u64 cs = 0;
    vmread_u64(vmcs_field::guest_cs_sel, cs);
    return static_cast<u8>(cs & 3);
}

auto descriptor_handler::visible_cr4() -> u64 {
    u64 guest = 0;
    u64 shadow = 0;
    u64 mask = 0;
    vmread_u64(vmcs_field::guest_cr4, guest);
    vmread_u64(vmcs_field::cr4_read_shadow, shadow);
    vmread_u64(vmcs_field::cr4_guest_host_mask, mask);
    return (guest & ~mask) | (shadow & mask);
}

auto descriptor_handler::current_code_is_64_bit() -> bool {
    u64 cs_ar = 0;
    u64 efer = 0;
    vmread_u64(vmcs_field::guest_cs_ar, cs_ar);
    vmread_u64(vmcs_field::guest_ia32_efer, efer);

    constexpr u64 efer_lma = 1ULL << 10;
    constexpr u64 code_long_bit = 1ULL << 13;
    return (efer & efer_lma) != 0 && (cs_ar & code_long_bit) != 0;
}

auto descriptor_handler::is_privileged_descriptor_instruction(ZydisMnemonic mnemonic) -> bool {
    return mnemonic == ZYDIS_MNEMONIC_LGDT ||
           mnemonic == ZYDIS_MNEMONIC_LIDT ||
           mnemonic == ZYDIS_MNEMONIC_LLDT ||
           mnemonic == ZYDIS_MNEMONIC_LTR;
}

auto descriptor_handler::is_umip_descriptor_instruction(ZydisMnemonic mnemonic) -> bool {
    return mnemonic == ZYDIS_MNEMONIC_SGDT ||
           mnemonic == ZYDIS_MNEMONIC_SIDT ||
           mnemonic == ZYDIS_MNEMONIC_SLDT ||
           mnemonic == ZYDIS_MNEMONIC_STR;
}

auto descriptor_handler::read_guest_instruction(u64 rip, u8* bytes, size_t& bytes_read) -> bool {
    if (!bytes || !rip) return false;

    bytes_read = 0;
    while (bytes_read < 15) {
        u64 physical = 0;
        u64 remaining = 0;
        if (!memory_access::get()->translate(0, rip + bytes_read, physical, remaining)) break;

        auto needed = static_cast<u64>(15 - bytes_read);
        auto chunk = remaining < needed ? remaining : needed;
        if (!chunk) break;
        if (!memory_access::get()->read_virtual(0, rip + bytes_read,
                                                bytes + bytes_read, chunk)) break;
        bytes_read += static_cast<size_t>(chunk);
    }

    return bytes_read != 0;
}

auto descriptor_handler::fill_zydis_context(guest_gprs* gprs, u64 rip,
                                            ZydisRegisterContext& ctx) -> void {
    RtlZeroMemory(&ctx, sizeof(ctx));
    if (!gprs) return;

    u64 rsp = 0;
    vmread_u64(vmcs_field::guest_rsp, rsp);

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

    ctx.values[ZYDIS_REGISTER_EAX] = static_cast<u32>(gprs->rax);
    ctx.values[ZYDIS_REGISTER_ECX] = static_cast<u32>(gprs->rcx);
    ctx.values[ZYDIS_REGISTER_EDX] = static_cast<u32>(gprs->rdx);
    ctx.values[ZYDIS_REGISTER_EBX] = static_cast<u32>(gprs->rbx);
    ctx.values[ZYDIS_REGISTER_ESP] = static_cast<u32>(rsp);
    ctx.values[ZYDIS_REGISTER_EBP] = static_cast<u32>(gprs->rbp);
    ctx.values[ZYDIS_REGISTER_ESI] = static_cast<u32>(gprs->rsi);
    ctx.values[ZYDIS_REGISTER_EDI] = static_cast<u32>(gprs->rdi);
}

auto descriptor_handler::memory_operand_address(const ZydisDecodedInstruction& instruction,
                                                const ZydisDecodedOperand& operand,
                                                guest_gprs* gprs, u64 rip,
                                                u64& address) -> bool {
    if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY) return false;

    ZydisRegisterContext ctx;
    fill_zydis_context(gprs, rip, ctx);
    ZyanU64 effective = 0;
    if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddressEx(&instruction, &operand, rip,
                                                 &ctx, &effective))) {
        return false;
    }

    address = static_cast<u64>(effective);
    return true;
}

auto descriptor_handler::write_gpr16(guest_gprs* gprs, ZydisRegister reg, u64 value) -> bool {
    if (!gprs) return false;

    auto write = [value](u64& target) -> bool {
        target = (target & ~0xffffULL) | (value & 0xffffULL);
        return true;
    };

    switch (reg) {
    case ZYDIS_REGISTER_RAX: case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_AX: return write(gprs->rax);
    case ZYDIS_REGISTER_RCX: case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_CX: return write(gprs->rcx);
    case ZYDIS_REGISTER_RDX: case ZYDIS_REGISTER_EDX: case ZYDIS_REGISTER_DX: return write(gprs->rdx);
    case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_BX: return write(gprs->rbx);
    case ZYDIS_REGISTER_RSP: case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_SP: {
        u64 rsp = 0;
        if (!vmread_u64(vmcs_field::guest_rsp, rsp)) return false;
        return __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_rsp),
                             static_cast<size_t>((rsp & ~0xffffULL) | (value & 0xffffULL))) == 0;
    }
    case ZYDIS_REGISTER_RBP: case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_BP: return write(gprs->rbp);
    case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_SI: return write(gprs->rsi);
    case ZYDIS_REGISTER_RDI: case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_DI: return write(gprs->rdi);
    case ZYDIS_REGISTER_R8:  case ZYDIS_REGISTER_R8D:  case ZYDIS_REGISTER_R8W: return write(gprs->r8);
    case ZYDIS_REGISTER_R9:  case ZYDIS_REGISTER_R9D:  case ZYDIS_REGISTER_R9W: return write(gprs->r9);
    case ZYDIS_REGISTER_R10: case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10W: return write(gprs->r10);
    case ZYDIS_REGISTER_R11: case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11W: return write(gprs->r11);
    case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12W: return write(gprs->r12);
    case ZYDIS_REGISTER_R13: case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13W: return write(gprs->r13);
    case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14W: return write(gprs->r14);
    case ZYDIS_REGISTER_R15: case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15W: return write(gprs->r15);
    default: return false;
    }
}

auto descriptor_handler::write_descriptor_pointer(u64 gva, u16 limit, u64 base,
                                                  bool is_64_bit) -> bool {
    u8 data[10] = {};
    *reinterpret_cast<u16*>(data) = limit;

    if (is_64_bit) {
        *reinterpret_cast<u64*>(data + sizeof(u16)) = base;
        return memory_access::get()->write_virtual(0, gva, data, sizeof(data));
    }

    *reinterpret_cast<u32*>(data + sizeof(u16)) = static_cast<u32>(base);
    return memory_access::get()->write_virtual(0, gva, data, 6);
}

auto descriptor_handler::read_descriptor_pointer(u64 gva, u16& limit, u64& base,
                                                 bool is_64_bit) -> bool {
    u8 data[10] = {};
    auto size = is_64_bit ? sizeof(data) : static_cast<size_t>(6);
    if (!memory_access::get()->read_virtual(0, gva, data, size)) return false;

    limit = *reinterpret_cast<u16*>(data);
    base = is_64_bit ? *reinterpret_cast<u64*>(data + sizeof(u16))
                     : *reinterpret_cast<u32*>(data + sizeof(u16));
    return true;
}

auto descriptor_handler::descriptor_exit_handler(guest_gprs* gprs) -> bool {
    u64 rip = 0;
    if (!vmread_u64(vmcs_field::guest_rip, rip)) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    u8 bytes[15] = {};
    size_t bytes_read = 0;
    if (!read_guest_instruction(rip, bytes, bytes_read)) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    auto is_64_bit = current_code_is_64_bit();
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    if (!svm::disassembler::get()->decode_full(bytes, bytes_read, is_64_bit ? 64 : 32,
                                          &instruction, operands) ||
        instruction.operand_count_visible == 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    auto cpl = guest_cpl();
    constexpr u64 cr4_umip_bit = 1ULL << 11;
    if (is_privileged_descriptor_instruction(instruction.mnemonic) && cpl != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    if (is_umip_descriptor_instruction(instruction.mnemonic) &&
        cpl != 0 &&
        (visible_cr4() & cr4_umip_bit) != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    auto& operand = operands[0];
    u64 address = 0;
    u64 base = 0;
    u64 limit = 0;

    switch (instruction.mnemonic) {
    case ZYDIS_MNEMONIC_SGDT:
    case ZYDIS_MNEMONIC_SIDT:
        if (!memory_operand_address(instruction, operand, gprs, rip, address)) {
            event_handler::get()->inject_gp(0);
            return false;
        }
        if (!vmread_u64(instruction.mnemonic == ZYDIS_MNEMONIC_SGDT
                ? vmcs_field::guest_gdtr_base : vmcs_field::guest_idtr_base, base) ||
            !vmread_u64(instruction.mnemonic == ZYDIS_MNEMONIC_SGDT
                ? vmcs_field::guest_gdtr_limit : vmcs_field::guest_idtr_limit, limit)) {
            event_handler::get()->inject_gp(0);
            return false;
        }
        if (!write_descriptor_pointer(address, static_cast<u16>(limit), base, is_64_bit)) {
            event_handler::get()->inject_gp(0);
            return false;
        }
        return true;

    case ZYDIS_MNEMONIC_SLDT:
    case ZYDIS_MNEMONIC_STR: {
        auto field = instruction.mnemonic == ZYDIS_MNEMONIC_SLDT
            ? vmcs_field::guest_ldtr_sel : vmcs_field::guest_tr_sel;
        u64 selector = 0;
        if (!vmread_u64(field, selector)) {
            event_handler::get()->inject_gp(0);
            return false;
        }

        if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            if (!write_gpr16(gprs, operand.reg.value, selector)) {
                event_handler::get()->inject_gp(0);
                return false;
            }
            return true;
        }

        if (!memory_operand_address(instruction, operand, gprs, rip, address) ||
            !memory_access::get()->write_virtual(0, address, &selector, sizeof(u16))) {
            event_handler::get()->inject_gp(0);
            return false;
        }
        return true;
    }

    case ZYDIS_MNEMONIC_LGDT:
    case ZYDIS_MNEMONIC_LIDT: {
        if (!memory_operand_address(instruction, operand, gprs, rip, address)) {
            event_handler::get()->inject_gp(0);
            return false;
        }

        u16 descriptor_limit = 0;
        u64 descriptor_base = 0;
        if (!read_descriptor_pointer(address, descriptor_limit, descriptor_base, is_64_bit)) {
            event_handler::get()->inject_gp(0);
            return false;
        }

        if (__vmx_vmwrite(static_cast<size_t>(instruction.mnemonic == ZYDIS_MNEMONIC_LGDT
                ? vmcs_field::guest_gdtr_base : vmcs_field::guest_idtr_base),
                static_cast<size_t>(descriptor_base)) != 0 ||
            __vmx_vmwrite(static_cast<size_t>(instruction.mnemonic == ZYDIS_MNEMONIC_LGDT
                ? vmcs_field::guest_gdtr_limit : vmcs_field::guest_idtr_limit),
                descriptor_limit) != 0) {
            event_handler::get()->inject_gp(0);
            return false;
        }
        return true;
    }

    case ZYDIS_MNEMONIC_LLDT:
    case ZYDIS_MNEMONIC_LTR:
        event_handler::get()->inject_gp(0);
        return false;

    default:
        event_handler::get()->inject_gp(0);
        return false;
    }
}

}
