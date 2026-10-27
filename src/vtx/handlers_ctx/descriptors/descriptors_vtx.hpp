#pragma once
#include "../../../includes.h"

namespace vtx {

class descriptor_handler {
private:
    descriptor_handler() = default;

    auto vmread_u64(vmcs_field field, u64& value) -> bool;
    auto guest_cpl() -> u8;
    auto visible_cr4() -> u64;
    auto current_code_is_64_bit() -> bool;
    auto is_privileged_descriptor_instruction(ZydisMnemonic mnemonic) -> bool;
    auto is_umip_descriptor_instruction(ZydisMnemonic mnemonic) -> bool;
    auto read_guest_instruction(u64 rip, u8* bytes, size_t& bytes_read) -> bool;
    auto fill_zydis_context(guest_gprs* gprs, u64 rip, ZydisRegisterContext& ctx) -> void;
    auto memory_operand_address(const ZydisDecodedInstruction& instruction,
                                const ZydisDecodedOperand& operand,
                                guest_gprs* gprs, u64 rip, u64& address) -> bool;
    auto write_gpr16(guest_gprs* gprs, ZydisRegister reg, u64 value) -> bool;
    auto write_descriptor_pointer(u64 gva, u16 limit, u64 base, bool is_64_bit) -> bool;
    auto read_descriptor_pointer(u64 gva, u16& limit, u64& base, bool is_64_bit) -> bool;

public:
    static auto get() -> descriptor_handler*;
    auto descriptor_exit_handler(guest_gprs* gprs) -> bool;
};

}
