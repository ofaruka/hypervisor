#pragma once
#include "../../../../includes.h"

namespace vtx {

class mmio {
public:
    static constexpr size_t max_ranges = 16;
    static constexpr size_t max_instruction_length = 15;

    enum class operation : u8 {
        none,
        mov_reg_mem,
        mov_mem_reg,
        mov_mem_imm,
        movzx_reg_mem,
        movsx_reg_mem,
        string_movs,
        string_stos,
        string_lods
    };

    struct range {
        u64 start;
        u64 end;
    };

    struct decoded_instruction {
        bool valid;
        bool is_string_op;
        bool is_high_byte;
        u8 reg_index;
        u8 access_size;
        u8 reg_size;
        u8 inst_length;
        bool direction_down;
        bool has_rep;
        operation op;
        u64 immediate;
    };

    struct access_context {
        u64 physical_address;
        u32 offset;
        u8 size;
        bool is_write;
        u64 write_value;
        u64* read_value;
    };

    mmio();

    static auto get() -> mmio*;

    auto register_range(u64 start, u64 end) -> bool;
    auto setup_ept() -> bool;
    auto is_mmio_address(u64 physical_address) const -> bool;
    auto handle_fault(pvcpu_t vcpu, guest_gprs* gprs, u64 gpa, u64 qualification) -> bool;

private:
    auto reg_to_index(ZydisRegister reg, bool& is_high_byte) -> u8;
    auto get_reg_ptr(guest_gprs* gprs, u8 reg_index) -> u64*;
    auto sign_extend_value(u64 value, u8 size) -> u64;
    auto fill_register_context(guest_gprs* gprs, u64 rip, ZydisRegisterContext& ctx) -> void;

    auto get_range(u64 physical_address) const -> const range*;
    auto read_instruction_bytes(u64 rip, u8* buffer, size_t& bytes_read) -> bool;
    auto decode_instruction(u64 rip, bool is_write, guest_gprs* gprs, u64 gla) -> decoded_instruction;
    auto read_reg(guest_gprs* gprs, u8 reg_index, u8 size, bool is_high_byte) -> u64;
    auto write_reg(guest_gprs* gprs, u8 reg_index, u64 value, u8 size, bool is_high_byte) -> void;
    auto copy_from_guest(void* dst, u64 guest_va, size_t size) -> bool;
    auto copy_to_guest(u64 guest_va, const void* src, size_t size) -> bool;
    auto valid_qualification(u64 qualification) const -> bool;
    auto guest_code_is_64_bit() -> bool;
    auto canonical_address(size_t value) -> bool;
    auto advanced_guest_rip(size_t rip, size_t length) -> size_t;
    auto advance_rip(u8 length) -> void;
    auto dispatch_access(const access_context& access) -> bool;
    auto emulate_regular(pvcpu_t vcpu, guest_gprs* gprs, u64 gpa, bool is_write,
                         const decoded_instruction& inst) -> bool;
    auto emulate_string(pvcpu_t vcpu, guest_gprs* gprs, u64 gpa, bool is_write,
                        const decoded_instruction& inst) -> bool;

    KSPIN_LOCK lock_;
    range ranges_[max_ranges];
    size_t range_count_;
};

}
