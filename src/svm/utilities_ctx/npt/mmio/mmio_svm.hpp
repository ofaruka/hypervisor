#pragma once
#include "../includes.h"

namespace svm {

class mmio {
  public:
    static constexpr size_t MAX_MMIO_RANGES = 16;
    static constexpr size_t MAX_INSTRUCTION_LENGTH = 15;
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
    struct mmio_range_t {
        u64 start;
        u64 end;
        u32 flags;
    };
    struct decoded_instruction_t {
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
    struct mmio_access_t {
        u64 physical_address;
        u32 offset;
        u8 size;
        bool is_write;
        u64 write_value;
        u64* read_value;
    };
    mmio();
    static mmio* get();
    bool register_range(u64 start, u64 end);
    bool is_mmio_address(u64 physical_address) const;
    const mmio_range_t* get_range(u64 physical_address) const;
    bool setup_npt(svm::pvcpu_t vcpu);
    bool handle_fault(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, const page_context& ctx);
    bool prepare_mmio_pages(svm::pvcpu_t vcpu) {
        return setup_npt(vcpu);
    }
    bool register_mmio_range(u64 start, u64 end) {
        return register_range(start, end);
    }
    bool handle_mmio_fault(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, const page_context& ctx) {
        return handle_fault(vcpu, guest_ctx, ctx);
    }

  private:
    decoded_instruction_t decode_instruction(svm::pvcpu_t vcpu, bool is_write);
    u8 reg_to_index(ZydisRegister reg, bool& is_high_byte);
    bool read_inst_bytes(svm::pvcpu_t vcpu, u8* buffer, size_t& bytes_read);
    bool emulate_regular(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u64 guest_pa, bool is_write,
                         const decoded_instruction_t& inst);
    bool emulate_string(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u64 guest_pa, bool is_write,
                        const decoded_instruction_t& inst);
    u64* get_reg_ptr(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u8 reg_index);
    u64 read_reg(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u8 reg_index, u8 size, bool is_high_byte);
    void write_reg(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u8 reg_index, u64 value, u8 size, bool is_high_byte);
    void* translate_gva(svm::pvcpu_t vcpu, u64 guest_va);
    bool copy_from_guest(svm::pvcpu_t vcpu, void* dst, u64 guest_va, size_t size);
    bool copy_to_guest(svm::pvcpu_t vcpu, u64 guest_va, const void* src, size_t size);
    u64 sign_extend_value(u64 value, u8 size);
    bool dispatch_access(const mmio_access_t& access);
    bool configure_pte(svm::pvcpu_t vcpu, u64 page_pa);
    mutable KSPIN_LOCK lock_;
    mmio_range_t ranges_[MAX_MMIO_RANGES];
    size_t range_count_;
};
}
