#pragma once
#include "../includes.h"
namespace svm {
struct pte_access {
    bool present;
    bool writable;
    bool execute;
};
struct npf_exit_info {
    union {
        UINT64 as_uint64;
        struct {
            UINT64 valid : 1;
            UINT64 write : 1;
            UINT64 user : 1;
            UINT64 reserved : 1;
            UINT64 execute : 1;
            UINT64 reserved2 : 27;
            UINT64 guest_physical_address : 1;
            UINT64 guest_page_tables : 1;
        } fields;
    };
};
struct segment_register_t {
    segment_selector_t selector;
    segment_attributes_t attribute;
    uint32_t limit;
    uint64_t base;
    void get_attributes(uint64_t descriptor) {
        auto desc = reinterpret_cast<psegment_descriptor_t>(descriptor + selector.index * 8);
        attribute.fields.type = desc->fields.type;
        attribute.fields.system = desc->fields.system;
        attribute.fields.dpl = desc->fields.dpl;
        attribute.fields.present = desc->fields.present;
        attribute.fields.avl = desc->fields.avl;
        attribute.fields.long_mode = desc->fields.long_mode;
        attribute.fields.default_bit = desc->fields.default_bit;
        attribute.fields.granularity = desc->fields.granularity;
        attribute.fields.present = desc->fields.present;
        attribute.fields.reserved1 = 0;
    }
};
static_assert(sizeof(segment_register_t) == 0x10, "seg_register size mismatch");
typedef struct {
    uint16_t intercept_cr_read;
    uint16_t intercept_cr_write;
    uint16_t intercept_dr_read;
    uint16_t intercept_dr_write;
    uint32_t intercept_exception;
    uint32_t intercept_misc1;
    uint32_t intercept_misc2;
    uint8_t reserved1[0x03c - 0x014];
    uint16_t pause_filter_threshhold;
    uint16_t pause_filter_count;
    uint64_t iopm_base_pa;
    uint64_t msrpm_base_pa;
    uint64_t tsc_offset;
    uint32_t guest_asid;
    uint32_t tlb_control;
    uint64_t vintr;
    uint64_t interrupt_shadow;
    uint64_t exit_code;
    uint64_t exit_info1;
    uint64_t exit_info2;
    uint64_t exit_int_info;
    uint64_t np_enable;
    uint64_t avic_apic_bar;
    uint64_t guest_pa_of_ghcb;
    uint64_t event_inj;
    uint64_t ncr3;
    uint64_t lbr_virtualization_enable;
    uint64_t vmcb_clean;
    uint64_t next_rip;
    uint8_t num_of_bytes_fetched;
    uint8_t guest_instruction_bytes[15];
    uint64_t avic_apic_backing_page_ptr;
    uint64_t reserved2;
    uint64_t avic_logical_table_ptr;
    uint64_t avic_physical_table_ptr;
    uint64_t reserved3;
    uint64_t vmcb_save_state_ptr;
    uint8_t reserved4[0x400 - 0x110];
} vmcb_ctrl_area_t, *pvmcb_ctrl_area_t;
static_assert(sizeof(vmcb_ctrl_area_t) == 0x400, "vmcb_ctrl_area size mismatch");
enum vmcb_clean_bits : u32 {
    intercepts = (1 << 0),
    iopm_bases = (1 << 1),
    asid = (1 << 2),
    tpr = (1 << 3),
    np_enable = (1 << 4),
    ctrl_regs = (1 << 5),
    dbg_regs = (1 << 6),
    dt_regs = (1 << 7),
    seg_regs = (1 << 8),
    cr2_bit = (1 << 9),
    lbr_virt = (1 << 10),
    avic = (1 << 11),
    cet = (1 << 12),
    all = 0x1fff
};
typedef enum _vmcb_state_save_area_offset {
    es = 0x000,
    cs = 0x010,
    ss = 0x020,
    ds = 0x030,
    fs = 0x040,
    gs = 0x050,
    gdtr = 0x060,
    ldtr = 0x070,
    idtr = 0x080,
    tr = 0x090,
    reserved1 = 0x0a0,
    cpl = 0x0cb,
    reserved2 = 0x0cc,
    msr_efer = 0x0d0,
    reserved3 = 0x0d8,
    cr4 = 0x148,
    cr3 = 0x150,
    cr0 = 0x158,
    dr7 = 0x160,
    dr6 = 0x168,
    rflags = 0x170,
    rip = 0x178,
    reserved4 = 0x180,
    rsp = 0x1d8,
    reserved5 = 0x1e0,
    rax = 0x1f8,
    star = 0x200,
    msr_lstar = 0x208,
    msr_cstar = 0x210,
    sfmask = 0x218,
    kernel_gs_base = 0x220,
    sysenter_cs = 0x228,
    sysenter_esp = 0x230,
    sysenter_eip = 0x238,
    cr2 = 0x240,
    reserved6 = 0x248,
    gpat = 0x268,
    dbg_ctl = 0x270,
    br_from = 0x278,
    br_to = 0x280,
    last_excep_from = 0x288,
    last_exep_to = 0x290
} vmcb_state_save_area_offset,
    *pvmcb_state_save_area_offset;
typedef struct {
    segment_register_t es;
    segment_register_t cs;
    segment_register_t ss;
    segment_register_t ds;
    segment_register_t fs;
    segment_register_t gs;
    segment_register_t gdtr;
    segment_register_t ldtr;
    segment_register_t idtr;
    segment_register_t tr;
    uint8_t reserved1[0x0cb - 0x0a0];
    uint8_t cpl;
    uint32_t reserved2;
    svm::efer_msr efer;
    uint8_t reserved3[0x148 - 0x0d8];
    svm::cr4_t cr4;
    svm::cr3_t cr3;
    svm::cr0_t cr0;
    uint64_t dr7;
    uint64_t dr6;
    uint64_t rflags;
    uint64_t rip;
    uint8_t reserved4[0x1d8 - 0x180];
    uint64_t rsp;
    uint8_t reserved5[0x1f8 - 0x1e0];
    uint64_t rax;
    uint64_t star;
    uint64_t lstar;
    uint64_t cstar;
    uint64_t sfmask;
    uint64_t kernel_gs_base;
    uint64_t sysenter_cs;
    uint64_t sysenter_esp;
    uint64_t sysenter_eip;
    svm::cr2_t cr2;
    uint8_t reserved6[0x268 - 0x248];
    uint64_t gpat;
    uint64_t dbg_ctl;
    uint64_t br_from;
    uint64_t br_to;
    uint64_t last_excep_from;
    uint64_t last_exep_to;
} vmcb_state_save_area_t, *pvmcb_state_save_area_t;
static_assert(sizeof(vmcb_state_save_area_t) == 0x298, "vmcb_state_save_area size mismatch");
typedef struct {
    vmcb_ctrl_area_t control_area;
    vmcb_state_save_area_t state_save_area;
    uint8_t reserved1[0x1000 - sizeof(vmcb_ctrl_area_t) - sizeof(vmcb_state_save_area_t)];
} vmcb_t, *pvmcb_t;
static_assert(sizeof(vmcb_t) == 0x1000, "vmcb size mismatch");
struct register_t {
    union {
        u64 value;
        union {
            struct {
                u32 low;
                u32 high;
            };
            struct {
                u64 qword;
            };
            struct {
                u32 dword1;
                u32 dword2;
            };
            struct {
                u16 word1;
                u16 word2;
                u16 word3;
                u16 word4;
            };
            struct {
                u8 byte1;
                u8 byte2;
                u8 byte3;
                u8 byte4;
                u8 byte5;
                u8 byte6;
                u8 byte7;
                u8 byte8;
            };
        };
    };
    inline bool operator==(uint64_t val) {
        return value == val;
    }

    inline bool operator!=(uint64_t val) {
        return value != val;
    }

    inline register_t& operator=(uint64_t val) {
        value = val;
        return *this;
    }

    operator uint64_t() {
        return value;
    }
};
typedef struct {
    register_t r15;
    register_t r14;
    register_t r13;
    register_t r12;
    register_t r11;
    register_t r10;
    register_t r9;
    register_t r8;
    register_t rdi;
    register_t rsi;
    register_t rbp;
    register_t rsp;
    register_t rbx;
    register_t rdx;
    register_t rcx;
    register_t rax;
} guest_registers_t, *pguest_registers_t;
typedef struct {
    pguest_registers_t vprocessor_registers;
    bool should_exit;
} guest_ctx_t, *pguest_ctx_t;
}
