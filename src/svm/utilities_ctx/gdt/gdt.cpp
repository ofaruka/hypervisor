#include "gdt.hpp"

namespace svm {

u16 gdt::setup_tss(svm::pvcpu_t vcpu) {
    RtlZeroMemory(&vcpu->host_tss, sizeof(svm::tss64_t));
    vcpu->ist1_stack = memory::get()->alloc_nonpaged_pool(IST_STACK_SIZE);
    if (!vcpu->ist1_stack) {
        debug::panicf("Failed allocating IST1 stack\n");
        return 0;
    }

    RtlZeroMemory(vcpu->ist1_stack, IST_STACK_SIZE);
    vcpu->host_tss.ist1 = (u64)vcpu->ist1_stack + IST_STACK_SIZE;
    vcpu->ist2_stack = memory::get()->alloc_nonpaged_pool(IST_STACK_SIZE);
    if (!vcpu->ist2_stack) {
        debug::panicf("Failed allocating IST2 stack\n");
        memory::get()->free_nonpaged_pool(vcpu->ist1_stack);
        vcpu->ist1_stack = nullptr;
        return 0;
    }

    RtlZeroMemory(vcpu->ist2_stack, IST_STACK_SIZE);
    vcpu->host_tss.ist2 = (u64)vcpu->ist2_stack + IST_STACK_SIZE;
    vcpu->host_tss.iopb_offset = sizeof(svm::tss64_t);
    u64 tss_base = (u64)&vcpu->host_tss;
    u32 tss_limit = sizeof(svm::tss64_t) - 1;
    u32 original_gdt_bytes = vcpu->original_gdtr.limit + 1;
    u32 tss_entry_index = original_gdt_bytes / sizeof(svm::segment_descriptor_t);
    u16 tss_selector = static_cast<u16>(tss_entry_index * 8);
    svm::segment_descriptor_t* tss_desc_low = &((svm::segment_descriptor_t*)vcpu->host_gdt_entries)[tss_entry_index];
    svm::segment_descriptor_t* tss_desc_high = tss_desc_low + 1;
    tss_desc_low->fields.limit_low = tss_limit & 0xFFFF;
    tss_desc_low->fields.base_low = tss_base & 0xFFFF;
    tss_desc_low->fields.base_middle = (tss_base >> 16) & 0xFF;
    tss_desc_low->fields.base_high = (tss_base >> 24) & 0xFF;
    tss_desc_low->fields.type = 0x9;
    tss_desc_low->fields.system = 0;
    tss_desc_low->fields.dpl = 0;
    tss_desc_low->fields.present = 1;
    tss_desc_low->fields.limit_high = (tss_limit >> 16) & 0xF;
    tss_desc_low->fields.avl = 0;
    tss_desc_low->fields.long_mode = 0;
    tss_desc_low->fields.default_bit = 0;
    tss_desc_low->fields.granularity = 0;
    tss_desc_high->value = 0;
    *((u32*)tss_desc_high) = (tss_base >> 32) & 0xFFFFFFFF;
    vcpu->host_gdtr_limit = static_cast<u16>(((tss_entry_index + 2) * sizeof(svm::segment_descriptor_t)) - 1);
    debug::panicf("TSS setup: selector=0x%x, base=0x%llx\n", tss_selector, tss_base);
    return tss_selector;
}

void gdt::prepare_host_gdt(svm::pvcpu_t vcpu) {
    __sgdt(&vcpu->original_gdtr);
    u32 gdt_size = vcpu->original_gdtr.limit + 1;
    RtlCopyMemory(vcpu->host_gdt_entries, (void*)vcpu->original_gdtr.base, gdt_size);
    vcpu->host_tr_selector = setup_tss(vcpu);
    debug::panicf("Host GDT prepared: original_limit=0x%x, new_limit=0x%x\n", vcpu->original_gdtr.limit,
                  vcpu->host_gdtr_limit);
}

void gdt::restore_guest_gdt(svm::pvcpu_t vcpu) {
    __lgdt(&vcpu->original_gdtr);
}

gdt* gdt::get() {
    static gdt instance;
    return &instance;
}
}
