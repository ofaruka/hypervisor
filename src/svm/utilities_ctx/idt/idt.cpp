#include "idt.hpp"

namespace svm {

void idt::prepare_host_idt(svm::pvcpu_t vcpu) {
    if (!vcpu) {
        return;
    }

    __sidt(&vcpu->original_idtr);
    auto original_entries = reinterpret_cast<svm::idt_entry_t*>(vcpu->original_idtr.base);
    RtlCopyMemory(vcpu->host_idt_entries, original_entries, sizeof(vcpu->host_idt_entries));
    uint16_t cs_selector = __read_cs();
    constexpr uint8_t handler_count = static_cast<uint8_t>(sizeof(handler_table) / sizeof(handler_table[0]));
    for (uint8_t i = 0; i < handler_count; i++) {
        if (handler_table[i].handler != nullptr) {
            set_idt_entry(vcpu->host_idt_entries, i, handler_table[i].handler, cs_selector, 0xE, 0,
                          handler_table[i].ist_index);
        }
    }

    debug::panicf("Per-vCPU IDT prepared for processor with %u entries\n", 256);
}

void idt::set_idt_entry(svm::idt_entry_t* idt_table, uint8_t vector, void* handler, uint16_t selector, uint8_t type,
                        uint8_t dpl, uint8_t ist) {
    if (!idt_table || vector >= 256) {
        return;
    }

    uint64_t handler_addr = (uint64_t)handler;
    idt_table[vector].offset_low = handler_addr & 0xFFFF;
    idt_table[vector].selector = selector;
    idt_table[vector].ist = ist & 0x7;
    idt_table[vector].reserved0 = 0;
    idt_table[vector].type = type;
    idt_table[vector].zero = 0;
    idt_table[vector].dpl = dpl;
    idt_table[vector].present = 1;
    idt_table[vector].offset_mid = (handler_addr >> 16) & 0xFFFF;
    idt_table[vector].offset_high = (handler_addr >> 32) & 0xFFFFFFFF;
    idt_table[vector].reserved1 = 0;
}

void idt::restore_guest_idt(svm::pvcpu_t vcpu) {
    if (vcpu && vcpu->original_idtr.base != 0) {
        __lidt(&vcpu->original_idtr);
    }
}

idt* idt::get() {
    static idt instance;
    return &instance;
}
}
