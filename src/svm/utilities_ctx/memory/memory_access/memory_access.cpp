#include "memory_access.hpp"

namespace svm {

auto memory_access::read_physical_memory(svm::pvcpu_t vcpu, u64 destination_gva, u64 source, u64 size)
    -> svm::svmroot_error_t {
    if (!page_table::is_mapped_physical_range(source, size)) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }
    source += reinterpret_cast<u64>(host_physical_memory_base);
    u64 bytes_read = 0;

    while (bytes_read < size) {
        u64 destination_remaining{};
        auto destination = page_table::get()->gva_to_hva(vcpu->guest_vmcb.state_save_area.cr3,
                                                         destination_gva + bytes_read, destination_remaining);
        if (!destination) {
            return svm::svmroot_error_t::svmroot_translate_failure;
        }

        u64 bytes_to_copy = min(destination_remaining, size - bytes_read);
        memcpy(reinterpret_cast<void*>(destination), reinterpret_cast<void*>(source + bytes_read), bytes_to_copy);
        bytes_read += bytes_to_copy;
    }

    return svm::svmroot_error_t::error_success;
}

auto memory_access::read_physical_to_host(svm::pvcpu_t vcpu, void* destination, u64 source, u64 size)
    -> svm::svmroot_error_t {
    UNREFERENCED_PARAMETER(vcpu);

    if (!destination) {
        return svm::svmroot_error_t::error_failed;
    }

    if (!page_table::is_mapped_physical_range(source, size)) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }

    memcpy(destination, host_physical_memory_base + source, size);
    return svm::svmroot_error_t::error_success;
}

auto memory_access::write_physical_memory(svm::pvcpu_t vcpu, u64 destination, u64 source_gva, u64 size) -> u64 {
    if (!page_table::is_mapped_physical_range(destination, size)) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }
    destination += reinterpret_cast<u64>(host_physical_memory_base);
    u64 bytes_written = 0;

    while (bytes_written < size) {
        u64 remaining{};
        auto source =
            page_table::get()->gva_to_hva(vcpu->guest_vmcb.state_save_area.cr3, source_gva + bytes_written, remaining);
        if (!source) {
            return svm::svmroot_error_t::svmroot_translate_failure;
        }

        u64 bytes_to_copy = min(remaining, size - bytes_written);
        memcpy(reinterpret_cast<void*>(destination + bytes_written), reinterpret_cast<void*>(source), bytes_to_copy);
        bytes_written += bytes_to_copy;
    }

    return svm::svmroot_error_t::error_success;
}

auto memory_access::read_virtual_memory(svm::pvcpu_t vcpu, svm::cr3_t process_cr3, u64 destination_gva, u64 source_gva,
                                        u64 size) -> svm::svmroot_error_t {
    if (!process_cr3.value)
        process_cr3.value = vcpu->host_stack_layout.shared_vcpu->system_cr3.value;
    if (!process_cr3.pml4) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }

    u64 bytes_read = 0;

    while (bytes_read < size) {
        u64 source_remaining{}, destination_remaining{};
        auto source = page_table::get()->gva_to_hva(process_cr3, source_gva + bytes_read, source_remaining);
        if (!source) {
            return svm::svmroot_error_t::svmroot_translate_failure;
        }

        auto destination = page_table::get()->gva_to_hva(vcpu->guest_vmcb.state_save_area.cr3,
                                                         destination_gva + bytes_read, destination_remaining);
        if (!destination) {
            return svm::svmroot_error_t::svmroot_translate_failure;
        }

        u64 bytes_to_copy = min(min(source_remaining, destination_remaining), size - bytes_read);
        memcpy(reinterpret_cast<void*>(destination), reinterpret_cast<void*>(source), bytes_to_copy);
        bytes_read += bytes_to_copy;
    }

    return svm::svmroot_error_t::error_success;
}

auto memory_access::write_virtual_memory(svm::pvcpu_t vcpu, svm::cr3_t process_cr3, u64 destination_gva, u64 source_gva,
                                         u64 size) -> svm::svmroot_error_t {
    if (!process_cr3.value)
        process_cr3.value = vcpu->host_stack_layout.shared_vcpu->system_cr3.value;
    if (!process_cr3.pml4) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }

    u64 bytes_written = 0;

    while (bytes_written < size) {
        u64 source_remaining{}, destination_remaining{};
        auto source = page_table::get()->gva_to_hva(vcpu->guest_vmcb.state_save_area.cr3, source_gva + bytes_written,
                                                    source_remaining);
        if (!source) {
            return svm::svmroot_error_t::svmroot_translate_failure;
        }

        auto destination =
            page_table::get()->gva_to_hva(process_cr3, destination_gva + bytes_written, destination_remaining);
        if (!destination) {
            return svm::svmroot_error_t::svmroot_translate_failure;
        }

        u64 bytes_to_copy = min(min(source_remaining, destination_remaining), size - bytes_written);
        memcpy(reinterpret_cast<void*>(destination), reinterpret_cast<void*>(source), bytes_to_copy);
        bytes_written += bytes_to_copy;
    }

    return svm::svmroot_error_t::error_success;
}

auto memory_access::is_page_present(svm::cr3_t process_cr3, u64 gva) -> bool {
    u64 offset_to_next_page{};
    u64 gpa = page_table::get()->gva_to_gpa(process_cr3, gva, offset_to_next_page);
    bool present = (gpa != 0);
    return present;
}

auto memory_access::request_page_in(svm::cr3_t process_cr3, u64 gva) -> bool {
    u64 page_aligned = gva & ~static_cast<u64>(PAGE_SIZE - 1);
    u64 cr3_canonical = static_cast<u64>(process_cr3.pml4) << 12;

    if (!cr3_canonical) {
        return false;
    }

    for (u32 i = 0; i < max_pending_slots; i++) {
        u64 existing_cr3 = m_pending[i].process_cr3;
        u64 existing_gva = m_pending[i].gva;

        if (existing_cr3 == cr3_canonical && existing_gva == page_aligned) {
            return true;
        }
    }

    for (u32 i = 0; i < max_pending_slots; i++) {
        u64 expected = 0;

        if (InterlockedCompareExchange64(reinterpret_cast<volatile LONG64*>(&m_pending[i].process_cr3),
                                         static_cast<LONG64>(cr3_canonical), static_cast<LONG64>(expected)) == 0) {
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&m_pending[i].gva),
                                  static_cast<LONG64>(page_aligned));
            return true;
        }
    }

    return false;
}

auto memory_access::try_consume_pending(svm::pvcpu_t vcpu) -> bool {
    if (vcpu->guest_vmcb.state_save_area.cpl != 3) {
        return false;
    }

    if (vcpu->guest_vmcb.control_area.event_inj & (1ULL << 31)) {
        return false;
    }

    {
        u64 shadow_ncr3 = MmGetPhysicalAddress(&vcpu->npt[npt::nested_page_table::shadow].pml4).QuadPart;
        if (vcpu->guest_vmcb.control_area.ncr3 == shadow_ncr3) {
            return false;
        }
    }

    svm::cr3_t guest_cr3_t = vcpu->guest_vmcb.state_save_area.cr3;
    u64 guest_cr3 = static_cast<u64>(guest_cr3_t.pml4) << 12;

    if (!guest_cr3) {
        return false;
    }

    for (u32 i = 0; i < max_pending_slots; i++) {
        u64 slot_cr3 = m_pending[i].process_cr3;

        if (!slot_cr3) {
            continue;
        }

        if (slot_cr3 != guest_cr3) {
            continue;
        }

        u64 slot_gva = m_pending[i].gva;

        if (!slot_gva) {
            continue;
        }

        svm::cr3_t target_cr3{};
        target_cr3.value = slot_cr3;

        if (is_page_present(target_cr3, slot_gva)) {
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&m_pending[i].gva), 0);
            InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&m_pending[i].process_cr3), 0);
            continue;
        }

        u64 prev = InterlockedCompareExchange64(reinterpret_cast<volatile LONG64*>(&m_pending[i].gva), 0,
                                                static_cast<LONG64>(slot_gva));
        if (static_cast<u64>(prev) != slot_gva) {
            continue;
        }

        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&m_pending[i].process_cr3), 0);
        event_inj_t event{};
        event.value = 0;
        event.fields.vector = 14;
        event.fields.type = 3;
        event.fields.error_code_valid = 1;
        event.fields.error_code = 0x4;
        event.fields.valid = 1;
        vcpu->guest_vmcb.state_save_area.cr2.value = slot_gva;
        vcpu->guest_vmcb.control_area.event_inj = event.value;
        vcpu->guest_vmcb.control_area.vmcb_clean &= ~static_cast<u32>(svm::vmcb_clean_bits::cr2_bit);
        return true;
    }

    return false;
}

auto memory_access::get() -> memory_access* {
    static memory_access instance;
    return &instance;
}
}
