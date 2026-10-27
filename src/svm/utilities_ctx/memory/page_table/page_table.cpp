#include "page_table.hpp"

namespace svm {

auto page_table::gva_to_gpa(svm::cr3_t guest_cr3, u64 address, u64& offset_to_next_page) -> u64 {
    static constexpr uint64_t pdpt_address_range = 0x40000000;
    static constexpr uint64_t pd_address_range = 0x200000;
    static constexpr uint64_t pt_address_range = 0x1000;
    uint64_t offset{};
    _virt_addr_t const va{address};
    auto& base = host_physical_memory_base;

    // The CR3 and every PFN below come from a live guest address space that
    // the guest memory manager can rewrite mid-walk. Never dereference a
    // value that points outside the host 1:1 physical map: a root-mode fault
    // here freezes the machine.
    if (!is_mapped_physical(guest_cr3.pml4 << 12)) {
        return {};
    }

    auto const pml4 = reinterpret_cast<pml4e_64*>(base + (guest_cr3.pml4 << 12));
    auto const pml4e = pml4[va.pml4_index];

    if (!pml4e.present || !is_mapped_physical(pml4e.page_frame_number << 12)) {
        return {};
    }

    auto const pdpt = reinterpret_cast<pdpte_64*>(base + (pml4e.page_frame_number << 12));
    auto const pdpte = pdpt[va.pdpt_index];

    if (!pdpte.present) {
        return {};
    }

    if (pdpte.large_page) {
        offset = (va.pd_index << 21) + (va.pt_index << 12) + va.offset_4kb;
        offset_to_next_page = pdpt_address_range - offset;
        u64 const gpa =
            ((pdpte.page_frame_number << 12) & ~((1ULL << 30) - 1)) | (offset & ((1ULL << 30) - 1));
        return is_mapped_physical(gpa) ? gpa : 0;
    }

    if (!is_mapped_physical(pdpte.page_frame_number << 12)) {
        return {};
    }

    auto const pd = reinterpret_cast<pde_64*>(base + (pdpte.page_frame_number << 12));
    auto const pde = pd[va.pd_index];

    if (!pde.present) {
        return {};
    }

    if (pde.large_page) {
        offset = (va.pt_index << 12) + va.offset_4kb;
        offset_to_next_page = pd_address_range - offset;
        u64 const gpa =
            ((pde.page_frame_number << 12) & ~((1ULL << 21) - 1)) | (offset & ((1ULL << 21) - 1));
        return is_mapped_physical(gpa) ? gpa : 0;
    }

    if (!is_mapped_physical(pde.page_frame_number << 12)) {
        return {};
    }

    auto const pt = reinterpret_cast<pte_64*>(base + (pde.page_frame_number << 12));
    auto const pte = pt[va.pt_index];

    if (!pte.present) {
        return {};
    }

    offset = va.offset_4kb;
    offset_to_next_page = pt_address_range - offset;
    u64 const gpa = (pte.page_frame_number << 12) | offset;
    return is_mapped_physical(gpa) ? gpa : 0;
}

auto page_table::gpa_to_gva(svm::cr3_t guest_cr3, u64 physical_address) -> u64 {
    if (!is_mapped_physical(guest_cr3.pml4 << 12)) {
        return 0;
    }

    auto pml4 = reinterpret_cast<pml4e_64*>(host_physical_memory_base + (guest_cr3.pml4 << 12));
    physical_address &= ~0xFFF;

    for (u64 pml4_index = 0; pml4_index < 512; pml4_index++) {
        auto& pml4e = pml4[pml4_index];

        if (!pml4e.present || !is_mapped_physical(pml4e.page_frame_number << 12))
            continue;
        auto pdpt = reinterpret_cast<pdpte_64*>(host_physical_memory_base + (pml4e.page_frame_number << 12));

        for (u64 pdpt_index = 0; pdpt_index < 512; pdpt_index++) {
            auto& pdpte = pdpt[pdpt_index];

            if (!pdpte.present)
                continue;
            if (pdpte.large_page) {
                u64 page_base = (pdpte.page_frame_number << 12) & ~((1ULL << 30) - 1);

                if (physical_address >= page_base && physical_address < page_base + 0x40000000) {
                    u64 offset = physical_address - page_base;
                    return (pml4_index << 39) | (pdpt_index << 30) | offset;
                }

                continue;
            }

            if (!is_mapped_physical(pdpte.page_frame_number << 12))
                continue;
            auto pd = reinterpret_cast<pde_64*>(host_physical_memory_base + (pdpte.page_frame_number << 12));

            for (u64 pd_index = 0; pd_index < 512; pd_index++) {
                auto& pde = pd[pd_index];

                if (!pde.present)
                    continue;
                if (pde.large_page) {
                    u64 page_base = (pde.page_frame_number << 12) & ~((1ULL << 21) - 1);

                    if (physical_address >= page_base && physical_address < page_base + 0x200000) {
                        u64 offset = physical_address - page_base;
                        return (pml4_index << 39) | (pdpt_index << 30) | (pd_index << 21) | offset;
                    }

                    continue;
                }

                if (!is_mapped_physical(pde.page_frame_number << 12))
                    continue;
                auto pt = reinterpret_cast<pte_64*>(host_physical_memory_base + (pde.page_frame_number << 12));

                for (u64 pt_index = 0; pt_index < 512; pt_index++) {
                    auto& pte = pt[pt_index];

                    if (!pte.present)
                        continue;
                    u64 page_base = pte.page_frame_number << 12;

                    if (physical_address == page_base) {
                        return (pml4_index << 39) | (pdpt_index << 30) | (pd_index << 21) | (pt_index << 12);
                    }
                }
            }
        }
    }

    return 0;
}

auto page_table::gva_to_hva(svm::cr3_t guest_cr3, u64 address, u64& offset_to_next_page) -> void* {
    uint64_t gpa = gva_to_gpa(guest_cr3, address, offset_to_next_page);

    if (!gpa)
        return nullptr;
    return gpa + host_physical_memory_base;
}

auto page_table::get_physical_address(svm::pvcpu_t vcpu, svm::cr3_t process_cr3, u64 virtual_address) -> u64 {
    if (!process_cr3.value)
        process_cr3.value = vcpu->host_stack_layout.shared_vcpu->system_cr3.value;
    u64 offset_to_next_page{};
    u64 physical_address = gva_to_gpa(process_cr3, virtual_address, offset_to_next_page);

    if (!physical_address) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }

    return physical_address;
}

auto page_table::get_virtual_address(svm::pvcpu_t vcpu, svm::cr3_t process_cr3, u64 physical_address) -> u64 {
    if (!process_cr3.value)
        process_cr3.value = vcpu->host_stack_layout.shared_vcpu->system_cr3.value;
    u64 virtual_address = gpa_to_gva(process_cr3, physical_address);

    if (!virtual_address) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }

    virtual_address |= 0xFFFF000000000000;
    return virtual_address;
}

auto page_table::clear_guest_pte_nx(svm::pvcpu_t vcpu, svm::cr3_t process_cr3, u64 gva, bool make_writable) -> u64 {
    if (!process_cr3.value)
        process_cr3.value = vcpu->host_stack_layout.shared_vcpu->system_cr3.value;
    _virt_addr_t const va{gva};
    auto& base = host_physical_memory_base;

    if (!is_mapped_physical(process_cr3.pml4 << 12))
        return svm::svmroot_error_t::svmroot_translate_failure;
    auto pml4 = reinterpret_cast<pml4e_64*>(base + (process_cr3.pml4 << 12));

    if (!pml4[va.pml4_index].present || !is_mapped_physical(pml4[va.pml4_index].page_frame_number << 12))
        return svm::svmroot_error_t::svmroot_translate_failure;
    auto pdpt = reinterpret_cast<pdpte_64*>(base + (pml4[va.pml4_index].page_frame_number << 12));

    if (!pdpt[va.pdpt_index].present)
        return svm::svmroot_error_t::svmroot_translate_failure;
    if (pdpt[va.pdpt_index].large_page) {
        pdpt[va.pdpt_index].execute_disable = 0;

        if (make_writable) {
            pdpt[va.pdpt_index].write = 1;
        }

        return svm::svmroot_error_t::error_success;
    }

    if (!is_mapped_physical(pdpt[va.pdpt_index].page_frame_number << 12))
        return svm::svmroot_error_t::svmroot_translate_failure;
    auto pd = reinterpret_cast<pde_64*>(base + (pdpt[va.pdpt_index].page_frame_number << 12));

    if (!pd[va.pd_index].present)
        return svm::svmroot_error_t::svmroot_translate_failure;
    if (pd[va.pd_index].large_page) {
        pd[va.pd_index].execute_disable = 0;

        if (make_writable) {
            pd[va.pd_index].write = 1;
        }

        return svm::svmroot_error_t::error_success;
    }

    if (!is_mapped_physical(pd[va.pd_index].page_frame_number << 12))
        return svm::svmroot_error_t::svmroot_translate_failure;
    auto pt = reinterpret_cast<pte_64*>(base + (pd[va.pd_index].page_frame_number << 12));

    if (!pt[va.pt_index].present)
        return svm::svmroot_error_t::svmroot_translate_failure;
    pt[va.pt_index].execute_disable = 0;

    if (make_writable) {
        pt[va.pt_index].write = 1;
    }

    return svm::svmroot_error_t::error_success;
}

auto page_table::get() -> page_table* {
    static page_table instance;
    return &instance;
}
}
