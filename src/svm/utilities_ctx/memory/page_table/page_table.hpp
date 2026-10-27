#pragma once
#include "../includes.h"

namespace svm {

class page_table {
  public:
    page_table() = default;
    ~page_table() = default;

    // The host 1:1 physical map covers exactly
    // [0, host_physical_memory_pd_count * 1GB) (see defines_ctx/memory-data.hpp).
    // Guest page-table walks run in root mode racing the guest memory manager:
    // a page-table page can be freed and repurposed mid-walk, leaving a
    // "present" entry whose PFN is garbage. Dereferencing such a PFN past the
    // mapped range faults in root mode, and a root-mode fault lands in the
    // guest's KiPageFault with a root-mode RIP/RSP and freezes the machine.
    // Every PFN pulled out of a guest table (and every guest CR3) must pass
    // this check before use. (Literal: 512 PDs * 1GB = 512GB; mirrors
    // host_physical_memory_pd_count without depending on include order.)
    static constexpr u64 host_physical_memory_limit = 512ULL << 30;

    static auto is_mapped_physical(u64 physical_address) -> bool {
        return physical_address < host_physical_memory_limit;
    }

    static auto is_mapped_physical_range(u64 physical_address, u64 size) -> bool {
        return size <= host_physical_memory_limit &&
               physical_address <= host_physical_memory_limit - size;
    }

    auto gva_to_gpa(svm::cr3_t guest_cr3, u64 address, u64& offset_to_next_page) -> u64;
    auto gpa_to_gva(svm::cr3_t guest_cr3, u64 physical_address) -> u64;
    auto gva_to_hva(svm::cr3_t guest_cr3, u64 address, u64& offset_to_next_page) -> void*;
    auto get_physical_address(svm::pvcpu_t vcpu, svm::cr3_t process_cr3, u64 virtual_address) -> u64;
    auto get_virtual_address(svm::pvcpu_t vcpu, svm::cr3_t process_cr3, u64 physical_address) -> u64;
    auto clear_guest_pte_nx(svm::pvcpu_t vcpu, svm::cr3_t process_cr3, u64 gva, bool make_writable) -> u64;
    static auto get() -> page_table*;
};
}
