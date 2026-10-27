#pragma once
#include "../../../includes.h"

namespace vtx {

class ept {
private:
    ept() = default;
    ept_state* state_ = nullptr;
    u64 ept_pointer_  = 0;
    KSPIN_LOCK hook_lock_;

    auto leaf_address_mask() const -> u64 { return 0x000ffffffffff000ULL; }
    auto split_2mb(u32 pdpt_idx, u32 pd_idx) -> bool;
    auto get_pte_for_gpa(u64 gpa, bool force_split) -> u64*;
    auto set_large_memory_type(u64 gpa, u64 memory_type) -> bool;
    auto set_page_memory_type(u64 gpa, u64 memory_type) -> bool;
    auto set_range_memory_type(u64 start, u64 size, u64 memory_type) -> bool;
    auto setup_ram_memory_type() -> bool;
    auto allocate_hidden_dummy_page(void*& dummy_page, u64& dummy_pfn) -> bool;
    auto free_hidden_dummy_page(void* dummy_page) -> void;
    auto update_hook_list(u64 orig_pfn, u64 exec_pfn, u16 patch_offset,
                          u16 patch_size, u64 data_entry, u64 exec_entry,
                          u64* pte_addr) -> bool;
    auto remove_hook_from_list(u64 orig_pfn) -> bool;
    auto find_hidden_page_locked(u64 page_pfn) -> ept_hidden_page_node*;
    auto add_hidden_page_locked(u64 page_pfn, u64 original_entry, u64* pte_addr,
                                void* dummy_page, u64 dummy_pfn) -> bool;
    auto remove_hidden_page_locked(u64 page_pfn) -> ept_hidden_page_node*;

public:
    static auto get() -> ept*;

    auto init() -> bool;

    auto ept_pointer() const -> u64 { return ept_pointer_; }

    auto install_ept_hook(u64 orig_pfn, u64 exec_pfn, u16 patch_offset, u16 patch_size) -> bool;
    auto remove_ept_hook(u64 orig_pfn) -> bool;
    auto hide_physical_page(u64 page_pfn) -> bool;
    auto unhide_physical_page(u64 page_pfn) -> bool;
    auto configure_mmio_page(u64 gpa) -> bool;
    auto is_hidden_physical_range(u64 gpa, u64 size) -> bool;

    auto find_hook_by_gpa(u64 gpa) -> ept_hook_node*;
    auto handle_hook_violation(u64 gpa, u64 qualification) -> bool;
};

}
