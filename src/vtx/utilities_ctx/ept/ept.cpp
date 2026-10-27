#include "ept.hpp"
#include "../memory/memory_access_vtx.hpp"

namespace vtx {

auto ept::init() -> bool {
    if (state_) return true;

    KeInitializeSpinLock(&hook_lock_);

    u64 eptcap = __readmsr(vtx::msr::ia32_vmx_ept_vpid_cap);
    constexpr u64 required_caps =
        ept_cap_execute_only |
        ept_cap_page_walk_length_4 |
        ept_cap_memory_type_writeback |
        ept_cap_pde_2mb |
        ept_cap_invept |
        ept_cap_invept_single_context |
        ept_cap_invvpid |
        ept_cap_invvpid_all_contexts;

    if ((eptcap & required_caps) != required_caps) {
        debug::panicf("[ept] missing EPT caps eptcap=%llx required=%llx\n",
                      eptcap, required_caps);
        return false;
    }

    state_ = reinterpret_cast<ept_state*>(
        svm::memory::get()->alloc_contiguous_memory(sizeof(ept_state)));
    if (!state_) {
        debug::panicf("[ept] alloc_contiguous_memory(%llu) failed\n",
                      static_cast<u64>(sizeof(ept_state)));
        return false;
    }

    auto pml4_pa = static_cast<u64>(MmGetPhysicalAddress(&state_->pml4[0]).QuadPart);
    auto pdpt_pa = static_cast<u64>(MmGetPhysicalAddress(&state_->pdpt[0]).QuadPart);

    state_->pml4[0] = pdpt_pa | ept_read | ept_write | ept_execute;

    for (u32 i = 0; i < 512; ++i) {
        auto pd_pa = static_cast<u64>(MmGetPhysicalAddress(&state_->pd[i][0]).QuadPart);
        state_->pdpt[i] = pd_pa | ept_read | ept_write | ept_execute;

        for (u32 j = 0; j < 512; ++j) {
            u64 page_pa = (static_cast<u64>(i) << 30) | (static_cast<u64>(j) << 21);
            state_->pd[i][j] = page_pa
                             | ept_read | ept_write | ept_execute
                             | ept_pagesize
                             | (ept_mt_uncacheable << 3);
        }
    }

    for (u32 i = 0; i < ept_pt_pool_count; ++i) {
        state_->pt_pool_pfn[i] =
            static_cast<u64>(MmGetPhysicalAddress(&state_->pt_pool[i][0]).QuadPart) >> 12;
    }
    state_->pt_pool_used = 0;

    if (!setup_ram_memory_type()) {
        debug::panicf("[ept] setup_ram_memory_type failed\n");
        svm::memory::get()->free_contiguous_memory(state_);
        state_ = nullptr;
        return false;
    }

    state_->hooks_active = nullptr;
    state_->hooks_free   = &state_->hooks_buffer[0];
    for (u32 i = 0; i < ept_max_hooks - 1; ++i) {
        state_->hooks_buffer[i].next = &state_->hooks_buffer[i + 1];
    }
    state_->hooks_buffer[ept_max_hooks - 1].next = nullptr;

    state_->hidden_active = nullptr;
    state_->hidden_free   = &state_->hidden_buffer[0];
    for (u32 i = 0; i < ept_max_hidden_pages - 1; ++i) {
        state_->hidden_buffer[i].next = &state_->hidden_buffer[i + 1];
    }
    state_->hidden_buffer[ept_max_hidden_pages - 1].next = nullptr;

    ept_pointer_ = pml4_pa | ept_mt_writeback | (3ULL << 3);

    debug::panicf("[ept] init OK: pml4_pa=%llx eptp=%llx pt_pool=%u hooks=%u hidden=%u\n",
                  pml4_pa, ept_pointer_, ept_pt_pool_count, ept_max_hooks,
                  ept_max_hidden_pages);
    return true;
}

auto ept::split_2mb(u32 pdpt_idx, u32 pd_idx) -> bool {
    if (!state_) return false;
    auto& pde = state_->pd[pdpt_idx][pd_idx];
    if (!(pde & ept_pagesize)) return true;
    if (state_->pt_pool_used >= ept_pt_pool_count) return false;

    auto slot = state_->pt_pool_used++;
    auto pt   = state_->pt_pool[slot];
    auto pt_pfn = state_->pt_pool_pfn[slot];

    u64 base_pfn = (pde >> 12) & ~0x1ffULL;
    u64 perms_and_mt = pde & (ept_read | ept_write | ept_execute | (7ULL << 3));

    for (u32 i = 0; i < 512; ++i) {
        u64 page_pfn = base_pfn + i;
        pt[i] = (page_pfn << 12) | perms_and_mt;
    }

    pde = (pt_pfn << 12) | ept_read | ept_write | ept_execute;
    return true;
}

auto ept::get_pte_for_gpa(u64 gpa, bool force_split) -> u64* {
    if (!state_) return nullptr;

    u32 pml4_idx = static_cast<u32>((gpa >> 39) & 0x1ff);
    u32 pdpt_idx = static_cast<u32>((gpa >> 30) & 0x1ff);
    u32 pd_idx   = static_cast<u32>((gpa >> 21) & 0x1ff);
    u32 pt_idx   = static_cast<u32>((gpa >> 12) & 0x1ff);

    if (pml4_idx != 0) return nullptr;
    if (pdpt_idx >= 512) return nullptr;

    auto& pde = state_->pd[pdpt_idx][pd_idx];
    if (pde & ept_pagesize) {
        if (!force_split) return nullptr;
        if (!split_2mb(pdpt_idx, pd_idx)) return nullptr;
    }

    u64 pt_pfn = (pde >> 12) & 0xffffffffffULL;
    for (u32 i = 0; i < state_->pt_pool_used; ++i) {
        if (state_->pt_pool_pfn[i] == pt_pfn) {
            return &state_->pt_pool[i][pt_idx];
        }
    }
    return nullptr;
}

auto ept::set_large_memory_type(u64 gpa, u64 memory_type) -> bool {
    if (!state_) return false;

    u32 pml4_idx = static_cast<u32>((gpa >> 39) & 0x1ff);
    u32 pdpt_idx = static_cast<u32>((gpa >> 30) & 0x1ff);
    u32 pd_idx   = static_cast<u32>((gpa >> 21) & 0x1ff);
    if (pml4_idx != 0 || pdpt_idx >= 512) return false;

    auto& pde = state_->pd[pdpt_idx][pd_idx];
    if (pde & ept_pagesize) {
        pde = (pde & ~(7ULL << 3)) | (memory_type << 3);
        return true;
    }

    u64 pt_pfn = (pde >> 12) & 0xffffffffffULL;
    for (u32 i = 0; i < state_->pt_pool_used; ++i) {
        if (state_->pt_pool_pfn[i] != pt_pfn) continue;

        for (u32 j = 0; j < 512; ++j) {
            state_->pt_pool[i][j] =
                (state_->pt_pool[i][j] & ~(7ULL << 3)) | (memory_type << 3);
        }
        return true;
    }
    return false;
}

auto ept::set_page_memory_type(u64 gpa, u64 memory_type) -> bool {
    auto pte = get_pte_for_gpa(gpa, true);
    if (!pte) return false;

    *pte = (*pte & ~(7ULL << 3)) | (memory_type << 3);
    return true;
}

auto ept::set_range_memory_type(u64 start, u64 size, u64 memory_type) -> bool {
    if (!size) return true;

    u64 end = (start + size + page_4kb - 1) & ~(page_4kb - 1);
    start &= ~(page_4kb - 1);
    if (end <= start) return false;

    while (start < end) {
        auto remaining = end - start;
        if (!(start & (page_2mb - 1)) && remaining >= page_2mb) {
            if (!set_large_memory_type(start, memory_type)) return false;
            start += page_2mb;
            continue;
        }

        if (!set_page_memory_type(start, memory_type)) return false;
        start += page_4kb;
    }
    return true;
}

auto ept::setup_ram_memory_type() -> bool {
    auto ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return false;

    bool success = true;
    for (auto range = ranges; range->NumberOfBytes.QuadPart != 0; ++range) {
        auto start = static_cast<u64>(range->BaseAddress.QuadPart);
        auto size  = static_cast<u64>(range->NumberOfBytes.QuadPart);
        if (!set_range_memory_type(start, size, ept_mt_writeback)) {
            success = false;
            break;
        }
    }

    ExFreePool(ranges);
    return success;
}

auto ept::allocate_hidden_dummy_page(void*& dummy_page, u64& dummy_pfn) -> bool {
    dummy_page = svm::memory::get()->alloc_nonpaged_pool(PAGE_SIZE);
    dummy_pfn = 0;
    if (!dummy_page) return false;
    if (PAGE_ALIGN(dummy_page) != dummy_page) {
        svm::memory::get()->free_nonpaged_pool(dummy_page);
        dummy_page = nullptr;
        return false;
    }

    dummy_pfn = static_cast<u64>(MmGetPhysicalAddress(dummy_page).QuadPart) >> 12;
    if (!dummy_pfn) {
        svm::memory::get()->free_nonpaged_pool(dummy_page);
        dummy_page = nullptr;
        return false;
    }

    return true;
}

auto ept::free_hidden_dummy_page(void* dummy_page) -> void {
    if (dummy_page) svm::memory::get()->free_nonpaged_pool(dummy_page);
}

auto ept::install_ept_hook(u64 orig_pfn, u64 exec_pfn,
                           u16 patch_offset, u16 patch_size) -> bool {
    if (!state_) return false;

    u64 gpa = orig_pfn << 12;
    auto pte = get_pte_for_gpa(gpa, true);
    if (!pte) return false;

    u64 mt = ept_mt_writeback << 3;
    auto data_entry = (orig_pfn << 12) | ept_read | ept_write  | mt;
    auto exec_entry = (exec_pfn << 12) | ept_execute           | mt;

    KIRQL old_irql = {};
    KeAcquireSpinLock(&hook_lock_, &old_irql);

    if (!update_hook_list(orig_pfn, exec_pfn, patch_offset, patch_size,
                          data_entry, exec_entry, pte)) {
        KeReleaseSpinLock(&hook_lock_, old_irql);
        return false;
    }

    *pte = data_entry;
    KeReleaseSpinLock(&hook_lock_, old_irql);
    return true;
}

auto ept::remove_ept_hook(u64 orig_pfn) -> bool {
    if (!state_) return false;

    KIRQL old_irql = {};
    KeAcquireSpinLock(&hook_lock_, &old_irql);

    ept_hook_node* node = nullptr;
    for (auto cur = state_->hooks_active; cur; cur = cur->next) {
        if (cur->orig_pfn == orig_pfn) {
            node = cur;
            break;
        }
    }
    if (!node) {
        KeReleaseSpinLock(&hook_lock_, old_irql);
        return false;
    }

    if (node->pte_addr) {
        *node->pte_addr = (orig_pfn << 12)
                        | ept_read | ept_write | ept_execute
                        | (ept_mt_writeback << 3);
    }
    KeMemoryBarrier();

    auto removed = remove_hook_from_list(orig_pfn);
    KeReleaseSpinLock(&hook_lock_, old_irql);
    return removed;
}

auto ept::hide_physical_page(u64 page_pfn) -> bool {
    if (!state_) return false;

    auto pte = get_pte_for_gpa(page_pfn << 12, true);
    if (!pte) return false;

    void* dummy_page = nullptr;
    u64 dummy_pfn = 0;
    if (!allocate_hidden_dummy_page(dummy_page, dummy_pfn)) return false;

    KIRQL old_irql = {};
    KeAcquireSpinLock(&hook_lock_, &old_irql);

    if (find_hidden_page_locked(page_pfn)) {
        KeReleaseSpinLock(&hook_lock_, old_irql);
        free_hidden_dummy_page(dummy_page);
        return true;
    }

    auto original_entry = *pte;
    if (!add_hidden_page_locked(page_pfn, original_entry, pte,
                                dummy_page, dummy_pfn)) {
        KeReleaseSpinLock(&hook_lock_, old_irql);
        free_hidden_dummy_page(dummy_page);
        return false;
    }

    *pte = (original_entry & ~leaf_address_mask())
         | ((dummy_pfn << 12) & leaf_address_mask());
    KeMemoryBarrier();
    KeReleaseSpinLock(&hook_lock_, old_irql);
    return true;
}

auto ept::unhide_physical_page(u64 page_pfn) -> bool {
    if (!state_) return false;

    KIRQL old_irql = {};
    KeAcquireSpinLock(&hook_lock_, &old_irql);

    auto node = remove_hidden_page_locked(page_pfn);
    if (!node || !node->pte_addr) {
        KeReleaseSpinLock(&hook_lock_, old_irql);
        return false;
    }

    auto dummy_page = node->dummy_page;

    *node->pte_addr = node->original_entry;
    node->page_pfn = 0;
    node->original_entry = 0;
    node->pte_addr = nullptr;
    node->dummy_page = nullptr;
    node->dummy_pfn = 0;
    node->next = state_->hidden_free;
    state_->hidden_free = node;
    KeMemoryBarrier();

    KeReleaseSpinLock(&hook_lock_, old_irql);
    free_hidden_dummy_page(dummy_page);
    return true;
}

auto ept::update_hook_list(u64 orig_pfn, u64 exec_pfn, u16 patch_offset,
                           u16 patch_size, u64 data_entry, u64 exec_entry,
                           u64* pte_addr) -> bool {
    if (!state_ || !state_->hooks_free) return false;

    auto node = state_->hooks_free;
    state_->hooks_free = node->next;

    node->orig_pfn     = orig_pfn;
    node->exec_pfn     = exec_pfn;
    node->patch_offset = patch_offset;
    node->patch_size   = patch_size;
    node->data_entry   = data_entry;
    node->exec_entry   = exec_entry;
    node->pte_addr     = pte_addr;
    node->next         = state_->hooks_active;

    KeMemoryBarrier();
    state_->hooks_active = node;
    return true;
}

auto ept::remove_hook_from_list(u64 orig_pfn) -> bool {
    if (!state_) return false;

    auto prev = &state_->hooks_active;
    while (*prev) {
        if ((*prev)->orig_pfn == orig_pfn) {
            auto node = *prev;
            *prev = node->next;

            node->orig_pfn     = 0;
            node->exec_pfn     = 0;
            node->patch_offset = 0;
            node->patch_size   = 0;
            node->data_entry   = 0;
            node->exec_entry   = 0;
            node->pte_addr     = nullptr;
            node->next         = state_->hooks_free;
            state_->hooks_free = node;
            return true;
        }
        prev = &(*prev)->next;
    }
    return false;
}

auto ept::find_hidden_page_locked(u64 page_pfn) -> ept_hidden_page_node* {
    if (!state_) return nullptr;

    for (auto cur = state_->hidden_active; cur; cur = cur->next) {
        if (cur->page_pfn == page_pfn) return cur;
    }
    return nullptr;
}

auto ept::add_hidden_page_locked(u64 page_pfn, u64 original_entry, u64* pte_addr,
                                 void* dummy_page, u64 dummy_pfn) -> bool {
    if (!state_ || !state_->hidden_free) return false;

    auto node = state_->hidden_free;
    state_->hidden_free = node->next;

    node->page_pfn = page_pfn;
    node->original_entry = original_entry;
    node->pte_addr = pte_addr;
    node->dummy_page = dummy_page;
    node->dummy_pfn = dummy_pfn;
    node->next = state_->hidden_active;

    KeMemoryBarrier();
    state_->hidden_active = node;
    return true;
}

auto ept::remove_hidden_page_locked(u64 page_pfn) -> ept_hidden_page_node* {
    if (!state_) return nullptr;

    auto prev = &state_->hidden_active;
    while (*prev) {
        if ((*prev)->page_pfn == page_pfn) {
            auto node = *prev;
            *prev = node->next;
            return node;
        }
        prev = &(*prev)->next;
    }
    return nullptr;
}

auto ept::configure_mmio_page(u64 gpa) -> bool {
    auto pte = get_pte_for_gpa(gpa, true);
    if (!pte) return false;

    *pte = (gpa & ~0xfffULL) | (ept_mt_uncacheable << 3);
    return true;
}

auto ept::is_hidden_physical_range(u64 gpa, u64 size) -> bool {
    if (!state_ || !size) return false;

    auto first_pfn = gpa >> 12;
    auto last_byte = gpa + size - 1;
    auto last_pfn = last_byte >> 12;
    if (last_byte < gpa) {
        first_pfn = 0;
        last_pfn = maxu64;
    }

    KIRQL old_irql = {};
    KeAcquireSpinLock(&hook_lock_, &old_irql);

    for (auto cur = state_->hidden_active; cur; cur = cur->next) {
        if (cur->page_pfn >= first_pfn && cur->page_pfn <= last_pfn) {
            KeReleaseSpinLock(&hook_lock_, old_irql);
            return true;
        }
    }

    KeReleaseSpinLock(&hook_lock_, old_irql);
    return false;
}

auto ept::find_hook_by_gpa(u64 gpa) -> ept_hook_node* {
    if (!state_) return nullptr;
    u64 pfn = gpa >> 12;
    for (auto cur = state_->hooks_active; cur; cur = cur->next) {
        if (cur->orig_pfn == pfn) return cur;
    }
    return nullptr;
}

auto ept::handle_hook_violation(u64 gpa, u64 qualification) -> bool {
    if (!state_) return false;

    KIRQL old_irql = {};
    KeAcquireSpinLock(&hook_lock_, &old_irql);

    auto node = find_hook_by_gpa(gpa);
    if (!node || !node->pte_addr) {
        KeReleaseSpinLock(&hook_lock_, old_irql);
        return false;
    }

    *node->pte_addr = (qualification & ept_qual_instr_fetch)
        ? node->exec_entry
        : node->data_entry;
    KeMemoryBarrier();

    KeReleaseSpinLock(&hook_lock_, old_irql);
    vtx_invept_all(ept_pointer_);
    return true;
}

auto ept::get() -> ept* {
    static ept instance;
    return &instance;
}

}
