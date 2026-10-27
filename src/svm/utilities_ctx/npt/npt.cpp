#include "npt.hpp"

namespace svm {

auto npt::prepare_npt(npt_data_t& npt, nested_page_table npt_type) -> svm::svmroot_error_t {
    memset(&npt, 0, sizeof(npt));
    npt.dummy_page_pfn = MmGetPhysicalAddress(npt.dummy_page).QuadPart >> 12;
    npt.num_used_free_pages = 0;

    for (size_t i = 0; i < npt_free_page_count; ++i) {
        npt.free_page_pfns[i] = MmGetPhysicalAddress(&npt.free_pages[i]).QuadPart >> 12;
    }

    npt.hooks.active_list_head = nullptr;
    npt.hooks.free_list_head = &npt.hooks.buffer[0];

    for (size_t i = 0; i < npt.hooks.capacity - 1; ++i) {
        npt.hooks.buffer[i].next = &npt.hooks.buffer[i + 1];
        npt.hooks.buffer[i].orig_pfn = 0;
        npt.hooks.buffer[i].exec_pfn = 0;
        npt.hooks.buffer[i].patch_offset = 0;
        npt.hooks.buffer[i].patch_size = 0;
    }

    npt.hooks.buffer[npt.hooks.capacity - 1].next = nullptr;
    auto& pml4e = npt.pml4[0];
    pml4e.flags = 0;
    pml4e.present = 1;
    pml4e.write = 1;
    pml4e.supervisor = 1;
    pml4e.page_level_write_through = 0;
    pml4e.page_level_cache_disable = 0;
    pml4e.accessed = 0;
    pml4e.reserved_1 = 0;
    pml4e.must_be_zero = 0;
    pml4e.ignored_1 = 0;
    pml4e.execute_disable = 0;
    pml4e.page_frame_number = MmGetPhysicalAddress(&npt.pdpt).QuadPart >> 12;

    for (size_t i = 0; i < npt_pd_count; ++i) {
        auto& pdpte = npt.pdpt[i];
        pdpte.flags = 0;
        pdpte.present = 1;
        pdpte.write = 1;
        pdpte.supervisor = 1;
        pdpte.page_level_write_through = 0;
        pdpte.page_level_cache_disable = 0;
        pdpte.accessed = 0;
        pdpte.reserved_1 = 0;
        pdpte.large_page = 0;
        pdpte.ignored_1 = 0;
        pdpte.execute_disable = 0;
        pdpte.page_frame_number = MmGetPhysicalAddress(&npt.pds[i]).QuadPart >> 12;

        for (size_t j = 0; j < 512; ++j) {
            auto& pde = npt.pds_2mb[i][j];
            pde.flags = 0;
            pde.present = 1;
            pde.write = 1;
            pde.supervisor = 1;
            pde.page_level_write_through = 0;
            pde.page_level_cache_disable = 0;
            pde.accessed = 0;
            pde.dirty = 0;
            pde.large_page = 1;
            pde.global = 0;
            pde.ignored_1 = 0;
            pde.execute_disable = (npt_type == nested_page_table::shadow) ? 1 : 0;
            pde.pat = 0;
            pde.reserved_1 = 0;
            pde.page_frame_number = (i << 9) + j;
        }
    }

    return svm::svmroot_error_t::error_success;
}

auto npt::split_npt_pde(npt_data_t& npt, pde_2mb_64* const pde_2mb) -> void {
    if (!pde_2mb->large_page) {
        return;
    }

    if (npt.num_used_free_pages >= npt_free_page_count) {
        return;
    }

    auto const pt_pfn = npt.free_page_pfns[npt.num_used_free_pages];
    auto const pt = reinterpret_cast<pte_64*>(&npt.free_pages[npt.num_used_free_pages]);
    ++npt.num_used_free_pages;

    for (size_t i = 0; i < 512; ++i) {
        auto& pte = pt[i];
        pte.flags = 0;
        pte.present = pde_2mb->present;
        pte.write = pde_2mb->write;
        pte.supervisor = pde_2mb->supervisor;
        pte.page_level_write_through = pde_2mb->page_level_write_through;
        pte.page_level_cache_disable = pde_2mb->page_level_cache_disable;
        pte.accessed = pde_2mb->accessed;
        pte.dirty = pde_2mb->dirty;
        pte.pat = pde_2mb->pat;
        pte.global = pde_2mb->global;
        pte.execute_disable = pde_2mb->execute_disable;
        pte.page_frame_number = (pde_2mb->page_frame_number << 9) + i;
    }

    auto const pde = reinterpret_cast<pde_64*>(pde_2mb);
    pde->flags = 0;
    pde->present = 1;
    pde->write = 1;
    pde->supervisor = 1;
    pde->execute_disable = 0;
    pde->large_page = 0;
    pde->page_frame_number = pt_pfn;
}

auto npt::get_npt_pte(npt_data_t& npt, u64 const physical_address, bool const force_split) -> pte_64* {
    virt_addr_t const addr = {physical_address};

    if (addr.pml4_index != 0) {
        return nullptr;
    }

    if (addr.pdpt_index >= npt_pd_count) {
        return nullptr;
    }

    auto& pde_2mb = npt.pds_2mb[addr.pdpt_index][addr.pd_index];

    if (pde_2mb.large_page) {
        if (!force_split) {
            return nullptr;
        }

        split_npt_pde(npt, &pde_2mb);

        if (pde_2mb.large_page) {
            return nullptr;
        }
    }

    auto& pde = npt.pds[addr.pdpt_index][addr.pd_index];
    if (auto split_pt = find_split_pt(npt, pde.page_frame_number)) {
        return &split_pt[addr.pt_index];
    }

    auto const pt = reinterpret_cast<pte_64*>(host_physical_memory_base + (pde.page_frame_number << 12));
    return &pt[addr.pt_index];
}

auto npt::find_split_pt(npt_data_t& npt, u64 pt_pfn) -> pte_64* {
    for (size_t i = 0; i < npt.num_used_free_pages; ++i) {
        if (npt.free_page_pfns[i] == pt_pfn) {
            return reinterpret_cast<pte_64*>(&npt.free_pages[i]);
        }
    }

    return nullptr;
}

bool npt::update_hook_list(npt_data_t& npt, u64 orig_pfn, u64 exec_pfn, u16 patch_offset, u16 patch_size) {
    for (auto curr = npt.hooks.active_list_head; curr; curr = curr->next) {
        if (curr->orig_pfn == orig_pfn) {
            curr->exec_pfn = exec_pfn;
            auto begin = curr->patch_offset < patch_offset ? curr->patch_offset : patch_offset;
            auto current_end = static_cast<u32>(curr->patch_offset) + curr->patch_size;
            auto new_end = static_cast<u32>(patch_offset) + patch_size;
            auto end = current_end > new_end ? current_end : new_end;
            curr->patch_offset = static_cast<u16>(begin);
            curr->patch_size = static_cast<u16>(end - begin);
            return true;
        }
    }

    if (!npt.hooks.free_list_head) {
        return false;
    }

    auto hook_node = npt.hooks.free_list_head;
    npt.hooks.free_list_head = hook_node->next;
    hook_node->next = npt.hooks.active_list_head;
    npt.hooks.active_list_head = hook_node;
    hook_node->orig_pfn = orig_pfn;
    hook_node->exec_pfn = exec_pfn;
    hook_node->patch_offset = patch_offset;
    hook_node->patch_size = patch_size;
    return true;
}

void npt::sync_hook_page(npt_hook_node_t* hook_node) {
    if (!hook_node) {
        return;
    }

    u8* original = host_physical_memory_base + (static_cast<u64>(hook_node->orig_pfn) << 12);
    u8* hook = host_physical_memory_base + (static_cast<u64>(hook_node->exec_pfn) << 12);

    if (hook_node->patch_offset > 0) {
        memcpy(hook, original, hook_node->patch_offset);
    }

    u32 after = static_cast<u32>(hook_node->patch_offset) + hook_node->patch_size;

    if (after < PAGE_SIZE) {
        memcpy(hook + after, original + after, PAGE_SIZE - after);
    }
}

auto npt::find_npt_hook(npt_data_t& npt_data, u64 page_pfn) -> npt_hook_node_t* {
    for (auto curr = npt_data.hooks.active_list_head; curr; curr = curr->next) {
        if (curr->orig_pfn == page_pfn) {
            return curr;
        }
    }

    return nullptr;
}

auto npt::install_npt_hook(u64 original_page_pfn, u64 executable_page_pfn, u16 patch_offset, u16 patch_size)
    -> svm::svmroot_error_t {
    u32 processor_count = virtualization::get()->get_processor_count();

    for (u32 cpu = 0; cpu < processor_count; cpu++) {
        auto target_vcpu = virtualization::get()->vcpus[cpu];

        if (!target_vcpu) {
            continue;
        }

        auto result = install_npt_hook(target_vcpu, target_vcpu->npt[nested_page_table::primary],
                                       target_vcpu->npt[nested_page_table::shadow], original_page_pfn,
                                       executable_page_pfn, patch_offset, patch_size);

        if (result != svm::svmroot_error_t::error_success) {
            for (u32 rollback_cpu = 0; rollback_cpu < cpu; rollback_cpu++) {
                auto rollback_vcpu = virtualization::get()->vcpus[rollback_cpu];

                if (!rollback_vcpu) {
                    continue;
                }

                remove_npt_hook(rollback_vcpu, rollback_vcpu->npt[nested_page_table::primary],
                                rollback_vcpu->npt[nested_page_table::shadow], original_page_pfn);
            }

            return result;
        }
    }

    return svm::svmroot_error_t::error_success;
}

auto npt::remove_npt_hook(u64 original_page_pfn) -> svm::svmroot_error_t {
    u32 processor_count = virtualization::get()->get_processor_count();
    auto first_error = svm::svmroot_error_t::error_success;

    for (u32 cpu = 0; cpu < processor_count; cpu++) {
        auto target_vcpu = virtualization::get()->vcpus[cpu];

        if (!target_vcpu) {
            continue;
        }

        auto result = remove_npt_hook(target_vcpu, target_vcpu->npt[nested_page_table::primary],
                                      target_vcpu->npt[nested_page_table::shadow], original_page_pfn);

        if (result != svm::svmroot_error_t::error_success &&
            first_error == svm::svmroot_error_t::error_success) {
            first_error = result;
        }
    }

    return first_error;
}

auto npt::install_npt_hook(svm::pvcpu_t vcpu, npt_data_t& primary_npt, npt_data_t& shadow_npt, u64 original_page_pfn,
                           u64 executable_page_pfn, u16 patch_offset, u16 patch_size) -> svm::svmroot_error_t {
    if (!vcpu) {
        return svm::svmroot_error_t::error_failed;
    }

    bool success = false;
    auto primary_pte = static_cast<pte_64*>(nullptr);
    auto shadow_pte = static_cast<pte_64*>(nullptr);
    u64 original_primary_flags = 0;
    u64 original_shadow_flags = 0;
    bool primary_modified = false;
    bool shadow_modified = false;
    do {
        primary_pte = get_npt_pte(primary_npt, original_page_pfn << 12, true);

        if (!primary_pte) {
            break;
        }

        original_primary_flags = primary_pte->flags;
        primary_pte->flags = 0;
        primary_pte->present = 1;
        primary_pte->write = 1;
        primary_pte->supervisor = 1;
        primary_pte->execute_disable = 1;
        primary_pte->page_frame_number = original_page_pfn;
        primary_pte->accessed = 1;
        primary_pte->dirty = 1;
        primary_modified = true;
        shadow_pte = get_npt_pte(shadow_npt, original_page_pfn << 12, true);

        if (!shadow_pte) {
            break;
        }

        original_shadow_flags = shadow_pte->flags;
        shadow_pte->flags = 0;
        shadow_pte->present = 1;
        shadow_pte->write = 1;
        shadow_pte->supervisor = 1;
        shadow_pte->execute_disable = 0;
        shadow_pte->page_frame_number = executable_page_pfn;
        shadow_pte->accessed = 1;
        shadow_pte->dirty = 1;
        shadow_modified = true;

        if (!update_hook_list(primary_npt, original_page_pfn, executable_page_pfn, patch_offset, patch_size))
            break;
        vcpu->guest_vmcb.control_area.ncr3 = MmGetPhysicalAddress(&primary_npt.pml4).QuadPart;
        vcpu->guest_vmcb.control_area.vmcb_clean &= ~static_cast<u64>(svm::vmcb_clean_bits::np_enable);
        flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
        success = true;
    } while (false);

    if (!success) {
        if (shadow_modified && shadow_pte) {
            shadow_pte->flags = original_shadow_flags;
        }

        if (primary_modified && primary_pte) {
            primary_pte->flags = original_primary_flags;
        }
    }

    return success ? svm::svmroot_error_t::error_success : svm::svmroot_error_t::error_failed;
}

void npt::remove_hook_from_list(npt_data_t& npt, u64 original_page_pfn) {
    if (!npt.hooks.active_list_head) {
        return;
    }

    if (npt.hooks.active_list_head->orig_pfn == original_page_pfn) {
        auto node = npt.hooks.active_list_head;
        npt.hooks.active_list_head = node->next;
        node->next = npt.hooks.free_list_head;
        npt.hooks.free_list_head = node;
        node->orig_pfn = 0;
        node->exec_pfn = 0;
        node->patch_offset = 0;
        node->patch_size = 0;
    } else {
        auto prev = npt.hooks.active_list_head;

        while (prev->next && prev->next->orig_pfn != original_page_pfn) {
            prev = prev->next;
        }

        if (prev->next) {
            auto node = prev->next;
            prev->next = node->next;
            node->next = npt.hooks.free_list_head;
            npt.hooks.free_list_head = node;
            node->orig_pfn = 0;
            node->exec_pfn = 0;
            node->patch_offset = 0;
            node->patch_size = 0;
        }
    }
}

auto npt::remove_npt_hook(svm::pvcpu_t vcpu, npt_data_t& primary_npt, npt_data_t& shadow_npt, u64 original_page_pfn)
    -> svm::svmroot_error_t {
    if (!vcpu) {
        return svm::svmroot_error_t::error_failed;
    }

    auto primary_pte = get_npt_pte(primary_npt, original_page_pfn << 12, true);

    if (!primary_pte) {
        return svm::svmroot_error_t::error_failed;
    }

    primary_pte->flags = 0;
    primary_pte->present = 1;
    primary_pte->write = 1;
    primary_pte->supervisor = 1;
    primary_pte->execute_disable = 0;
    primary_pte->page_frame_number = original_page_pfn;
    primary_pte->accessed = 1;
    primary_pte->dirty = 1;
    auto shadow_pte = get_npt_pte(shadow_npt, original_page_pfn << 12, true);

    if (!shadow_pte) {
        remove_hook_from_list(primary_npt, original_page_pfn);
        vcpu->guest_vmcb.control_area.ncr3 = MmGetPhysicalAddress(&primary_npt.pml4).QuadPart;
        vcpu->guest_vmcb.control_area.vmcb_clean &= ~static_cast<u64>(svm::vmcb_clean_bits::np_enable);
        flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
        return svm::svmroot_error_t::error_failed;
    }

    shadow_pte->flags = 0;
    shadow_pte->present = 1;
    shadow_pte->write = 1;
    shadow_pte->supervisor = 1;
    shadow_pte->execute_disable = 1;
    shadow_pte->page_frame_number = original_page_pfn;
    shadow_pte->accessed = 1;
    shadow_pte->dirty = 1;
    remove_hook_from_list(primary_npt, original_page_pfn);
    vcpu->guest_vmcb.control_area.ncr3 = MmGetPhysicalAddress(&primary_npt.pml4).QuadPart;
    vcpu->guest_vmcb.control_area.vmcb_clean &= ~static_cast<u64>(svm::vmcb_clean_bits::np_enable);
    flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
    return svm::svmroot_error_t::error_success;
}

auto npt::cleanup() -> void {
    u32 processor_count = virtualization::get()->get_processor_count();

    for (ULONG i = 0; i < processor_count; i++) {
        auto vcpu = virtualization::get()->vcpus[i];

        if (!vcpu) {
            continue;
        }

        auto hook_head = vcpu->npt[nested_page_table::primary].hooks.active_list_head;

        while (hook_head) {
            auto current = hook_head;
            hook_head = hook_head->next;
            remove_npt_hook(vcpu, vcpu->npt[nested_page_table::primary], vcpu->npt[nested_page_table::shadow],
                            current->orig_pfn);
        }

        vcpu->guest_vmcb.control_area.ncr3 = MmGetPhysicalAddress(&vcpu->npt[nested_page_table::primary].pml4).QuadPart;
        vcpu->guest_vmcb.control_area.vmcb_clean &= ~static_cast<u64>(svm::vmcb_clean_bits::np_enable);
        flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
    }
}

auto npt::get() -> npt* {
    static npt instance;
    return &instance;
}
}
