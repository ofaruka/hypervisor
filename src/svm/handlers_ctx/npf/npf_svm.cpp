#include "npf_svm.hpp"
#include "../../../hv_spinlock.hpp"

namespace svm {

void npf_handler::setup_pte(pte_64* pte, u64 pfn, bool allow_exec, bool allow_write) {
    if (!pte) {
        return;
    }

    pte->flags = 0;
    pte->present = 1;
    pte->write = allow_write ? 1 : 0;
    pte->supervisor = 1;
    pte->execute_disable = allow_exec ? 0 : 1;
    pte->page_frame_number = pfn;
    pte->accessed = 1;
    pte->dirty = allow_write ? 1 : 0;
}

bool npf_handler::is_shadow_npt_active(svm::pvcpu_t vcpu) {
    if (!vcpu) {
        return false;
    }

    return vcpu->guest_vmcb.control_area.ncr3 ==
           static_cast<u64>(MmGetPhysicalAddress(&vcpu->npt[npt::nested_page_table::shadow].pml4).QuadPart);
}

bool npf_handler::setup_new_page_in_primary(svm::pvcpu_t vcpu, u64 page_pfn) {
    auto primary_pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::primary], page_pfn << 12, true);

    if (!primary_pte) {
        return false;
    }

    setup_pte(primary_pte, page_pfn, true, true);
    return true;
}

bool npf_handler::setup_new_page_in_shadow(svm::pvcpu_t vcpu, u64 page_pfn) {
    auto shadow_pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::shadow], page_pfn << 12, true);

    if (!shadow_pte) {
        return false;
    }

    setup_pte(shadow_pte, page_pfn, false, true);
    return true;
}

bool npf_handler::handle_not_present_fault(svm::pvcpu_t vcpu, const page_context& ctx) {
    if (!vcpu) {
        return false;
    }

    u64 page_pfn = ctx.guest_pa >> 12;

    if (!setup_new_page_in_primary(vcpu, page_pfn) || !setup_new_page_in_shadow(vcpu, page_pfn)) {
        return false;
    }

    vcpu->guest_vmcb.control_area.vmcb_clean &= ~(1ULL << 4);
    flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
    return true;
}

bool npf_handler::is_crossing_boundary_instruction(svm::pvcpu_t vcpu) {
    if (!vcpu) {
        return false;
    }

    u64 current_rip = vcpu->guest_vmcb.state_save_area.rip;
    bool cross_boundary = ((current_rip / 0x1000) != ((current_rip + ZYDIS_MAX_INSTRUCTION_LENGTH) / 0x1000));
    return cross_boundary;
}

bool npf_handler::is_page_active_in_shadow(svm::pvcpu_t vcpu, u64 virtual_address) {
    if (!vcpu) {
        return false;
    }

    svm::cr3_t guest_cr3 = vcpu->guest_vmcb.state_save_area.cr3;
    u64 offset_to_next_page = 0;
    u64 physical_address = page_table::get()->gva_to_gpa(guest_cr3, virtual_address, offset_to_next_page);

    if (!physical_address) {
        return false;
    }

    auto shadow_pte =
        npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::shadow], physical_address & ~0xFFFull, false);
    return (shadow_pte && !shadow_pte->execute_disable);
}

bool npf_handler::enable_shadow_execute(svm::pvcpu_t vcpu, u64 virtual_address) {
    if (!vcpu) {
        return false;
    }

    svm::cr3_t guest_cr3 = vcpu->guest_vmcb.state_save_area.cr3;
    u64 offset_to_next_page = 0;
    u64 physical_address = page_table::get()->gva_to_gpa(guest_cr3, virtual_address, offset_to_next_page);

    if (!physical_address) {
        return false;
    }

    u64 aligned_pa = physical_address & ~0xFFFull;
    u64 original_pfn = aligned_pa >> 12;
    auto shadow_pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::shadow], aligned_pa, true);

    if (!shadow_pte) {
        return false;
    }

    auto hook_node = npt::get()->find_npt_hook(vcpu->npt[npt::nested_page_table::primary], original_pfn);

    if (hook_node) {
        setup_pte(shadow_pte, hook_node->exec_pfn, true, true);
    } else {
        setup_pte(shadow_pte, original_pfn, true, true);
    }

    return true;
}

bool npf_handler::handle_instruction_splitting(svm::pvcpu_t vcpu) {
    if (!vcpu) {
        return false;
    }

    u64 current_rip = vcpu->guest_vmcb.state_save_area.rip;
    u64 next_page_va = current_rip + ZYDIS_MAX_INSTRUCTION_LENGTH;

    if (is_page_active_in_shadow(vcpu, next_page_va)) {
        enable_shadow_execute(vcpu, current_rip);
    }

    if (is_page_active_in_shadow(vcpu, current_rip)) {
        enable_shadow_execute(vcpu, next_page_va);
    }

    return true;
}

bool npf_handler::handle_execute_fault(svm::pvcpu_t vcpu, const page_context& ctx) {
    if (!vcpu) {
        return false;
    }

    u64 page_pfn = ctx.guest_pa >> 12;
    bool in_shadow = is_shadow_npt_active(vcpu);
    auto hook_node = npt::get()->find_npt_hook(vcpu->npt[npt::nested_page_table::primary], page_pfn);

    if (in_shadow) {
        if (is_crossing_boundary_instruction(vcpu)) {
            handle_instruction_splitting(vcpu);
        }

        vcpu->guest_vmcb.control_area.ncr3 =
            MmGetPhysicalAddress(&vcpu->npt[npt::nested_page_table::primary].pml4).QuadPart;
    } else {
        if (hook_node) {
            npt::get()->sync_hook_page(hook_node);
        }

        vcpu->guest_vmcb.control_area.ncr3 =
            MmGetPhysicalAddress(&vcpu->npt[npt::nested_page_table::shadow].pml4).QuadPart;
    }

    vcpu->guest_vmcb.control_area.vmcb_clean &= ~(1ULL << 4);
    flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
    return true;
}

bool npf_handler::handle_write_fault(svm::pvcpu_t vcpu, const page_context& ctx) {
    if (!vcpu) {
        return false;
    }

    u64 page_pfn = ctx.guest_pa >> 12;
    u64 aligned_pa = ctx.guest_pa & ~0xFFFull;

    auto primary_pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::primary], aligned_pa, true);

    if (primary_pte) {
        bool allow_exec = !primary_pte->execute_disable;
        setup_pte(primary_pte, page_pfn, allow_exec, true);
    }

    auto shadow_pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::shadow], aligned_pa, false);

    if (shadow_pte) {
        bool shadow_allow_exec = !shadow_pte->execute_disable;
        u64 shadow_pfn = shadow_pte->page_frame_number;
        setup_pte(shadow_pte, shadow_pfn, shadow_allow_exec, true);
    }

    vcpu->guest_vmcb.control_area.vmcb_clean &= ~(1ULL << 4);
    flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
    return true;
}

void npf_handler::npf_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    hv_shared_lock_guard lock;
    if (!vcpu) {
        return;
    }

    svm::npf_exit_info npt_fault_code{vcpu->guest_vmcb.control_area.exit_info1};
    u64 guest_physical_address = vcpu->guest_vmcb.control_area.exit_info2;
    page_context ctx{.is_execution = npt_fault_code.fields.execute != 0,
                     .is_write = npt_fault_code.fields.write != 0,
                     .is_present = npt_fault_code.fields.valid != 0,
                     .guest_pa = guest_physical_address,
                     .host_pa = guest_physical_address};
    bool handled = false;

    if (!ctx.is_execution && mmio::get()->is_mmio_address(guest_physical_address)) {
        handled = mmio::get()->handle_mmio_fault(vcpu, guest_ctx, ctx);
    } else {
        if (!ctx.is_present) {
            handled = handle_not_present_fault(vcpu, ctx);
        } else if (ctx.is_execution) {
            handled = handle_execute_fault(vcpu, ctx);
        } else if (ctx.is_write) {
            handled = handle_write_fault(vcpu, ctx);
        }
    }

    if (!handled) {
        debug::log_info("Failed to handle NPF at PA: 0x%llx, Type: %s%s%s\n", guest_physical_address,
                        ctx.is_execution ? "EXEC " : "", ctx.is_write ? "WRITE " : "",
                        ctx.is_present ? "PRESENT" : "NOT_PRESENT");
        event_inj_t{}.general_protection_exception(vcpu);
    }
}

npf_handler* npf_handler::get() {
    static npf_handler instance;
    return &instance;
}
}
