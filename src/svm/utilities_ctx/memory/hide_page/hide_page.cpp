#include "hide_page.hpp"

namespace svm {

hide_page::hide_page() {
    KeInitializeSpinLock(&hide_lock);
}

auto hide_page::hide_physical_page(svm::pvcpu_t vcpu, u64 page_pfn) -> svm::svmroot_error_t {
    if (!vcpu) {
        return svm::svmroot_error_t::error_failed;
    }

    KIRQL old_irql;
    KeAcquireSpinLock(&hide_lock, &old_irql);
    auto primary_pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::primary], page_pfn << 12, true);
    auto shadow_pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::shadow], page_pfn << 12, true);

    if (!primary_pte || !shadow_pte) {
        KeReleaseSpinLock(&hide_lock, old_irql);
        return svm::svmroot_error_t::error_failed;
    }

    primary_pte->page_frame_number = vcpu->npt[npt::nested_page_table::primary].dummy_page_pfn;
    shadow_pte->page_frame_number = vcpu->npt[npt::nested_page_table::shadow].dummy_page_pfn;
    vcpu->guest_vmcb.control_area.vmcb_clean &= ~(1ULL << 4);
    flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
    KeReleaseSpinLock(&hide_lock, old_irql);
    return svm::svmroot_error_t::error_success;
}

auto hide_page::unhide_physical_page(svm::pvcpu_t vcpu, u64 page_pfn) -> svm::svmroot_error_t {
    if (!vcpu) {
        return svm::svmroot_error_t::error_failed;
    }

    KIRQL old_irql;
    KeAcquireSpinLock(&hide_lock, &old_irql);
    bool success = false;
    do {
        auto primary_pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::primary], page_pfn << 12, false);
        auto shadow_pte = npt::get()->get_npt_pte(vcpu->npt[npt::nested_page_table::shadow], page_pfn << 12, false);

        if (!primary_pte || !shadow_pte) {
            break;
        }

        primary_pte->page_frame_number = page_pfn;
        shadow_pte->page_frame_number = page_pfn;
        vcpu->guest_vmcb.control_area.vmcb_clean &= ~(1ULL << 4);
        flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
        success = true;
    } while (false);
    KeReleaseSpinLock(&hide_lock, old_irql);
    return success ? svm::svmroot_error_t::error_success : svm::svmroot_error_t::error_failed;
}

hide_page* hide_page::get() {
    static hide_page instance;
    return &instance;
}
}
