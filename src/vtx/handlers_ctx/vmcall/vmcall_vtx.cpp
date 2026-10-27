#include "vmcall_vtx.hpp"
#include "../../../hv_spinlock.hpp"

namespace vtx {

auto vmcall_handler::get() -> vmcall_handler* {
    static vmcall_handler instance;
    return &instance;
}

template<typename T>
auto vmcall_handler::get_params(guest_gprs* gprs) -> T {
    T params{};
    if (!gprs || !gprs->rdx) return params;

    memory_access::get()->read_virtual(0, gprs->rdx, &params, sizeof(T));
    return params;
}

template<typename T>
auto vmcall_handler::set_params(guest_gprs* gprs, const T& params) -> void {
    if (!gprs || !gprs->rdx) return;

    memory_access::get()->write_virtual(0, gprs->rdx, &params, sizeof(T));
}

auto vmcall_handler::vmcall_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> result {
    // Locking is scoped to the non-blocking EPT/hook/hide sections, not the whole handler.

    if (!gprs) {
        event_handler::get()->inject_ud();
        return result::no_advance;
    }

    auto magic = gprs->rcx;

    switch (magic) {
    case vmcall_magic_invept: {
        vtx_invept_all(ept::get()->ept_pointer());
        return result::advance_rip;
    }
    case vmcall_ping_hv: {
        auto p = get_params<ping_hv_params>(gprs);
        p.result = (p.magic == 0xDEADBEEFCAFEBABE)
            ? 0xBAADF00DDEADBEEF
            : 0;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_get_hv_base: {
        auto p = get_params<get_hv_base_params>(gprs);
        p.hv_base = reinterpret_cast<u64>(&__ImageBase);
        p.hv_size = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<u64>(&__ImageBase) +
            reinterpret_cast<PIMAGE_DOS_HEADER>(&__ImageBase)->e_lfanew
        )->OptionalHeader.SizeOfImage;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_get_physical_address: {
        auto p = get_params<get_physical_address_params>(gprs);
        p.physical_address = memory_access::get()->get_physical_address(
            p.process_cr3.value,
            p.virtual_address
        );
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_get_virtual_address: {
        auto p = get_params<get_virtual_address_params>(gprs);
        p.virtual_address = memory_access::get()->get_virtual_address(
            p.process_cr3.value,
            p.physical_address
        );
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_get_process_cr3: {
        auto p = get_params<get_process_cr3_params>(gprs);
        p.process_cr3 = memory_access::get()->get_process_cr3(p.target_pid);
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_get_process_base: {
        auto p = get_params<get_process_base_params>(gprs);
        p.process_base = memory_access::get()->get_process_base(p.target_pid);
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_get_process_module: {
        auto p = get_params<get_process_module_params>(gprs);
        p.process_module = memory_access::get()->get_process_module(
            p.target_pid,
            p.module_name
        );
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_ensure_page_present: {
        auto p = get_params<ensure_page_present_params>(gprs);
        if (memory_access::get()->is_page_present(p.process_cr3, p.gva)) {
            p.status = page_present;
            p.result = 0;
        }
        else if (memory_access::get()->request_page_in(p.process_cr3, p.gva)) {
            p.status = page_pending;
            p.result = 0;
        }
        else {
            p.status = page_error;
            p.result = 1;
        }
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_is_page_present: {
        auto p = get_params<is_page_present_params>(gprs);
        p.result = memory_access::get()->is_page_present(p.process_cr3, p.gva) ? 0 : 1;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_clear_guest_pte_nx: {
        auto p = get_params<clear_guest_pte_nx_params>(gprs);
        p.result = memory_access::get()->clear_guest_pte_nx(
            p.process_cr3,
            p.gva,
            p.make_writable != 0
        );
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_read_physical_memory: {
        auto p = get_params<read_physical_memory_params>(gprs);
        p.result = memory_access::get()->read_physical_memory(
            vcpu,
            p.destination_gva,
            p.source_gva,
            p.size
        );
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_write_physical_memory: {
        auto p = get_params<write_physical_memory_params>(gprs);
        p.result = memory_access::get()->write_physical_memory(
            vcpu,
            p.destination_gva,
            p.source_gva,
            p.size
        );
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_read_virtual_memory: {
        auto p = get_params<read_virtual_memory_params>(gprs);
        p.result = memory_access::get()->read_virtual_memory(
            vcpu,
            p.process_cr3.value,
            p.destination_gva,
            p.source_gva,
            p.size
        );
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_write_virtual_memory: {
        auto p = get_params<write_virtual_memory_params>(gprs);
        p.result = memory_access::get()->write_virtual_memory(
            vcpu,
            p.process_cr3.value,
            p.destination_gva,
            p.source_gva,
            p.size
        );
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_install_function_hook: {
        auto p = get_params<install_function_hook_params>(gprs);
        if (!p.address || !p.proxy || !p.detour) return result::advance_rip;

        bool ok = hook::get()->install_function_hook(
            p.address, p.proxy, p.detour, p.target_cr3, false);
        if (ok) vtx_invept_all(ept::get()->ept_pointer());
        p.result = ok ? svm::svmroot_error_t::error_success : svm::svmroot_error_t::error_failed;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_install_driver_hooks: {
        auto p = get_params<install_driver_hooks_params>(gprs);
        if (!p.driver_name[0] || !p.proxy || !p.detour ||
            p.major_function > IRP_MJ_MAXIMUM_FUNCTION) {
            p.result = svm::svmroot_error_t::error_failed;
            set_params(gprs, p);
            return result::advance_rip;
        }

        bool ok = hook::get()->install_driver_hooks(
            p.driver_name, p.major_function, p.proxy, p.detour, &p.target, false);
        if (ok) vtx_invept_all(ept::get()->ept_pointer());
        p.result = ok ? svm::svmroot_error_t::error_success : svm::svmroot_error_t::error_failed;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_remove_function_hook: {
        auto p = get_params<remove_function_hook_params>(gprs);
        if (!p.address) return result::advance_rip;

        bool ok = hook::get()->remove_function_hook(p.address, false);
        if (ok) vtx_invept_all(ept::get()->ept_pointer());
        p.result = ok ? svm::svmroot_error_t::error_success : svm::svmroot_error_t::error_failed;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_install_ept_hook: {
        hv_exclusive_lock_guard lock;
        auto p = get_params<install_ept_hook_params>(gprs);
        if (p.patch_size == 0) p.patch_size = PAGE_SIZE;

        bool ok = ept::get()->install_ept_hook(
            p.original_page_pfn,
            p.executable_page_pfn,
            p.patch_offset,
            p.patch_size
        );
        if (ok) vtx_invept_all(ept::get()->ept_pointer());
        p.result = ok ? svm::svmroot_error_t::error_success : svm::svmroot_error_t::error_failed;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_remove_ept_hook: {
        hv_exclusive_lock_guard lock;
        auto p = get_params<remove_ept_hook_params>(gprs);
        bool ok = ept::get()->remove_ept_hook(p.original_page_pfn);
        if (ok) vtx_invept_all(ept::get()->ept_pointer());
        p.result = ok ? svm::svmroot_error_t::error_success : svm::svmroot_error_t::error_failed;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_get_tpm_key: {
        auto p = get_params<get_tpm_key_params>(gprs);
        p.result = svm::svmroot_error_t::error_failed;

        auto key_size = svm::tpm::get()->get_ek_public_size();
        if (p.buffer_gva &&
            key_size > 0 &&
            key_size <= sizeof(TPM2B_PUBLIC_KEY_RSA_TRANSFER::buffer)) {
            TPM2B_PUBLIC_KEY_RSA_TRANSFER transfer = {};
            transfer.size = static_cast<u16>(key_size);
            RtlCopyMemory(transfer.buffer, svm::tpm::get()->get_ek_public(), key_size);

            p.result = memory_access::get()->write_virtual(
                0,
                p.buffer_gva,
                &transfer,
                sizeof(transfer)
            ) ? svm::svmroot_error_t::error_success : svm::svmroot_error_t::error_failed;
        }

        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_set_tpm_pcrs: {
        auto p = get_params<set_tpm_pcrs_params>(gprs);
        p.result = svm::svmroot_error_t::error_failed;

        if (p.buffer_gva) {
            svm::tpm::pcr_all_banks banks = {};
            if (memory_access::get()->read_virtual(
                0,
                p.buffer_gva,
                &banks,
                sizeof(banks))) {
                svm::tpm::get()->set_pcr_values(banks);
                p.result = svm::svmroot_error_t::error_success;
            }
        }

        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_set_tpm_seed: {
        auto p = get_params<set_tpm_seed_params>(gprs);
        svm::tpm::get()->set_identity_seed(p.seed);
        p.result = svm::svmroot_error_t::error_success;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_hide_physical_page: {
        hv_exclusive_lock_guard lock;
        auto p = get_params<hide_physical_page_params>(gprs);
        auto ok = ept::get()->hide_physical_page(p.page_pfn);
        if (ok) vtx_invept_all(ept::get()->ept_pointer());
        p.result = ok ? svm::svmroot_error_t::error_success : svm::svmroot_error_t::error_failed;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_unhide_physical_page: {
        hv_exclusive_lock_guard lock;
        auto p = get_params<unhide_physical_page_params>(gprs);
        auto ok = ept::get()->unhide_physical_page(p.page_pfn);
        if (ok) vtx_invept_all(ept::get()->ept_pointer());
        p.result = ok ? svm::svmroot_error_t::error_success : svm::svmroot_error_t::error_failed;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_flush_logs: {
        auto p = get_params<flush_logs_params>(gprs);
        auto count = p.count;
        if (count > max_log_flush_batch) count = max_log_flush_batch;

        if (!p.buffer_gva || count == 0 ||
            !memory_access::get()->guest_range_mapped(p.buffer_gva, sizeof(svm::logs::message_t) * count)) {
            p.count = 0;
            p.result = svm::svmroot_error_t::svmroot_translate_failure;
            set_params(gprs, p);
            return result::advance_rip;
        }

        svm::logs::message_t messages[max_log_flush_batch];
        RtlZeroMemory(messages, sizeof(messages));

        auto flush_count = count;
        auto status = svm::logs::get()->flush_logs(messages, flush_count);
        if (status == svm::svmroot_error_t::error_success && flush_count != 0) {
            if (!memory_access::get()->write_virtual(
                    0,
                    p.buffer_gva,
                    messages,
                    sizeof(svm::logs::message_t) * flush_count)) {
                status = svm::svmroot_error_t::svmroot_translate_failure;
                flush_count = 0;
            }
        }

        p.count = flush_count;
        p.result = status;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_write_log: {
        auto p = get_params<write_log_params>(gprs);
        svm::logs::get()->write("%s", p.message);
        p.result = 0;
        set_params(gprs, p);
        return result::advance_rip;
    }
    case vmcall_magic_devirtualize: {
        size_t guest_rip = 0, guest_rsp = 0, guest_rflags = 0, instr_len = 0;
        size_t guest_cr0 = 0, guest_cr3 = 0, guest_cr4 = 0;
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rip),        &guest_rip);
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rsp),        &guest_rsp);
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_rflags),     &guest_rflags);
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cr0),        &guest_cr0);
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cr3),        &guest_cr3);
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cr4),        &guest_cr4);
        __vmx_vmread(static_cast<size_t>(vmcs_field::vm_exit_instr_len), &instr_len);
        if (instr_len == 0 || instr_len > 15) instr_len = 1;

        vcpu->devirt_rip    = guest_rip + instr_len;
        vcpu->devirt_rsp    = guest_rsp;
        vcpu->devirt_rflags = guest_rflags;
        vcpu->devirt_cr0    = guest_cr0;
        vcpu->devirt_cr3    = guest_cr3;
        vcpu->devirt_cr4    = guest_cr4 & ~(1ULL << 13);
        return result::devirtualize;
    }
    default: {
        event_handler::get()->inject_ud();
        return result::no_advance;
    }
    }
}

}
