#include "vmmcall_svm.hpp"
#include "../../../hv_spinlock.hpp"

namespace svm {

template <typename T>

bool vmmcall_handler::get_command_internal(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, T& local_params) {
    local_params = {};
    return memory_access::get()->write_virtual_memory(vcpu, vcpu->host_vmcb.state_save_area.cr3,
                                                      reinterpret_cast<u64>(&local_params),
                                                      guest_ctx->vprocessor_registers->rdx.value,
                                                      sizeof(T)) == svm::svmroot_error_t::error_success;
}

template <typename T>

void vmmcall_handler::set_command_internal(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, const T& params) {
    memory_access::get()->read_virtual_memory(vcpu, vcpu->host_vmcb.state_save_area.cr3,
                                              guest_ctx->vprocessor_registers->rdx.value,
                                              reinterpret_cast<u64>(&params), sizeof(T));
}

void vmmcall_handler::vmmcall_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    // Locking is scoped to the non-blocking NPT/hook/hide sections, not the whole handler.
    u64 vmmcall_func = guest_ctx->vprocessor_registers->rcx.value;

    switch (vmmcall_func) {
    case vmmcall_codes::disable_hv: {
        guest_ctx->should_exit = true;
        break;
    }
    case vmmcall_codes::ping_hv: {
        vmmcall_params::ping_hv_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }

        if (params.magic == 0xDEADBEEFCAFEBABE) {
            params.result = 0xBAADF00DDEADBEEF;
        } else {
            params.result = 0;
        }

        set_command_internal<vmmcall_params::ping_hv_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::get_hv_base: {
        vmmcall_params::get_hv_base_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.hv_base = reinterpret_cast<u64>(&__ImageBase);
        params.hv_size =
            (reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<u64>(&__ImageBase) +
                                                 reinterpret_cast<PIMAGE_DOS_HEADER>(&__ImageBase)->e_lfanew))
                ->OptionalHeader.SizeOfImage;
        set_command_internal<vmmcall_params::get_hv_base_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::get_process_cr3: {
        vmmcall_params::get_process_cr3_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.process_cr3 = memory::get()->get_process_cr3(vcpu, params.target_pid);
        set_command_internal<vmmcall_params::get_process_cr3_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::get_process_base: {
        vmmcall_params::get_process_base_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.process_base = memory::get()->get_process_base(vcpu, params.target_pid);
        set_command_internal<vmmcall_params::get_process_base_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::get_process_module: {
        vmmcall_params::get_process_module_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.process_module = memory::get()->get_process_module(vcpu, params.target_pid, params.module_name);
        set_command_internal<vmmcall_params::get_process_module_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::get_physical_address: {
        vmmcall_params::get_physical_address_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.physical_address =
            page_table::get()->get_physical_address(vcpu, params.process_cr3, params.virtual_address);
        set_command_internal<vmmcall_params::get_physical_address_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::get_virtual_address: {
        vmmcall_params::get_virtual_address_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.virtual_address =
            page_table::get()->get_virtual_address(vcpu, params.process_cr3, params.physical_address);
        set_command_internal<vmmcall_params::get_virtual_address_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::write_virtual_memory: {
        vmmcall_params::write_virtual_memory_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result = memory_access::get()->write_virtual_memory(vcpu, params.process_cr3, params.destination_gva,
                                                                   params.source_gva, params.size);
        set_command_internal<vmmcall_params::write_virtual_memory_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::ensure_page_present: {
        vmmcall_params::ensure_page_present_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }

        if (memory_access::get()->is_page_present(params.process_cr3, params.gva)) {
            params.status = vmmcall_params::ensure_page_present_status::page_present;
            params.result = svm::svmroot_error_t::error_success;
        } else if (memory_access::get()->request_page_in(params.process_cr3, params.gva)) {
            params.status = vmmcall_params::ensure_page_present_status::page_pending;
            params.result = svm::svmroot_error_t::error_success;
        } else {
            params.status = vmmcall_params::ensure_page_present_status::page_error;
            params.result = svm::svmroot_error_t::error_failed;
        }

        set_command_internal<vmmcall_params::ensure_page_present_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::is_page_present: {
        vmmcall_params::is_page_present_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result = memory_access::get()->is_page_present(params.process_cr3, params.gva)
                            ? svm::svmroot_error_t::error_success
                            : svm::svmroot_error_t::error_failed;
        set_command_internal<vmmcall_params::is_page_present_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::clear_guest_pte_nx: {
        vmmcall_params::clear_guest_pte_nx_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result =
            page_table::get()->clear_guest_pte_nx(vcpu, params.process_cr3, params.gva, params.make_writable != 0);
        flush_tlb_t{}.flush_tlb(vcpu, flush_tlb_t::tlb_control_id::flush_entire_tlb);
        set_command_internal<vmmcall_params::clear_guest_pte_nx_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::read_virtual_memory: {
        vmmcall_params::read_virtual_memory_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result = memory_access::get()->read_virtual_memory(vcpu, params.process_cr3, params.destination_gva,
                                                                  params.source_gva, params.size);
        set_command_internal<vmmcall_params::read_virtual_memory_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::write_physical_memory: {
        vmmcall_params::write_physical_memory_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result =
            memory_access::get()->write_physical_memory(vcpu, params.destination_gva, params.source_gva, params.size);
        set_command_internal<vmmcall_params::write_physical_memory_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::read_physical_memory: {
        vmmcall_params::read_physical_memory_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result =
            memory_access::get()->read_physical_memory(vcpu, params.destination_gva, params.source_gva, params.size);
        set_command_internal<vmmcall_params::read_physical_memory_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::install_function_hook: {
        vmmcall_params::install_function_hook_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result =
            hook::get()->install_function_hook(vcpu, params.address, params.proxy, params.detour, params.target_cr3);
        set_command_internal<vmmcall_params::install_function_hook_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::remove_function_hook: {
        vmmcall_params::remove_function_hook_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result = hook::get()->remove_function_hook(vcpu, params.address);
        set_command_internal<vmmcall_params::remove_function_hook_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::install_driver_hooks: {
        vmmcall_params::install_driver_hooks_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result = hook::get()->install_driver_hooks(vcpu, params.driver_name, params.major_function,
                                                          params.proxy, params.detour, &params.target);
        set_command_internal<vmmcall_params::install_driver_hooks_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::install_npt_hook: {
        hv_exclusive_lock_guard lock;
        vmmcall_params::install_npt_hook_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result =
            npt::get()->install_npt_hook(params.original_page_pfn, params.executable_page_pfn, 0, PAGE_SIZE);
        set_command_internal<vmmcall_params::install_npt_hook_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::remove_npt_hook: {
        hv_exclusive_lock_guard lock;
        vmmcall_params::remove_npt_hook_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result = npt::get()->remove_npt_hook(params.original_page_pfn);
        set_command_internal<vmmcall_params::remove_npt_hook_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::get_tpm_key: {
        vmmcall_params::get_tpm_key_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result = tpm_crypto::get()->get_tpm_key(vcpu, params.buffer_gva);
        set_command_internal<vmmcall_params::get_tpm_key_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::set_tpm_pcrs: {
        vmmcall_params::set_tpm_pcrs_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        tpm::pcr_all_banks banks = {};
        auto result = memory_access::get()->write_virtual_memory(
            vcpu, vcpu->host_vmcb.state_save_area.cr3, reinterpret_cast<u64>(&banks), params.buffer_gva, sizeof(banks));
        if (result == svm::svmroot_error_t::error_success) {
            tpm::get()->set_pcr_values(banks);
            params.result = svm::svmroot_error_t::error_success;
        } else {
            params.result = svm::svmroot_error_t::error_failed;
        }

        set_command_internal<vmmcall_params::set_tpm_pcrs_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::set_tpm_seed: {
        vmmcall_params::set_tpm_seed_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        tpm::get()->set_identity_seed(params.seed);
        params.result = svm::svmroot_error_t::error_success;
        set_command_internal<vmmcall_params::set_tpm_seed_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::hide_physical_page: {
        hv_exclusive_lock_guard lock;
        vmmcall_params::hide_physical_page_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result = hide_page::get()->hide_physical_page(vcpu, params.page_pfn);
        set_command_internal<vmmcall_params::hide_physical_page_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::unhide_physical_page: {
        hv_exclusive_lock_guard lock;
        vmmcall_params::unhide_physical_page_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result = hide_page::get()->unhide_physical_page(vcpu, params.page_pfn);
        set_command_internal<vmmcall_params::unhide_physical_page_params>(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::flush_logs: {
        vmmcall_params::flush_logs_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        params.result = static_cast<u32>(logs::get()->flush_logs(vcpu, params.buffer_gva, params.count));
        set_command_internal(vcpu, guest_ctx, params);
        break;
    }
    case vmmcall_codes::write_log: {
        vmmcall_params::write_log_params params{};
        if (!get_command_internal(vcpu, guest_ctx, params)) {
            return;
        }
        logs::get()->write("%s", params.message);
        params.result = svm::svmroot_error_t::error_success;
        set_command_internal(vcpu, guest_ctx, params);
        break;
    }
    default: {
        event_inj_t{}.invalid_opcode_exception(vcpu);
        return;
    }
    }

    vcpu->guest_vmcb.state_save_area.rip = advance_rip_or_next(vcpu, 3);
}

vmmcall_handler* vmmcall_handler::get() {
    static vmmcall_handler instance;
    return &instance;
}
}
