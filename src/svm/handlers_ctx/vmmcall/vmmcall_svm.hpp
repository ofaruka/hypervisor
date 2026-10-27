#pragma once
#include "../includes.h"

namespace svm {

enum vmmcall_codes : u64 {
    disable_hv = 0x10000000,
    ping_hv = 0x10000001,
    read_physical_memory = 0x10001000,
    write_physical_memory = 0x10001001,
    read_virtual_memory = 0x10001002,
    write_virtual_memory = 0x10001003,
    get_physical_address = 0x10001004,
    get_virtual_address = 0x10001005,
    ensure_page_present = 0x10001006,
    is_page_present = 0x10001007,
    clear_guest_pte_nx = 0x10001008,
    get_process_cr3 = 0x10002000,
    get_process_base = 0x10002001,
    get_process_module = 0x10002002,
    install_function_hook = 0x10003000,
    remove_function_hook = 0x10003001,
    install_npt_hook = 0x10003002,
    remove_npt_hook = 0x10003003,
    install_driver_hooks = 0x10003004,
    get_tpm_key = 0x10004000,
    set_tpm_pcrs = 0x10004001,
    set_tpm_seed = 0x10004002,
    hide_physical_page = 0x10005000,
    unhide_physical_page = 0x10005001,
    get_hv_base = 0x10006000,
    flush_logs = 0x10007000,
    write_log = 0x10007001,
};
class vmmcall_params {
  public:
    enum ensure_page_present_status : u64 { page_present = 0, page_pending = 1, page_error = 2 };

    struct ping_hv_params {
        u64 magic;
        u64 result;
    };
    struct get_hv_base_params {
        u64 hv_base;
        u64 hv_size;
    };
    struct install_npt_hook_params {
        u64 original_page_pfn;
        u64 executable_page_pfn;
        u64 result;
    };
    struct remove_npt_hook_params {
        u64 original_page_pfn;
        u64 result;
    };
    struct install_function_hook_params {
        void* address;
        void* proxy;
        void** detour;
        u64 target_cr3;
        u64 result;
    };
    struct remove_function_hook_params {
        void* address;
        u64 result;
    };
    struct install_driver_hooks_params {
        wchar_t driver_name[128];
        u32 major_function;
        u32 reserved;
        void* proxy;
        void** detour;
        void* target;
        u64 result;
    };
    struct read_virtual_memory_params {
        svm::cr3_t process_cr3;
        u64 destination_gva;
        u64 source_gva;
        u64 size;
        u64 result;
    };
    struct write_virtual_memory_params {
        svm::cr3_t process_cr3;
        u64 destination_gva;
        u64 source_gva;
        u64 size;
        u64 result;
    };
    struct ensure_page_present_params {
        svm::cr3_t process_cr3;
        u64 gva;
        u64 status;
        u64 result;
    };
    struct is_page_present_params {
        svm::cr3_t process_cr3;
        u64 gva;
        u64 result;
    };
    struct clear_guest_pte_nx_params {
        svm::cr3_t process_cr3;
        u64 gva;
        u64 make_writable;
        u64 result;
    };
    struct read_physical_memory_params {
        u64 destination_gva;
        u64 source_gva;
        u64 size;
        u64 result;
    };
    struct write_physical_memory_params {
        u64 destination_gva;
        u64 source_gva;
        u64 size;
        u64 result;
    };
    struct get_physical_address_params {
        svm::cr3_t process_cr3;
        u64 virtual_address;
        u64 physical_address;
    };
    struct get_virtual_address_params {
        svm::cr3_t process_cr3;
        u64 physical_address;
        u64 virtual_address;
    };
    struct get_process_cr3_params {
        u64 target_pid;
        u64 process_cr3;
    };
    struct get_process_base_params {
        u64 target_pid;
        u64 process_base;
    };
    struct get_process_module_params {
        u64 target_pid;
        wchar_t module_name[MAX_PATH];
        u64 process_module;
    };
    struct hide_physical_page_params {
        u64 page_pfn;
        u64 result;
    };
    struct unhide_physical_page_params {
        u64 page_pfn;
        u64 result;
    };
    struct get_tpm_key_params {
        u64 buffer_gva;
        u64 result;
    };
    struct set_tpm_pcrs_params {
        u64 buffer_gva;
        u64 result;
    };
    struct set_tpm_seed_params {
        u64 seed;
        u64 result;
    };
    struct flush_logs_params {
        u64 buffer_gva;
        u32 count;
        u64 result;
    };
    struct write_log_params {
        char message[256];
        u64 result;
    };
};
class vmmcall_handler {
  private:
    template <typename T> bool get_command_internal(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, T& params);
    template <typename T> void set_command_internal(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, const T& params);

  public:
    static vmmcall_handler* get();
    void vmmcall_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
};
extern "C" {
u64 __stdcall svm_vmmcall(vmmcall_codes vmmcall_id, ...);
}
}
