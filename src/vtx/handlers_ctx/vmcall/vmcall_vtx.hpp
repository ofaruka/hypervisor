#pragma once
#include "../../../includes.h"

namespace vtx {

enum vmcall_codes : u64 {
    vmcall_ping_hv               = 0x10000001,
    vmcall_read_physical_memory  = 0x10001000,
    vmcall_write_physical_memory = 0x10001001,
    vmcall_read_virtual_memory   = 0x10001002,
    vmcall_write_virtual_memory  = 0x10001003,
    vmcall_get_physical_address  = 0x10001004,
    vmcall_get_virtual_address   = 0x10001005,
    vmcall_ensure_page_present   = 0x10001006,
    vmcall_is_page_present       = 0x10001007,
    vmcall_clear_guest_pte_nx    = 0x10001008,
    vmcall_get_process_cr3       = 0x10002000,
    vmcall_get_process_base      = 0x10002001,
    vmcall_get_process_module    = 0x10002002,
    vmcall_install_function_hook = 0x10003000,
    vmcall_remove_function_hook  = 0x10003001,
    vmcall_install_ept_hook      = 0x10003002,
    vmcall_remove_ept_hook       = 0x10003003,
    vmcall_install_driver_hooks  = 0x10003004,
    vmcall_get_tpm_key           = 0x10004000,
    vmcall_set_tpm_pcrs          = 0x10004001,
    vmcall_set_tpm_seed          = 0x10004002,
    vmcall_hide_physical_page    = 0x10005000,
    vmcall_unhide_physical_page  = 0x10005001,
    vmcall_get_hv_base           = 0x10006000,
    vmcall_flush_logs            = 0x10007000,
    vmcall_write_log             = 0x10007001,
};

struct ping_hv_params {
    u64 magic;
    u64 result;
};

struct get_hv_base_params {
    u64 hv_base;
    u64 hv_size;
};

struct install_function_hook_params {
    void* address;
    void* proxy;
    void** detour;
    u64 target_cr3;
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

struct ensure_page_present_params {
    u64 process_cr3;
    u64 gva;
    u64 status;
    u64 result;
};

enum ensure_page_present_status : u64 {
    page_present = 0,
    page_pending = 1,
    page_error = 2
};

struct is_page_present_params {
    u64 process_cr3;
    u64 gva;
    u64 result;
};

struct clear_guest_pte_nx_params {
    u64 process_cr3;
    u64 gva;
    u64 make_writable;
    u64 result;
};

struct remove_function_hook_params {
    void* address;
    u64 result;
};

struct install_ept_hook_params {
    u64 original_page_pfn;
    u64 executable_page_pfn;
    u16 patch_offset;
    u16 patch_size;
    u64 result;
};

struct remove_ept_hook_params {
    u64 original_page_pfn;
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

struct hide_physical_page_params {
    u64 page_pfn;
    u64 result;
};

struct unhide_physical_page_params {
    u64 page_pfn;
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

class vmcall_handler {
private:
    vmcall_handler() = default;

    static constexpr u32 max_log_flush_batch = 32;

    template<typename T>
    auto get_params(guest_gprs* gprs) -> T;

    template<typename T>
    auto set_params(guest_gprs* gprs, const T& params) -> void;

public:
    enum class result : u8 {
        advance_rip,
        no_advance,
        devirtualize,
    };

    static auto get() -> vmcall_handler*;

    auto vmcall_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> result;
};

}
