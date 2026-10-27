#pragma once
#include "../../../includes.h"

namespace vtx {

struct hook_record {
    void* original_va;
    void* target_va;
    void* proxy_fn;
    void* detour_fn;
    void* exec_page;
    u64 orig_pfn;
    u64 exec_pfn;
    u16 patch_offset;
    u16 patch_size;
    bool is_active;
    PMDL exec_mdl;
    PMDL orig_mdl;
};

class hook {
public:
    static auto get() -> hook*;

    // issue_invept=true issues vtx_invept_via_vmcall() at the end (caller is in
    // non-root). Set false when calling from the vmcall handler (already root)
    // — caller must vtx_invept_all(eptp) itself.
    auto install_function_hook(void* target_va, void* proxy_fn, void** out_detour_fn,
                               u64 target_cr3 = 0, bool issue_invept = true) -> bool;
    auto install_driver_hooks(const wchar_t* driver_name, u32 major_function, void* proxy_fn,
                              void** out_detour_fn, void** out_target_fn,
                              bool issue_invept = true) -> bool;
    auto remove_function_hook(void* target_va, bool issue_invept = true) -> bool;

    auto get_record(size_t idx) const -> const hook_record* {
        return idx < record_count_ ? &records_[idx] : nullptr;
    }
    auto record_count() const -> size_t { return record_count_; }

private:
    hook();

    static constexpr size_t max_hook_records = 128;
    static constexpr u32    hook_length      = 14;
    static constexpr u32    detour_length    = 14;

    hook_record records_[max_hook_records];
    volatile size_t record_count_;

    auto fix_rip_relative(void* original_va, void* detour_buf, u32 patch_size,
                          u8* abs_jump_table, u32& abs_jump_offset) -> bool;
};

}
