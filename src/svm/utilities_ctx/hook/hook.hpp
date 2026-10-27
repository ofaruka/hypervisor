#pragma once
#include "../includes.h"
#pragma warning(disable : 6385)
namespace svm {

struct hook_context {
    void* original_address;
    void* target_address;
    void* proxy_address;
    void* detour_address;
    void* hook_address;
    size_t hook_size;
    u64 original_pfn;
    u64 hook_pfn;
    bool is_active;
    PMDL original_mdl;
    PMDL hook_mdl;
};
class hook {
  private:
    static constexpr size_t MAX_HOOKS = 128;
    hook_context hooks[MAX_HOOKS];
    volatile size_t hook_count;
    auto fix_relative_instructions(void* original_address, void* detour_ptr, u32 patch_size, u8* abs_jump_table,
                                   u32& abs_jump_offset) -> bool;

  public:
    hook();
    auto install_function_hook(svm::pvcpu_t vcpu, void* address, void* proxy, void** detour, u64 target_cr3 = 0)
        -> svm::svmroot_error_t;
    auto install_driver_hooks(svm::pvcpu_t vcpu, const wchar_t* driver_name, u32 major_function, void* proxy,
                              void** detour, void** target) -> svm::svmroot_error_t;
    auto remove_function_hook(svm::pvcpu_t vcpu, void* target) -> svm::svmroot_error_t;
    static auto get() -> hook*;
};
}
