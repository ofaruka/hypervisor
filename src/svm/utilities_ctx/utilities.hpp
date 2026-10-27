#pragma once
#include "../includes.h"

namespace svm {

class utilities {
  private:
    utilities() = default;

  public:
    static utilities* get();
    bool is_amd();
    bool is_svm_supported();
    bool is_npt_supported();
    bool check_support();
    bool can_svm_be_enabled();
    void enable_svme();
    bool lock_pages(void* address, size_t size, PMDL* out_mdl);
    void unlock_pages(PMDL mdl);
    void* get_process_id_by_name(const wchar_t* process_name);
    svm::os_version_t get_os_version();
    PIMAGE_SECTION_HEADER get_section(void* image_base, const char* section_name);
    unsigned long long get_exported_function(const unsigned long long module_address, const char* proc_name);
    u32 get_patch_size(PVOID code, u32 min_hook_length);
};
}
