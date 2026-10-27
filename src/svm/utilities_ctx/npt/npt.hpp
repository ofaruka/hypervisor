#pragma once
#include "../includes.h"

namespace svm {

class npt {
  public:
    enum nested_page_table : u64 { primary, shadow };
    auto prepare_npt(npt_data_t& npt, nested_page_table npt_type) -> svm::svmroot_error_t;
    auto split_npt_pde(npt_data_t& npt, pde_2mb_64* const pde_2mb) -> void;
    auto get_npt_pte(npt_data_t& npt, u64 const physical_address, bool const force_split) -> pte_64*;
    auto find_npt_hook(npt_data_t& npt_data, u64 page_pfn) -> npt_hook_node_t*;
    bool update_hook_list(npt_data_t& npt, u64 orig_pfn, u64 exec_pfn, u16 patch_offset, u16 patch_size);
    void remove_hook_from_list(npt_data_t& npt, u64 original_page_pfn);
    auto install_npt_hook(u64 original_page_pfn, u64 executable_page_pfn, u16 patch_offset, u16 patch_size)
        -> svm::svmroot_error_t;
    auto remove_npt_hook(u64 original_page_pfn) -> svm::svmroot_error_t;
    auto cleanup() -> void;
    void sync_hook_page(npt_hook_node_t* hook_node);
    static auto get() -> npt*;

  private:
    auto find_split_pt(npt_data_t& npt, u64 pt_pfn) -> pte_64*;
    auto install_npt_hook(svm::pvcpu_t vcpu, npt_data_t& primary_npt, npt_data_t& shadow_npt, u64 original_page_pfn,
                          u64 executable_page_pfn, u16 patch_offset, u16 patch_size) -> svm::svmroot_error_t;
    auto remove_npt_hook(svm::pvcpu_t vcpu, npt_data_t& primary_npt, npt_data_t& shadow_npt, u64 original_page_pfn)
        -> svm::svmroot_error_t;
};
}
