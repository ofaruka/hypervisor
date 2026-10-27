#pragma once
#include "../includes.h"
inline constexpr size_t npt_pd_count = 512;
inline constexpr size_t npt_free_page_count = 1000;
struct npt_hook_node_t {
    npt_hook_node_t* next;
    u64 orig_pfn;
    u64 exec_pfn;
    u16 patch_offset;
    u16 patch_size;
};
struct npt_hooks_t {
    static constexpr size_t capacity = 1000;
    npt_hook_node_t buffer[capacity];
    npt_hook_node_t* active_list_head;
    npt_hook_node_t* free_list_head;
};
enum mmr_memory_mode { mmr_memory_mode_r = 0b001, mmr_memory_mode_w = 0b010, mmr_memory_mode_x = 0b100 };
struct npt_mmr_entry_t {
    u64 start;
    u32 size;
    u8 mode;
};
struct npt_data_t {
    alignas(0x1000) pml4e_64 pml4[512];
    alignas(0x1000) pdpte_64 pdpt[512];
    static_assert(npt_pd_count <= 512, "Only 512 NPT PDs are supported!");
    union {
        alignas(0x1000) pde_64 pds[npt_pd_count][512];
        alignas(0x1000) pde_2mb_64 pds_2mb[npt_pd_count][512];
    };
    alignas(0x1000) u8 free_pages[npt_free_page_count][0x1000];
    alignas(0x1000) u8 dummy_page[0x1000];
    u64 dummy_page_pfn;
    u64 free_page_pfns[npt_free_page_count];
    size_t num_used_free_pages;
    npt_hooks_t hooks;
};
