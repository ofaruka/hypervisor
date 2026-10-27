#pragma once
#include "../../includes.h"

namespace vtx {

constexpr u32 ept_pt_pool_count = 256;
constexpr u32 ept_max_hooks     = 128;
constexpr u32 ept_max_hidden_pages = max_core_count * 96;

constexpr u64 ept_mt_uncacheable = 0;
constexpr u64 ept_mt_writeback   = 6;

constexpr u64 ept_read     = 1ULL << 0;
constexpr u64 ept_write    = 1ULL << 1;
constexpr u64 ept_execute  = 1ULL << 2;
constexpr u64 ept_pagesize = 1ULL << 7;

constexpr u64 ept_cap_execute_only          = 1ULL << 0;
constexpr u64 ept_cap_page_walk_length_4    = 1ULL << 6;
constexpr u64 ept_cap_memory_type_writeback = 1ULL << 14;
constexpr u64 ept_cap_pde_2mb               = 1ULL << 16;
constexpr u64 ept_cap_invept                = 1ULL << 20;
constexpr u64 ept_cap_invept_single_context = 1ULL << 25;
constexpr u64 ept_cap_invvpid               = 1ULL << 32;
constexpr u64 ept_cap_invvpid_all_contexts  = 1ULL << 42;

constexpr u64 ept_qual_data_read   = 1ULL << 0;
constexpr u64 ept_qual_data_write  = 1ULL << 1;
constexpr u64 ept_qual_instr_fetch = 1ULL << 2;
constexpr u64 ept_qual_readable    = 1ULL << 3;
constexpr u64 ept_qual_writable    = 1ULL << 4;
constexpr u64 ept_qual_executable  = 1ULL << 5;
constexpr u64 ept_qual_gla_valid   = 1ULL << 7;
constexpr u64 ept_qual_translated  = 1ULL << 8;

struct ept_hook_node {
    ept_hook_node* next;
    u64 orig_pfn;
    u64 exec_pfn;
    u16 patch_offset;
    u16 patch_size;
    u64 data_entry;
    u64 exec_entry;
    u64* pte_addr;
};

struct ept_hidden_page_node {
    ept_hidden_page_node* next;
    u64 page_pfn;
    u64 original_entry;
    u64* pte_addr;
    void* dummy_page;
    u64 dummy_pfn;
};

struct alignas(0x1000) ept_state {
    alignas(0x1000) u64 pml4[512];
    alignas(0x1000) u64 pdpt[512];
    alignas(0x1000) u64 pd[512][512];
    alignas(0x1000) u64 pt_pool[ept_pt_pool_count][512];

    u64 pt_pool_pfn[ept_pt_pool_count];
    u32 pt_pool_used;

    ept_hook_node  hooks_buffer[ept_max_hooks];
    ept_hook_node* hooks_active;
    ept_hook_node* hooks_free;

    ept_hidden_page_node  hidden_buffer[ept_max_hidden_pages];
    ept_hidden_page_node* hidden_active;
    ept_hidden_page_node* hidden_free;
};

}
