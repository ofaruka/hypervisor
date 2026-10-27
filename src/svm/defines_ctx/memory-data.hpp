#pragma once
#include "../includes.h"
inline constexpr u64 host_physical_memory_pd_count = 512;
inline constexpr u64 host_physical_memory_pml4_idx = 255;
inline u8* const host_physical_memory_base = reinterpret_cast<u8*>(host_physical_memory_pml4_idx << (9 + 9 + 9 + 12));
union virtual_address_t {
    struct {
        u64 offset : 12;
        u64 pt_index : 9;
        u64 pd_index : 9;
        u64 pdpt_index : 9;
        u64 pml4_index : 9;
        u64 reserved : 16;
    };
    u64 value;
};
typedef union {
    struct {
        u64 present : 1;
        u64 write : 1;
        u64 supervisor : 1;
        u64 page_level_write_through : 1;
        u64 page_level_cache_disable : 1;
        u64 accessed : 1;
        u64 reserved_1 : 1;
        u64 must_be_zero : 1;
        u64 ignored_1 : 3;
        u64 restart : 1;
        u64 page_frame_number : 36;
        u64 reserved_2 : 4;
        u64 ignored_2 : 11;
        u64 execute_disable : 1;
    };
    u64 flags;
} pml4e_64;
typedef union {
    struct {
        u64 present : 1;
        u64 write : 1;
        u64 supervisor : 1;
        u64 page_level_write_through : 1;
        u64 page_level_cache_disable : 1;
        u64 accessed : 1;
        u64 dirty : 1;
        u64 large_page : 1;
        u64 global : 1;
        u64 ignored_1 : 2;
        u64 restart : 1;
        u64 pat : 1;
        u64 reserved_1 : 17;
        u64 page_frame_number : 18;
        u64 reserved_2 : 4;
        u64 ignored_2 : 7;
        u64 protection_key : 4;
        u64 execute_disable : 1;
    };
    u64 flags;
} pdpte_1gb_64;
typedef union {
    struct {
        u64 present : 1;
        u64 write : 1;
        u64 supervisor : 1;
        u64 page_level_write_through : 1;
        u64 page_level_cache_disable : 1;
        u64 accessed : 1;
        u64 reserved_1 : 1;
        u64 large_page : 1;
        u64 ignored_1 : 3;
        u64 restart : 1;
        u64 page_frame_number : 36;
        u64 reserved_2 : 4;
        u64 ignored_2 : 11;
        u64 execute_disable : 1;
    };
    u64 flags;
} pdpte_64;
typedef union {
    struct {
        u64 present : 1;
        u64 write : 1;
        u64 supervisor : 1;
        u64 page_level_write_through : 1;
        u64 page_level_cache_disable : 1;
        u64 accessed : 1;
        u64 dirty : 1;
        u64 large_page : 1;
        u64 global : 1;
        u64 ignored_1 : 2;
        u64 restart : 1;
        u64 pat : 1;
        u64 reserved_1 : 8;
        u64 page_frame_number : 27;
        u64 reserved_2 : 4;
        u64 ignored_2 : 7;
        u64 protection_key : 4;
        u64 execute_disable : 1;
    };
    u64 flags;
} pde_2mb_64;
typedef union {
    struct {
        u64 present : 1;
        u64 write : 1;
        u64 supervisor : 1;
        u64 page_level_write_through : 1;
        u64 page_level_cache_disable : 1;
        u64 accessed : 1;
        u64 reserved_1 : 1;
        u64 large_page : 1;
        u64 ignored_1 : 3;
        u64 restart : 1;
        u64 page_frame_number : 36;
        u64 reserved_2 : 4;
        u64 ignored_2 : 11;
        u64 execute_disable : 1;
    };
    u64 flags;
} pde_64;
typedef union {
    struct {
        u64 present : 1;
        u64 write : 1;
        u64 supervisor : 1;
        u64 page_level_write_through : 1;
        u64 page_level_cache_disable : 1;
        u64 accessed : 1;
        u64 dirty : 1;
        u64 pat : 1;
        u64 global : 1;
        u64 ignored_1 : 2;
        u64 restart : 1;
        u64 page_frame_number : 36;
        u64 reserved_1 : 4;
        u64 ignored_2 : 7;
        u64 protection_key : 4;
        u64 execute_disable : 1;
    };
    u64 flags;
} pte_64;
typedef union {
    struct {
        u64 present : 1;
        u64 write : 1;
        u64 supervisor : 1;
        u64 page_level_write_through : 1;
        u64 page_level_cache_disable : 1;
        u64 accessed : 1;
        u64 dirty : 1;
        u64 large_page : 1;
        u64 global : 1;
        u64 ignored_1 : 2;
        u64 restart : 1;
        u64 page_frame_number : 36;
        u64 reserved_1 : 4;
        u64 ignored_2 : 7;
        u64 protection_key : 4;
        u64 execute_disable : 1;
    };
    u64 flags;
} pt_entry_64;
struct host_pt_t {
    alignas(0x1000) pml4e_64 pml4[512];
    alignas(0x1000) pdpte_64 pdpt[512];
    alignas(0x1000) pde_2mb_64 pd[host_physical_memory_pd_count][512];
};
