#pragma once
#include "../includes.h"

namespace svm {

class memory {
  public:
    // The arena must be initialized in guest mode before virtualizing.
    // All root-mode allocations are served from it; root mode must never
    // call ExAllocatePool & friends: those take memory-manager locks that
    // TLB-shootdown shooters hold while waiting at IPI barriers for every
    // CPU - a CPU parked in root mode cannot ack the IPI, and the shooter
    // holds the lock the root-mode allocation needs. That circular wait
    // froze the machine at boot repeatedly.
    auto init_arena() -> bool;
    auto alloc_contiguous_memory(u64 size) -> void*;
    auto free_contiguous_memory(void* base) -> void;
    auto alloc_nonpaged_pool(u64 size) -> void*;
    auto alloc_executable_pool(u64 size) -> void*;
    auto free_nonpaged_pool(void* base) -> void;
    auto map_physical_memory(host_pt_t& pt) -> void;
    auto prepare_host_page_tables() -> svm::svmroot_error_t;
    auto get_process_cr3(svm::pvcpu_t vcpu, u64 target_pid) -> u64;
    auto get_process_module(svm::pvcpu_t vcpu, u64 target_pid, const wchar_t* module_name) -> u64;
    auto get_process_peb(u64 target_pid) -> u64;
    auto get_process_base(svm::pvcpu_t vcpu, u64 target_pid) -> u64;
    static auto get() -> memory*;

  private:
    // Page-granular arena over one contiguous (resident, executable)
    // allocation. page_runs[i] == 0 means page i is free or a continuation;
    // page_runs[i] == n (>0) means an n-page allocation starts at page i.
    static constexpr u64 arena_size = 16ull * 1024 * 1024;
    static constexpr u32 arena_pages = static_cast<u32>(arena_size / PAGE_SIZE);
    static_assert(arena_pages == 4096);

    u8* arena_base = nullptr;
    u32 arena_page_count = 0;
    u16 page_runs[arena_pages]{};
    volatile LONG arena_lock = 0;

    auto arena_alloc(u64 size) -> void*;
    auto arena_free(void* base) -> void;
};
}
