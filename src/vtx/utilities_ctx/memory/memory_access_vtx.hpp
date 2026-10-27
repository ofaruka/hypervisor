#pragma once
#include "../../../includes.h"

namespace vtx {

class memory_access {
private:
    static constexpr u64 mapped_physical_size =
        host_physical_memory_pd_count * 0x40000000ULL;

    memory_access() = default;

    host_pt_t host_pt;

    auto map_physical_memory(host_pt_t& pt) -> void;

    auto physical_to_virtual(u64 physical_address, u64 size, void*& virtual_address) -> bool;
    auto read_physical(u64 physical_address, void* buffer, u64 size) -> bool;
    auto write_physical(u64 physical_address, const void* buffer, u64 size) -> bool;
    auto guest_cr3() -> u64;

    auto copy_virtual_to_host(u64 cr3, u64 source_gva, void* destination, u64 size) -> bool;
    auto copy_host_to_virtual(u64 cr3, u64 destination_gva, const void* source, u64 size) -> bool;

public:
    static auto get() -> memory_access*;

    auto prepare_host_page_tables() -> svm::svmroot_error_t;
    auto prepare_host_page_tables(host_pt_t& pt, u64& cr3) -> svm::svmroot_error_t;
    auto host_cr3() -> u64;
    auto hpa_to_hva(u64 physical_address, u64 size, void*& virtual_address) -> bool;

    auto translate(u64 cr3, u64 virtual_address, u64& physical_address, u64& bytes_to_next_page) -> bool;
    auto guest_range_mapped(u64 gva, u64 size) -> bool;
    auto get_physical_address(u64 cr3, u64 virtual_address) -> u64;
    auto get_virtual_address(u64 cr3, u64 physical_address) -> u64;
    auto is_page_present(u64 cr3, u64 virtual_address) -> bool;
    auto request_page_in(u64 cr3, u64 virtual_address) -> bool;
    auto try_consume_pending(pvcpu_t vcpu) -> bool;
    auto clear_guest_pte_nx(u64 cr3, u64 virtual_address, bool make_writable)
        -> svm::svmroot_error_t;

    auto read_virtual(u64 cr3, u64 source_gva, void* destination, u64 size) -> bool;
    auto write_virtual(u64 cr3, u64 destination_gva, const void* source, u64 size) -> bool;

    auto get_process_cr3(u64 target_pid) -> u64;
    auto get_process_base(u64 target_pid) -> u64;
    auto get_process_module(u64 target_pid, const wchar_t* module_name) -> u64;

    auto read_physical_memory(pvcpu_t vcpu, u64 destination_gva, u64 source_gpa, u64 size)
        -> svm::svmroot_error_t;
    auto write_physical_memory(pvcpu_t vcpu, u64 destination_gpa, u64 source_gva, u64 size)
        -> svm::svmroot_error_t;
    auto read_virtual_memory(pvcpu_t vcpu, u64 process_cr3, u64 destination_gva, u64 source_gva, u64 size)
        -> svm::svmroot_error_t;
    auto write_virtual_memory(pvcpu_t vcpu, u64 process_cr3, u64 destination_gva, u64 source_gva, u64 size)
        -> svm::svmroot_error_t;

private:
    struct pending_page_in_t {
        volatile u64 process_cr3;
        volatile u64 gva;
    };

    static constexpr u32 max_pending_slots = 64;
    pending_page_in_t m_pending[max_pending_slots]{};
};

}
