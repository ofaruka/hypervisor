#pragma once
#include "../includes.h"

namespace svm {

class memory_access {
  public:
    static auto get() -> memory_access*;
    auto read_physical_memory(svm::pvcpu_t vcpu, u64 destination_gva, u64 source, u64 size) -> svm::svmroot_error_t;
    auto read_physical_to_host(svm::pvcpu_t vcpu, void* destination, u64 source, u64 size) -> svm::svmroot_error_t;
    auto write_physical_memory(svm::pvcpu_t vcpu, u64 destination, u64 source_gva, u64 size) -> u64;
    auto read_virtual_memory(svm::pvcpu_t vcpu, svm::cr3_t process_cr3, u64 destination_gva, u64 source_gva, u64 size)
        -> svm::svmroot_error_t;
    auto write_virtual_memory(svm::pvcpu_t vcpu, svm::cr3_t process_cr3, u64 destination_gva, u64 source_gva, u64 size)
        -> svm::svmroot_error_t;
    auto is_page_present(svm::cr3_t process_cr3, u64 gva) -> bool;
    auto request_page_in(svm::cr3_t process_cr3, u64 gva) -> bool;
    auto try_consume_pending(svm::pvcpu_t vcpu) -> bool;

  private:
    struct pending_page_in_t {
        volatile u64 process_cr3;
        volatile u64 gva;
    };
    static constexpr u32 max_pending_slots = 64;
    pending_page_in_t m_pending[max_pending_slots]{};
};
}
