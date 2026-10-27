#pragma once
#include "../includes.h"

namespace vtx {
    class virtualization {
    private:
        virtualization();

        u32 processor_count;
        bool vcpu_pages_protected;
        u32 protected_vcpu_page_count;
        volatile LONG launched_processors[max_core_count];

        static auto broadcast_invept_ipi_worker(ULONG_PTR context) -> ULONG_PTR;
        auto protect_vcpu_pages(pvcpu_t vcpu) -> bool;
        auto unprotect_vcpu_pages(pvcpu_t vcpu) -> void;
        auto protect_all_vcpu_pages() -> bool;
        auto unprotect_all_vcpu_pages() -> void;
        auto free_vcpus() -> void;

    public:
        static virtualization* get();

        // VCPUs
        pvcpu_t* vcpus;

        u32 get_processor_count() const { return processor_count; }

        bool is_core_virtualized(u8 core_number);
        pvcpu_t current_vcpu();

        // Virtualization methods
        bool virtualize();
        void devirtualize();
        void broadcast_invept();

        // Processor management
        bool virtualize_processor(PVOID ctx);
        bool devirtualize_processor(PVOID ctx);
    };
}
