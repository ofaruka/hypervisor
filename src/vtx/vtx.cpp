#include "vtx.hpp"
#include "utilities_ctx/ept/ept.hpp"
#include "utilities_ctx/ept/mmio/mmio_vtx.hpp"
#include "utilities_ctx/memory/memory_access_vtx.hpp"

namespace vtx {

auto virtualization::broadcast_invept_ipi_worker(ULONG_PTR context) -> ULONG_PTR {
    UNREFERENCED_PARAMETER(context);

    PROCESSOR_NUMBER pn{};
    KeGetCurrentProcessorNumberEx(&pn);
    auto cpu_idx = static_cast<u8>(KeGetProcessorIndexFromNumber(&pn));

    if (virtualization::get()->is_core_virtualized(cpu_idx)) {
        vtx_invept_via_vmcall();
    }
    return 0;
}

virtualization::virtualization() : processor_count(0), vcpu_pages_protected(false),
    protected_vcpu_page_count(0), vcpus(nullptr) {
    processor_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    RtlZeroMemory(const_cast<LONG*>(launched_processors), sizeof(launched_processors));

    vcpus = reinterpret_cast<pvcpu_t*>(
        svm::memory::get()->alloc_nonpaged_pool(sizeof(pvcpu_t) * processor_count));

    if (!vcpus) {
        debug::panicf("[vtx] Failed to allocate VCPU array for %u processors\n", processor_count);
        processor_count = 0;
        return;
    }

    for (ULONG i = 0; i < processor_count; ++i) {
        vcpus[i] = nullptr;
    }
}

bool virtualization::is_core_virtualized(u8 core_number) {
    if (core_number >= processor_count) return false;
    return launched_processors[core_number] != 0;
}

pvcpu_t virtualization::current_vcpu() {
    auto cpu_idx = KeGetCurrentProcessorIndex();
    if (cpu_idx >= processor_count) return nullptr;
    return vcpus[cpu_idx];
}

auto virtualization::protect_vcpu_pages(pvcpu_t vcpu) -> bool {
    if (!vcpu) return false;

    auto base = reinterpret_cast<u64>(vcpu);
    if ((base & (PAGE_SIZE - 1)) != 0) return false;

    u32 protected_pages = 0;
    for (u32 i = 0; i < vprocessor_data_page_count; ++i) {
        auto offset = static_cast<u64>(i) * PAGE_SIZE;
        auto va = reinterpret_cast<void*>(base + offset);
        auto pa = static_cast<u64>(MmGetPhysicalAddress(va).QuadPart);
        if (!pa || !ept::get()->hide_physical_page(pa >> 12)) {
            while (protected_pages != 0) {
                protected_pages--;
                va = reinterpret_cast<void*>(
                    base + static_cast<u64>(protected_pages) * PAGE_SIZE);
                pa = static_cast<u64>(MmGetPhysicalAddress(va).QuadPart);
                if (pa) ept::get()->unhide_physical_page(pa >> 12);
            }
            return false;
        }
        protected_pages++;
    }

    protected_vcpu_page_count += protected_pages;
    return true;
}

auto virtualization::unprotect_vcpu_pages(pvcpu_t vcpu) -> void {
    if (!vcpu) return;

    auto base = reinterpret_cast<u64>(vcpu);
    if ((base & (PAGE_SIZE - 1)) != 0) return;

    for (u32 i = 0; i < vprocessor_data_page_count; ++i) {
        auto offset = static_cast<u64>(i) * PAGE_SIZE;
        auto va = reinterpret_cast<void*>(base + offset);
        auto pa = static_cast<u64>(MmGetPhysicalAddress(va).QuadPart);
        if (pa) ept::get()->unhide_physical_page(pa >> 12);
    }
}

auto virtualization::protect_all_vcpu_pages() -> bool {
    if (vcpu_pages_protected) return true;

    protected_vcpu_page_count = 0;
    for (ULONG i = 0; i < processor_count; ++i) {
        if (!vcpus[i]) continue;
        if (!protect_vcpu_pages(vcpus[i])) {
            unprotect_all_vcpu_pages();
            return false;
        }
    }

    vcpu_pages_protected = true;
    return true;
}

auto virtualization::unprotect_all_vcpu_pages() -> void {
    if (!vcpu_pages_protected && protected_vcpu_page_count == 0) return;

    for (ULONG i = 0; i < processor_count; ++i) {
        if (vcpus[i]) unprotect_vcpu_pages(vcpus[i]);
    }

    vcpu_pages_protected = false;
    protected_vcpu_page_count = 0;
}

auto virtualization::free_vcpus() -> void {
    for (ULONG i = 0; i < processor_count; ++i) {
        if (!vcpus[i]) continue;
        if (vcpus[i]->host_pt) {
            svm::memory::get()->free_nonpaged_pool(vcpus[i]->host_pt);
            vcpus[i]->host_pt = nullptr;
        }
        svm::memory::get()->free_nonpaged_pool(vcpus[i]);
        vcpus[i] = nullptr;
    }
}

bool virtualization::virtualize_processor(PVOID ctx) {
    UNREFERENCED_PARAMETER(ctx);

    PROCESSOR_NUMBER pn{};
    KeGetCurrentProcessorNumberEx(&pn);
    auto cpu_idx = static_cast<u8>(KeGetProcessorIndexFromNumber(&pn));

    if (is_core_virtualized(cpu_idx)) return true;
    if (cpu_idx >= processor_count || !vcpus[cpu_idx]) return false;

    auto vcpu = vcpus[cpu_idx];
    auto vmx_ctx = vmx::get();

    if (!vcpu->host_pt) {
        vcpu->host_pt = reinterpret_cast<host_pt_t*>(
            svm::memory::get()->alloc_nonpaged_pool(sizeof(host_pt_t)));
        if (!vcpu->host_pt) {
            return false;
        }
    }

    if (memory_access::get()->prepare_host_page_tables(*vcpu->host_pt,
                                                       vcpu->host_cr3) !=
        svm::svmroot_error_t::error_success) {
        return false;
    }
    if (!vmx_ctx->enter_vmx_root(vcpu)) {
        return false;
    }

    if (!vmx_ctx->vmcs_init(vcpu)) {
        vmx_ctx->leave_vmx_root(vcpu);
        return false;
    }

    if (!vmx_ctx->setup_vmcs(vcpu)) {
        vmx_ctx->leave_vmx_root(vcpu);
        return false;
    }

    vtx_invept_all(ept::get()->ept_pointer());

    auto host_rsp_top = reinterpret_cast<u64>(&vcpu->self);
    if (__vmx_vmwrite(static_cast<size_t>(vmcs_field::host_rsp),
                      static_cast<size_t>(host_rsp_top)) != 0 ||
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::host_rip),
                      reinterpret_cast<size_t>(&vtx_vmexit_entry)) != 0) {
        vmx_ctx->leave_vmx_root(vcpu);
        return false;
    }

    vcpu->launched = 1;
    auto launched = vtx_vmlaunch_entry(vcpu, host_rsp_top);

    if (!launched) {
        vcpu->launched = 0;
        vmx_ctx->leave_vmx_root(vcpu);
        return false;
    }

    InterlockedExchange(&launched_processors[cpu_idx], 1);
    return true;
}

bool virtualization::devirtualize_processor(PVOID ctx) {
    UNREFERENCED_PARAMETER(ctx);

    PROCESSOR_NUMBER pn{};
    KeGetCurrentProcessorNumberEx(&pn);
    auto cpu_idx = static_cast<u8>(KeGetProcessorIndexFromNumber(&pn));

    if (!is_core_virtualized(cpu_idx)) return true;

    vtx_devirtualize_via_vmcall();

    InterlockedExchange(&launched_processors[cpu_idx], 0);
    return true;
}

bool virtualization::virtualize() {
    svm::logs::get()->initialize();

    if (!utilities::get()->check_support()) {
        debug::panicf("[vtx] check_support() failed; bailing out (no VMXON attempted)\n");
        return false;
    }

    if (!ept::get()->init()) {
        debug::panicf("[vtx] ept::init() failed; bailing out\n");
        return false;
    }

    if (!mmio::get()->register_range(0xFED40000, 0xFED44FFF) ||
        !mmio::get()->setup_ept()) {
        debug::panicf("[vtx] MMIO EPT setup failed\n");
        return false;
    }

    for (ULONG i = 0; i < processor_count; ++i) {
        if (!vcpus[i]) {
            vcpus[i] = reinterpret_cast<pvcpu_t>(
                svm::memory::get()->alloc_nonpaged_pool(sizeof(vprocessor_data)));
            if (!vcpus[i]) {
                debug::panicf("[vtx] Failed allocating VCPU for CPU %u\n", i);
                return false;
            }
            RtlZeroMemory(vcpus[i], sizeof(vprocessor_data));
            vcpus[i]->self = vcpus[i];
        }
    }

    if (!protect_all_vcpu_pages()) {
        debug::panicf("[vtx] Failed protecting VCPU pages\n");
        free_vcpus();
        return false;
    }

    ULONG launched_count = 0;

    for (ULONG i = 0; i < processor_count; ++i) {
        PROCESSOR_NUMBER processor_number = { 0 };
        auto status = KeGetProcessorNumberFromIndex(i, &processor_number);
        if (!NT_SUCCESS(status)) {
            debug::panicf("[vtx] Failed resolving processor index %u: 0x%08x\n",
                i, status);
            devirtualize();
            return false;
        }

        GROUP_AFFINITY affinity = { 0 };
        affinity.Group = processor_number.Group;
        affinity.Mask = 1ULL << processor_number.Number;

        GROUP_AFFINITY old_affinity;
        KeSetSystemGroupAffinityThread(&affinity, &old_affinity);

        auto result = virtualize_processor(nullptr);

        KeRevertToUserGroupAffinityThread(&old_affinity);

        if (!result) {
            debug::panicf("[vtx] Failed virtualizing processor index %u\n", i);
            devirtualize();
            return false;
        }

        launched_count++;
    }

    debug::panicf("[vtx] virtualized %u/%u processors\n",
        launched_count, processor_count);
    return true;
}

void virtualization::devirtualize() {
    for (ULONG i = 0; i < processor_count; i++) {
        PROCESSOR_NUMBER pn = { 0 };
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &pn))) continue;

        GROUP_AFFINITY aff = { 0 };
        aff.Group = pn.Group;
        aff.Mask = 1ULL << pn.Number;

        GROUP_AFFINITY old_aff;
        KeSetSystemGroupAffinityThread(&aff, &old_aff);

        devirtualize_processor(nullptr);

        KeRevertToUserGroupAffinityThread(&old_aff);
    }

    unprotect_all_vcpu_pages();
    free_vcpus();
}

virtualization* virtualization::get() {
    static virtualization instance;
    return &instance;
}

void virtualization::broadcast_invept() {
    KeIpiGenericCall(broadcast_invept_ipi_worker, 0);
}

}
