#include "svm.hpp"

namespace svm {

extern "C" void __stdcall vmenter(PVOID host_rsp, PVOID guest_ctx);

virtualization::virtualization() : processor_count(0), vcpus(nullptr) {
    processor_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    RtlZeroMemory(&shared_host_pt, sizeof(host_pt_t));
    vcpus = reinterpret_cast<svm::pvcpu_t*>(memory::get()->alloc_nonpaged_pool(sizeof(svm::pvcpu_t) * processor_count));
    if (!vcpus) {
        debug::panicf("Failed to allocate VCPU array for %u processors\n", processor_count);
        processor_count = 0;
        return;
    }

    for (ULONG i = 0; i < processor_count; ++i) {
        vcpus[i] = nullptr;
    }
}

svm::cr4_t virtualization::build_host_cr4() const {
    svm::cr4_t cr4{};
    cr4.value = __readcr4();
    cr4.smep = 0;
    cr4.smap = 0;
    return cr4;
}

bool virtualization::is_core_virtualized(u32 core_number) {
    if (core_number >= processor_count) {
        return false;
    }

    return vcpus[core_number] != nullptr;
}

void virtualization::release_vcpu(u32 processor_index) {
    if (processor_index >= processor_count || !vcpus || !vcpus[processor_index]) {
        return;
    }

    auto vcpu = vcpus[processor_index];

    if (vcpu->ist1_stack) {
        memory::get()->free_nonpaged_pool(vcpu->ist1_stack);
    }

    if (vcpu->ist2_stack) {
        memory::get()->free_nonpaged_pool(vcpu->ist2_stack);
    }

    if (vcpu->host_stack_layout.shared_vcpu) {
        memory::get()->free_nonpaged_pool(vcpu->host_stack_layout.shared_vcpu);
    }

    if (vcpu->host_stack_layout.active_msrpm) {
        memory::get()->free_contiguous_memory(vcpu->host_stack_layout.active_msrpm);
    }

    memory::get()->free_nonpaged_pool(vcpu);
    vcpus[processor_index] = nullptr;
}

void virtualization::setup_control_fields(svm::pvcpu_t vcpu) {
    auto& control = vcpu->guest_vmcb.control_area;
    control.guest_asid = 1;
    control.msrpm_base_pa = MmGetPhysicalAddress(vcpu->host_stack_layout.active_msrpm).QuadPart;
    control.lbr_virtualization_enable = 0;
    control.np_enable = 1;
    control.ncr3 = MmGetPhysicalAddress(&vcpu->npt[npt::nested_page_table::primary].pml4).QuadPart;
    control.intercept_misc1 |= misc1_intercept::intercept_cpuid | misc1_intercept::intercept_msr_prot |
                               misc1_intercept::intercept_invlpga /*| misc1_intercept::intercept_rdtsc*/;
    control.intercept_exception |= exception_intercept::intercept_gp;
    control.intercept_misc2 |=
        misc2_intercept::intercept_vmrun | misc2_intercept::intercept_vmcall | misc2_intercept::intercept_vmload |
        misc2_intercept::intercept_vmsave | misc2_intercept::intercept_stgi | misc2_intercept::intercept_clgi |
        misc2_intercept::intercept_skinit | misc2_intercept::intercept_incebp | misc2_intercept::intercept_efer |
        misc2_intercept::intercept_rdtscp;
    control.tlb_control = static_cast<u32>(flush_tlb_t::tlb_control_id::flush_entire_tlb);
    control.tsc_offset = 0;
    vcpu->host_stack_layout.pending_tlb_flush = 0;
    vcpu->cpuid_exit_tsc = 0;
    vcpu->measured_rdtsc_delta = 0;
    vcpu->host_stack_layout.vmexit_entry_tsc = 0;
    vcpu->vmexit_leave_tsc = 0;
    vcpu->measured_cpuid_delta = 0;
    vcpu->measured_exit_overhead = 0;
    vcpu->last_timing_window = 0;
    vcpu->armed_cpuid_rip = 0;
    RtlZeroMemory(vcpu->last_rdtsc, sizeof(vcpu->last_rdtsc));
}

void virtualization::setup_guest(svm::pvcpu_t vcpu, const svm::pcontext_t ctx) {
    auto& state = vcpu->guest_vmcb.state_save_area;
    auto& host_stack = vcpu->host_stack_layout;
    auto& cs = state.cs;
    auto& ds = state.ds;
    auto& es = state.es;
    auto& ss = state.ss;
    svm::descriptor_table_register_t idtr{}, gdtr{};
    __sidt(&idtr);
    _sgdt(&gdtr);
    state.gdtr.base = gdtr.base;
    state.gdtr.limit = gdtr.limit;
    state.idtr.base = idtr.base;
    state.idtr.limit = idtr.limit;
    state.cr0.value = __readcr0();
    state.cr2.value = __readcr2();
    state.cr3.value = __readcr3();
    state.cr4.value = __readcr4();
    state.efer.value = __readmsr(MSR_EFER);
    state.gpat = __readmsr(MSR_PAT);
    state.lstar = __readmsr(MSR_LSTAR);
    state.dbg_ctl = __readmsr(MSR_DEBUG_CTL);
    state.cstar = __readmsr(MSR_CSTAR);
    state.sfmask = __readmsr(MSR_SFMASK);
    state.sysenter_cs = __readmsr(MSR_SYSENTER_CS);
    state.sysenter_esp = __readmsr(MSR_SYSENTER_ESP);
    state.sysenter_eip = __readmsr(MSR_SYSENTER_EIP);
    state.rsp = ctx->rsp;
    state.rip = ctx->rip;
    state.rax = ctx->rax;
    state.rflags = __readeflags();
    cs.selector.value = __read_cs();
    cs.limit = __segmentlimit(cs.selector.value);
    cs.get_attributes(gdtr.base);
    ds.selector.value = __read_ds();
    ds.limit = __segmentlimit(ds.selector.value);
    ds.get_attributes(gdtr.base);
    es.selector.value = __read_es();
    es.limit = __segmentlimit(es.selector.value);
    es.get_attributes(gdtr.base);
    ss.selector.value = __read_ss();
    ss.limit = __segmentlimit(ss.selector.value);
    ss.get_attributes(gdtr.base);
    host_stack.shadow_data.efer.value = vcpu->guest_vmcb.state_save_area.efer.value;
    host_stack.shadow_data.efer.svme = 0;
    state.efer.svme = 1;
    host_stack.shadow_data.hsave_pa.value = 0;
    host_stack.pending_tlb_flush = 0;
    host_stack.shared_vcpu = vcpu->host_stack_layout.shared_vcpu;
    host_stack.self = vcpu;
    host_stack.host_vmcb_pa = MmGetPhysicalAddress(&vcpu->host_vmcb).QuadPart;
    host_stack.guest_vmcb_pa = MmGetPhysicalAddress(&vcpu->guest_vmcb).QuadPart;
    __svm_vmsave(host_stack.guest_vmcb_pa);
    state.efer.svme = 1;
}

void virtualization::setup_host(svm::pvcpu_t vcpu) {
    svm::cr3_t& host_cr3 = vcpu->host_vmcb.state_save_area.cr3;
    host_cr3.value = 0;
    host_cr3.pcd = 0;
    host_cr3.pwt = 0;
    host_cr3.pml4 = MmGetPhysicalAddress(&shared_host_pt.pml4).QuadPart >> 12;
    svm::cr4_t& host_cr4 = vcpu->host_vmcb.state_save_area.cr4;
    host_cr4 = build_host_cr4();
    __writecr3(host_cr3.value);
    __writecr4(host_cr4.value);
    svm::descriptor_table_register_t host_idtr{};
    host_idtr.limit = 0xFFF;
    host_idtr.base = (uint64_t)vcpu->host_idt_entries;
    svm::descriptor_table_register_t host_gdtr{};
    host_gdtr.limit = vcpu->host_gdtr_limit;
    host_gdtr.base = (uintptr_t)vcpu->host_gdt_entries;
    __lidt(&host_idtr);
    __lgdt(&host_gdtr);
    __write_tr(vcpu->host_tr_selector);
    svm::hsave_pa_msr hsave_pa{.value = static_cast<uint64_t>(MmGetPhysicalAddress(&vcpu->host_state_area).QuadPart)};
    svm::pat_msr host_pat{};
    host_pat.pa0 = svm::attribute_type::write_back;
    host_pat.pa1 = svm::attribute_type::write_through;
    host_pat.pa2 = svm::attribute_type::uncacheable_no_write_combinining;
    host_pat.pa3 = svm::attribute_type::uncacheable;
    host_pat.pa4 = svm::attribute_type::write_back;
    host_pat.pa5 = svm::attribute_type::write_through;
    host_pat.pa6 = svm::attribute_type::uncacheable_no_write_combinining;
    host_pat.pa7 = svm::attribute_type::uncacheable;
    __writemsr(MSR_VM_HSAVE_PA, hsave_pa.value);
    __writemsr(MSR_PAT, host_pat.value);
}

bool virtualization::virtualize_processor(PVOID ctx) {
    UNREFERENCED_PARAMETER(ctx);

    svm::processor_number processor_number{};
    u32 processor_index = processor_number.get_processor_index();

    if (!is_core_virtualized(processor_index)) {
        svm::context_t current_ctx{};
        RtlCaptureContext(reinterpret_cast<PCONTEXT>(&current_ctx));
        constexpr u64 guest_resume_marker = 0x53564D524553554DULL;
        if (current_ctx.rax == guest_resume_marker && is_core_virtualized(processor_index)) {
            return true;
        }

        vcpus[processor_index] =
            reinterpret_cast<svm::pvcpu_t>(memory::get()->alloc_nonpaged_pool(sizeof(svm::vprocessor_data)));
        if (!vcpus[processor_index]) {
            debug::panicf("Failed allocating memory for VCPU\n");
            return false;
        }

        RtlZeroMemory(vcpus[processor_index], sizeof(svm::vprocessor_data));
        vcpus[processor_index]->host_stack_layout.shared_vcpu =
            reinterpret_cast<svm::pshared_vcpu_t>(memory::get()->alloc_nonpaged_pool(sizeof(svm::shared_vcpu)));
        if (!vcpus[processor_index]->host_stack_layout.shared_vcpu) {
            debug::panicf("Failed allocating memory for shared VCPU\n");
            release_vcpu(processor_index);
            return false;
        }

        RtlZeroMemory(vcpus[processor_index]->host_stack_layout.shared_vcpu, sizeof(svm::shared_vcpu));
        vcpus[processor_index]->host_stack_layout.active_msrpm =
            reinterpret_cast<msrpm_t*>(memory::get()->alloc_contiguous_memory(sizeof(msrpm_t)));
        if (!vcpus[processor_index]->host_stack_layout.active_msrpm) {
            debug::panicf("Failed allocating contiguous MSRPM\n");
            release_vcpu(processor_index);
            return false;
        }

        vcpus[processor_index]->host_stack_layout.shared_vcpu->os_type = utilities::get()->get_os_version();
        vcpus[processor_index]->host_stack_layout.shared_vcpu->system_eprocess =
            reinterpret_cast<_EPROCESS*>(PsInitialSystemProcess);
        vcpus[processor_index]->host_stack_layout.shared_vcpu->system_cr3 =
            *reinterpret_cast<svm::cr3_t*>(reinterpret_cast<u8*>(PsInitialSystemProcess) + 0x28);
        dr_handler::get()->prepare_debug_state(vcpus[processor_index]);
        idt::get()->prepare_host_idt(vcpus[processor_index]);
        gdt::get()->prepare_host_gdt(vcpus[processor_index]);
        if (!vcpus[processor_index]->host_tr_selector) {
            release_vcpu(processor_index);
            return false;
        }

        if (npt::get()->prepare_npt(vcpus[processor_index]->npt[npt::nested_page_table::primary],
                                    npt::nested_page_table::primary) != svm::svmroot_error_t::error_success) {
            release_vcpu(processor_index);
            return false;
        }

        if (npt::get()->prepare_npt(vcpus[processor_index]->npt[npt::nested_page_table::shadow],
                                    npt::nested_page_table::shadow) != svm::svmroot_error_t::error_success) {
            release_vcpu(processor_index);
            return false;
        }

        if (msrs::get()->prepare_msrpm(*vcpus[processor_index]->host_stack_layout.active_msrpm) !=
            svm::svmroot_error_t::error_success) {
            release_vcpu(processor_index);
            return false;
        }

        svm::efer_msr efer{};
        efer.value = __readmsr(MSR_EFER);
        efer.svme = 1;
        __writemsr(MSR_EFER, efer.value);
        current_ctx.rax = guest_resume_marker;
        setup_control_fields(vcpus[processor_index]);
        setup_guest(vcpus[processor_index], &current_ctx);

        if (!mmio::get()->prepare_mmio_pages(vcpus[processor_index])) {
            debug::panicf("Failed preparing TPM MMIO NPT pages\n");
            release_vcpu(processor_index);
            return false;
        }

        setup_host(vcpus[processor_index]);
        __svm_vmsave(vcpus[processor_index]->host_stack_layout.host_vmcb_pa);

        debug::panicf("Processor %u virtualized successfully\n", processor_index);
        vmenter(&vcpus[processor_index]->host_stack_layout.guest_vmcb_pa, &current_ctx);
        KeBugCheck(0xB16B00B5UL);
    }

    return true;
}

bool virtualization::devirtualize_processor(PVOID ctx) {
    svm::processor_number processor_number{};
    u32 processor_index = processor_number.get_processor_index();

    if (is_core_virtualized(processor_index)) {
        svm_vmmcall(vmmcall_codes::disable_hv, nullptr);
        idt::get()->restore_guest_idt(vcpus[processor_index]);
        gdt::get()->restore_guest_gdt(vcpus[processor_index]);
        release_vcpu(processor_index);
        debug::panicf("Processor %u is devirtualized\n", processor_index);
    } else {
        debug::panicf("Processor %u is not virtualized\n", processor_index);
        return false;
    }

    return true;
}

bool virtualization::virtualize() {
    logs::get()->initialize();

    if (!utilities::get()->check_support()) {
        debug::panicf("Your processor does not support virtualization\n");
        return false;
    }

    if (memory::get()->prepare_host_page_tables() != svm::svmroot_error_t::error_success) {
        debug::panicf("Failed preparing host page tables\n");
        return false;
    }

    if (!mmio::get()->register_mmio_range(0xFED40000ULL, 0xFED44FFFULL)) {
        debug::panicf("Failed registering TPM MMIO range 0x%llx-0x%llx\n", 0xFED40000ULL, 0xFED44FFFULL);
        return false;
    }

    for (ULONG i = 0; i < processor_count; i++) {
        PROCESSOR_NUMBER processor_number = {0};
        NTSTATUS status = KeGetProcessorNumberFromIndex(i, &processor_number);

        if (!NT_SUCCESS(status)) {
            debug::panicf("Failed to get processor number from index %u\n", i);
            return false;
        }

        GROUP_AFFINITY affinity = {0};
        affinity.Group = processor_number.Group;
        affinity.Mask = 1ULL << processor_number.Number;
        GROUP_AFFINITY old_affinity;
        KeSetSystemGroupAffinityThread(&affinity, &old_affinity);
        bool result = virtualize_processor(nullptr);
        KeRevertToUserGroupAffinityThread(&old_affinity);

        if (!result) {
            debug::panicf("Failed virtualizing processor %u\n", i);
            return false;
        }
    }

    return true;
}

void virtualization::devirtualize() {
    npt::get()->cleanup();

    for (ULONG i = 0; i < processor_count; i++) {
        PROCESSOR_NUMBER processor_number = {0};
        NTSTATUS status = KeGetProcessorNumberFromIndex(i, &processor_number);

        if (!NT_SUCCESS(status)) {
            debug::panicf("Failed to get processor number from index %u\n", i);
            continue;
        }

        GROUP_AFFINITY affinity = {0};
        affinity.Group = processor_number.Group;
        affinity.Mask = 1ULL << processor_number.Number;
        GROUP_AFFINITY old_affinity;
        KeSetSystemGroupAffinityThread(&affinity, &old_affinity);
        bool result = devirtualize_processor(nullptr);
        KeRevertToUserGroupAffinityThread(&old_affinity);

        if (!result) {
            debug::panicf("Failed devirtualizing processor %u\n", i);
        }
    }
}

virtualization* virtualization::get() {
    static virtualization instance;
    return &instance;
}
}
