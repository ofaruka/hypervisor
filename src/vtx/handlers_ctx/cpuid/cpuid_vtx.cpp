#include "cpuid_vtx.hpp"

namespace vtx {

auto cpuid_handler::get() -> cpuid_handler* {
    static cpuid_handler instance;
    return &instance;
}

auto cpuid_handler::cpuid_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> void {
    u32 leaf = static_cast<u32>(gprs->rax & MAXUINT);
    u32 subleaf = static_cast<u32>(gprs->rcx & MAXUINT);
    const auto hyperv_leaf = leaf >= CPUID_HV_VENDOR_ID && leaf <= CPUID_HV_RANGE_END;

    int leaf0[4];
    __cpuidex(leaf0, 0, 0);
    const auto max_basic_leaf = static_cast<u32>(leaf0[0]);
    if (!hyperv_leaf && leaf > max_basic_leaf && leaf < CPUID_LEAF_EXTENDED_BASE) {
        leaf = max_basic_leaf;
    }

    int regs[4];
    u64 cpuid_cost = 0;
    if (hyperv_leaf) {
        RtlZeroMemory(regs, sizeof(regs));
    }
    else {
        // Timing the host-side execution gives the native (bare-metal) cost
        // of the instruction the guest tried to run.
        const u64 cpuid_start = __rdtsc();
        __cpuidex(regs, leaf, subleaf);
        cpuid_cost = __rdtsc() - cpuid_start;
    }

    cpuid_result_t result{};
    result.eax = static_cast<u32>(regs[0]);
    result.ebx = static_cast<u32>(regs[1]);
    result.ecx = static_cast<u32>(regs[2]);
    result.edx = static_cast<u32>(regs[3]);

    switch (leaf) {
    case CPUID_LEAF_FEATURE_INFO:
        result.ecx |= (1u << 31);
        result.ecx &= ~static_cast<u32>(cpuid::cpu_ecx_vmx);
        break;

    case CPUID_HV_VENDOR_ID:
        result.eax = CPUID_HV_MAX_LEAF;
        result.ebx = 0x7263694D;
        result.ecx = 0x666F736F;
        result.edx = 0x76482074;
        break;

    case CPUID_HV_INTERFACE:
        result.eax = 0x31237648;
        break;

    case CPUID_HV_VERSION: {
        RTL_OSVERSIONINFOW version{};
        version.dwOSVersionInfoSize = sizeof(version);
        if (NT_SUCCESS(RtlGetVersion(&version))) {
            result.eax = version.dwBuildNumber;
            result.ebx = (version.dwMajorVersion << 16) | version.dwMinorVersion;
        }
        break;
    }

    // Values mirror a real bare-metal Hyper-V root partition (captured on a
    // Windows host with the hypervisor active). Invented bitmasks here are
    // cross-checked by anti-cheat against the other VBS channels.
    case CPUID_HV_FEATURES:
        // Bit 5 (AccessHypercallMsrs) must stay clear: this hypervisor cannot
        // back the Hyper-V MSR interface. When the bit was set, the guest
        // established no hypercall page (the WRMSRs #GP) but still issued
        // hypercalls on the DMA-enrollment path, crashing in
        // nt!HvlMapDmaRanges during PCI device start (0xA reading [0x10]).
        result.eax = 0x0000BFDF;
        // EBX bit 12 must also stay clear: pci!PciMapDmaRanges gates its
        // HvlMapDmaRanges call on CPUID.0x40000003:EBX bit 12 (checked via
        // HviGetHypervisorFeatures when a hypervisor is present). With the bit
        // set, every PCI device start issues a hypercall through the null
        // hypercall page and bugchecks 0xA.
        result.ebx = 0x002BA9FF;
        result.ecx = 0x00000022;
        result.edx = 0x71FFFBF6;
        break;

    case CPUID_HV_ENLIGHTENMENTS:
        result.eax = 0x00050D1C;
        result.ebx = 0x00000FFF;
        break;

    case CPUID_HV_LIMITS:
        result.eax = 0x00000400;
        result.ebx = 0x00000400;
        result.ecx = 0x0000BA00;
        break;

    case CPUID_HV_HARDWARE:
        // Clear DmaRemappingInUse (bit 4), InterruptRemappingInUse (bit 5) and
        // DMAProtectionInUse (bit 7). Advertising them made pci.sys enroll every
        // starting device into a hypervisor DMA domain via HvlMapDmaRanges,
        // which requires working hypercalls this hypervisor cannot service.
        result.eax = 0x001E000E;
        break;

    case CPUID_HV_CPU_MANAGEMENT:
        result.eax = 0x80000007;
        result.ebx = 0x00000003;
        break;

    case CPUID_HV_SVM_FEATURES:
        result.eax = 0x00100001;
        result.ebx = 0x00000001;
        result.ecx = 0x0000AAAA;
        break;

    // Isolation type: 1 = VBS. 2 would claim AMD SEV-SNP (confidential VM),
    // which contradicts leaf 0x8000001F on non-SNP machines.
    case CPUID_HV_VBS_STATUS:
        result.ebx = 0x00000001;
        break;

    default:
        break;
    }

    gprs->rax = result.eax;
    gprs->rbx = result.ebx;
    gprs->rcx = result.ecx;
    gprs->rdx = result.edx;

    if (vcpu) {
        // Only basic-leaf cpuids feed the estimate: those are the cheap ones
        // timing checks execute, and mixing in expensive leaves (0xD, 0x1F)
        // would inflate the "native cpuid cost" beyond what a guest sees.
        if (cpuid_cost && leaf <= 1) {
            vcpu->measured_cpuid_delta = vcpu->measured_cpuid_delta
                ? (vcpu->measured_cpuid_delta * 7 + cpuid_cost) / 8
                : cpuid_cost;
        }

        auto timing = timing_handler::get();
        const u64 adjustment = timing->calculated_cpuid_adjustment(vcpu);
        auto guest_entry_tsc = vcpu->vmexit_entry_tsc + vcpu->tsc_offset;
        vcpu->cpuid_exit_tsc = guest_entry_tsc > adjustment
            ? guest_entry_tsc - adjustment
            : guest_entry_tsc;

        _mm_lfence();
        auto t1 = __rdtsc();
        _mm_lfence();
        auto t2 = __rdtsc();
        auto sample = t2 - t1;
        vcpu->measured_rdtsc_delta = vcpu->measured_rdtsc_delta
            ? (vcpu->measured_rdtsc_delta * 7 + sample) / 8
            : sample;

        timing->synthesize_cpuid_timing(vcpu);
        timing->arm_timing_exiting(vcpu);
    }
}

}
