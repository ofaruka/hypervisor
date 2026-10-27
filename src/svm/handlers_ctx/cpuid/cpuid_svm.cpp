#include "cpuid_svm.hpp"

namespace svm {

cpuid_handler* cpuid_handler::get() {
    static cpuid_handler instance;
    return &instance;
}

void cpuid_handler::cpuid_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    const auto gprs = guest_ctx->vprocessor_registers;
    const auto leaf = static_cast<u32>(gprs->rax.value & MAXUINT);
    const auto subleaf = static_cast<u32>(gprs->rcx.value & MAXUINT);
    const auto hyperv_leaf = leaf >= CPUID_HV_VENDOR_ID && leaf <= CPUID_HV_RANGE_END;

    int regs[4];
    u64 cpuid_cost = 0;
    if (hyperv_leaf) {
        RtlZeroMemory(regs, sizeof(regs));
    }
    else {
        // Timing the host-side execution gives the native (bare-metal) cost
        // of the instruction the guest tried to run.
        const u64 cpuid_start = __rdtsc();
        __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
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
        break;

    case CPUID_LEAF_EXTENDED_FEATURES:
        result.ecx &= ~static_cast<u32>(cpuid::cpu_ecx_svm);
        break;

    case CPUID_LEAF_SVM_REVISION:
        result = {};
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

    case CPUID_HV_VERSION:
        // Replicate this machine's pre-spoof baseline exactly (captured by
        // vg_probe_before.txt while the native VBS Hyper-V was active):
        // EAX = hvix64 build 26100, EBX = major/minor 10.0, ECX = 9,
        // EDX = 0x23D0 (branch build). Reporting the guest OS build via
        // RtlGetVersion instead (26200 here) diverges from what the machine
        // natively answers - a hypervisor-identity delta between probe runs.
        result.eax = 0x000065F4;
        result.ebx = 0x000A0000;
        result.ecx = 0x00000009;
        result.edx = 0x000023D0;
        break;

    case CPUID_HV_FEATURES:
        result.eax = 0x0000BFDF;
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

    case CPUID_HV_VBS_STATUS:
        result.ebx = 0x00000001;
        break;

    default:
        break;
    }

    gprs->rax.value = result.eax;
    gprs->rbx.value = result.ebx;
    gprs->rcx.value = result.ecx;
    gprs->rdx.value = result.edx;

    if (vcpu) {
        auto timing = timing_handler::get();
        vcpu->armed_cpuid_rip = vcpu->guest_vmcb.state_save_area.rip;

        // Only basic-leaf cpuids feed the estimate: those are the cheap ones
        // timing checks execute, and mixing in expensive leaves (0xD, 0x1F)
        // would inflate the "native cpuid cost" beyond what a guest sees.
        if (cpuid_cost && leaf <= 1) {
            timing->record_cpuid_cost(cpuid_cost);
        }

        _mm_lfence();
        const u64 t1 = __rdtsc();
        _mm_lfence();
        const u64 t2 = __rdtsc();
        timing->record_rdtsc_cost(t2 - t1);

        timing->synthesize_cpuid_anchor(vcpu);
        timing->arm_timing_exiting(vcpu);
    }

    vcpu->guest_vmcb.state_save_area.rip = advance_rip_or_next(vcpu, 2);
}
}
