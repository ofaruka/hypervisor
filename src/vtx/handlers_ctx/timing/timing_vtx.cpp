#include "timing_vtx.hpp"

namespace vtx {

auto timing_handler::get() -> timing_handler* {
    static timing_handler instance;
    return &instance;
}

auto timing_handler::arm_timing_exiting(pvcpu_t vcpu) -> void {
    if (!vcpu) return;

    size_t controls = 0;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::procbased_ctls), &controls) == 0) {
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::procbased_ctls),
                      controls | procbased_rdtsc_exiting | procbased_rdpmc_exiting);
    }
    vcpu->intercept_rdtsc_pending = 1;
    vcpu->timing_record_next = 0;
    vcpu->timing_window_open = 1;
}

auto timing_handler::arm_timing_record(pvcpu_t vcpu) -> void {
    if (!vcpu) return;

    size_t controls = 0;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::procbased_ctls), &controls) == 0) {
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::procbased_ctls),
                      controls | procbased_rdtsc_exiting | procbased_rdpmc_exiting);
    }
    vcpu->intercept_rdtsc_pending = 0;
    vcpu->synthetic_timing_source = timing_source_none;
    vcpu->timing_record_next = 1;
}

auto timing_handler::clear_timing_exiting(pvcpu_t vcpu) -> void {
    if (!vcpu) return;

    vcpu->intercept_rdtsc_pending = 0;
    vcpu->synthetic_timing_source = timing_source_none;
    vcpu->timing_record_next = 0;
    vcpu->timing_window_open = 0;

    size_t controls = 0;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::procbased_ctls), &controls) == 0) {
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::procbased_ctls),
                      controls & ~(procbased_rdtsc_exiting | procbased_rdpmc_exiting));
    }
}

auto timing_handler::calculated_cpuid_adjustment(pvcpu_t vcpu) -> u64 {
    if (!vcpu) return cpuid_tsc_entry_adjustment;

    // Exit-side latency estimate: tightest measured cpuid->rdtsc round-trip
    // minus the re-entry share (vmresume + one guest instruction). A minimum
    // statistic is used because the round-trip also contains the variable
    // vmresume/TLB-flush cost, while the exit side is stable -- only the
    // tightest samples approximate it. Tuned constant until the first sample.
    u64 exit_side = 0;
    if (vcpu->measured_exit_overhead > vmexit_reentry_overhead) {
        exit_side = vcpu->measured_exit_overhead - vmexit_reentry_overhead;
    }
    if (exit_side < 400) {
        if (!vcpu->measured_exit_overhead) return cpuid_tsc_entry_adjustment;
        exit_side = 400;
    }
    if (exit_side > 4000) exit_side = 4000;

    // The guest should observe the native cost of the intercepted cpuid
    // (measured on the host) plus one rdtsc, so subtract everything else.
    const u64 adjustment = exit_side > vcpu->measured_cpuid_delta
        ? exit_side - vcpu->measured_cpuid_delta
        : exit_side;
    return adjustment < 200 ? 200 : adjustment;
}

auto timing_handler::record_exit_overhead_sample(pvcpu_t vcpu, u64 window) -> void {
    if (!vcpu) return;
    if (window < exit_overhead_sample_min || window > exit_overhead_sample_max) return;

    if (!vcpu->measured_exit_overhead || window < vcpu->measured_exit_overhead) {
        vcpu->measured_exit_overhead = window;
    }
}

auto timing_handler::adjusted_tsc(pvcpu_t vcpu) -> u64 {
    return vcpu && vcpu->intercept_rdtsc_pending
        ? vcpu->cpuid_exit_tsc + vcpu->measured_rdtsc_delta
        : __rdtsc() + (vcpu ? vcpu->tsc_offset : 0);
}

auto timing_handler::record_timing_read(pvcpu_t vcpu, u8 source, u64 value) -> void {
    if (!vcpu || !source) return;

    vcpu->last_timing_source = source;
    vcpu->last_timing_read_value = value;
    vcpu->last_timing_read_host_tsc = __rdtsc();
}

auto timing_handler::consume_timing_read(pvcpu_t vcpu, u8 source, u64& value) -> bool {
    if (!vcpu || !source || !vcpu->intercept_rdtsc_pending ||
        vcpu->synthetic_timing_source != source) return false;

    value = vcpu->synthetic_timing_value;
    vcpu->synthetic_timing_source = timing_source_none;
    arm_timing_record(vcpu);
    return true;
}

auto timing_handler::synthesize_cpuid_timing(pvcpu_t vcpu) -> void {
    if (!vcpu || vcpu->last_timing_source == timing_source_none ||
        vcpu->vmexit_entry_tsc - vcpu->last_timing_read_host_tsc >= 100000) {
        if (vcpu) vcpu->last_timing_source = timing_source_none;
        return;
    }

    u64 delta = 0;
    if (measure_cpuid_timing_delta(vcpu->last_timing_source, delta)) {
        auto synthetic = vcpu->last_timing_read_value + delta;
        vcpu->synthetic_timing_source = vcpu->last_timing_source;
        vcpu->synthetic_timing_value = synthetic;
        if (vcpu->last_timing_source == timing_source_tsc &&
            synthetic > vcpu->measured_rdtsc_delta) {
            vcpu->cpuid_exit_tsc = synthetic - vcpu->measured_rdtsc_delta;
        }
    }
    vcpu->last_timing_source = timing_source_none;
}

auto timing_handler::capture_fixed_counters(pvcpu_t vcpu) -> void {
    if (!vcpu) return;

    for (u32 i = 0; i < 3; ++i) {
        u64 value = 0;
        if (msr_handler::get()->read_raw_msr(MSR_IA32_FIXED_CTR0 + i, value)) {
            vcpu->fixed_ctr_exit[i] = value;
        }
    }
}

auto timing_handler::guest_cpl() -> u8 {
    size_t cs = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cs_sel), &cs);
    return static_cast<u8>(cs & 3);
}

auto timing_handler::guest_cr4() -> u64 {
    size_t cr4 = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cr4), &cr4);
    return cr4;
}

auto timing_handler::read_pmc(u32 counter, u64& value) -> bool {
    __try {
        value = __readpmc(counter);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        value = 0;
        return false;
    }
}

auto timing_handler::read_timing_counter(u8 source, u64& value) -> bool {
    switch (source) {
    case timing_source_tsc:
    case timing_source_rdtscp:
        return msr_handler::get()->read_raw_msr(MSR_TSC, value);
    case timing_source_aperf:
        return msr_handler::get()->read_raw_msr(MSR_IA32_APERF, value);
    case timing_source_mperf:
        return msr_handler::get()->read_raw_msr(MSR_IA32_MPERF, value);
    case timing_source_rdpmc_fixed1:
        return read_pmc((1u << 30) | 1, value);
    case timing_source_rdpmc_fixed2:
        return read_pmc((1u << 30) | 2, value);
    default:
        value = 0;
        return false;
    }
}

auto timing_handler::measure_cpuid_timing_delta(u8 source, u64& delta) -> bool {
    u64 start = 0;
    u64 end = 0;
    if (!read_timing_counter(source, start)) return false;
    int regs[4] = {};
    __cpuid(regs, 0);
    if (!read_timing_counter(source, end)) return false;
    delta = end - start;
    return end >= start;
}

auto timing_handler::pmc_adjustment(pvcpu_t vcpu, u32 counter) -> u64 {
    constexpr u32 fixed_counter_bit = 1u << 30;
    constexpr u32 cpu_clk_unhalted = 0x3c;

    const u64 adjustment = calculated_cpuid_adjustment(vcpu);

    if ((counter & fixed_counter_bit) != 0) {
        auto index = counter & 0x3fffffff;
        return index == 1 || index == 2 ? adjustment : 0;
    }

    auto index = counter & 0x3fffffff;
    if (index > 7) return 0;

    u64 evtsel = 0;
    if (!msr_handler::get()->read_raw_msr(MSR_PERFEVTSEL0 + index, evtsel)) return 0;
    return static_cast<u8>(evtsel) == cpu_clk_unhalted ? adjustment : 0;
}

auto timing_handler::rdpmc_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool {
    if (!vcpu || !gprs) return false;

    constexpr u64 cr4_pce_bit = 1ULL << 8;
    if (guest_cpl() != 0 && (guest_cr4() & cr4_pce_bit) == 0) {
        event_handler::get()->inject_gp(0);
        clear_timing_exiting(vcpu);
        return false;
    }

    u64 value = 0;
    auto counter = static_cast<u32>(gprs->rcx);
    constexpr u32 fixed_counter_bit = 1u << 30;
    if ((counter & fixed_counter_bit) != 0) {
        capture_fixed_counters(vcpu);

        auto index = counter & 0x3fffffff;
        auto source = index == 1 ? timing_source_rdpmc_fixed1 :
                      index == 2 ? timing_source_rdpmc_fixed2 :
                                   timing_source_none;
        if (consume_timing_read(vcpu, source, value)) {
            gprs->rax = static_cast<u32>(value);
            gprs->rdx = static_cast<u32>(value >> 32);
            return true;
        }

        if (index < 3) {
            value = vcpu->fixed_ctr_exit[index];
            auto adjustment = vcpu->intercept_rdtsc_pending ? pmc_adjustment(vcpu, counter) : 0;
            if (value > adjustment) value -= adjustment;
            if (!vcpu->intercept_rdtsc_pending) {
                if (index == 1) record_timing_read(vcpu, timing_source_rdpmc_fixed1, value);
                if (index == 2) record_timing_read(vcpu, timing_source_rdpmc_fixed2, value);
            }
            gprs->rax = static_cast<u32>(value);
            gprs->rdx = static_cast<u32>(value >> 32);
            if (vcpu->intercept_rdtsc_pending) clear_timing_exiting(vcpu);
            return true;
        }
    }

    if (!read_pmc(counter, value)) {
        event_handler::get()->inject_gp(0);
        clear_timing_exiting(vcpu);
        return false;
    }

    auto adjustment = vcpu->intercept_rdtsc_pending ? pmc_adjustment(vcpu, counter) : 0;
    if (value > adjustment) value -= adjustment;
    if (!vcpu->intercept_rdtsc_pending && ((counter & fixed_counter_bit) != 0)) {
        auto index = counter & 0x3fffffff;
        if (index == 1) record_timing_read(vcpu, timing_source_rdpmc_fixed1, value);
        if (index == 2) record_timing_read(vcpu, timing_source_rdpmc_fixed2, value);
    }

    gprs->rax = static_cast<u32>(value);
    gprs->rdx = static_cast<u32>(value >> 32);
    if (vcpu->intercept_rdtsc_pending) clear_timing_exiting(vcpu);
    return true;
}

auto timing_handler::rdtsc_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool {
    if (!vcpu || !gprs) return false;

    if (vcpu->timing_window_open) {
        vcpu->timing_window_open = 0;
        const u64 window = vcpu->vmexit_entry_tsc - vcpu->vmexit_leave_tsc;
        if (window > exit_window_stale_threshold && vcpu->intercept_rdtsc_pending) {
            // The anchor belongs to unrelated earlier guest code; never hand
            // it out -- the read gets the native clock instead.
            clear_timing_exiting(vcpu);
        }
        else {
            record_exit_overhead_sample(vcpu, window);
        }
    }

    constexpr u64 cr4_tsd_bit = 1ULL << 2;
    if (guest_cpl() != 0 && (guest_cr4() & cr4_tsd_bit) != 0) {
        event_handler::get()->inject_gp(0);
        clear_timing_exiting(vcpu);
        return false;
    }

    u64 tsc = 0;
    if (consume_timing_read(vcpu, timing_source_tsc, tsc)) {
        gprs->rax = static_cast<u32>(tsc);
        gprs->rdx = static_cast<u32>(tsc >> 32);
        return true;
    }

    tsc = adjusted_tsc(vcpu);
    gprs->rax = static_cast<u32>(tsc);
    gprs->rdx = static_cast<u32>(tsc >> 32);
    if (vcpu->intercept_rdtsc_pending) {
        arm_timing_record(vcpu);
    }
    else if (vcpu->timing_record_next) {
        record_timing_read(vcpu, timing_source_tsc, tsc);
        clear_timing_exiting(vcpu);
    }
    return true;
}

auto timing_handler::rdtscp_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool {
    if (!vcpu || !gprs) return false;

    if (vcpu->timing_window_open) {
        vcpu->timing_window_open = 0;
        const u64 window = vcpu->vmexit_entry_tsc - vcpu->vmexit_leave_tsc;
        if (window > exit_window_stale_threshold && vcpu->intercept_rdtsc_pending) {
            // The anchor belongs to unrelated earlier guest code; never hand
            // it out -- the read gets the native clock instead.
            clear_timing_exiting(vcpu);
        }
        else {
            record_exit_overhead_sample(vcpu, window);
        }
    }

    constexpr u64 cr4_tsd_bit = 1ULL << 2;
    if (guest_cpl() != 0 && (guest_cr4() & cr4_tsd_bit) != 0) {
        event_handler::get()->inject_gp(0);
        clear_timing_exiting(vcpu);
        return false;
    }

    u64 aux_msr = 0;
    msr_handler::get()->read_guest_msr(vcpu, MSR_TSC_AUX, aux_msr);

    u64 tsc = 0;
    if (consume_timing_read(vcpu, timing_source_rdtscp, tsc)) {
        gprs->rax = static_cast<u32>(tsc);
        gprs->rdx = static_cast<u32>(tsc >> 32);
        gprs->rcx = static_cast<u32>(aux_msr);
        return true;
    }

    tsc = adjusted_tsc(vcpu);
    gprs->rax = static_cast<u32>(tsc);
    gprs->rdx = static_cast<u32>(tsc >> 32);
    gprs->rcx = static_cast<u32>(aux_msr);
    if (vcpu->intercept_rdtsc_pending) {
        arm_timing_record(vcpu);
    }
    else if (vcpu->timing_record_next) {
        record_timing_read(vcpu, timing_source_rdtscp, tsc);
        clear_timing_exiting(vcpu);
    }
    return true;
}

}
    