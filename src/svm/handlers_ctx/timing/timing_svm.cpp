#include "timing_svm.hpp"

namespace svm {

namespace {
// Cross-vcpu calibration state. The exit-side latency and the instruction
// costs are microarchitecture constants, so every core feeds one estimate
// and convergence does not restart when a process migrates.
u64 g_min_exit_roundtrip = 0;
u64 g_measured_cpuid_delta = 0;
u64 g_measured_rdtsc_delta = 0;
}

timing_handler* timing_handler::get() {
    static timing_handler instance;
    return &instance;
}

void timing_handler::arm_timing_exiting(pvcpu_t vcpu) {
    // rdtsc/rdtscp exits stay enabled permanently (setup_control_fields);
    // arming only marks that the next read may close a cpuid;rdtsc pair.
    vcpu->host_stack_layout.shadow_data.intercept_rdtsc_pending = true;
    vcpu->host_stack_layout.shadow_data.timing_window_open = true;
}

void timing_handler::record_cpuid_cost(u64 cost) {
    if (!cost) {
        return;
    }
    g_measured_cpuid_delta = g_measured_cpuid_delta
        ? (g_measured_cpuid_delta * 7 + cost) / 8
        : cost;
}

void timing_handler::record_rdtsc_cost(u64 cost) {
    if (!cost) {
        return;
    }
    g_measured_rdtsc_delta = g_measured_rdtsc_delta
        ? (g_measured_rdtsc_delta * 7 + cost) / 8
        : cost;
}

u64 timing_handler::calculated_cpuid_adjustment(pvcpu_t vcpu) {
    UNREFERENCED_PARAMETER(vcpu);

    // Exit-side latency estimate: tightest measured cpuid->rdtsc round-trip
    // minus the re-entry share (vmrun + one guest instruction). A minimum
    // statistic is used because the round-trip also contains the variable
    // vmrun/TLB-flush cost, while the exit side is stable -- only the
    // tightest samples approximate it. Seeded until the first sample.
    u64 exit_side = default_cpuid_exit_adjustment;
    if (g_min_exit_roundtrip > vmexit_reentry_overhead) {
        exit_side = g_min_exit_roundtrip - vmexit_reentry_overhead;
    }
    if (exit_side < 400) {
        exit_side = 400;
    }
    if (exit_side > 4000) {
        exit_side = 4000;
    }

    const u64 adjustment = exit_side > g_measured_cpuid_delta
        ? exit_side - g_measured_cpuid_delta
        : exit_side;
    return adjustment < 200 ? 200 : adjustment;
}

void timing_handler::synthesize_cpuid_anchor(pvcpu_t vcpu) {
    const u64 guest_entry_tsc =
        vcpu->host_stack_layout.vmexit_entry_tsc + vcpu->guest_vmcb.control_area.tsc_offset;
    const u64 adjustment = calculated_cpuid_adjustment(vcpu);
    vcpu->cpuid_exit_tsc = guest_entry_tsc > adjustment ? guest_entry_tsc - adjustment : guest_entry_tsc;
}

void timing_handler::record_exit_overhead_sample(pvcpu_t vcpu, u64 window) {
    vcpu->last_timing_window = window;
    if (window < exit_overhead_sample_min || window > exit_overhead_sample_max) {
        return;
    }

    if (!g_min_exit_roundtrip || window < g_min_exit_roundtrip) {
        g_min_exit_roundtrip = window;
    }
}

rdtsc_track_t& timing_handler::tracked_read(pvcpu_t vcpu) {
    const u32 index = vcpu->guest_vmcb.state_save_area.cpl ? 1 : 0;
    return vcpu->last_rdtsc[index];
}

bool timing_handler::is_cpuid_pair(pvcpu_t vcpu) {
    // The intercepted read closes a cpuid;rdtsc pair only when it sits right
    // after the arming cpuid in the guest instruction stream (a few bytes of
    // result stores in between are fine). This bounds the anchor's staleness
    // structurally: anything else is an unrelated consumer of an old anchor.
    if (!vcpu->host_stack_layout.shadow_data.intercept_rdtsc_pending) {
        return false;
    }

    const i64 distance =
        static_cast<i64>(vcpu->guest_vmcb.state_save_area.rip - vcpu->armed_cpuid_rip);
    return distance > 0 && distance <= static_cast<i64>(armed_cpuid_max_distance);
}

bool timing_handler::is_sequential_read(pvcpu_t vcpu) {
    // Two rdtsc reads a few bytes apart in the instruction stream are a
    // back-to-back granularity probe. A loop re-reading the same RIP has
    // distance 0 and gets the real clock, so stall loops cannot freeze.
    const i64 distance =
        static_cast<i64>(vcpu->guest_vmcb.state_save_area.rip - tracked_read(vcpu).rip);
    return distance > 0 && distance <= static_cast<i64>(sequential_rdtsc_max_distance);
}

u64 timing_handler::pair_value(pvcpu_t vcpu, u64 entry_tsc) {
    // Anchor to the guest's own last rdtsc when it is close: the pair then
    // reproduces exactly the native cpuid cost, independent of any preemption
    // between the two reads. Only a read from the same CPL and the same
    // process qualifies, so kernel or other-process readers in between (e.g.
    // during a preemption) cannot clobber the detector's t1. Otherwise fall
    // back to the cpuid-exit anchor.
    auto& last = tracked_read(vcpu);
    const u64 since_last = entry_tsc - last.entry_tsc;
    if (last.entry_tsc && last.cr3 == vcpu->guest_vmcb.state_save_area.cr3.value &&
        since_last <= t1_anchor_max_window) {
        return last.value + g_measured_cpuid_delta + g_measured_rdtsc_delta;
    }

    return vcpu->cpuid_exit_tsc + g_measured_rdtsc_delta;
}

void timing_handler::rdtsc_exit_handler(pvcpu_t vcpu, pguest_ctx_t guest_ctx) {
    auto& shadow_data = vcpu->host_stack_layout.shadow_data;
    const u64 entry_tsc = vcpu->host_stack_layout.vmexit_entry_tsc;

    u64 value = 0;
    if (is_cpuid_pair(vcpu)) {
        value = pair_value(vcpu, entry_tsc);
        record_exit_overhead_sample(vcpu, entry_tsc - vcpu->vmexit_leave_tsc);
    }
    else if (is_sequential_read(vcpu)) {
        // Back-to-back rdtsc (granularity probe): report the native cost of
        // one rdtsc so the pair looks bare-metal.
        value = tracked_read(vcpu).value + g_measured_rdtsc_delta;
    }
    else {
        value = __rdtsc();
    }
    shadow_data.intercept_rdtsc_pending = false;

    // Every intercepted read is tracked per CPL and process: with exits
    // permanently enabled, the guest's next cpuid;rdtsc pair can anchor to
    // this exact value (its t1).
    auto& last = tracked_read(vcpu);
    last.entry_tsc = entry_tsc;
    last.value = value;
    last.rip = vcpu->guest_vmcb.state_save_area.rip;
    last.cr3 = vcpu->guest_vmcb.state_save_area.cr3.value;

    guest_ctx->vprocessor_registers->rax.value = value & MAXUINT;
    guest_ctx->vprocessor_registers->rdx.value = value >> 32;
    vcpu->guest_vmcb.state_save_area.rip = advance_rip_or_next(vcpu, 2);
}

void timing_handler::rdtscp_exit_handler(pvcpu_t vcpu, pguest_ctx_t guest_ctx) {
    auto& shadow_data = vcpu->host_stack_layout.shadow_data;
    const u64 entry_tsc = vcpu->host_stack_layout.vmexit_entry_tsc;

    unsigned int aux = 0;
    const u64 host_value = __rdtscp(&aux);

    u64 value = 0;
    if (is_cpuid_pair(vcpu)) {
        value = pair_value(vcpu, entry_tsc);
        record_exit_overhead_sample(vcpu, entry_tsc - vcpu->vmexit_leave_tsc);
    }
    else if (is_sequential_read(vcpu)) {
        value = tracked_read(vcpu).value + g_measured_rdtsc_delta;
    }
    else {
        value = host_value;
    }
    shadow_data.intercept_rdtsc_pending = false;

    auto& last = tracked_read(vcpu);
    last.entry_tsc = entry_tsc;
    last.value = value;
    last.rip = vcpu->guest_vmcb.state_save_area.rip;
    last.cr3 = vcpu->guest_vmcb.state_save_area.cr3.value;

    guest_ctx->vprocessor_registers->rax.value = value & MAXUINT;
    guest_ctx->vprocessor_registers->rdx.value = value >> 32;
    guest_ctx->vprocessor_registers->rcx.value = aux;
    vcpu->guest_vmcb.state_save_area.rip = advance_rip_or_next(vcpu, 3);
}

}
