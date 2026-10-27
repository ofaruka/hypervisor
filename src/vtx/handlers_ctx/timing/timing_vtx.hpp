#pragma once
#include "../../../includes.h"

namespace vtx {

class timing_handler {
private:
    timing_handler() = default;

public:
    static auto get() -> timing_handler*;

    auto arm_timing_exiting(pvcpu_t vcpu) -> void;
    auto arm_timing_record(pvcpu_t vcpu) -> void;
    auto clear_timing_exiting(pvcpu_t vcpu) -> void;
    auto adjusted_tsc(pvcpu_t vcpu) -> u64;
    auto calculated_cpuid_adjustment(pvcpu_t vcpu) -> u64;
    auto record_exit_overhead_sample(pvcpu_t vcpu, u64 window) -> void;
    auto record_timing_read(pvcpu_t vcpu, u8 source, u64 value) -> void;
    auto consume_timing_read(pvcpu_t vcpu, u8 source, u64& value) -> bool;
    auto synthesize_cpuid_timing(pvcpu_t vcpu) -> void;
    auto capture_fixed_counters(pvcpu_t vcpu) -> void;
    auto rdpmc_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool;
    auto rdtsc_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool;
    auto rdtscp_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool;

private:
    auto guest_cpl() -> u8;
    auto guest_cr4() -> u64;
    auto read_pmc(u32 counter, u64& value) -> bool;
    auto read_timing_counter(u8 source, u64& value) -> bool;
    auto measure_cpuid_timing_delta(u8 source, u64& delta) -> bool;
    auto pmc_adjustment(pvcpu_t vcpu, u32 counter) -> u64;
};

}
