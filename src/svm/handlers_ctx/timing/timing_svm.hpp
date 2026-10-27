#pragma once
#include "../../../includes.h"

namespace svm {

class timing_handler {
  private:
    timing_handler() = default;

  public:
    static timing_handler* get();
    void arm_timing_exiting(pvcpu_t vcpu);
    void synthesize_cpuid_anchor(pvcpu_t vcpu);
    void record_cpuid_cost(u64 cost);
    void record_rdtsc_cost(u64 cost);
    void rdtsc_exit_handler(pvcpu_t vcpu, pguest_ctx_t guest_ctx);
    void rdtscp_exit_handler(pvcpu_t vcpu, pguest_ctx_t guest_ctx);

  private:
    u64 calculated_cpuid_adjustment(pvcpu_t vcpu);
    void record_exit_overhead_sample(pvcpu_t vcpu, u64 window);
    bool is_cpuid_pair(pvcpu_t vcpu);
    bool is_sequential_read(pvcpu_t vcpu);
    rdtsc_track_t& tracked_read(pvcpu_t vcpu);
    u64 pair_value(pvcpu_t vcpu, u64 entry_tsc);
};

}
