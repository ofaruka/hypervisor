#pragma once
#include "../includes.h"

namespace svm {

class virtualization {
  private:
    virtualization();
    svm::cr4_t build_host_cr4() const;
    void release_vcpu(u32 processor_index);
    u32 processor_count;

  public:
    static virtualization* get();
    svm::pvcpu_t* vcpus;
    host_pt_t shared_host_pt;
    u32 get_processor_count() const {
        return processor_count;
    }
    bool is_core_virtualized(u32 core_number);
    bool virtualize();
    void devirtualize();
    void setup_control_fields(svm::pvcpu_t vcpu);
    void setup_guest(svm::pvcpu_t vcpu, const svm::pcontext_t ctx);
    void setup_host(svm::pvcpu_t vcpu);
    bool virtualize_processor(PVOID ctx);
    bool devirtualize_processor(PVOID ctx);
};
}
