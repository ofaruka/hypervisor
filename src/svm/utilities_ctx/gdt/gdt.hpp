#pragma once
#include "../includes.h"

namespace svm {

class gdt {
  private:
    static constexpr size_t IST_STACK_SIZE = 0x4000;
    u16 setup_tss(svm::pvcpu_t vcpu);

  public:
    void prepare_host_gdt(svm::pvcpu_t vcpu);
    void restore_guest_gdt(svm::pvcpu_t vcpu);
    static gdt* get();
};
}
