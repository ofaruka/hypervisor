#pragma once
#include "../../../includes.h"

namespace svm {

class event_handler {
  private:
    event_handler() = default;

  public:
    static event_handler* get();
    void debug_exception_exit_handler(pvcpu_t vcpu);
    void general_protection_exit_handler(pvcpu_t vcpu);
    void invalid_opcode_exit_handler(pvcpu_t vcpu);
};

}
