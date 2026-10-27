#pragma once
#include "../includes.h"

namespace svm {

class nmi_handler {
  public:
    static nmi_handler* get();
    void nmi_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx);
};
}
