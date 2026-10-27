#pragma once
#include "../../../includes.h"

namespace svm {

class gif_handler {
  private:
    gif_handler() = default;

  public:
    static gif_handler* get();
    void gif_exit_handler(pvcpu_t vcpu);
};

}
