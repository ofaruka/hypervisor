#pragma once
#include "../includes.h"

namespace svm {

class msrs {
  private:
    void setup_svm_msrs(msrpm_t& msrpm);
    void setup_system_msrs(msrpm_t& msrpm);
    void setup_perf_msrs(msrpm_t& msrpm);
    void setup_syscfg_msrs(msrpm_t& msrpm);
    void setup_debug_msrs(msrpm_t& msrpm);
    void setup_lbr_msrs(msrpm_t& msrpm);
    void setup_feature_msrs(msrpm_t& msrpm);

  public:
    static msrs* get();
    svm::svmroot_error_t prepare_msrpm(msrpm_t& msrpm);
};
}
