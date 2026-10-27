#pragma once
#include "../includes.h"

namespace svm {

class hide_page {
  private:
    KSPIN_LOCK hide_lock;

  public:
    hide_page();
    static hide_page* get();
    auto hide_physical_page(svm::pvcpu_t vcpu, u64 page_pfn) -> svm::svmroot_error_t;
    auto unhide_physical_page(svm::pvcpu_t vcpu, u64 page_pfn) -> svm::svmroot_error_t;
};
}
