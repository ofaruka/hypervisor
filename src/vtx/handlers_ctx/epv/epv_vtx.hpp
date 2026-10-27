#pragma once
#include "../../../includes.h"

namespace vtx {

class epv_handler {
private:
    epv_handler() = default;

public:
    static auto get() -> epv_handler*;

    // Returns true if the violation matched a hook entry and was rearmed
    // (caller resumes guest). Returns false on unknown GPA — caller treats
    // as fatal.
    auto epv_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> bool;
};

}
