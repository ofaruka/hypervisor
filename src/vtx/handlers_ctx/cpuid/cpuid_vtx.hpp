#pragma once
#include "../../../includes.h"

namespace vtx {

class cpuid_handler {
private:
    cpuid_handler() = default;

    enum cpuid_leaf : u32 {
        CPUID_LEAF_FEATURE_INFO      = 0x00000001,
        CPUID_LEAF_EXTENDED_BASE     = 0x80000000,
        CPUID_LEAF_EXTENDED_FEATURES = 0x80000001,
        CPUID_HV_VENDOR_ID           = 0x40000000,
        CPUID_HV_INTERFACE           = 0x40000001,
        CPUID_HV_VERSION             = 0x40000002,
        CPUID_HV_FEATURES            = 0x40000003,
        CPUID_HV_ENLIGHTENMENTS      = 0x40000004,
        CPUID_HV_LIMITS              = 0x40000005,
        CPUID_HV_HARDWARE            = 0x40000006,
        CPUID_HV_CPU_MANAGEMENT      = 0x40000007,
        CPUID_HV_SVM_FEATURES        = 0x40000008,
        CPUID_HV_VBS_STATUS          = 0x4000000C,
        CPUID_HV_MAX_LEAF            = CPUID_HV_VBS_STATUS,
        CPUID_HV_RANGE_END           = 0x400000FF,
    };

    struct cpuid_result_t {
        u32 eax;
        u32 ebx;
        u32 ecx;
        u32 edx;
    };

public:
    static auto get() -> cpuid_handler*;
    auto cpuid_exit_handler(pvcpu_t vcpu, guest_gprs* gprs) -> void;
};

}
