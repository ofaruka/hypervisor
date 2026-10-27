#pragma once
#include "../../includes.h"

namespace vtx {
    class utilities {
    private:
        utilities() = default;

    public:
        static utilities* get();

        // CPU and Virtualization Support
        bool is_intel();
        bool is_vmx_supported();
        bool is_ept_supported();
        bool can_vmx_be_enabled();
        bool ensure_feature_control();
        bool is_hypervisor_vendor_installed();
        bool check_support();
        void enable_vmxe();
    };
}
