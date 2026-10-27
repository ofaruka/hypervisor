#pragma once
#include "../../includes.h"

namespace vtx
{
    enum class cpuid : uint32_t
    {
        cpu_vendor_string = 0x00000000,
        processor_feature_id = 0x00000001,
        hypervisor_present_ex = 0x80000000,
        hypervisor_vendor_id = 0x40000000,
        hypervisor_interface = 0x40000001,

        cpu_ecx_vmx = 0x20,             // CPUID(1).ECX bit 5
    };

    enum msr : uint32_t
    {
        ia32_feature_control = 0x0000003a,
        ia32_vmx_basic = 0x00000480,
        ia32_vmx_pinbased_ctls = 0x00000481,
        ia32_vmx_procbased_ctls = 0x00000482,
        ia32_vmx_exit_ctls = 0x00000483,
        ia32_vmx_entry_ctls = 0x00000484,
        ia32_vmx_misc = 0x00000485,
        ia32_vmx_cr0_fixed0 = 0x00000486,
        ia32_vmx_cr0_fixed1 = 0x00000487,
        ia32_vmx_cr4_fixed0 = 0x00000488,
        ia32_vmx_cr4_fixed1 = 0x00000489,
        ia32_vmx_procbased_ctls2 = 0x0000048b,
        ia32_vmx_true_pinbased_ctls = 0x0000048d,
        ia32_vmx_true_procbased_ctls = 0x0000048e,
        ia32_vmx_true_exit_ctls = 0x0000048f,
        ia32_vmx_true_entry_ctls = 0x00000490,
        ia32_vmx_ept_vpid_cap = 0x0000048c,

        feature_control_lock = 0x1,
        feature_control_vmx_in_smx = 0x2,
        feature_control_vmx_outside_smx = 0x4,
    };

    enum vtxroot_error_t : u64
    {
        error_success,
        vmx_not_supported,
        vmx_disabled_in_bios,
        ept_not_supported,
        invalid_guest_physical,
        invalid_guest_virtual,
        ept_pte_not_present,
        page_table_init_failed,
        vmxon_failed,
        vmclear_failed,
        vmptrld_failed,
        vmwrite_failed,
        vmlaunch_failed,
        error_failed,
    };
}
