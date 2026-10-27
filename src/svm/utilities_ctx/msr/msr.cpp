#include "msr.hpp"

namespace svm {

void msrs::setup_debug_msrs(msrpm_t& msrpm) {
    msrpm.set(MSR_DEBUG_CTL, access::read);
    msrpm.set(MSR_DEBUG_CTL, access::write);
    msrpm.set(MSR_TSC, access::read);
    msrpm.set(MSR_TSC, access::write);
}

void msrs::setup_system_msrs(msrpm_t& msrpm) {
    msrpm.set(MSR_PAT, access::read);
    msrpm.set(MSR_PAT, access::write);
    msrpm.set(MSR_LSTAR, access::read);
    msrpm.set(MSR_LSTAR, access::write);
    msrpm.set(MSR_CSTAR, access::read);
    msrpm.set(MSR_CSTAR, access::write);
    msrpm.set(MSR_SFMASK, access::read);
    msrpm.set(MSR_SFMASK, access::write);
    msrpm.set(MSR_SYSENTER_CS, access::read);
    msrpm.set(MSR_SYSENTER_CS, access::write);
    msrpm.set(MSR_SYSENTER_ESP, access::read);
    msrpm.set(MSR_SYSENTER_ESP, access::write);
    msrpm.set(MSR_SYSENTER_EIP, access::read);
    msrpm.set(MSR_SYSENTER_EIP, access::write);
}

void msrs::setup_perf_msrs(msrpm_t& msrpm) {
    msrpm.set(MSR_IA32_MPERF, access::read);
    msrpm.set(MSR_IA32_MPERF, access::write);
    msrpm.set(MSR_IA32_APERF, access::read);
    msrpm.set(MSR_IA32_APERF, access::write);
    msrpm.set(MSR_PERF_CTR0, access::read);
    msrpm.set(MSR_PERF_CTR0, access::write);
    msrpm.set(MSR_PERF_CTR1, access::read);
    msrpm.set(MSR_PERF_CTR1, access::write);
    msrpm.set(MSR_PERF_CTR2, access::read);
    msrpm.set(MSR_PERF_CTR2, access::write);
    msrpm.set(MSR_PERF_CTR3, access::read);
    msrpm.set(MSR_PERF_CTR3, access::write);
    msrpm.set(MSR_PERFEVTSEL0, access::read);
    msrpm.set(MSR_PERFEVTSEL0, access::write);
    msrpm.set(MSR_PERFEVTSEL1, access::read);
    msrpm.set(MSR_PERFEVTSEL1, access::write);
    msrpm.set(MSR_PERFEVTSEL2, access::read);
    msrpm.set(MSR_PERFEVTSEL2, access::write);
    msrpm.set(MSR_PERFEVTSEL3, access::read);
    msrpm.set(MSR_PERFEVTSEL3, access::write);
}

void msrs::setup_svm_msrs(msrpm_t& msrpm) {
    msrpm.set(MSR_EFER, access::read);
    msrpm.set(MSR_EFER, access::write);
    msrpm.set(MSR_VM_HSAVE_PA, access::read);
    msrpm.set(MSR_VM_HSAVE_PA, access::write);
    msrpm.set(MSR_VM_CR, access::read);
    msrpm.set(MSR_VM_CR, access::write);
    msrpm.set(MSR_DEBUG_CTL, access::read);
    msrpm.set(MSR_DEBUG_CTL, access::write);
}

void msrs::setup_syscfg_msrs(msrpm_t& msrpm) {
    msrpm.set(MSR_HWCR, access::read);
    msrpm.set(MSR_HWCR, access::write);
    msrpm.set(MSR_K8_SYSCFG, access::read);
    msrpm.set(MSR_K8_SYSCFG, access::write);
}

void msrs::setup_lbr_msrs(msrpm_t& msrpm) {
    msrpm.set(MSR_LASTBRANCHFROMIP, access::read);
    msrpm.set(MSR_LASTBRANCHFROMIP, access::write);
    msrpm.set(MSR_LASTBRANCHTOIP, access::read);
    msrpm.set(MSR_LASTBRANCHTOIP, access::write);
    msrpm.set(MSR_LASTINTFROMIP, access::read);
    msrpm.set(MSR_LASTINTFROMIP, access::write);
    msrpm.set(MSR_LASTINTTOIP, access::read);
    msrpm.set(MSR_LASTINTTOIP, access::write);
    msrpm.set(MSR_P6M_LBSTK_TOS, access::read);
    msrpm.set(MSR_P6M_LBSTK_TOS, access::write);
}

void msrs::setup_feature_msrs(msrpm_t& msrpm) {
    msrpm.set(MSR_IA32_FEATURE_CONTROL, access::read);
    msrpm.set(MSR_IA32_FEATURE_CONTROL, access::write);
    msrpm.set(MSR_IA32_SPEC_CTRL, access::read);
    msrpm.set(MSR_IA32_SPEC_CTRL, access::write);
    msrpm.set(MSR_IA32_PRED_CMD, access::write);
    msrpm.set(MSR_IA32_BIOS_SIGN_ID, access::read);
    msrpm.set(MSR_IA32_PLATFORM_INFO, access::read);
    msrpm.set(MSR_IA32_MTRRCAP, access::read);
    msrpm.set(MSR_IA32_ARCH_CAPABILITIES, access::read);
    msrpm.set(MSR_IA32_MCG_CAP, access::read);
    msrpm.set(MSR_IA32_MCG_STATUS, access::read);
    msrpm.set(MSR_IA32_MCG_STATUS, access::write);
    msrpm.set(MSR_IA32_MISC_ENABLE, access::read);
    msrpm.set(MSR_IA32_MISC_ENABLE, access::write);
    msrpm.set(MSR_IA32_MTRR_DEF_TYPE, access::read);
    msrpm.set(MSR_IA32_MTRR_DEF_TYPE, access::write);
    msrpm.set(MSR_STAR, access::read);
    msrpm.set(MSR_STAR, access::write);
    msrpm.set(MSR_FS_BASE, access::read);
    msrpm.set(MSR_FS_BASE, access::write);
    msrpm.set(MSR_GS_BASE, access::read);
    msrpm.set(MSR_GS_BASE, access::write);
    msrpm.set(MSR_KERNEL_GS_BASE, access::read);
    msrpm.set(MSR_KERNEL_GS_BASE, access::write);
    msrpm.set(MSR_TSC_AUX, access::read);
    msrpm.set(MSR_TSC_AUX, access::write);
}

svm::svmroot_error_t msrs::prepare_msrpm(msrpm_t& msrpm) {
    RtlZeroMemory(&msrpm, sizeof(msrpm));
    setup_svm_msrs(msrpm);
    return svm::svmroot_error_t::error_success;
}

msrs* msrs::get() {
    static msrs instance;
    return &instance;
}
}
