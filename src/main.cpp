#include "includes.h"
#pragma warning(disable : 6387)

NTSTATUS driver_entry(PVOID arg1, SIZE_T arg2) {
    UNREFERENCED_PARAMETER(arg1);
    UNREFERENCED_PARAMETER(arg2);

    debug::panicf("Initializing core components...\n");
    svm::disassembler::get();
    svm::memory::get();

    if (!svm::memory::get()->init_arena()) {
        debug::panicf("Failed to initialize hypervisor arena\n");
        return STATUS_UNSUCCESSFUL;
    }

    svm::tpm_crypto::get();
    svm::tpm::get();

    if (svm::utilities::get()->is_amd()) {
        int feature_registers[4];
        __cpuid(feature_registers, static_cast<int>(svm::cpuid::processor_feature_id));
        const auto hypervisor_present = (feature_registers[2] & (1u << 31)) != 0;

        debug::panicf("AMD detected. SVM=%u NPT=%u CanEnable=%u HVPresent=%u\n",
            svm::utilities::get()->is_svm_supported() ? 1u : 0u,
            svm::utilities::get()->is_npt_supported() ? 1u : 0u,
            svm::utilities::get()->can_svm_be_enabled() ? 1u : 0u,
            hypervisor_present ? 1u : 0u);

        debug::panicf("AMD detected, starting SVM virtualization...\n");
        if (!svm::virtualization::get()->virtualize()) {
            debug::panicf("SVM virtualization failed\n");
            return STATUS_UNSUCCESSFUL;
        }

        debug::panicf("SVM virtualization returned to startup thread\n");
        return STATUS_SUCCESS;
    }

    if (vtx::utilities::get()->is_intel()) {
        debug::panicf("Intel detected. VMX=%u EPT=%u CanEnable=%u HVPresent=%u\n",
            vtx::utilities::get()->is_vmx_supported() ? 1u : 0u,
            vtx::utilities::get()->is_ept_supported() ? 1u : 0u,
            vtx::utilities::get()->can_vmx_be_enabled() ? 1u : 0u,
            vtx::utilities::get()->is_hypervisor_vendor_installed() ? 1u : 0u);
        debug::panicf("Starting VTX virtualization...\n");
        if (!vtx::virtualization::get()->virtualize()) {
            debug::panicf("VTX virtualization failed\n");
            return STATUS_UNSUCCESSFUL;
        }

        svm::logs::get()->write("VTX virtualization returned to startup thread\n");
        return STATUS_SUCCESS;
    }

    debug::panicf("Unsupported CPU vendor\n");
    return STATUS_NOT_SUPPORTED;
}
