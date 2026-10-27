#include "utilities.hpp"

namespace vtx {

bool utilities::is_intel() {
    int registers[4]; // eax ebx ecx edx

    __cpuid(registers, static_cast<int>(vtx::cpuid::cpu_vendor_string));

    // an Intel processor should always return GenuineIntel
    return ((registers[1] == 'uneG') &&
        (registers[3] == 'Ieni') &&
        (registers[2] == 'letn'));
}

bool utilities::is_vmx_supported() {
    int registers[4]; // eax ebx ecx edx

    __cpuid(registers, static_cast<int>(vtx::cpuid::processor_feature_id));
    return (registers[2] & static_cast<int>(vtx::cpuid::cpu_ecx_vmx)) != 0;
}

bool utilities::is_ept_supported() {
    // IA32_VMX_PROCBASED_CTLS2 is gated by IA32_VMX_PROCBASED_CTLS bit 31 (allow secondary).
    // EPT is the secondary control bit 1 (sits in the upper 32 of the MSR's allowed-1 word).
    u64 procbased = __readmsr(vtx::msr::ia32_vmx_procbased_ctls);
    if (((procbased >> 32) & (1ULL << 31)) == 0) return false;

    u64 procbased2 = __readmsr(vtx::msr::ia32_vmx_procbased_ctls2);
    return ((procbased2 >> 32) & (1ULL << 1)) != 0;
}

bool utilities::can_vmx_be_enabled() {
    u64 fc = __readmsr(vtx::msr::ia32_feature_control);

    // If lock bit is clear, BIOS hasn't finalised — we can set the bits ourselves.
    // If lock is set, the enable-outside-SMX bit must already be on, otherwise VMXON #GPs.
    if ((fc & vtx::msr::feature_control_lock) == 0) return true;
    return (fc & vtx::msr::feature_control_vmx_outside_smx) != 0;
}

bool utilities::ensure_feature_control() {
    u64 fc = __readmsr(vtx::msr::ia32_feature_control);

    if ((fc & vtx::msr::feature_control_lock) == 0) {
        fc |= vtx::msr::feature_control_lock |
              vtx::msr::feature_control_vmx_outside_smx;
        __writemsr(vtx::msr::ia32_feature_control, fc);
    }

    fc = __readmsr(vtx::msr::ia32_feature_control);
    return ((fc & vtx::msr::feature_control_lock) != 0) &&
        ((fc & vtx::msr::feature_control_vmx_outside_smx) != 0);
}

bool utilities::is_hypervisor_vendor_installed() {
    int registers[4];
    char vendor_id[13];

    __cpuid(registers, static_cast<int>(vtx::cpuid::hypervisor_vendor_id));
    RtlCopyMemory(vendor_id + 0, &registers[1], sizeof(registers[1]));
    RtlCopyMemory(vendor_id + 4, &registers[2], sizeof(registers[2]));
    RtlCopyMemory(vendor_id + 8, &registers[3], sizeof(registers[3]));
    vendor_id[12] = ANSI_NULL;

    return (strcmp(vendor_id, "vtx         ") == 0);
}

bool utilities::check_support() {
    return is_intel() &&
        is_vmx_supported() &&
        is_ept_supported() &&
        ensure_feature_control() &&
        !is_hypervisor_vendor_installed();
}

void utilities::enable_vmxe() {
    auto cr4 = __readcr4();
    cr4 |= (1ULL << 13);   // CR4.VMXE
    __writecr4(cr4);
}

utilities* utilities::get() {
    static utilities instance;
    return &instance;
}

}
