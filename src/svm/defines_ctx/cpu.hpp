#pragma once
#include "../includes.h"
#define SVM_MSR_PERMISSIONS_MAP_SIZE (PAGE_SIZE * 2)
#define SVM_MSR_VM_HSAVE_PA 0xC0010117
#define IA32_MSR_APIC_BAR 0x1b
#define IA32_MSR_EFER 0xC0000080
#define IA32_MSR_EFER_SVME (1UL << 12)
#define IA32_MSR_PAT 0x00000277
#define IA32_MSR_LSTAR 0xc0000082
#define SVM_MSR_VM_CR 0xc0010114
#define SVM_MSR_VM_HSAVE_PA 0xc0010117
#define IA32_LSTAR 0xC0000082
#define POOL_NX_OPTIN 1
#define SVM_VM_CR_SVMDIS (1UL << 4)
#define SVM_NP_ENABLE_NP_ENABLE (1UL << 0)
#define EFER_SVME (1UL << 12)
#define IA32_APIC_BASE 0x0000001b
namespace svm {
enum class cpuid : uint32_t {
    cpu_vendor_string = 0x00000000,
    processor_feature_id = 0x00000001,
    hypervisor_present_ex = 0x80000000,
    processor_feature_id_ex = 0x80000001,
    svm_features = 0x8000000a,
    svm_features_ex = 0x80000001,
    hypervisor_vendor_id = 0x40000000,
    hypervisor_interface = 0x40000001,
    cpu_ecx_svm = 0x4,
    cpu_edx_np = 0x1,
};
enum msr : uint32_t {
    svm_vm_cr = 0xc0010114,
    svm_vm_cr_svmdis = 0x10,
    svm_vm_cr_svm_lock = 0x4,
    efer = 0xc0000080,
    lstar = 0xC0000082,
    msr_pat = 0x00000277,
    msr_mtrr = 0x000002FF,
    vm_hsave_pa = 0xC0010117,
    apic_bar = 0x1b,
    efer_sce = 0x1,
    efer_lme = 0x100,
    efer_lma = 0x400,
    efer_nxe = 0x800,
    efer_svme = 0x1000,
    efer_lmsle = 0x2000,
    efer_ffxsr = 0x4000,
    efer_tce = 0x8000,
    efer_mcommit = 0x20000,
    efer_intwb = 0x40000,
    efer_uaie = 0x100000,
    efer_aibrse = 0x200000,
    vmcr_disa20m = 0x4,
    vmcr_r_init = 0x1,
};
enum svmroot_error_t : u64 {
    error_success,
    pml4e_not_present,
    pdpte_not_present,
    pde_not_present,
    pte_not_present,
    svmroot_translate_failure,
    invalid_self_ref_pml4e,
    invalid_mapping_pml4e,
    invalid_host_virtual,
    invalid_guest_physical,
    invalid_guest_virtual,
    page_table_init_failed,
    invalid_pid,
    error_failed
};
struct apic_bar_msr {
    union {
        uint64_t value;
        struct {
            uint64_t reserved1 : 8;
            uint64_t bootstrap_processor : 1;
            uint64_t reserved2 : 1;
            uint64_t x2apic_mode : 1;
            uint64_t xapic_global : 1;
            uint64_t apic_base : 24;
        };
    };
};
struct cr0_t {
    union {
        uint64_t value;
        struct {
            uint64_t pe : 1;
            uint64_t mp : 1;
            uint64_t em : 1;
            uint64_t ts : 1;
            uint64_t et : 1;
            uint64_t ne : 1;
            uint64_t reserved6 : 10;
            uint64_t wp : 1;
            uint64_t reserved17 : 1;
            uint64_t am : 1;
            uint64_t reserved19 : 10;
            uint64_t nw : 1;
            uint64_t cd : 1;
            uint64_t pg : 1;
            uint64_t reserved32 : 32;
        };
    };
};
struct cr2_t {
    union {
        uint64_t value;
        struct {
            uint64_t pfl : 64;
        };
    };
};
struct cr3_t {
    union {
        uint64_t value;
        union {
            struct {
                uint64_t reserved0 : 3;
                uint64_t pwt : 1;
                uint64_t pcd : 1;
                uint64_t reserved5 : 7;
                uint64_t pml4 : 40;
                uint64_t reserved52 : 12;
            };
            struct {
                uint64_t pci : 12;
                uint64_t pml4 : 40;
                uint64_t reserved52 : 12;
            } pcide_on;
        };
    };
};
struct cr4_t {
    union {
        uint64_t value;
        struct {
            uint64_t vme : 1;
            uint64_t pvi : 1;
            uint64_t tsd : 1;
            uint64_t de : 1;
            uint64_t pse : 1;
            uint64_t pae : 1;
            uint64_t mce : 1;
            uint64_t pge : 1;
            uint64_t pce : 1;
            uint64_t osfxsr : 1;
            uint64_t osxmmexcpt : 1;
            uint64_t umip : 1;
            uint64_t la57 : 1;
            uint64_t reserved13 : 3;
            uint64_t fsgsbase : 1;
            uint64_t pcide : 1;
            uint64_t osxsave : 1;
            uint64_t reserved19 : 1;
            uint64_t smep : 1;
            uint64_t smap : 1;
            uint64_t pke : 1;
            uint64_t cet : 1;
            uint64_t reserved24 : 40;
        };
    };
};
struct cr8_t {
    union {
        uint64_t value;
        struct {
            uint64_t tpr : 4;
            uint64_t reserved4 : 60;
        };
    };
};
extern "C" void _sgdt(PVOID descriptor);
}
