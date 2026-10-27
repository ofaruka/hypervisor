#include "msr_svm.hpp"

namespace svm {

bool msr_handler::read_msr(u32 msr, u64& value) {
    __try {
        value = __readmsr(msr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        value = 0;
        return false;
    }
}

bool msr_handler::write_msr(u32 msr, u64 value) {
    __try {
        __writemsr(msr, value);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void msr_handler::msr_exit_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx) {
    u32 msr = guest_ctx->vprocessor_registers->rcx.value & MAXUINT;
    bool is_write = (vcpu->guest_vmcb.control_area.exit_info1 != 0);

    if (is_write) {
        wrmsr_handler(vcpu, guest_ctx, msr);
    } else {
        rdmsr_handler(vcpu, guest_ctx, msr);
    }

    if (!has_pending_event_injection(vcpu)) {
        vcpu->guest_vmcb.state_save_area.rip = advance_rip_or_next(vcpu, 2);
    }
}

void msr_handler::rdmsr_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u32 msr) {
    ULARGE_INTEGER value{};

    switch (msr) {
    case MSR_PAT:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.gpat;
        break;
    case MSR_LSTAR:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.lstar;
        break;
    case MSR_CSTAR:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.cstar;
        break;
    case MSR_SFMASK:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.sfmask;
        break;
    case MSR_SYSENTER_CS:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.sysenter_cs;
        break;
    case MSR_SYSENTER_ESP:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.sysenter_esp;
        break;
    case MSR_SYSENTER_EIP:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.sysenter_eip;
        break;
    case MSR_TSC:
        value.QuadPart = __readmsr(msr) + vcpu->guest_vmcb.control_area.tsc_offset;
        break;
    case MSR_IA32_MPERF:
    case MSR_IA32_APERF:
    case MSR_PERF_CTR0:
    case MSR_PERF_CTR1:
    case MSR_PERF_CTR2:
    case MSR_PERF_CTR3:
    case MSR_PERFEVTSEL0:
    case MSR_PERFEVTSEL1:
    case MSR_PERFEVTSEL2:
    case MSR_PERFEVTSEL3:
    case MSR_HWCR:
    case MSR_K8_SYSCFG:
    case MSR_LASTBRANCHFROMIP:
    case MSR_LASTBRANCHTOIP:
    case MSR_LASTINTFROMIP:
    case MSR_LASTINTTOIP:
    case MSR_P6M_LBSTK_TOS:
    case MSR_IA32_FEATURE_CONTROL:
    case MSR_IA32_SPEC_CTRL:
    case MSR_IA32_BIOS_SIGN_ID:
    case MSR_IA32_PLATFORM_INFO:
    case MSR_IA32_MTRRCAP:
    case MSR_IA32_ARCH_CAPABILITIES:
    case MSR_IA32_MCG_CAP:
    case MSR_IA32_MCG_STATUS:
    case MSR_IA32_MTRR_DEF_TYPE:
    case MSR_TSC_AUX:
        // Several of these (FEATURE_CONTROL, PLATFORM_INFO, ...) are
        // Intel-only and #GP on AMD hosts. Never execute a raw RDMSR in VMM
        // context: a fault here would kill the host instead of delivering
        // the native #GP to the guest reader.
        if (!read_msr(msr, value.QuadPart)) {
            event_inj_t{}.general_protection_exception(vcpu);
            return;
        }
        break;
    case MSR_IA32_MISC_ENABLE:
        event_inj_t{}.general_protection_exception(vcpu);
        return;
    case MSR_STAR:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.star;
        break;
    case MSR_FS_BASE:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.fs.base;
        break;
    case MSR_GS_BASE:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.gs.base;
        break;
    case MSR_KERNEL_GS_BASE:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.kernel_gs_base;
        break;
    case MSR_EFER:
        value.QuadPart = vcpu->host_stack_layout.shadow_data.efer.value;
        break;
    case MSR_VM_HSAVE_PA:
        value.QuadPart = vcpu->host_stack_layout.shadow_data.hsave_pa.value;
        break;
    case MSR_VM_CR:
        value.QuadPart = 0;
        break;
    case MSR_DEBUG_CTL:
        value.QuadPart = vcpu->guest_vmcb.state_save_area.dbg_ctl;
        break;
    case MSR_KVM_SIGNATURE:
        event_inj_t{}.general_protection_exception(vcpu);
        return;
    default:
        if (!read_msr(msr, value.QuadPart)) {
            event_inj_t{}.general_protection_exception(vcpu);
            return;
        }
        break;
    }

    guest_ctx->vprocessor_registers->rax.value = value.LowPart;
    guest_ctx->vprocessor_registers->rdx.value = value.HighPart;
}

void msr_handler::wrmsr_handler(svm::pvcpu_t vcpu, svm::pguest_ctx_t guest_ctx, u32 msr) {
    ULARGE_INTEGER value{};
    value.LowPart = guest_ctx->vprocessor_registers->rax.value & MAXUINT;
    value.HighPart = guest_ctx->vprocessor_registers->rdx.value & MAXUINT;

    switch (msr) {
    case MSR_PERFEVTSEL0:
    case MSR_PERFEVTSEL1:
    case MSR_PERFEVTSEL2:
    case MSR_PERFEVTSEL3:
    case MSR_PERF_CTR0:
    case MSR_PERF_CTR1:
    case MSR_PERF_CTR2:
    case MSR_PERF_CTR3:
    case MSR_IA32_MPERF:
    case MSR_IA32_APERF:
    case MSR_HWCR:
    case MSR_K8_SYSCFG:
    case MSR_LASTBRANCHFROMIP:
    case MSR_LASTBRANCHTOIP:
    case MSR_LASTINTFROMIP:
    case MSR_LASTINTTOIP:
    case MSR_P6M_LBSTK_TOS:
    case MSR_IA32_SPEC_CTRL:
    case MSR_IA32_PRED_CMD:
    case MSR_IA32_MCG_STATUS:
    case MSR_IA32_MTRR_DEF_TYPE:
    case MSR_TSC_AUX:
        // Same protection as the read path: a #GP from a raw WRMSR in VMM
        // context would bugcheck the host.
        if (!write_msr(msr, value.QuadPart)) {
            event_inj_t{}.general_protection_exception(vcpu);
            return;
        }
        break;
    case MSR_TSC:
    case MSR_IA32_FEATURE_CONTROL:
    case MSR_IA32_MISC_ENABLE:
        break;
    case MSR_STAR:
        vcpu->guest_vmcb.state_save_area.star = value.QuadPart;
        break;
    case MSR_FS_BASE:
        vcpu->guest_vmcb.state_save_area.fs.base = value.QuadPart;
        break;
    case MSR_GS_BASE:
        vcpu->guest_vmcb.state_save_area.gs.base = value.QuadPart;
        break;
    case MSR_KERNEL_GS_BASE:
        vcpu->guest_vmcb.state_save_area.kernel_gs_base = value.QuadPart;
        break;
    case MSR_PAT:
        for (u32 i = 0; i < 8; ++i) {
            const u8 type = static_cast<u8>((value.QuadPart >> (i * 8)) & 0xFF);
            if (type != 0 && type != 1 && type != 4 && type != 5 && type != 6 && type != 7) {
                event_inj_t{}.general_protection_exception(vcpu);
                return;
            }
        }

        vcpu->guest_vmcb.state_save_area.gpat = value.QuadPart;
        break;
    case MSR_LSTAR:
        vcpu->guest_vmcb.state_save_area.lstar = value.QuadPart;
        break;
    case MSR_CSTAR:
        vcpu->guest_vmcb.state_save_area.cstar = value.QuadPart;
        break;
    case MSR_SFMASK:
        vcpu->guest_vmcb.state_save_area.sfmask = value.QuadPart;
        break;
    case MSR_SYSENTER_CS:
        vcpu->guest_vmcb.state_save_area.sysenter_cs = value.QuadPart;
        break;
    case MSR_SYSENTER_ESP:
        vcpu->guest_vmcb.state_save_area.sysenter_esp = value.QuadPart;
        break;
    case MSR_SYSENTER_EIP:
        vcpu->guest_vmcb.state_save_area.sysenter_eip = value.QuadPart;
        break;
    case MSR_EFER: {
        vcpu->host_stack_layout.shadow_data.efer.value = value.QuadPart;
        vcpu->guest_vmcb.state_save_area.efer.value = value.QuadPart & ~(1ULL << 12);
        break;
    }
    case MSR_VM_HSAVE_PA: {
        if (value.QuadPart & 0xFFF) {
            event_inj_t{}.general_protection_exception(vcpu);
            return;
        }

        vcpu->host_stack_layout.shadow_data.hsave_pa.value = value.QuadPart;
        break;
    }
    case MSR_VM_CR:
        break;
    case MSR_DEBUG_CTL:
        vcpu->guest_vmcb.state_save_area.dbg_ctl = value.QuadPart;
        if (!write_msr(msr, value.QuadPart & ~0x3ULL)) {
            event_inj_t{}.general_protection_exception(vcpu);
            return;
        }
        break;
    default:
        if (!write_msr(msr, value.QuadPart)) {
            event_inj_t{}.general_protection_exception(vcpu);
            return;
        }
        break;
    }
}

msr_handler* msr_handler::get() {
    static msr_handler instance;
    return &instance;
}
}
