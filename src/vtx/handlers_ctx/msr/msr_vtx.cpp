#include "msr_vtx.hpp"
#include "../events/events_vtx.hpp"

namespace vtx {

auto msr_handler::get() -> msr_handler* {
    static msr_handler instance;
    return &instance;
}

auto msr_handler::read_msr(u32 msr, u64& value) -> bool {
    __try {
        value = __readmsr(msr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        value = 0;
        return false;
    }
}

auto msr_handler::read_raw_msr(u32 msr, u64& value) -> bool {
    return read_msr(msr, value);
}

auto msr_handler::read_guest_msr(pvcpu_t vcpu, u32 msr, u64& value) -> bool {
    return get_managed_msr(vcpu, msr, value) || read_msr(msr, value);
}

auto msr_handler::write_msr(u32 msr, u64 value) -> bool {
    __try {
        __writemsr(msr, value);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

auto msr_handler::validate_msr_write(u32 msr, u64 value) -> bool {
    u64 old_value = 0;
    if (!read_msr(msr, old_value)) return false;
    if (!write_msr(msr, value)) return false;
    return write_msr(msr, old_value);
}

auto msr_handler::add_managed_msr(pvcpu_t vcpu, u32 msr, bool required) -> bool {
    if (!vcpu) return false;

    u64 value = 0;
    if (!read_msr(msr, value)) return !required;
    if (vcpu->managed_msr_count >= managed_msr_count_max) return false;

    auto index = vcpu->managed_msr_count++;
    vcpu->managed_msrs[index].index = msr;
    vcpu->managed_msrs[index].reserved = 0;
    vcpu->managed_msrs[index].value = value;

    vcpu->host_msrs[index].index = msr;
    vcpu->host_msrs[index].reserved = 0;
    vcpu->host_msrs[index].value = value;
    return true;
}

auto msr_handler::get_managed_msr(pvcpu_t vcpu, u32 msr, u64& value) -> bool {
    if (!vcpu) return false;

    for (u32 i = 0; i < vcpu->managed_msr_count; ++i) {
        if (vcpu->managed_msrs[i].index == msr) {
            value = vcpu->managed_msrs[i].value;
            return true;
        }
    }
    return false;
}

auto msr_handler::set_managed_msr(pvcpu_t vcpu, u32 msr, u64 value) -> bool {
    if (!vcpu) return false;

    for (u32 i = 0; i < vcpu->managed_msr_count; ++i) {
        if (vcpu->managed_msrs[i].index == msr) {
            vcpu->managed_msrs[i].value = value;
            return true;
        }
    }
    return false;
}

auto msr_handler::is_canonical(u64 value) -> bool {
    auto sign = static_cast<i64>(value) >> 47;
    return sign == 0 || sign == -1;
}

auto msr_handler::is_valid_pat(u64 value) -> bool {
    for (u32 i = 0; i < 8; ++i) {
        auto type = static_cast<u8>((value >> (i * 8)) & 0xff);
        if (type == 0 || type == 1 || type == 4 || type == 5 || type == 6 || type == 7) {
            continue;
        }
        return false;
    }
    return true;
}

auto msr_handler::is_mtrr_msr(u32 msr) -> bool {
    return msr == MSR_IA32_MTRRCAP ||
           msr == MSR_IA32_MTRR_DEF_TYPE ||
           (msr >= 0x200 && msr <= 0x2ff);
}

auto msr_handler::is_vmx_msr(u32 msr) -> bool {
    return msr >= vtx::msr::ia32_vmx_basic && msr <= 0x491;
}

auto msr_handler::is_kvm_msr(u32 msr) -> bool {
    return msr >= MSR_KVM_SIGNATURE && msr <= 0x4b564dff;
}

auto msr_handler::is_lbr_msr(u32 msr, u32& index) -> bool {
    switch (msr) {
    case MSR_LASTBRANCHFROMIP: index = 0; return true;
    case MSR_LASTBRANCHTOIP:   index = 1; return true;
    case MSR_LASTINTFROMIP:    index = 2; return true;
    case MSR_LASTINTTOIP:      index = 3; return true;
    case MSR_P6M_LBSTK_TOS:    index = 4; return true;
    default: return false;
    }
}

auto msr_handler::debugctl_valid_bits() -> u64 {
    constexpr u64 bit_lbr = 1ULL << 0;
    constexpr u64 bit_btf = 1ULL << 1;
    constexpr u64 bit_tr = 1ULL << 6;
    constexpr u64 bit_bts = 1ULL << 7;
    constexpr u64 bit_btint = 1ULL << 8;
    constexpr u64 bit_bts_off_os = 1ULL << 9;
    constexpr u64 bit_bts_off_usr = 1ULL << 10;
    constexpr u64 bit_freeze_lbrs_on_pmi = 1ULL << 11;
    constexpr u64 bit_freeze_perfmon_on_pmi = 1ULL << 12;
    constexpr u64 bit_enable_uncore_pmi = 1ULL << 13;
    constexpr u64 bit_freeze_while_smm = 1ULL << 14;
    constexpr u64 bit_rtm_debug = 1ULL << 15;
    constexpr u32 ia32_perf_capabilities_msr = 0x345;

    u64 mask = bit_lbr | bit_btf | bit_tr | bit_bts | bit_btint |
               bit_bts_off_os | bit_bts_off_usr | bit_enable_uncore_pmi;

    int regs[4] = {};
    __cpuidex(regs, 0, 0);
    auto max_leaf = static_cast<u32>(regs[0]);

    __cpuidex(regs, 1, 0);
    auto has_perf_capabilities = (static_cast<u32>(regs[2]) & (1u << 15)) != 0;

    if (max_leaf >= 0x0a) {
        int perf_regs[4] = {};
        __cpuidex(perf_regs, 0x0a, 0);
        auto perfmon_version = static_cast<u32>(perf_regs[0]) & 0xff;
        if (has_perf_capabilities && perfmon_version > 1) {
            mask |= bit_freeze_lbrs_on_pmi | bit_freeze_perfmon_on_pmi;
        }
    }

    if (has_perf_capabilities) {
        u64 perf_capabilities = 0;
        if (read_msr(ia32_perf_capabilities_msr, perf_capabilities) &&
            (perf_capabilities & (1ULL << 12)) != 0) {
            mask |= bit_freeze_while_smm;
        }
    }

    if (max_leaf >= 7) {
        int ext_regs[4] = {};
        __cpuidex(ext_regs, 7, 0);
        if ((static_cast<u32>(ext_regs[1]) & (1u << 11)) != 0) {
            mask |= bit_rtm_debug;
        }
    }

    return mask;
}

auto msr_handler::setup_managed_msrs(pvcpu_t vcpu) -> bool {
    if (!vcpu) return false;

    vcpu->managed_msr_count = 0;
    RtlZeroMemory(vcpu->managed_msrs, sizeof(vcpu->managed_msrs));
    RtlZeroMemory(vcpu->host_msrs, sizeof(vcpu->host_msrs));
    read_msr(MSR_IA32_TSC_ADJUST, vcpu->tsc_adjust);

    if (!add_managed_msr(vcpu, MSR_STAR, true)) return false;
    if (!add_managed_msr(vcpu, MSR_LSTAR, true)) return false;
    if (!add_managed_msr(vcpu, MSR_CSTAR, false)) return false;
    if (!add_managed_msr(vcpu, MSR_SFMASK, true)) return false;
    if (!add_managed_msr(vcpu, MSR_KERNEL_GS_BASE, true)) return false;
    if (!add_managed_msr(vcpu, MSR_TSC_AUX, false)) return false;
    if (!add_managed_msr(vcpu, MSR_IA32_SPEC_CTRL, false)) return false;
    return true;
}

auto msr_handler::load_managed_msrs(pvcpu_t vcpu) -> void {
    if (!vcpu) return;

    for (u32 i = 0; i < vcpu->managed_msr_count; ++i) {
        write_msr(vcpu->managed_msrs[i].index, vcpu->managed_msrs[i].value);
    }
}

auto msr_handler::set_bitmap(u8* bitmap, u32 msr, bool read, bool write) -> void {
    if (!bitmap) return;

    u32 bit = 0;
    u32 read_base = 0;
    u32 write_base = 0;

    if (msr <= 0x1fff) {
        bit = msr;
        read_base = 0x000;
        write_base = 0x800;
    }
    else if (msr >= 0xc0000000 && msr <= 0xc0001fff) {
        bit = msr - 0xc0000000;
        read_base = 0x400;
        write_base = 0xc00;
    }
    else {
        return;
    }

    u8 mask = static_cast<u8>(1u << (bit & 7));
    if (read) bitmap[read_base + (bit >> 3)] |= mask;
    if (write) bitmap[write_base + (bit >> 3)] |= mask;
}

auto msr_handler::prepare_bitmap(u8* bitmap) -> void {
    if (!bitmap) return;

    RtlZeroMemory(bitmap, PAGE_SIZE);

    set_bitmap(bitmap, MSR_TSC, true, true);
    set_bitmap(bitmap, MSR_IA32_TSC_ADJUST, true, true);
    set_bitmap(bitmap, MSR_IA32_TSC_DEADLINE, true, true);
    set_bitmap(bitmap, MSR_IA32_FEATURE_CONTROL, true, true);
    set_bitmap(bitmap, MSR_DEBUG_CTL, true, true);
    set_bitmap(bitmap, MSR_LASTBRANCHFROMIP, true, true);
    set_bitmap(bitmap, MSR_LASTBRANCHTOIP, true, true);
    set_bitmap(bitmap, MSR_LASTINTFROMIP, true, true);
    set_bitmap(bitmap, MSR_LASTINTTOIP, true, true);
    set_bitmap(bitmap, MSR_P6M_LBSTK_TOS, true, true);
    for (u32 msr = vtx::msr::ia32_vmx_basic; msr <= 0x491; ++msr) {
        set_bitmap(bitmap, msr, true, true);
    }
    for (u32 i = 0; i < perf_counter_count_max; ++i) {
        set_bitmap(bitmap, MSR_PERF_CTR0 + i, true, true);
        set_bitmap(bitmap, MSR_PERFEVTSEL0 + i, true, true);
    }
    set_bitmap(bitmap, MSR_IA32_FIXED_CTR0, true, true);
    set_bitmap(bitmap, MSR_IA32_FIXED_CTR1, true, true);
    set_bitmap(bitmap, MSR_IA32_FIXED_CTR2, true, true);
    set_bitmap(bitmap, MSR_IA32_FIXED_CTR_CTRL, true, true);
    set_bitmap(bitmap, MSR_IA32_PERF_GLOBAL_CTRL, true, true);
    set_bitmap(bitmap, MSR_APIC_BASE, true, true);
    set_bitmap(bitmap, MSR_IA32_SPEC_CTRL, true, true);
    set_bitmap(bitmap, MSR_IA32_PRED_CMD, false, true);
    set_bitmap(bitmap, MSR_PAT, true, true);
    set_bitmap(bitmap, MSR_SYSENTER_CS, true, true);
    set_bitmap(bitmap, MSR_SYSENTER_ESP, true, true);
    set_bitmap(bitmap, MSR_SYSENTER_EIP, true, true);
    set_bitmap(bitmap, MSR_IA32_MISC_ENABLE, false, true);
    for (u32 msr = 0x200; msr <= 0x2ff; ++msr) {
        set_bitmap(bitmap, msr, true, true);
    }

    set_bitmap(bitmap, MSR_EFER, true, true);
    set_bitmap(bitmap, MSR_STAR, true, true);
    set_bitmap(bitmap, MSR_LSTAR, true, true);
    set_bitmap(bitmap, MSR_CSTAR, true, true);
    set_bitmap(bitmap, MSR_SFMASK, true, true);
    set_bitmap(bitmap, MSR_FS_BASE, true, true);
    set_bitmap(bitmap, MSR_GS_BASE, true, true);
    set_bitmap(bitmap, MSR_KERNEL_GS_BASE, true, true);
    set_bitmap(bitmap, MSR_TSC_AUX, true, true);
}

auto msr_handler::inject_gp() -> void {
    event_handler::get()->inject_gp(0);
}

auto msr_handler::rdmsr_handler(pvcpu_t vcpu, guest_gprs* gprs, u32 msr) -> bool {
    u64 value = 0;
    auto timing = timing_handler::get();
    u32 lbr_index = 0;

    if (is_vmx_msr(msr)) {
        inject_gp();
        return false;
    }

    if (msr >= 0x40000000 && msr <= 0x400001ff) {
        inject_gp();
        return false;
    }

    if (is_lbr_msr(msr, lbr_index)) {
        value = vcpu->lbr_shadow[lbr_index];
        gprs->rax = static_cast<u32>(value);
        gprs->rdx = static_cast<u32>(value >> 32);
        return true;
    }

    auto adjust_counter = [&](u64 adjustment) -> void {
        if (!vcpu->intercept_rdtsc_pending) return;
        if (value > adjustment) value -= adjustment;
        timing->clear_timing_exiting(vcpu);
    };

    if (msr >= MSR_PERF_CTR0 && msr < MSR_PERF_CTR0 + perf_counter_count_max) {
        if (!read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        if (vcpu->intercept_rdtsc_pending) {
            u64 evtsel = 0;
            if (read_msr(MSR_PERFEVTSEL0 + (msr - MSR_PERF_CTR0), evtsel) &&
                static_cast<u8>(evtsel) == 0x3c) {
                adjust_counter(timing->calculated_cpuid_adjustment(vcpu));
            }
        }
        gprs->rax = static_cast<u32>(value);
        gprs->rdx = static_cast<u32>(value >> 32);
        return true;
    }

    if (msr >= MSR_PERFEVTSEL0 && msr < MSR_PERFEVTSEL0 + perf_counter_count_max) {
        if (!read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        gprs->rax = static_cast<u32>(value);
        gprs->rdx = static_cast<u32>(value >> 32);
        return true;
    }

    switch (msr) {
    case MSR_TSC:
        if (timing->consume_timing_read(vcpu, timing_source_tsc, value)) {
            break;
        }
        value = timing->adjusted_tsc(vcpu);
        if (vcpu->intercept_rdtsc_pending) {
            timing->clear_timing_exiting(vcpu);
        }
        else {
            timing->record_timing_read(vcpu, timing_source_tsc, value);
        }
        break;
    case MSR_IA32_FEATURE_CONTROL:
        if (!read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        value &= ~(static_cast<u64>(vtx::msr::feature_control_vmx_in_smx) |
                   static_cast<u64>(vtx::msr::feature_control_vmx_outside_smx));
        break;
    case MSR_IA32_TSC_ADJUST:
        if (!read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        value = vcpu->tsc_adjust;
        break;
    case MSR_IA32_TSC_DEADLINE:
        if (!read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        if (value) value += vcpu->tsc_offset;
        break;
    case MSR_IA32_MPERF:
        if (timing->consume_timing_read(vcpu, timing_source_mperf, value)) {
            break;
        }
        if (!read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        if (vcpu->intercept_rdtsc_pending) {
            adjust_counter(timing->calculated_cpuid_adjustment(vcpu));
        }
        else {
            timing->record_timing_read(vcpu, timing_source_mperf, value);
        }
        break;
    case MSR_IA32_APERF:
        if (timing->consume_timing_read(vcpu, timing_source_aperf, value)) {
            break;
        }
        if (!read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        if (vcpu->intercept_rdtsc_pending) {
            adjust_counter(timing->calculated_cpuid_adjustment(vcpu));
        }
        else {
            timing->record_timing_read(vcpu, timing_source_aperf, value);
        }
        break;
    case MSR_IA32_FIXED_CTR0:
    case MSR_IA32_FIXED_CTR1:
    case MSR_IA32_FIXED_CTR2:
        timing->capture_fixed_counters(vcpu);
        value = vcpu->fixed_ctr_exit[msr - MSR_IA32_FIXED_CTR0];
        if (vcpu->intercept_rdtsc_pending) {
            auto adjustment = timing->calculated_cpuid_adjustment(vcpu);
            if (value > adjustment) value -= adjustment;
            timing->clear_timing_exiting(vcpu);
        }
        break;
    case MSR_IA32_FIXED_CTR_CTRL:
    case MSR_IA32_PERF_GLOBAL_CTRL:
        if (!read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        break;
    case MSR_APIC_BASE:
        if (!read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        break;
    case MSR_PAT:
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_ia32_pat),
                     reinterpret_cast<size_t*>(&value));
        break;
    case MSR_EFER:
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_ia32_efer),
                     reinterpret_cast<size_t*>(&value));
        break;
    case MSR_SYSENTER_CS:
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_sysenter_cs),
                     reinterpret_cast<size_t*>(&value));
        break;
    case MSR_SYSENTER_ESP:
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_sysenter_esp),
                     reinterpret_cast<size_t*>(&value));
        break;
    case MSR_SYSENTER_EIP:
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_sysenter_eip),
                     reinterpret_cast<size_t*>(&value));
        break;
    case MSR_STAR:
    case MSR_LSTAR:
    case MSR_CSTAR:
    case MSR_SFMASK:
    case MSR_KERNEL_GS_BASE:
    case MSR_TSC_AUX:
    case MSR_IA32_SPEC_CTRL:
        if (!get_managed_msr(vcpu, msr, value) && !read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        break;
    case MSR_FS_BASE:
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_fs_base),
                     reinterpret_cast<size_t*>(&value));
        break;
    case MSR_GS_BASE:
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_gs_base),
                     reinterpret_cast<size_t*>(&value));
        break;
    case MSR_IA32_MISC_ENABLE:
        if (!read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        break;
    case MSR_DEBUG_CTL:
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_ia32_debugctl),
                     reinterpret_cast<size_t*>(&value));
        break;
    default:
        if (is_kvm_msr(msr)) {
            inject_gp();
            return false;
        }

        if (is_mtrr_msr(msr)) {
            if (!read_msr(msr, value)) {
                inject_gp();
                return false;
            }
            break;
        }

        if (!read_msr(msr, value)) {
            inject_gp();
            return false;
        }
        break;
    }

    gprs->rax = static_cast<u32>(value);
    gprs->rdx = static_cast<u32>(value >> 32);
    return true;
}

auto msr_handler::wrmsr_handler(pvcpu_t vcpu, guest_gprs* gprs, u32 msr) -> bool {
    u64 value = (gprs->rax & 0xffffffffULL) | ((gprs->rdx & 0xffffffffULL) << 32);
    u32 lbr_index = 0;

    if (is_vmx_msr(msr) || msr == MSR_IA32_FEATURE_CONTROL || is_kvm_msr(msr)) {
        inject_gp();
        return false;
    }

    if (msr >= 0x40000000 && msr <= 0x400001ff) {
        inject_gp();
        return false;
    }

    if (is_lbr_msr(msr, lbr_index)) {
        vcpu->lbr_shadow[lbr_index] = value;
        return true;
    }

    if (msr == MSR_TSC) {
        auto old_tsc = __rdtsc() + vcpu->tsc_offset;
        auto delta = value - old_tsc;
        vcpu->tsc_offset += delta;
        vcpu->tsc_adjust += delta;
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::tsc_offset),
                      static_cast<size_t>(vcpu->tsc_offset));
        timing_handler::get()->clear_timing_exiting(vcpu);
        return true;
    }

    if ((msr >= MSR_PERF_CTR0 && msr < MSR_PERF_CTR0 + perf_counter_count_max) ||
        (msr >= MSR_PERFEVTSEL0 && msr < MSR_PERFEVTSEL0 + perf_counter_count_max)) {
        if (!write_msr(msr, value)) {
            inject_gp();
            return false;
        }
        return true;
    }

    switch (msr) {
    case MSR_IA32_TSC_ADJUST: {
        u64 ignored = 0;
        if (!read_msr(msr, ignored)) {
            inject_gp();
            return false;
        }

        auto delta = value - vcpu->tsc_adjust;
        vcpu->tsc_adjust = value;
        vcpu->tsc_offset += delta;
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::tsc_offset),
                      static_cast<size_t>(vcpu->tsc_offset));
        timing_handler::get()->clear_timing_exiting(vcpu);
        break;
    }
    case MSR_IA32_TSC_DEADLINE:
        if (!write_msr(msr, value ? value - vcpu->tsc_offset : 0)) {
            inject_gp();
            return false;
        }
        break;
    case MSR_APIC_BASE:
    case MSR_IA32_MISC_ENABLE:
        {
            u64 current = 0;
            if (!read_msr(msr, current) || current != value) {
                inject_gp();
                return false;
            }
        }
        break;
    case MSR_DEBUG_CTL: {
        if ((value & ~debugctl_valid_bits()) != 0 ||
            __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_ia32_debugctl),
                          static_cast<size_t>(value)) != 0) {
            inject_gp();
            return false;
        }
        break;
    }
    case MSR_IA32_MPERF:
    case MSR_IA32_APERF:
    case MSR_IA32_FIXED_CTR0:
    case MSR_IA32_FIXED_CTR1:
    case MSR_IA32_FIXED_CTR2:
    case MSR_IA32_FIXED_CTR_CTRL:
    case MSR_IA32_PERF_GLOBAL_CTRL:
        if (!write_msr(msr, value)) {
            inject_gp();
            return false;
        }
        break;
    case MSR_PAT:
        if (!is_valid_pat(value)) {
            inject_gp();
            return false;
        }
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_ia32_pat),
                      static_cast<size_t>(value));
        break;
    case MSR_EFER: {
        constexpr u64 efer_sce = 1ULL << 0;
        constexpr u64 efer_lme = 1ULL << 8;
        constexpr u64 efer_lma = 1ULL << 10;
        constexpr u64 efer_nxe = 1ULL << 11;
        constexpr u64 efer_valid = efer_sce | efer_lme | efer_lma | efer_nxe;

        if ((value & ~efer_valid) != 0) {
            inject_gp();
            return false;
        }

        size_t cr0 = 0;
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cr0), &cr0);
        if ((cr0 & (1ULL << 31)) != 0 && (value & efer_lme) == 0) {
            inject_gp();
            return false;
        }

        size_t old_efer = 0;
        __vmx_vmread(static_cast<size_t>(vmcs_field::guest_ia32_efer), &old_efer);
        value = (value & ~efer_lma) | (old_efer & efer_lma);
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_ia32_efer),
                      static_cast<size_t>(value));
        break;
    }
    case MSR_SYSENTER_CS:
        if ((value >> 32) != 0) {
            inject_gp();
            return false;
        }
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_sysenter_cs),
                      static_cast<size_t>(value));
        break;
    case MSR_SYSENTER_ESP:
        if (!is_canonical(value)) {
            inject_gp();
            return false;
        }
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_sysenter_esp),
                      static_cast<size_t>(value));
        break;
    case MSR_SYSENTER_EIP:
        if (!is_canonical(value)) {
            inject_gp();
            return false;
        }
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_sysenter_eip),
                      static_cast<size_t>(value));
        break;
    case MSR_LSTAR:
    case MSR_CSTAR:
    case MSR_KERNEL_GS_BASE:
        if (!is_canonical(value)) {
            inject_gp();
            return false;
        }
        if (!set_managed_msr(vcpu, msr, value) && !write_msr(msr, value)) {
            inject_gp();
            return false;
        }
        break;
    case MSR_STAR:
    case MSR_SFMASK:
    case MSR_TSC_AUX:
    case MSR_IA32_SPEC_CTRL:
        if (!validate_msr_write(msr, value)) {
            inject_gp();
            return false;
        }
        if (!set_managed_msr(vcpu, msr, value) && !write_msr(msr, value)) {
            inject_gp();
            return false;
        }
        break;
    case MSR_FS_BASE:
        if (!is_canonical(value)) {
            inject_gp();
            return false;
        }
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_fs_base),
                      static_cast<size_t>(value));
        break;
    case MSR_GS_BASE:
        if (!is_canonical(value)) {
            inject_gp();
            return false;
        }
        __vmx_vmwrite(static_cast<size_t>(vmcs_field::guest_gs_base),
                      static_cast<size_t>(value));
        break;
    case MSR_IA32_PRED_CMD:
        if (!write_msr(msr, value)) {
            inject_gp();
            return false;
        }
        break;
    case MSR_VM_HSAVE_PA:
    case MSR_VM_CR:
        inject_gp();
        return false;
    default:
        if (is_mtrr_msr(msr)) {
            u64 current = 0;
            if (!read_msr(msr, current) || current != value) {
                inject_gp();
                return false;
            }
            break;
        }

        inject_gp();
        return false;
    }

    return true;
}

auto msr_handler::msr_exit_handler(pvcpu_t vcpu, guest_gprs* gprs, bool is_write) -> bool {
    if (!vcpu || !gprs) {
        inject_gp();
        return false;
    }

    auto msr = static_cast<u32>(gprs->rcx);
    return is_write ? wrmsr_handler(vcpu, gprs, msr)
                    : rdmsr_handler(vcpu, gprs, msr);
}

}
