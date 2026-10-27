#pragma once
#include "../../../includes.h"

namespace vtx {
    class vmx {
    private:
        static constexpr u64 cr4_vmxe_bit = 1ULL << 13;
        static constexpr u32 segment_unusable_bit = 1u << 16;

        vmx() = default;

    public:
        static vmx* get();

        u32 get_vmcs_revision_id();

        u64 adjust_cr0_for_vmx(u64 cr0);
        u64 adjust_cr4_for_vmx(u64 cr4);

        bool enter_vmx_root(pvcpu_t vcpu);
        void leave_vmx_root(pvcpu_t vcpu = nullptr);

        bool vmcs_init(pvcpu_t vcpu);
        bool setup_vmcs(pvcpu_t vcpu);

    private:
        u32 adjust_ctls(u32 wanted, u32 capability_msr_id);

        struct segment_info { u64 base; u32 limit; u32 ar; };
        segment_info read_segment(u64 gdt_base, u16 sel);
    };
}

    extern "C" {
    u8 vtx_vmlaunch_entry(vtx::pvcpu_t vcpu, u64 host_rsp_top);
    void vtx_vmexit_entry();
    void vtx_devirtualize_via_vmcall();
    void vtx_invept_all(u64 eptp);
    void vtx_invept_via_vmcall();
    void vtx_invvpid_all_contexts();
    void vtx_invd();
    void vtx_write_cr2(u64 value);
}
