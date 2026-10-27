#include "cache_vtx.hpp"

namespace vtx {

auto cache_handler::get() -> cache_handler* {
    static cache_handler instance;
    return &instance;
}

auto cache_handler::guest_cpl() -> u8 {
    size_t cs = 0;
    __vmx_vmread(static_cast<size_t>(vmcs_field::guest_cs_sel), &cs);
    return static_cast<u8>(cs & 3);
}

auto cache_handler::invd_exit_handler() -> bool {
    if (guest_cpl() != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    // Running INVD in VMX root can discard dirty host cache lines. Use the
    // write-back form as the safe virtualization boundary for guest INVD.
    __wbinvd();
    return true;
}

auto cache_handler::wbinvd_exit_handler() -> bool {
    if (guest_cpl() != 0) {
        event_handler::get()->inject_gp(0);
        return false;
    }

    __wbinvd();
    return true;
}

}
