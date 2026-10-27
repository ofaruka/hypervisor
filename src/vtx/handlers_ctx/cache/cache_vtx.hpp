#pragma once
#include "../../../includes.h"

namespace vtx {

class cache_handler {
private:
    cache_handler() = default;

    auto guest_cpl() -> u8;

public:
    static auto get() -> cache_handler*;
    auto invd_exit_handler() -> bool;
    auto wbinvd_exit_handler() -> bool;
};

}
