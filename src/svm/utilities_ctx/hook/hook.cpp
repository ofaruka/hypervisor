#include "hook.hpp"
#include "../../../hv_spinlock.hpp"

namespace svm {

hook::hook() : hook_count(0) {
    RtlZeroMemory(hooks, sizeof(hooks));

    for (size_t i = 0; i < MAX_HOOKS; i++) {
        hooks[i].original_address = nullptr;
        hooks[i].target_address = nullptr;
        hooks[i].proxy_address = nullptr;
        hooks[i].detour_address = nullptr;
        hooks[i].hook_address = nullptr;
        hooks[i].hook_size = 0;
        hooks[i].original_pfn = 0;
        hooks[i].hook_pfn = 0;
        hooks[i].is_active = false;
        hooks[i].original_mdl = nullptr;
        hooks[i].hook_mdl = nullptr;
    }
}

auto hook::fix_relative_instructions(void* original_address, void* detour_ptr, u32 patch_size, u8* abs_jump_table,
                                     u32& abs_jump_offset) -> bool {
    uint8_t* detour_bytes = static_cast<uint8_t*>(detour_ptr);
    uint64_t original_addr = reinterpret_cast<uint64_t>(original_address);
    uint64_t detour_addr = reinterpret_cast<uint64_t>(detour_ptr);
    uint32_t offset = 0;

    auto reg_index = [](ZydisRegister reg) -> int {
        auto full = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
        auto id = ZydisRegisterGetId(full);
        return id >= 0 && id <= 15 ? id : -1;
    };

    auto emit_mov_imm64 = [](u8*& out, int reg, u64 value) {
        *out++ = static_cast<u8>(0x48 | ((reg & 8) ? 1 : 0));
        *out++ = static_cast<u8>(0xB8 + (reg & 7));
        *reinterpret_cast<u64*>(out) = value;
        out += sizeof(u64);
    };

    auto emit_abs_jump = [](u8*& out, u64 target) {
        *out++ = 0xFF;
        *out++ = 0x25;
        *reinterpret_cast<u32*>(out) = 0;
        out += sizeof(u32);
        *reinterpret_cast<u64*>(out) = target;
        out += sizeof(u64);
    };

    auto rewrite_rip_memory = [&](u32 insn_offset, const ZydisDecodedInstruction& instruction,
                                  ZydisDecodedOperand* operands, u64 effective_addr) -> bool {
        if (instruction.length < 5 || abs_jump_offset + 64 > 256) {
            return false;
        }

        bool used_registers[16]{};
        for (u8 i = 0; i < instruction.operand_count; ++i) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                auto reg = reg_index(operands[i].reg.value);
                if (reg >= 0) {
                    used_registers[reg] = true;
                }
            } else if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                auto base = reg_index(operands[i].mem.base);
                auto index = reg_index(operands[i].mem.index);
                if (base >= 0) {
                    used_registers[base] = true;
                }
                if (index >= 0) {
                    used_registers[index] = true;
                }
            }
        }

        if (used_registers[4]) {
            return false;
        }

        constexpr int scratch_candidates[] = {11, 10, 9, 8, 2, 1, 0};
        int scratch = -1;
        for (auto candidate : scratch_candidates) {
            if (!used_registers[candidate]) {
                scratch = candidate;
                break;
            }
        }
        if (scratch < 0) {
            return false;
        }

        ZydisEncoderRequest request{};
        if (ZYAN_FAILED(ZydisEncoderDecodedInstructionToEncoderRequest(
                &instruction, operands, instruction.operand_count_visible, &request))) {
            return false;
        }

        bool replaced = false;
        for (u8 i = 0; i < request.operand_count; ++i) {
            if (request.operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                request.operands[i].mem.base == ZYDIS_REGISTER_RIP) {
                request.operands[i].mem.base = ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, static_cast<ZyanU8>(scratch));
                request.operands[i].mem.displacement = 0;
                replaced = true;
                break;
            }
        }
        if (!replaced) {
            return false;
        }

        u8 encoded[ZYDIS_MAX_INSTRUCTION_LENGTH]{};
        ZyanUSize encoded_length = sizeof(encoded);
        if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&request, encoded, &encoded_length))) {
            return false;
        }

        u8* stub = abs_jump_table + abs_jump_offset;
        auto stub_addr = reinterpret_cast<u64>(stub);
        auto jump_from = detour_addr + insn_offset + 5;
        auto rel_to_stub = static_cast<int64_t>(stub_addr) - static_cast<int64_t>(jump_from);
        if (rel_to_stub < INT32_MIN || rel_to_stub > INT32_MAX) {
            return false;
        }

        if (scratch >= 8) {
            *stub++ = 0x41;
        }
        *stub++ = static_cast<u8>(0x50 + (scratch & 7));
        emit_mov_imm64(stub, scratch, effective_addr);
        RtlCopyMemory(stub, encoded, encoded_length);
        stub += encoded_length;
        if (scratch >= 8) {
            *stub++ = 0x41;
        }
        *stub++ = static_cast<u8>(0x58 + (scratch & 7));

        emit_abs_jump(stub, detour_addr + insn_offset + instruction.length);
        abs_jump_offset = static_cast<u32>(stub - abs_jump_table);
        detour_bytes[insn_offset] = 0xE9;
        *reinterpret_cast<int32_t*>(detour_bytes + insn_offset + 1) = static_cast<int32_t>(rel_to_stub);
        RtlFillMemory(detour_bytes + insn_offset + 5, instruction.length - 5, 0x90);
        return true;
    };

    while (offset < patch_size) {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (!disassembler::get()->decode_full(detour_bytes + offset, 15, 64, &instruction, operands)) {
            offset++;
            continue;
        }

        uint32_t insn_length = instruction.length;

        if (insn_length == 0) {
            offset++;
            continue;
        }

        bool rewritten_rip_memory = false;
        for (uint8_t i = 0; i < instruction.operand_count; i++) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && operands[i].mem.base == ZYDIS_REGISTER_RIP &&
                instruction.raw.disp.size == 32) {
                int32_t orig_disp = *reinterpret_cast<int32_t*>(detour_bytes + offset + instruction.raw.disp.offset);
                uint64_t effective_addr = original_addr + offset + insn_length + orig_disp;
                int64_t new_disp =
                    static_cast<int64_t>(effective_addr) - static_cast<int64_t>(detour_addr + offset + insn_length);
                if (new_disp >= INT32_MIN && new_disp <= INT32_MAX) {
                    *reinterpret_cast<int32_t*>(detour_bytes + offset + instruction.raw.disp.offset) =
                        static_cast<int32_t>(new_disp);
                } else if (rewrite_rip_memory(offset, instruction, operands, effective_addr)) {
                    rewritten_rip_memory = true;
                } else {
                    return false;
                }

                break;
            }
        }

        if (rewritten_rip_memory) {
            offset += insn_length;
            continue;
        }

        uint8_t opcode = detour_bytes[offset];

        if (opcode == 0xEB && insn_length == 2) {
            int8_t rel8 = static_cast<int8_t>(detour_bytes[offset + 1]);
            uint64_t target = original_addr + offset + 2 + rel8;
            int64_t new_rel = static_cast<int64_t>(target) - static_cast<int64_t>(detour_addr + offset + 2);
            if (new_rel >= INT8_MIN && new_rel <= INT8_MAX) {
                detour_bytes[offset + 1] = static_cast<uint8_t>(static_cast<int8_t>(new_rel));
            } else {
                uint64_t stub_addr = reinterpret_cast<uint64_t>(abs_jump_table + abs_jump_offset);
                int64_t rel_to_stub = static_cast<int64_t>(stub_addr) - static_cast<int64_t>(detour_addr + offset + 2);
                if (rel_to_stub < INT8_MIN || rel_to_stub > INT8_MAX) {
                    return false;
                }

                detour_bytes[offset + 1] = static_cast<uint8_t>(static_cast<int8_t>(rel_to_stub));
                abs_jump_table[abs_jump_offset++] = 0xFF;
                abs_jump_table[abs_jump_offset++] = 0x25;
                *reinterpret_cast<uint32_t*>(&abs_jump_table[abs_jump_offset]) = 0;
                abs_jump_offset += 4;
                *reinterpret_cast<uint64_t*>(&abs_jump_table[abs_jump_offset]) = target;
                abs_jump_offset += 8;
            }
        } else if (opcode == 0xE9 && insn_length == 5) {
            int32_t rel32 = *reinterpret_cast<int32_t*>(detour_bytes + offset + 1);
            uint64_t target = original_addr + offset + 5 + rel32;
            int64_t new_rel = static_cast<int64_t>(target) - static_cast<int64_t>(detour_addr + offset + 5);
            if (new_rel >= INT32_MIN && new_rel <= INT32_MAX) {
                *reinterpret_cast<int32_t*>(detour_bytes + offset + 1) = static_cast<int32_t>(new_rel);
            } else {
                uint64_t stub_addr = reinterpret_cast<uint64_t>(abs_jump_table + abs_jump_offset);
                int64_t rel_to_stub = static_cast<int64_t>(stub_addr) - static_cast<int64_t>(detour_addr + offset + 5);
                if (rel_to_stub < INT32_MIN || rel_to_stub > INT32_MAX) {
                    return false;
                }

                *reinterpret_cast<int32_t*>(detour_bytes + offset + 1) = static_cast<int32_t>(rel_to_stub);
                abs_jump_table[abs_jump_offset++] = 0xFF;
                abs_jump_table[abs_jump_offset++] = 0x25;
                *reinterpret_cast<uint32_t*>(&abs_jump_table[abs_jump_offset]) = 0;
                abs_jump_offset += 4;
                *reinterpret_cast<uint64_t*>(&abs_jump_table[abs_jump_offset]) = target;
                abs_jump_offset += 8;
            }
        } else if (opcode == 0xE8 && insn_length == 5) {
            int32_t rel32 = *reinterpret_cast<int32_t*>(detour_bytes + offset + 1);
            uint64_t target = original_addr + offset + 5 + rel32;
            int64_t new_rel = static_cast<int64_t>(target) - static_cast<int64_t>(detour_addr + offset + 5);
            if (new_rel >= INT32_MIN && new_rel <= INT32_MAX) {
                *reinterpret_cast<int32_t*>(detour_bytes + offset + 1) = static_cast<int32_t>(new_rel);
            } else {
                uint64_t stub_addr = reinterpret_cast<uint64_t>(abs_jump_table + abs_jump_offset);
                int64_t rel_to_stub = static_cast<int64_t>(stub_addr) - static_cast<int64_t>(detour_addr + offset + 5);
                if (rel_to_stub < INT32_MIN || rel_to_stub > INT32_MAX) {
                    return false;
                }

                *reinterpret_cast<int32_t*>(detour_bytes + offset + 1) = static_cast<int32_t>(rel_to_stub);
                abs_jump_table[abs_jump_offset++] = 0xFF;
                abs_jump_table[abs_jump_offset++] = 0x25;
                *reinterpret_cast<uint32_t*>(&abs_jump_table[abs_jump_offset]) = 0;
                abs_jump_offset += 4;
                *reinterpret_cast<uint64_t*>(&abs_jump_table[abs_jump_offset]) = target;
                abs_jump_offset += 8;
            }
        } else if (opcode >= 0x70 && opcode <= 0x7F && insn_length == 2) {
            int8_t rel8 = static_cast<int8_t>(detour_bytes[offset + 1]);
            uint64_t target = original_addr + offset + 2 + rel8;
            int64_t new_rel = static_cast<int64_t>(target) - static_cast<int64_t>(detour_addr + offset + 2);
            if (new_rel >= INT8_MIN && new_rel <= INT8_MAX) {
                detour_bytes[offset + 1] = static_cast<uint8_t>(static_cast<int8_t>(new_rel));
            } else {
                uint64_t stub_addr = reinterpret_cast<uint64_t>(abs_jump_table + abs_jump_offset);
                int64_t rel_to_stub = static_cast<int64_t>(stub_addr) - static_cast<int64_t>(detour_addr + offset + 2);
                if (rel_to_stub < INT8_MIN || rel_to_stub > INT8_MAX) {
                    return false;
                }

                detour_bytes[offset + 1] = static_cast<uint8_t>(static_cast<int8_t>(rel_to_stub));
                abs_jump_table[abs_jump_offset++] = 0xFF;
                abs_jump_table[abs_jump_offset++] = 0x25;
                *reinterpret_cast<uint32_t*>(&abs_jump_table[abs_jump_offset]) = 0;
                abs_jump_offset += 4;
                *reinterpret_cast<uint64_t*>(&abs_jump_table[abs_jump_offset]) = target;
                abs_jump_offset += 8;
            }
        } else if (opcode == 0x0F && insn_length == 6) {
            uint8_t second = detour_bytes[offset + 1];

            if (second >= 0x80 && second <= 0x8F) {
                int32_t rel32 = *reinterpret_cast<int32_t*>(detour_bytes + offset + 2);
                uint64_t target = original_addr + offset + 6 + rel32;
                int64_t new_rel = static_cast<int64_t>(target) - static_cast<int64_t>(detour_addr + offset + 6);
                if (new_rel >= INT32_MIN && new_rel <= INT32_MAX) {
                    *reinterpret_cast<int32_t*>(detour_bytes + offset + 2) = static_cast<int32_t>(new_rel);
                } else {
                    uint64_t stub_addr = reinterpret_cast<uint64_t>(abs_jump_table + abs_jump_offset);
                    int64_t rel_to_stub =
                        static_cast<int64_t>(stub_addr) - static_cast<int64_t>(detour_addr + offset + 6);
                    if (rel_to_stub < INT32_MIN || rel_to_stub > INT32_MAX) {
                        return false;
                    }

                    *reinterpret_cast<int32_t*>(detour_bytes + offset + 2) = static_cast<int32_t>(rel_to_stub);
                    abs_jump_table[abs_jump_offset++] = 0xFF;
                    abs_jump_table[abs_jump_offset++] = 0x25;
                    *reinterpret_cast<uint32_t*>(&abs_jump_table[abs_jump_offset]) = 0;
                    abs_jump_offset += 4;
                    *reinterpret_cast<uint64_t*>(&abs_jump_table[abs_jump_offset]) = target;
                    abs_jump_offset += 8;
                }
            }
        }

        offset += insn_length;
    }

    return true;
}

auto hook::install_function_hook(svm::pvcpu_t vcpu, void* address, void* proxy, void** detour, u64 target_cr3)
    -> svm::svmroot_error_t {
    if (!address || !proxy || !detour || !vcpu) {
        debug::log_error("[Hook] Invalid arguments target=%p vcpu=%p\n", address, vcpu);
        debug::log_error("[Hook] Invalid arguments proxy=%p output=%p\n", proxy, detour);
        return svm::svmroot_error_t::error_failed;
    }

    auto find_existing_hook = [&](u64 original_pfn) -> hook_context* {
        for (size_t i = 0; i < hook_count; i++) {
            if (hooks[i].is_active && hooks[i].original_pfn == original_pfn && hooks[i].hook_address) {
                return &hooks[i];
            }
        }

        return nullptr;
    };

    {
        // Hook table reads only need exclusion against commit writers.
        hv_shared_lock_guard lock;

        for (size_t i = 0; i < hook_count; i++) {
            auto& installed = hooks[i];
            if (!installed.is_active || installed.target_address != address) {
                continue;
            }

            if (installed.proxy_address != proxy || !installed.detour_address) {
                logs::get()->write("[ERROR] [Hook] Target conflict target=%p owner=%p requested=%p\n",
                    address, installed.proxy_address, proxy);
                logs::get()->write("[ERROR] [Hook] Existing original=%p slot=%llu count=%llu\n",
                    installed.detour_address, static_cast<unsigned long long>(i),
                    static_cast<unsigned long long>(hook_count));
                return svm::svmroot_error_t::error_failed;
            }

            *detour = installed.detour_address;
            return svm::svmroot_error_t::error_success;
        }
    }

    void* readable_address = address;

    if (target_cr3) {
        svm::cr3_t cr3_val{};
        cr3_val.value = target_cr3;
        auto pa = page_table::get()->get_physical_address(vcpu, cr3_val, reinterpret_cast<u64>(address));

        if (pa < PAGE_SIZE) {
            debug::log_error("[Hook] Target translation failed target=%p status=0x%llX\n", address, pa);
            return svm::svmroot_error_t::error_failed;
        }

        readable_address = reinterpret_cast<void*>(host_physical_memory_base + pa);
    }

    auto make_proxy_executable = [&](svm::cr3_t cr3) -> bool {
        if (!cr3.value) {
            return false;
        }

        auto result = page_table::get()->clear_guest_pte_nx(vcpu, cr3, reinterpret_cast<u64>(proxy), true);
        return result == svm::svmroot_error_t::error_success;
    };

    bool proxy_executable = make_proxy_executable(vcpu->guest_vmcb.state_save_area.cr3);

    if (vcpu->host_stack_layout.shared_vcpu) {
        proxy_executable =
            make_proxy_executable(vcpu->host_stack_layout.shared_vcpu->system_cr3) || proxy_executable;
    }

    if (target_cr3) {
        svm::cr3_t cr3_val{};
        cr3_val.value = target_cr3;
        proxy_executable = make_proxy_executable(cr3_val) || proxy_executable;
    }

    if (!proxy_executable) {
        debug::log_error("[Hook] Proxy not executable proxy=%p target=%p cr3=0x%llX\n", proxy, address,
                      target_cr3);
        return svm::svmroot_error_t::error_failed;
    }

    for (u32 cpu = 0; cpu < virtualization::get()->get_processor_count(); cpu++) {
        flush_tlb_t{}.flush_tlb(virtualization::get()->vcpus[cpu], flush_tlb_t::tlb_control_id::flush_entire_tlb);
    }

    constexpr u32 hook_length = 14;
    constexpr u32 detour_length = 14;
    auto patch_size = utilities::get()->get_patch_size(readable_address, hook_length);

    if (patch_size == 0) {
        debug::log_error("[Hook] Decode failed target=%p readable=%p\n", address, readable_address);
        return svm::svmroot_error_t::error_failed;
    }

    *detour = memory::get()->alloc_executable_pool(patch_size + detour_length + 256);

    if (!*detour) {
        debug::log_error("[Hook] Detour allocation failed target=%p size=%lu\n",
            address, static_cast<unsigned long>(patch_size + detour_length + 256));
        return svm::svmroot_error_t::error_failed;
    }

    RtlFillMemory(*detour, patch_size + detour_length + 256, 0x90);

    // The target page must be pinned by the caller in guest mode. Root mode
    // must not call MmProbeAndLockPages (or any guest MM API): it can block
    // on locks that TLB-shootdown shooters hold across IPI barriers.
    PMDL original_mdl = nullptr;

    u8 hook_code[hook_length] = {0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0, 0x90, 0x90};
    u64 proxy_addr = reinterpret_cast<u64>(proxy);
    *reinterpret_cast<u64*>(hook_code + 2) = proxy_addr;
    u8 detour_code[detour_length] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};
    *reinterpret_cast<u64*>(detour_code + 6) = reinterpret_cast<u64>(address) + patch_size;
    memcpy(*detour, readable_address, patch_size);
    uint8_t* abs_jump_table = static_cast<uint8_t*>(*detour) + patch_size + detour_length;
    uint32_t abs_jump_offset = 0;

    if (!fix_relative_instructions(address, *detour, patch_size, abs_jump_table, abs_jump_offset)) {
        if (original_mdl) {
            utilities::get()->unlock_pages(original_mdl);
        }

        memory::get()->free_nonpaged_pool(*detour);
        debug::log_error("[Hook] Relocation failed target=%p detour=%p patch=%lu\n",
                      address, *detour, static_cast<unsigned long>(patch_size));
        return svm::svmroot_error_t::error_failed;
    }

    memcpy(static_cast<u8*>(*detour) + patch_size, detour_code, detour_length);
    auto const start_addr = reinterpret_cast<u64>(address);
    auto const start_page = start_addr & ~0xFFFULL;
    auto const end_addr = start_addr + hook_length;
    auto const end_page = (end_addr + 0xFFF) & ~0xFFFULL;
    auto const num_pages = (end_page - start_page) >> 12;
    debug::panicf("Detour at: %p, Hook spans %d pages\n", *detour, num_pages);

    struct page_info {
        void* exec_page;
        PMDL exec_mdl;
        u64 orig_pfn;
        u64 exec_pfn;
        u16 patch_offset;
        u16 patch_size;
        // Offset of this page's slice inside the 14-byte hook_code blob.
        // bytes_remaining is consumed by the preparation loop, so the commit
        // pass needs its own copy to re-apply the patch into a shared page.
        u16 patch_source_offset;
        bool installed;
        // True when the patch was applied into another hook's exec page that
        // already covers this physical frame (same page, second function).
        bool merged;
    };

    page_info* allocated_pages = (page_info*)memory::get()->alloc_nonpaged_pool(sizeof(page_info) * num_pages);

    if (!allocated_pages) {
        debug::log_error("[Hook] Page metadata allocation failed target=%p pages=%lu\n",
            address, static_cast<unsigned long>(num_pages));
        if (original_mdl) {
            utilities::get()->unlock_pages(original_mdl);
        }
        memory::get()->free_nonpaged_pool(*detour);
        *detour = nullptr;
        return svm::svmroot_error_t::error_failed;
    }

    RtlZeroMemory(allocated_pages, sizeof(page_info) * num_pages);

    // Preparation pass: everything here may block on guest locks (pool
    // allocator, MDL pinning), so it must run WITHOUT the hv lock. Holding
    // the hv lock across these calls deadlocks against guest threads that
    // hold those locks and then hit an NPF, whose handler needs the shared
    // hv lock (observed as a boot freeze with PiEngineLock held).
    bool success = true;
    auto current_addr = start_addr;
    size_t bytes_remaining = hook_length;

    for (u32 page = 0; page < num_pages && success; page++) {
        auto const page_base = current_addr & ~0xFFFULL;
        svm::cr3_t translate_cr3{};
        translate_cr3.value = target_cr3;
        auto const orig_pa = page_table::get()->get_physical_address(vcpu, translate_cr3, page_base);

        if (orig_pa < PAGE_SIZE) {
            debug::log_error("[Hook] Target page translation failed target=%p page=%u status=0x%llX\n",
                address, page, orig_pa);
            success = false;
            break;
        }

        auto& info = allocated_pages[page];
        info.orig_pfn = orig_pa >> 12;
        info.patch_offset = static_cast<u16>(current_addr & 0xFFF);
        info.patch_size = static_cast<u16>(min(bytes_remaining, PAGE_SIZE - info.patch_offset));
        info.patch_source_offset = static_cast<u16>(hook_length - bytes_remaining);

        info.exec_page = memory::get()->alloc_nonpaged_pool(PAGE_SIZE);

        if (!info.exec_page) {
            debug::log_error("[Hook] Shadow page allocation failed target=%p page=%u\n", address, page);
            success = false;
            break;
        }

        auto const exec_pa =
            page_table::get()->get_physical_address(vcpu, svm::cr3_t{}, reinterpret_cast<u64>(info.exec_page));

        if (exec_pa < PAGE_SIZE) {
            debug::log_error("[Hook] Shadow page translation failed target=%p page=%u status=0x%llX\n",
                address, page, exec_pa);
            success = false;
            break;
        }

        info.exec_pfn = exec_pa >> 12;

        if (target_cr3) {
            memcpy(info.exec_page, host_physical_memory_base + orig_pa, PAGE_SIZE);
        } else {
            memcpy(info.exec_page, reinterpret_cast<void*>(page_base), PAGE_SIZE);
        }

        memcpy(static_cast<u8*>(info.exec_page) + info.patch_offset,
               hook_code + (hook_length - bytes_remaining), info.patch_size);

        // Arena memory is contiguous and pinned for the lifetime of the
        // hypervisor; no MDL is needed for exec pages.
        info.exec_mdl = nullptr;

        current_addr = page_base + PAGE_SIZE;
        bytes_remaining -= info.patch_size;
    }

    void* our_detour = *detour;
    bool reused_existing = false;

    if (success) {
        // Commit: strictly non-blocking NPT/VMCB metadata updates under the
        // exclusive lock. NPF handlers on other CPUs wait at most a few
        // microseconds here, so they can never form a lock cycle with guest
        // locks held by their interrupted threads.
        hv_exclusive_lock_guard lock;

        // Another install may have won the race while we were preparing.
        for (size_t i = 0; i < hook_count; i++) {
            auto& installed = hooks[i];
            if (!installed.is_active || installed.target_address != address) {
                continue;
            }

            if (installed.proxy_address != proxy || !installed.detour_address) {
                logs::get()->write("[ERROR] [Hook] Target conflict at commit target=%p owner=%p requested=%p\n",
                    address, installed.proxy_address, proxy);
                success = false;
                break;
            }

            *detour = installed.detour_address;
            reused_existing = true;
            break;
        }

        auto const first_hook_index = hook_count;

        for (u32 page = 0; page < num_pages && success && !reused_existing; page++) {
            auto& info = allocated_pages[page];
            auto existing_hook = find_existing_hook(info.orig_pfn);

            if (existing_hook) {
                // A different function on this physical frame is already
                // hooked: the shadow NPT maps the frame to that hook's exec
                // page, so the new patch bytes must be applied THERE. The
                // prepared exec page for this install is redundant and gets
                // freed by the cleanup pass (installed stays false).
                memcpy(static_cast<u8*>(existing_hook->hook_address) + info.patch_offset,
                       hook_code + info.patch_source_offset, info.patch_size);

                auto hook_result = npt::get()->install_npt_hook(info.orig_pfn, existing_hook->hook_pfn,
                                                                info.patch_offset, info.patch_size);
                if (hook_result != svm::svmroot_error_t::error_success) {
                    debug::log_error("[Hook] NPT update failed target=%p page=%u status=0x%llX\n",
                        address, page, hook_result);
                    success = false;
                    break;
                }

                // Track this hook separately so it stays visible for
                // remove_function_hook. hook_address/hook_mdl stay null: the
                // shared exec page is owned (and freed) by the first hook's
                // entry - freeing it here as well would double-free.
                if (hook_count >= MAX_HOOKS) {
                    debug::log_error("[Hook] Hook table full target=%p count=%llu limit=%llu\n", address,
                        static_cast<unsigned long long>(hook_count), static_cast<unsigned long long>(MAX_HOOKS));
                    success = false;
                    break;
                }

                hooks[hook_count].original_address = reinterpret_cast<void*>(start_page + (static_cast<u64>(page) << 12));
                hooks[hook_count].target_address = address;
                hooks[hook_count].proxy_address = proxy;
                hooks[hook_count].detour_address = our_detour;
                hooks[hook_count].hook_address = nullptr;
                hooks[hook_count].hook_size = info.patch_size;
                hooks[hook_count].original_pfn = info.orig_pfn;
                hooks[hook_count].hook_pfn = existing_hook->hook_pfn;
                hooks[hook_count].is_active = true;
                hooks[hook_count].original_mdl = nullptr;
                hooks[hook_count].hook_mdl = nullptr;
                _InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hook_count));
                info.merged = true;
                continue;
            }

            if (hook_count >= MAX_HOOKS) {
                debug::log_error("[Hook] Hook table full target=%p count=%llu limit=%llu\n", address,
                    static_cast<unsigned long long>(hook_count), static_cast<unsigned long long>(MAX_HOOKS));
                success = false;
                break;
            }

            auto hook_result =
                npt::get()->install_npt_hook(info.orig_pfn, info.exec_pfn, info.patch_offset, info.patch_size);
            if (hook_result != svm::svmroot_error_t::error_success) {
                debug::log_error("[Hook] NPT install failed target=%p page=%u status=0x%llX\n",
                    address, page, hook_result);
                success = false;
                break;
            }

            hooks[hook_count].original_address = reinterpret_cast<void*>(start_page + (static_cast<u64>(page) << 12));
            hooks[hook_count].target_address = address;
            hooks[hook_count].proxy_address = proxy;
            hooks[hook_count].detour_address = our_detour;
            hooks[hook_count].hook_address = info.exec_page;
            hooks[hook_count].hook_size = info.patch_size;
            hooks[hook_count].original_pfn = info.orig_pfn;
            hooks[hook_count].hook_pfn = info.exec_pfn;
            hooks[hook_count].is_active = true;
            hooks[hook_count].original_mdl = (page == 0) ? original_mdl : nullptr;
            hooks[hook_count].hook_mdl = info.exec_mdl;
            _InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&hook_count));
            info.installed = true;
        }

        if (!success && !reused_existing) {
            // Roll back NPT hooks armed by this commit (still non-blocking)
            // and truncate the hook table entries we appended.
            for (u32 page = 0; page < num_pages; page++) {
                auto& rollback_info = allocated_pages[page];

                if (rollback_info.installed) {
                    npt::get()->remove_npt_hook(rollback_info.orig_pfn);
                    rollback_info.installed = false;
                    continue;
                }

                if (rollback_info.merged) {
                    // Undo the patch we applied into the sibling hook's
                    // shared exec page, or a failed install would leave an
                    // armed jump to a proxy the caller believes is gone.
                    auto sibling = find_existing_hook(rollback_info.orig_pfn);

                    if (sibling && sibling->hook_address) {
                        memcpy(static_cast<u8*>(sibling->hook_address) + rollback_info.patch_offset,
                               static_cast<u8*>(host_physical_memory_base + (rollback_info.orig_pfn << 12)) +
                                   rollback_info.patch_offset,
                               rollback_info.patch_size);
                    }

                    rollback_info.merged = false;
                }
            }

            while (hook_count > first_hook_index) {
                _InterlockedDecrement64(reinterpret_cast<volatile LONG64*>(&hook_count));
                RtlZeroMemory(&hooks[hook_count], sizeof(hooks[hook_count]));
            }
        }
    }

    // Cleanup: pool/MDL operations may block, keep them outside the lock.
    for (u32 page = 0; page < num_pages; page++) {
        auto& info = allocated_pages[page];
        if (info.installed) {
            continue;
        }
        if (info.exec_mdl) {
            utilities::get()->unlock_pages(info.exec_mdl);
        }
        if (info.exec_page) {
            memory::get()->free_nonpaged_pool(info.exec_page);
        }
    }

    memory::get()->free_nonpaged_pool(allocated_pages);

    if (reused_existing) {
        // We prepared a duplicate; the table already had this hook.
        if (original_mdl) {
            utilities::get()->unlock_pages(original_mdl);
        }
        memory::get()->free_nonpaged_pool(our_detour);
        return svm::svmroot_error_t::error_success;
    }

    if (!success) {
        if (original_mdl) {
            utilities::get()->unlock_pages(original_mdl);
        }
        memory::get()->free_nonpaged_pool(our_detour);
        *detour = nullptr;
        return svm::svmroot_error_t::error_failed;
    }

    return svm::svmroot_error_t::error_success;
}

auto hook::install_driver_hooks(svm::pvcpu_t vcpu, const wchar_t* driver_name, u32 major_function, void* proxy,
                                void** detour, void** target) -> svm::svmroot_error_t {
    if (!vcpu || !driver_name || !proxy || !detour || major_function > IRP_MJ_MAXIMUM_FUNCTION) {
        return svm::svmroot_error_t::error_failed;
    }

    UNICODE_STRING object_name{};
    RtlInitUnicodeString(&object_name, driver_name);

    PVOID object = nullptr;
    auto status = ObReferenceObjectByName(&object_name, OBJ_CASE_INSENSITIVE, nullptr, 0, *IoDriverObjectType,
                                          KernelMode, nullptr, &object);
    if (!NT_SUCCESS(status) || !object) {
        return svm::svmroot_error_t::error_failed;
    }

    auto driver_object = static_cast<PDRIVER_OBJECT>(object);
    auto dispatch = reinterpret_cast<void*>(driver_object->MajorFunction[major_function]);
    if (!dispatch) {
        ObfDereferenceObject(driver_object);
        return svm::svmroot_error_t::error_failed;
    }

    if (target) {
        *target = dispatch;
    }

    auto result = install_function_hook(vcpu, dispatch, proxy, detour);
    debug::panicf("[hook] driver %ws major=%lu dispatch=%p result=0x%llx\n",
                  driver_name,
                  static_cast<unsigned long>(major_function),
                  dispatch,
                  result);
    ObfDereferenceObject(driver_object);
    return result;
}

auto hook::remove_function_hook(svm::pvcpu_t vcpu, void* target) -> svm::svmroot_error_t {
    if (!target || !vcpu) {
        return svm::svmroot_error_t::error_failed;
    }

    struct removed_hook {
        PMDL hook_mdl;
        PMDL original_mdl;
        void* hook_address;
    };

    removed_hook removed[MAX_HOOKS];
    size_t removed_count = 0;
    bool found = false;
    auto result = svm::svmroot_error_t::error_success;
    u64 target_page = reinterpret_cast<u64>(target) & ~0xFFFULL;

    {
        // Non-blocking NPT unhook + table unlink under the exclusive lock;
        // MDL/pool frees run after release because they may block on guest
        // locks.
        hv_exclusive_lock_guard lock;

        for (size_t i = 0; i < hook_count;) {
            u64 hook_page = reinterpret_cast<u64>(hooks[i].original_address) & ~0xFFFULL;

            if (hook_page == target_page && hooks[i].is_active) {
                found = true;
                auto hook_result = npt::get()->remove_npt_hook(hooks[i].original_pfn);

                if (hook_result != svm::svmroot_error_t::error_success) {
                    debug::panicf("Failed to remove NPT hook for PFN %llx\n", hooks[i].original_pfn);
                    result = svm::svmroot_error_t::error_failed;
                    break;
                }

                removed[removed_count].hook_mdl = hooks[i].hook_mdl;
                removed[removed_count].original_mdl = hooks[i].original_mdl;
                removed[removed_count].hook_address = hooks[i].hook_address;
                removed_count++;

                debug::panicf("Removed hook at %p (PFN: %llx)\n", hooks[i].original_address, hooks[i].original_pfn);

                auto last_index = hook_count - 1;
                if (i != last_index) {
                    hooks[i] = hooks[last_index];
                }
                RtlZeroMemory(&hooks[last_index], sizeof(hooks[last_index]));
                _InterlockedDecrement64(reinterpret_cast<volatile LONG64*>(&hook_count));
                continue;
            }

            i++;
        }
    }

    for (size_t i = 0; i < removed_count; i++) {
        if (removed[i].hook_mdl) {
            utilities::get()->unlock_pages(removed[i].hook_mdl);
        }
        if (removed[i].original_mdl) {
            utilities::get()->unlock_pages(removed[i].original_mdl);
        }
        if (removed[i].hook_address) {
            memory::get()->free_nonpaged_pool(removed[i].hook_address);
        }
    }

    if (result != svm::svmroot_error_t::error_success) {
        return result;
    }

    return found ? svm::svmroot_error_t::error_success : svm::svmroot_error_t::error_failed;
}

auto hook::get() -> hook* {
    static hook instance;
    return &instance;
}
}
