#include "hook.hpp"
#include "../../../hv_spinlock.hpp"

namespace vtx {

hook::hook() : record_count_(0) {
    RtlZeroMemory(records_, sizeof(records_));
}

auto hook::fix_rip_relative(void* original_va, void* detour_buf, u32 patch_size,
                            u8* abs_jump_table, u32& abs_jump_offset) -> bool {
    auto bytes = static_cast<u8*>(detour_buf);
    auto orig_addr = reinterpret_cast<u64>(original_va);
    auto detour_addr = reinterpret_cast<u64>(detour_buf);
    u32 offset = 0;

    auto reg_index = [](ZydisRegister reg) -> int {
        auto full = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
        auto id = ZydisRegisterGetId(full);
        return id >= 0 && id <= 15 ? id : -1;
    };

    auto emit_rex = [](u8*& out, bool wide, int reg, int rm) {
        u8 rex = 0x40;
        if (wide) {
            rex |= 0x08;
        }
        if (reg & 8) {
            rex |= 0x04;
        }
        if (rm & 8) {
            rex |= 0x01;
        }
        if (rex != 0x40) {
            *out++ = rex;
        }
    };

    auto emit_mov_imm64 = [](u8*& out, int reg, u64 value) {
        *out++ = static_cast<u8>(0x48 | ((reg & 8) ? 1 : 0));
        *out++ = static_cast<u8>(0xB8 + (reg & 7));
        *reinterpret_cast<u64*>(out) = value;
        out += sizeof(u64);
    };

    auto emit_mov_reg_mem = [&](u8*& out, int reg, int base, bool wide) {
        emit_rex(out, wide, reg, base);
        *out++ = 0x8B;
        *out++ = static_cast<u8>(((reg & 7) << 3) | (base & 7));
    };

    auto emit_abs_jump_code = [](u8*& out, u64 target) {
        *out++ = 0xFF;
        *out++ = 0x25;
        *reinterpret_cast<u32*>(out) = 0;
        out += sizeof(u32);
        *reinterpret_cast<u64*>(out) = target;
        out += sizeof(u64);
    };

    auto emit_abs_stub = [&](u64 target) -> u64 {
        u64 stub = reinterpret_cast<u64>(abs_jump_table + abs_jump_offset);
        auto out = abs_jump_table + abs_jump_offset;
        emit_abs_jump_code(out, target);
        abs_jump_offset = static_cast<u32>(out - abs_jump_table);
        return stub;
    };

    auto rewrite_rip_memory = [&](u32 insn_offset, const ZydisDecodedInstruction& instruction,
                                  ZydisDecodedOperand* operands, u64 effective_addr) -> bool {
        if (instruction.length < 5 || abs_jump_offset + 64 > 256) {
            return false;
        }

        if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
            return false;
        }

        auto reg = reg_index(operands[0].reg.value);
        if (reg < 0 || reg == 4) {
            return false;
        }

        u8* stub = abs_jump_table + abs_jump_offset;
        auto stub_addr = reinterpret_cast<u64>(stub);
        auto jump_from = detour_addr + insn_offset + 5;
        auto rel_to_stub = static_cast<int64_t>(stub_addr) - static_cast<int64_t>(jump_from);
        if (rel_to_stub < INT32_MIN || rel_to_stub > INT32_MAX) {
            return false;
        }

        if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA && operands[0].size == 64) {
            emit_mov_imm64(stub, reg, effective_addr);
        } else if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV &&
                   operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                   (operands[0].size == 64 || operands[0].size == 32)) {
            constexpr int scratch = 11;
            auto preserve = reg != scratch;
            if (preserve) {
                *stub++ = 0x41;
                *stub++ = 0x53;
            }
            emit_mov_imm64(stub, scratch, effective_addr);
            emit_mov_reg_mem(stub, reg, scratch, operands[0].size == 64);
            if (preserve) {
                *stub++ = 0x41;
                *stub++ = 0x5B;
            }
        } else {
            return false;
        }

        emit_abs_jump_code(stub, detour_addr + insn_offset + instruction.length);
        abs_jump_offset = static_cast<u32>(stub - abs_jump_table);
        bytes[insn_offset] = 0xE9;
        *reinterpret_cast<int32_t*>(bytes + insn_offset + 1) = static_cast<int32_t>(rel_to_stub);
        RtlFillMemory(bytes + insn_offset + 5, instruction.length - 5, 0x90);
        return true;
    };

    while (offset < patch_size) {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (!svm::disassembler::get()->decode_full(
                bytes + offset, 15, 64, &instruction, operands)) {
            offset++;
            continue;
        }
        u32 insn_length = instruction.length;
        if (insn_length == 0) { offset++; continue; }

        bool rewritten_rip_memory = false;
        for (uint8_t i = 0; i < instruction.operand_count; i++) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[i].mem.base == ZYDIS_REGISTER_RIP &&
                instruction.raw.disp.size == 32) {
                int32_t orig_disp = *reinterpret_cast<int32_t*>(
                    bytes + offset + instruction.raw.disp.offset);
                u64 effective = orig_addr + offset + insn_length + orig_disp;
                int64_t new_disp = static_cast<int64_t>(effective) -
                                   static_cast<int64_t>(detour_addr + offset + insn_length);
                if (new_disp >= INT32_MIN && new_disp <= INT32_MAX) {
                    *reinterpret_cast<int32_t*>(
                        bytes + offset + instruction.raw.disp.offset) =
                        static_cast<int32_t>(new_disp);
                } else if (rewrite_rip_memory(offset, instruction, operands, effective)) {
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

        u8 opcode = bytes[offset];

        if (opcode == 0xEB && insn_length == 2) {
            int8_t rel8 = static_cast<int8_t>(bytes[offset + 1]);
            u64 target = orig_addr + offset + 2 + rel8;
            int64_t new_rel = static_cast<int64_t>(target) -
                              static_cast<int64_t>(detour_addr + offset + 2);
            if (new_rel >= INT8_MIN && new_rel <= INT8_MAX) {
                bytes[offset + 1] = static_cast<uint8_t>(static_cast<int8_t>(new_rel));
            } else {
                u64 stub = emit_abs_stub(target);
                int64_t rel = static_cast<int64_t>(stub) -
                              static_cast<int64_t>(detour_addr + offset + 2);
                if (rel < INT8_MIN || rel > INT8_MAX) return false;
                bytes[offset + 1] = static_cast<uint8_t>(static_cast<int8_t>(rel));
            }
        }
        else if (opcode == 0xE9 && insn_length == 5) {
            int32_t rel32 = *reinterpret_cast<int32_t*>(bytes + offset + 1);
            u64 target = orig_addr + offset + 5 + rel32;
            int64_t new_rel = static_cast<int64_t>(target) -
                              static_cast<int64_t>(detour_addr + offset + 5);
            if (new_rel >= INT32_MIN && new_rel <= INT32_MAX) {
                *reinterpret_cast<int32_t*>(bytes + offset + 1) = static_cast<int32_t>(new_rel);
            } else {
                u64 stub = emit_abs_stub(target);
                int64_t rel = static_cast<int64_t>(stub) -
                              static_cast<int64_t>(detour_addr + offset + 5);
                if (rel < INT32_MIN || rel > INT32_MAX) return false;
                *reinterpret_cast<int32_t*>(bytes + offset + 1) = static_cast<int32_t>(rel);
            }
        }
        else if (opcode == 0xE8 && insn_length == 5) {
            int32_t rel32 = *reinterpret_cast<int32_t*>(bytes + offset + 1);
            u64 target = orig_addr + offset + 5 + rel32;
            int64_t new_rel = static_cast<int64_t>(target) -
                              static_cast<int64_t>(detour_addr + offset + 5);
            if (new_rel >= INT32_MIN && new_rel <= INT32_MAX) {
                *reinterpret_cast<int32_t*>(bytes + offset + 1) = static_cast<int32_t>(new_rel);
            } else {
                u64 stub = emit_abs_stub(target);
                int64_t rel = static_cast<int64_t>(stub) -
                              static_cast<int64_t>(detour_addr + offset + 5);
                if (rel < INT32_MIN || rel > INT32_MAX) return false;
                *reinterpret_cast<int32_t*>(bytes + offset + 1) = static_cast<int32_t>(rel);
            }
        }
        else if (opcode >= 0x70 && opcode <= 0x7F && insn_length == 2) {
            int8_t rel8 = static_cast<int8_t>(bytes[offset + 1]);
            u64 target = orig_addr + offset + 2 + rel8;
            int64_t new_rel = static_cast<int64_t>(target) -
                              static_cast<int64_t>(detour_addr + offset + 2);
            if (new_rel >= INT8_MIN && new_rel <= INT8_MAX) {
                bytes[offset + 1] = static_cast<uint8_t>(static_cast<int8_t>(new_rel));
            } else {
                u64 stub = emit_abs_stub(target);
                int64_t rel = static_cast<int64_t>(stub) -
                              static_cast<int64_t>(detour_addr + offset + 2);
                if (rel < INT32_MIN || rel > INT8_MAX) return false;
                bytes[offset + 1] = static_cast<uint8_t>(static_cast<int8_t>(rel));
            }
        }
        else if (opcode == 0x0F && insn_length == 6) {
            u8 second = bytes[offset + 1];
            if (second >= 0x80 && second <= 0x8F) {
                int32_t rel32 = *reinterpret_cast<int32_t*>(bytes + offset + 2);
                u64 target = orig_addr + offset + 6 + rel32;
                int64_t new_rel = static_cast<int64_t>(target) -
                                  static_cast<int64_t>(detour_addr + offset + 6);
                if (new_rel >= INT32_MIN && new_rel <= INT32_MAX) {
                    *reinterpret_cast<int32_t*>(bytes + offset + 2) = static_cast<int32_t>(new_rel);
                } else {
                    u64 stub = emit_abs_stub(target);
                    int64_t rel = static_cast<int64_t>(stub) -
                                  static_cast<int64_t>(detour_addr + offset + 6);
                    if (rel < INT32_MIN || rel > INT32_MAX) return false;
                    *reinterpret_cast<int32_t*>(bytes + offset + 2) = static_cast<int32_t>(rel);
                }
            }
        }

        offset += insn_length;
    }

    return true;
}

auto hook::install_function_hook(void* target_va, void* proxy_fn, void** out_detour_fn,
                                 u64 target_cr3, bool issue_invept) -> bool {
    if (!target_va || !proxy_fn || !out_detour_fn) return false;

    auto find_record = [&](u64 orig_pfn) -> hook_record* {
        for (size_t idx = 0; idx < record_count_; ++idx) {
            auto& rec = records_[idx];
            if (rec.is_active && rec.orig_pfn == orig_pfn && rec.exec_page) {
                return &rec;
            }
        }
        return nullptr;
    };

    auto allocate_record = [&]() -> hook_record* {
        for (size_t idx = 0; idx < record_count_; ++idx) {
            auto& rec = records_[idx];
            if (!rec.is_active && !rec.exec_page) {
                return &rec;
            }
        }

        if (record_count_ >= max_hook_records) return nullptr;

        auto idx = record_count_;
        _InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&record_count_));
        return &records_[idx];
    };

    {
        // Hook table reads only need exclusion against commit writers.
        hv_shared_lock_guard lock;

        for (size_t idx = 0; idx < record_count_; ++idx) {
            auto& installed = records_[idx];
            if (!installed.is_active || installed.target_va != target_va) {
                continue;
            }

            if (installed.proxy_fn != proxy_fn || !installed.detour_fn) {
                return false;
            }

            *out_detour_fn = installed.detour_fn;
            return true;
        }
    }

    u8 target_bytes[64] = {};
    auto target_addr = reinterpret_cast<u64>(target_va);
    if (!memory_access::get()->read_virtual(target_cr3, target_addr,
        target_bytes, sizeof(target_bytes))) {
        return false;
    }

    auto patch_size = svm::utilities::get()->get_patch_size(target_bytes, hook_length);
    if (patch_size == 0) return false;

    *out_detour_fn = svm::memory::get()->alloc_executable_pool(patch_size + detour_length + 256);
    if (!*out_detour_fn) return false;
    RtlFillMemory(*out_detour_fn, patch_size + detour_length + 256, 0x90);

    // The target page must be pinned by the caller in guest mode. Root mode
    // must not call MmProbeAndLockPages (or any guest MM API): it can block
    // on locks that TLB-shootdown shooters hold across IPI barriers.
    PMDL original_mdl = nullptr;

    u8 hook_code[hook_length] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xE0,
        0x90, 0x90
    };
    auto proxy_addr = reinterpret_cast<u64>(proxy_fn);
    *reinterpret_cast<u64*>(hook_code + 2) = proxy_addr;

    // jmp [rip+0]; .qword (target_va + patch_size) — return path after detour body.
    u8 detour_code[detour_length] = {
        0xFF, 0x25, 0,0,0,0,
        0,0,0,0,0,0,0,0
    };
    *reinterpret_cast<u64*>(detour_code + 6) =
        reinterpret_cast<u64>(target_va) + patch_size;

    memcpy(*out_detour_fn, target_bytes, patch_size);

    auto abs_jump_table = static_cast<u8*>(*out_detour_fn) + patch_size + detour_length;
    u32 abs_jump_offset = 0;
    if (!fix_rip_relative(target_va, *out_detour_fn, patch_size, abs_jump_table, abs_jump_offset)) {
        svm::utilities::get()->unlock_pages(original_mdl);
        svm::memory::get()->free_nonpaged_pool(*out_detour_fn);
        *out_detour_fn = nullptr;
        return false;
    }
    memcpy(static_cast<u8*>(*out_detour_fn) + patch_size, detour_code, detour_length);

    auto start_addr = target_addr;
    auto start_page = start_addr & ~0xFFFULL;
    auto end_addr   = start_addr + hook_length;
    auto end_page   = (end_addr + 0xFFFULL) & ~0xFFFULL;
    auto num_pages  = (end_page - start_page) >> 12;

    struct page_info {
        void* exec_page;
        u64 orig_pfn;
        u64 exec_pfn;
        u16 patch_offset;
        u16 patch_size;
        hook_record* rec;
        bool installed;
    };

    page_info pages_info[2] = {};

    // Preparation pass: everything here may block on guest locks (pool
    // allocator, MDL pinning), so it must run WITHOUT the hv lock. Holding
    // the hv lock across these calls deadlocks against guest threads that
    // hold those locks and then hit an EPT violation, whose handler needs
    // the shared hv lock.
    bool ok = true;
    auto remaining = static_cast<size_t>(hook_length);
    auto current   = start_addr;

    for (u32 i = 0; i < num_pages && ok; i++) {
        auto page_base = current & ~0xFFFULL;

        u64 orig_pa = 0;
        u64 page_remaining = 0;
        if (!memory_access::get()->translate(target_cr3, page_base, orig_pa, page_remaining)) {
            ok = false;
            break;
        }

        if (!orig_pa) {
            ok = false;
            break;
        }

        auto& info = pages_info[i];
        info.orig_pfn     = orig_pa >> 12;
        info.patch_offset = static_cast<u16>(current & 0xFFFULL);
        info.patch_size   = static_cast<u16>(min(static_cast<u64>(remaining), 0x1000ULL - info.patch_offset));

        info.exec_page = svm::memory::get()->alloc_nonpaged_pool(0x1000ULL);
        if (!info.exec_page) { ok = false; break; }

        auto exec_pa = static_cast<u64>(MmGetPhysicalAddress(info.exec_page).QuadPart);
        if (!exec_pa) {
            ok = false;
            break;
        }
        info.exec_pfn = exec_pa >> 12;

        if (!memory_access::get()->read_virtual(target_cr3, page_base, info.exec_page, PAGE_SIZE)) {
            ok = false;
            break;
        }

        memcpy(static_cast<u8*>(info.exec_page) + info.patch_offset,
               hook_code + (hook_length - remaining),
               info.patch_size);

        current   = page_base + 0x1000ULL;
        remaining -= info.patch_size;
    }

    void* our_detour = *out_detour_fn;
    bool reused_existing = false;

    if (ok) {
        // Commit: strictly non-blocking EPT/VMCS metadata updates under the
        // exclusive lock. EPT violation handlers on other CPUs wait at most a
        // few microseconds here, so they can never form a lock cycle with
        // guest locks held by their interrupted threads.
        hv_exclusive_lock_guard lock;

        // Another install may have won the race while we were preparing.
        for (size_t idx = 0; idx < record_count_; ++idx) {
            auto& installed = records_[idx];
            if (!installed.is_active || installed.target_va != target_va) {
                continue;
            }

            if (installed.proxy_fn != proxy_fn || !installed.detour_fn) {
                ok = false;
                break;
            }

            *out_detour_fn = installed.detour_fn;
            reused_existing = true;
            break;
        }

        for (u32 i = 0; i < num_pages && ok && !reused_existing; i++) {
            auto& info = pages_info[i];
            auto existing = find_record(info.orig_pfn);

            if (existing) {
                if (!ept::get()->install_ept_hook(info.orig_pfn, existing->exec_pfn,
                                                  info.patch_offset, info.patch_size)) {
                    ok = false;
                    break;
                }
                continue;
            }

            auto rec_slot = allocate_record();
            if (!rec_slot) {
                ok = false;
                break;
            }

            if (!ept::get()->install_ept_hook(info.orig_pfn, info.exec_pfn,
                                              info.patch_offset, info.patch_size)) {
                ok = false;
                break;
            }

            rec_slot->original_va  = reinterpret_cast<void*>(start_page + (static_cast<u64>(i) << 12));
            rec_slot->target_va    = target_va;
            rec_slot->proxy_fn     = proxy_fn;
            rec_slot->detour_fn    = our_detour;
            rec_slot->exec_page    = info.exec_page;
            rec_slot->orig_pfn     = info.orig_pfn;
            rec_slot->exec_pfn     = info.exec_pfn;
            rec_slot->patch_offset = info.patch_offset;
            rec_slot->patch_size   = info.patch_size;
            rec_slot->exec_mdl     = nullptr;
            rec_slot->orig_mdl     = (i == 0) ? original_mdl : nullptr;
            KeMemoryBarrier();
            rec_slot->is_active    = true;
            info.rec               = rec_slot;
            info.installed         = true;
        }

        if (!ok && !reused_existing) {
            // Roll back EPT hooks armed by this commit (still non-blocking).
            for (u32 i = 0; i < num_pages; i++) {
                auto& info = pages_info[i];
                if (!info.installed) continue;

                ept::get()->remove_ept_hook(info.orig_pfn);
                info.installed = false;

                if (info.rec) {
                    info.rec->is_active = false;
                }
            }
        }
    }

    // Cleanup: pool/MDL operations may block, keep them outside the lock.
    for (u32 i = 0; i < num_pages; i++) {
        auto& info = pages_info[i];
        if (info.installed) continue;

        if (info.rec) {
            RtlZeroMemory(info.rec, sizeof(*info.rec));
        }
        if (info.exec_page) {
            svm::memory::get()->free_nonpaged_pool(info.exec_page);
        }
    }

    if (reused_existing) {
        // We prepared a duplicate; the table already had this hook.
        if (original_mdl) svm::utilities::get()->unlock_pages(original_mdl);
        svm::memory::get()->free_nonpaged_pool(our_detour);
        return true;
    }

    if (!ok) {
        if (original_mdl) svm::utilities::get()->unlock_pages(original_mdl);
        svm::memory::get()->free_nonpaged_pool(our_detour);
        *out_detour_fn = nullptr;
        return false;
    }

    if (issue_invept) {
        virtualization::get()->broadcast_invept();
    }
    return true;
}

auto hook::install_driver_hooks(const wchar_t* driver_name, u32 major_function, void* proxy_fn,
                                void** out_detour_fn, void** out_target_fn,
                                bool issue_invept) -> bool {
    if (!driver_name || !proxy_fn || !out_detour_fn || major_function > IRP_MJ_MAXIMUM_FUNCTION) {
        return false;
    }

    UNICODE_STRING object_name{};
    RtlInitUnicodeString(&object_name, driver_name);

    PVOID object = nullptr;
    auto status = ObReferenceObjectByName(&object_name, OBJ_CASE_INSENSITIVE, nullptr, 0, *IoDriverObjectType,
                                          KernelMode, nullptr, &object);
    if (!NT_SUCCESS(status) || !object) {
        return false;
    }

    auto driver_object = static_cast<PDRIVER_OBJECT>(object);
    auto dispatch = reinterpret_cast<void*>(driver_object->MajorFunction[major_function]);
    if (!dispatch) {
        ObfDereferenceObject(driver_object);
        return false;
    }

    if (out_target_fn) {
        *out_target_fn = dispatch;
    }

    auto result = install_function_hook(dispatch, proxy_fn, out_detour_fn, 0, issue_invept);
    debug::panicf("[vtx hook] driver %ws major=%lu dispatch=%p result=%d\n",
                  driver_name,
                  static_cast<unsigned long>(major_function),
                  dispatch,
                  result ? 1 : 0);
    ObfDereferenceObject(driver_object);
    return result;
}

auto hook::remove_function_hook(void* target_va, bool issue_invept) -> bool {
    if (!target_va) return false;

    auto target_addr = reinterpret_cast<u64>(target_va);
    auto target_page = target_addr & ~0xFFFULL;
    auto end_page = ((target_addr + hook_length + 0xFFFULL) & ~0xFFFULL);
    bool any = false;

    hook_record* removed[max_hook_records] = {};
    size_t removed_count = 0;

    {
        // Non-blocking EPT unhook under the exclusive lock; MDL/pool frees
        // run after release because they may block on guest locks.
        hv_exclusive_lock_guard lock;

        for (size_t i = 0; i < record_count_; i++) {
            auto& rec = records_[i];
            if (!rec.is_active) continue;
            auto rec_page = reinterpret_cast<u64>(rec.original_va) & ~0xFFFULL;
            if (rec_page < target_page || rec_page >= end_page) continue;

            ept::get()->remove_ept_hook(rec.orig_pfn);
            rec.is_active = false;
            removed[removed_count++] = &rec;
            any = true;
        }
    }

    if (!any) return false;

    if (issue_invept) {
        virtualization::get()->broadcast_invept();
    }

    for (size_t i = 0; i < removed_count; i++) {
        auto rec = removed[i];

        if (rec->exec_mdl) svm::utilities::get()->unlock_pages(rec->exec_mdl);
        if (rec->orig_mdl) svm::utilities::get()->unlock_pages(rec->orig_mdl);
        if (rec->exec_page) svm::memory::get()->free_nonpaged_pool(rec->exec_page);

        rec->original_va  = nullptr;
        rec->target_va    = nullptr;
        rec->proxy_fn     = nullptr;
        rec->detour_fn    = nullptr;
        rec->exec_page    = nullptr;
        rec->orig_pfn     = 0;
        rec->exec_pfn     = 0;
        rec->patch_size   = 0;
        rec->patch_offset = 0;
        rec->is_active    = false;
        rec->exec_mdl     = nullptr;
        rec->orig_mdl     = nullptr;
    }
    return true;
}

auto hook::get() -> hook* {
    static hook instance;
    return &instance;
}

}
