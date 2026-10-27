#include "memory.hpp"
#include "../svm/svm.hpp"
#pragma warning(disable : 6011)
namespace svm {

auto memory::map_physical_memory(host_pt_t& pt) -> void {
    auto& pml4e = pt.pml4[host_physical_memory_pml4_idx];
    pml4e.present = 1;
    pml4e.write = 1;
    pml4e.page_frame_number = MmGetPhysicalAddress(&pt.pdpt).QuadPart >> 12;

    for (u64 i = 0; i < host_physical_memory_pd_count; i++) {
        auto& pdpte = pt.pdpt[i];
        pdpte.present = 1;
        pdpte.write = 1;
        pdpte.page_frame_number = MmGetPhysicalAddress(&pt.pd[i]).QuadPart >> 12;

        for (u64 j = 0; j < 512; j++) {
            auto& pde = pt.pd[i][j];
            pde.present = 1;
            pde.write = 1;
            pde.large_page = 1;
            pde.page_frame_number = (i << 9) + j;
        }
    }
}

auto memory::prepare_host_page_tables() -> svm::svmroot_error_t {
    auto& pt = virtualization::get()->shared_host_pt;

    for (size_t i = 0; i < sizeof(pt.pml4) / sizeof(pt.pml4[0]); i++) {
        pt.pml4[i].flags = 0;
    }

    for (size_t i = 0; i < sizeof(pt.pdpt) / sizeof(pt.pdpt[0]); i++) {
        pt.pdpt[i].flags = 0;
    }

    for (size_t i = 0; i < host_physical_memory_pd_count; i++) {
        for (size_t j = 0; j < 512; j++) {
            pt.pd[i][j].flags = 0;
        }
    }

    map_physical_memory(pt);
    svm::cr3_t cr3;
    cr3.value = __readcr3();
    PHYSICAL_ADDRESS physical_addr;
    physical_addr.QuadPart = reinterpret_cast<long long>((void*)(cr3.pml4 << 12));
    auto guest_pml4 = reinterpret_cast<pml4e_64*>(MmGetVirtualForPhysical(physical_addr));

    if (!guest_pml4) {
        return svm::svmroot_error_t::error_failed;
    }

    for (int i = 256; i < 512; i++) {
        pt.pml4[i].flags = guest_pml4[i].flags;
    }

    return svm::svmroot_error_t::error_success;
}

auto memory::init_arena() -> bool {
    if (arena_base) {
        return true;
    }

    // Contiguous memory is resident and executable on this platform (the
    // hypervisor image itself runs from it), so one arena serves both the
    // data and executable pool entry points.
    u64 allocated_size = 0;
    for (u64 try_size = arena_size; !arena_base && try_size >= 4ull * 1024 * 1024; try_size /= 2) {
        arena_base = static_cast<u8*>(alloc_contiguous_memory(try_size));
        if (arena_base) {
            allocated_size = try_size;
        }
    }

    if (!arena_base) {
        debug::panicf("[arena] failed to allocate hypervisor arena\n");
        return false;
    }

    arena_page_count = static_cast<u32>(allocated_size / PAGE_SIZE);
    debug::panicf("[arena] hypervisor arena at %p (%llu MB)\n", arena_base, allocated_size / (1024 * 1024));
    return true;
}

auto memory::arena_alloc(u64 size) -> void* {
    if (!arena_base || !size) {
        return nullptr;
    }

    auto const pages_needed = static_cast<u32>((size + PAGE_SIZE - 1) / PAGE_SIZE);
    void* result = nullptr;

    while (_InterlockedCompareExchange(&arena_lock, 1, 0) != 0) {
        _mm_pause();
    }

    u32 run_start = 0;
    u32 run_length = 0;

    for (u32 i = 0; i < arena_page_count && !result; i++) {
        if (page_runs[i] != 0) {
            i += page_runs[i] - 1;
            run_length = 0;
            run_start = i + 1;
            continue;
        }

        if (run_length == 0) {
            run_start = i;
        }
        run_length++;

        if (run_length >= pages_needed) {
            page_runs[run_start] = static_cast<u16>(pages_needed);
            result = arena_base + (static_cast<u64>(run_start) << 12);
        }
    }

    _InterlockedExchange(&arena_lock, 0);

    if (result) {
        RtlZeroMemory(result, pages_needed << 12);
    } else {
        debug::panicf("[arena] exhausted, failed allocation of 0x%llx bytes\n", size);
    }

    return result;
}

auto memory::arena_free(void* base) -> void {
    if (!arena_base || !base) {
        return;
    }

    auto const offset = static_cast<u64>(static_cast<u8*>(base) - arena_base);

    if ((offset & 0xFFF) != 0 || (offset >> 12) >= arena_page_count) {
        // Not an arena pointer; should not happen after the arena switch.
        debug::panicf("[arena] free of foreign pointer %p\n", base);
        return;
    }

    while (_InterlockedCompareExchange(&arena_lock, 1, 0) != 0) {
        _mm_pause();
    }

    page_runs[offset >> 12] = 0;
    _InterlockedExchange(&arena_lock, 0);
}

auto memory::alloc_contiguous_memory(u64 size) -> void* {
    PHYSICAL_ADDRESS boundary, lowest, highest;
    boundary.QuadPart = lowest.QuadPart = 0;
    highest.QuadPart = -1;
    void* memory =
        MmAllocateContiguousMemorySpecifyCacheNode(size, lowest, highest, boundary, MmCached, MM_ANY_NODE_OK);
    if (memory)
        RtlZeroMemory(memory, size);
    return memory;
}

auto memory::free_contiguous_memory(void* base) -> void {
    MmFreeContiguousMemory(base);
}

// Served from the pre-allocated arena: no guest memory-manager calls in
// root mode (see init_arena comment). Large allocations (the multi-MB vcpu
// structs) only ever happen in guest mode during init, so they may use the
// guest allocator directly.
#define HV_ARENA_MAX_ALLOC (1024ull * 1024)

auto memory::alloc_nonpaged_pool(u64 size) -> void* {
    if (size > HV_ARENA_MAX_ALLOC) {
        void* memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'vmm');

        if (memory) {
            RtlZeroMemory(memory, size);
        }

        return memory;
    }

    return arena_alloc(size);
}

auto memory::alloc_executable_pool(u64 size) -> void* {
    if (size > HV_ARENA_MAX_ALLOC) {
        void* memory = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, size, 'vmm');

        if (memory) {
            RtlZeroMemory(memory, size);
        }

        return memory;
    }

    return arena_alloc(size);
}

auto memory::free_nonpaged_pool(void* base) -> void {
    if (arena_base && base &&
        static_cast<u8*>(base) >= arena_base &&
        static_cast<u8*>(base) < arena_base + (static_cast<u64>(arena_page_count) << 12)) {
        arena_free(base);
        return;
    }

    ExFreePoolWithTag(base, 'vmm');
}

auto memory::get_process_cr3(svm::pvcpu_t vcpu, u64 target_pid) -> u64 {
    if (!target_pid) {
        return 0;
    }

    // Bound the walk: a torn process list must never spin forever in root mode.
    u32 max_iterations = 100000;
    for (auto current = vcpu->host_stack_layout.shared_vcpu->system_eprocess;
         current->ActiveProcessLinks.Flink != &vcpu->host_stack_layout.shared_vcpu->system_eprocess->ActiveProcessLinks && max_iterations--;
         current = CONTAINING_RECORD(current->ActiveProcessLinks.Flink, _EPROCESS, ActiveProcessLinks)) {
        if (target_pid == reinterpret_cast<u64>(current->UniqueProcessId)) {
            return current->Pcb.DirectoryTableBase;
        }
    }

    return 0;
}

auto memory::get_process_peb(u64 target_pid) -> u64 {
    if (!target_pid) {
        return 0;
    }

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(target_pid), &process);

    if (!NT_SUCCESS(status)) {
        return 0;
    }

    PPEB peb = PsGetProcessPeb(process);

    if (peb == nullptr) {
        ObfDereferenceObject(process);
        return 0;
    }

    ObfDereferenceObject(process);
    return reinterpret_cast<u64>(peb);
}

auto memory::get_process_base(svm::pvcpu_t vcpu, u64 target_pid) -> u64 {
    if (!target_pid) {
        return svm::svmroot_error_t::invalid_pid;
    }

    // Bound the walk: a torn process list must never spin forever in root mode.
    u32 max_iterations = 100000;
    for (auto current = vcpu->host_stack_layout.shared_vcpu->system_eprocess;
         current->ActiveProcessLinks.Flink != &vcpu->host_stack_layout.shared_vcpu->system_eprocess->ActiveProcessLinks && max_iterations--;
         current = CONTAINING_RECORD(current->ActiveProcessLinks.Flink, _EPROCESS, ActiveProcessLinks)) {
        if (target_pid == reinterpret_cast<u64>(current->UniqueProcessId)) {
            return reinterpret_cast<u64>(current->SectionBaseAddress);
        }
    }

    return svm::svmroot_error_t::error_failed;
}

auto memory::get_process_module(svm::pvcpu_t vcpu, u64 target_pid, const wchar_t* module_name) -> u64 {
    if (!vcpu || !target_pid || !module_name) {
        debug::panicf("[get_process_module] Invalid parameters\n");
        return 0;
    }

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(target_pid), &process);

    if (!NT_SUCCESS(status)) {
        debug::panicf("[get_process_module] Process not found (PID: %llu)\n", target_pid);
        return 0;
    }

    NTSTATUS exit_status = PsGetProcessExitStatus(process);

    if (exit_status != STATUS_PENDING) {
        debug::panicf("[get_process_module] Process is exiting (PID: %llu)\n", target_pid);
        ObfDereferenceObject(process);
        return 0;
    }

    ObfDereferenceObject(process);
    auto process_cr3 = get_process_cr3(vcpu, target_pid);

    if (!process_cr3) {
        debug::panicf("[get_process_module] Failed to get CR3 for PID: %llu\n", target_pid);
        return 0;
    }

    auto peb_address = get_process_peb(target_pid);

    if (!peb_address) {
        debug::panicf("[get_process_module] Failed to get PEB for PID: %llu\n", target_pid);
        return 0;
    }

    svm::cr3_t cr3_struct{process_cr3};
    PEB peb_process = {0};
    auto peb_physical = page_table::get()->get_physical_address(vcpu, cr3_struct, peb_address);

    if (!peb_physical) {
        debug::panicf("[get_process_module] Failed to translate PEB address: 0x%llx\n", peb_address);
        return 0;
    }

    if (memory_access::get()->read_physical_to_host(vcpu, &peb_process, peb_physical, sizeof(PEB)) !=
        svm::svmroot_error_t::error_success) {
        debug::panicf("[get_process_module] Failed to read PEB\n");
        return 0;
    }

    if (!peb_process.Ldr) {
        debug::panicf("[get_process_module] Invalid PEB Ldr pointer\n");
        return 0;
    }

    PEB_LDR_DATA peb_ldr_data = {0};
    auto ldr_physical = page_table::get()->get_physical_address(vcpu, cr3_struct, (u64)peb_process.Ldr);

    if (!ldr_physical) {
        debug::panicf("[get_process_module] Failed to translate Ldr address: 0x%llx\n", (u64)peb_process.Ldr);
        return 0;
    }

    if (memory_access::get()->read_physical_to_host(vcpu, &peb_ldr_data, ldr_physical, sizeof(PEB_LDR_DATA)) !=
        svm::svmroot_error_t::error_success) {
        debug::panicf("[get_process_module] Failed to read PEB_LDR_DATA\n");
        return 0;
    }

    if (!peb_ldr_data.ModuleListLoadOrder.Flink ||
        peb_ldr_data.ModuleListLoadOrder.Flink == peb_ldr_data.ModuleListLoadOrder.Blink) {
        debug::panicf("[get_process_module] Invalid module list pointers\n");
        return 0;
    }

    debug::panicf("[get_process_module] Processing PID: %llu\n", target_pid);
    LIST_ENTRY* ldr_list_head = (LIST_ENTRY*)peb_ldr_data.ModuleListLoadOrder.Flink;
    LIST_ENTRY* ldr_current_node = ldr_list_head;
    do {
        LDR_DATA_TABLE_ENTRY lst_entry = {0};
        auto entry_physical = page_table::get()->get_physical_address(vcpu, cr3_struct, (u64)ldr_current_node);

        if (!entry_physical) {
            debug::panicf("[get_process_module] Failed to translate entry address: 0x%llx\n", (u64)ldr_current_node);
            break;
        }

        if (memory_access::get()->read_physical_to_host(vcpu, &lst_entry, entry_physical,
                                                        sizeof(LDR_DATA_TABLE_ENTRY)) !=
            svm::svmroot_error_t::error_success) {
            debug::panicf("[get_process_module] Failed to read LDR_DATA_TABLE_ENTRY\n");
            break;
        }

        if (!lst_entry.InLoadOrderModuleList.Flink) {
            debug::panicf("[get_process_module] Invalid next module pointer\n");
            break;
        }

        ldr_current_node = lst_entry.InLoadOrderModuleList.Flink;

        if (lst_entry.BaseDllName.Length > 0 && lst_entry.BaseDllName.Length < MAX_PATH * sizeof(WCHAR) &&
            lst_entry.BaseDllName.Buffer) {
            WCHAR sz_base_dll_name[MAX_PATH] = {0};
            auto name_physical =
                page_table::get()->get_physical_address(vcpu, cr3_struct, (u64)lst_entry.BaseDllName.Buffer);

            if (!name_physical) {
                continue;
            }

            if (memory_access::get()->read_physical_to_host(
                    vcpu, sz_base_dll_name, name_physical,
                    min(lst_entry.BaseDllName.Length, (USHORT)(MAX_PATH * sizeof(WCHAR) - sizeof(WCHAR)))) ==
                svm::svmroot_error_t::error_success) {
                if (crt_strcmp(sz_base_dll_name, module_name, true)) {
                    if (lst_entry.DllBase && lst_entry.SizeOfImage) {
                        debug::panicf("[get_process_module] Found module at: 0x%llx\n", (u64)lst_entry.DllBase);
                        return (u64)lst_entry.DllBase;
                    }
                }
            }
        }
    } while (ldr_current_node != ldr_list_head);
    debug::panicf("[get_process_module] Module not found for PID: %llu\n", target_pid);
    return 0;
}

auto memory::get() -> memory* {
    static memory instance;
    return &instance;
}
}
