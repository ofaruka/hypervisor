#include "memory_access_vtx.hpp"
#include "../ept/ept.hpp"
#include "../vmx/vmx.hpp"
#include "../../handlers_ctx/events/events_vtx.hpp"

namespace vtx {

auto memory_access::map_physical_memory(host_pt_t& pt) -> void {
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

auto memory_access::prepare_host_page_tables(host_pt_t& pt, u64& out_cr3) -> svm::svmroot_error_t {
    RtlZeroMemory(&pt, sizeof(pt));
    map_physical_memory(pt);

    svm::cr3_t cr3{};
    cr3.value = __readcr3();

    PHYSICAL_ADDRESS pa{};
    pa.QuadPart = static_cast<LONGLONG>(cr3.pml4 << 12);
    auto guest_pml4 = reinterpret_cast<pml4e_64*>(MmGetVirtualForPhysical(pa));
    if (!guest_pml4) {
        return svm::svmroot_error_t::error_failed;
    }

    for (u32 i = 256; i < 512; i++) {
        pt.pml4[i].flags = guest_pml4[i].flags;
    }

    out_cr3 = MmGetPhysicalAddress(pt.pml4).QuadPart;
    return svm::svmroot_error_t::error_success;
}

auto memory_access::prepare_host_page_tables() -> svm::svmroot_error_t {
    u64 cr3 = 0;
    return prepare_host_page_tables(host_pt, cr3);
}

auto memory_access::host_cr3() -> u64 {
    return MmGetPhysicalAddress(host_pt.pml4).QuadPart;
}

auto memory_access::physical_to_virtual(u64 physical_address, u64 size, void*& virtual_address) -> bool {
    if (size > mapped_physical_size || physical_address > mapped_physical_size - size) {
        virtual_address = nullptr;
        return false;
    }

    virtual_address = host_physical_memory_base + physical_address;
    return true;
}

auto memory_access::hpa_to_hva(u64 physical_address, u64 size, void*& virtual_address) -> bool {
    return physical_to_virtual(physical_address, size, virtual_address);
}

auto memory_access::read_physical(u64 physical_address, void* buffer, u64 size) -> bool {
    if (!buffer) return false;
    if (!size) return true;
    if (ept::get()->is_hidden_physical_range(physical_address, size)) return false;

    void* source = nullptr;
    if (!physical_to_virtual(physical_address, size, source)) return false;

    __try {
        RtlCopyMemory(buffer, source, static_cast<SIZE_T>(size));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return true;
}

auto memory_access::write_physical(u64 physical_address, const void* buffer, u64 size) -> bool {
    if (!buffer) return false;
    if (!size) return true;
    if (ept::get()->is_hidden_physical_range(physical_address, size)) return false;

    void* destination = nullptr;
    if (!physical_to_virtual(physical_address, size, destination)) return false;

    __try {
        RtlCopyMemory(destination, buffer, static_cast<SIZE_T>(size));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return true;
}

auto memory_access::guest_cr3() -> u64 {
    size_t cr3 = 0;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::guest_cr3), &cr3) != 0) {
        return 0;
    }

    return static_cast<u64>(cr3) & ~0xFFFULL;
}

auto memory_access::translate(u64 cr3, u64 virtual_address, u64& physical_address, u64& bytes_to_next_page) -> bool {
    if (!cr3) cr3 = guest_cr3();
    if (!cr3) return false;

    _virt_addr_t const va{ virtual_address };
    auto table = cr3 & ~0xFFFULL;

    pml4e_64 pml4e{};
    if (!read_physical(table + va.pml4_index * sizeof(pml4e), &pml4e, sizeof(pml4e)) ||
        !pml4e.present) {
        return false;
    }

    pdpte_64 pdpte{};
    if (!read_physical((pml4e.page_frame_number << 12) + va.pdpt_index * sizeof(pdpte),
        &pdpte, sizeof(pdpte)) || !pdpte.present) {
        return false;
    }

    if (pdpte.large_page) {
        physical_address = ((pdpte.page_frame_number << 12) & ~((1ULL << 30) - 1)) | va.offset_1gb;
        bytes_to_next_page = 0x40000000ULL - va.offset_1gb;
        return true;
    }

    pde_64 pde{};
    if (!read_physical((pdpte.page_frame_number << 12) + va.pd_index * sizeof(pde),
        &pde, sizeof(pde)) || !pde.present) {
        return false;
    }

    if (pde.large_page) {
        physical_address = ((pde.page_frame_number << 12) & ~((1ULL << 21) - 1)) | va.offset_2mb;
        bytes_to_next_page = 0x200000ULL - va.offset_2mb;
        return true;
    }

    pte_64 pte{};
    if (!read_physical((pde.page_frame_number << 12) + va.pt_index * sizeof(pte),
        &pte, sizeof(pte)) || !pte.present) {
        return false;
    }

    physical_address = (pte.page_frame_number << 12) | va.offset_4kb;
    bytes_to_next_page = PAGE_SIZE - va.offset_4kb;
    return true;
}

auto memory_access::guest_range_mapped(u64 gva, u64 size) -> bool {
    if (!gva || !size) return false;

    auto checked = 0ULL;
    while (checked < size) {
        u64 physical_address = 0;
        u64 remaining = 0;
        if (!translate(0, gva + checked, physical_address, remaining) ||
            remaining == 0) {
            return false;
        }

        auto chunk = remaining;
        if (chunk > size - checked) chunk = size - checked;
        checked += chunk;
    }

    return true;
}

auto memory_access::get_physical_address(u64 cr3, u64 virtual_address) -> u64 {
    u64 physical_address = 0;
    u64 remaining = 0;

    if (!translate(cr3, virtual_address, physical_address, remaining)) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }

    return physical_address;
}

auto memory_access::get_virtual_address(u64 cr3, u64 physical_address) -> u64 {
    if (!cr3) cr3 = guest_cr3();
    if (!cr3) return svm::svmroot_error_t::svmroot_translate_failure;

    auto canonicalize = [](u64 va) -> u64 {
        return (va & (1ULL << 47)) ? (va | 0xFFFF000000000000ULL) : va;
    };

    auto target = physical_address;
    auto table = cr3 & ~0xFFFULL;

    for (u64 pml4_idx = 0; pml4_idx < 512; ++pml4_idx) {
        pml4e_64 pml4e{};
        if (!read_physical(table + pml4_idx * sizeof(pml4e), &pml4e, sizeof(pml4e)) ||
            !pml4e.present) {
            continue;
        }

        for (u64 pdpt_idx = 0; pdpt_idx < 512; ++pdpt_idx) {
            pdpte_64 pdpte{};
            auto pdpt_pa = (pml4e.page_frame_number << 12) + pdpt_idx * sizeof(pdpte);
            if (!read_physical(pdpt_pa, &pdpte, sizeof(pdpte)) || !pdpte.present) {
                continue;
            }

            if (pdpte.large_page) {
                auto page_base = (pdpte.page_frame_number << 12) & ~((1ULL << 30) - 1);
                if (target >= page_base && target < page_base + 0x40000000ULL) {
                    auto va = (pml4_idx << 39) | (pdpt_idx << 30) | (target - page_base);
                    return canonicalize(va);
                }
                continue;
            }

            for (u64 pd_idx = 0; pd_idx < 512; ++pd_idx) {
                pde_64 pde{};
                auto pd_pa = (pdpte.page_frame_number << 12) + pd_idx * sizeof(pde);
                if (!read_physical(pd_pa, &pde, sizeof(pde)) || !pde.present) {
                    continue;
                }

                if (pde.large_page) {
                    auto page_base = (pde.page_frame_number << 12) & ~((1ULL << 21) - 1);
                    if (target >= page_base && target < page_base + 0x200000ULL) {
                        auto va = (pml4_idx << 39) | (pdpt_idx << 30) |
                                  (pd_idx << 21) | (target - page_base);
                        return canonicalize(va);
                    }
                    continue;
                }

                for (u64 pt_idx = 0; pt_idx < 512; ++pt_idx) {
                    pte_64 pte{};
                    auto pt_pa = (pde.page_frame_number << 12) + pt_idx * sizeof(pte);
                    if (!read_physical(pt_pa, &pte, sizeof(pte)) || !pte.present) {
                        continue;
                    }

                    auto page_base = pte.page_frame_number << 12;
                    if (target >= page_base && target < page_base + PAGE_SIZE) {
                        auto va = (pml4_idx << 39) | (pdpt_idx << 30) |
                                  (pd_idx << 21) | (pt_idx << 12) |
                                  (target - page_base);
                        return canonicalize(va);
                    }
                }
            }
        }
    }

    return svm::svmroot_error_t::svmroot_translate_failure;
}

auto memory_access::is_page_present(u64 cr3, u64 virtual_address) -> bool {
    u64 physical_address = 0;
    u64 remaining = 0;
    return translate(cr3, virtual_address, physical_address, remaining);
}

auto memory_access::request_page_in(u64 cr3, u64 virtual_address) -> bool {
    u64 page_aligned = virtual_address & ~static_cast<u64>(PAGE_SIZE - 1);
    u64 cr3_canonical = cr3 & ~0xfffULL;

    if (!cr3_canonical || !page_aligned) {
        return false;
    }

    for (u32 i = 0; i < max_pending_slots; i++) {
        u64 existing_cr3 = m_pending[i].process_cr3;
        u64 existing_gva = m_pending[i].gva;
        if (existing_cr3 == cr3_canonical && existing_gva == page_aligned) {
            return true;
        }
    }

    for (u32 i = 0; i < max_pending_slots; i++) {
        u64 expected = 0;
        if (InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&m_pending[i].process_cr3),
            static_cast<LONG64>(cr3_canonical),
            static_cast<LONG64>(expected)) == 0) {
            InterlockedExchange64(
                reinterpret_cast<volatile LONG64*>(&m_pending[i].gva),
                static_cast<LONG64>(page_aligned));
            return true;
        }
    }

    return false;
}

auto memory_access::try_consume_pending(pvcpu_t vcpu) -> bool {
    if (!vcpu) {
        return false;
    }

    size_t cs = 0;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::guest_cs_sel), &cs) != 0 ||
        (cs & 3) != 3) {
        return false;
    }

    size_t entry_info = 0;
    if (__vmx_vmread(static_cast<size_t>(vmcs_field::vm_entry_intr_info), &entry_info) == 0 &&
        (entry_info & vmx_event_valid) != 0) {
        return false;
    }

    u64 current_cr3 = guest_cr3() & ~0xfffULL;
    if (!current_cr3) {
        return false;
    }

    for (u32 i = 0; i < max_pending_slots; i++) {
        u64 slot_cr3 = m_pending[i].process_cr3;
        if (!slot_cr3 || slot_cr3 != current_cr3) {
            continue;
        }

        u64 slot_gva = m_pending[i].gva;
        if (!slot_gva) {
            continue;
        }

        if (is_page_present(slot_cr3, slot_gva)) {
            InterlockedExchange64(
                reinterpret_cast<volatile LONG64*>(&m_pending[i].gva), 0);
            InterlockedExchange64(
                reinterpret_cast<volatile LONG64*>(&m_pending[i].process_cr3), 0);
            continue;
        }

        u64 previous = InterlockedCompareExchange64(
            reinterpret_cast<volatile LONG64*>(&m_pending[i].gva),
            0,
            static_cast<LONG64>(slot_gva));
        if (previous != slot_gva) {
            continue;
        }

        InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&m_pending[i].process_cr3), 0);

        vtx_write_cr2(slot_gva);
        event_handler::get()->inject_exception(exception_vector_page_fault, 0x4, true);
        return true;
    }

    return false;
}

auto memory_access::clear_guest_pte_nx(u64 cr3, u64 virtual_address, bool make_writable)
    -> svm::svmroot_error_t {
    if (!cr3) cr3 = guest_cr3();
    if (!cr3) return svm::svmroot_error_t::svmroot_translate_failure;

    _virt_addr_t const va{ virtual_address };
    auto table = cr3 & ~0xFFFULL;

    pml4e_64 pml4e{};
    auto pml4e_pa = table + va.pml4_index * sizeof(pml4e);
    if (!read_physical(pml4e_pa, &pml4e, sizeof(pml4e)) || !pml4e.present) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }

    pdpte_64 pdpte{};
    auto pdpte_pa = (pml4e.page_frame_number << 12) + va.pdpt_index * sizeof(pdpte);
    if (!read_physical(pdpte_pa, &pdpte, sizeof(pdpte)) || !pdpte.present) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }

    if (pdpte.large_page) {
        pdpte.execute_disable = 0;
        if (make_writable) pdpte.write = 1;
        return write_physical(pdpte_pa, &pdpte, sizeof(pdpte))
            ? svm::svmroot_error_t::error_success
            : svm::svmroot_error_t::error_failed;
    }

    pde_64 pde{};
    auto pde_pa = (pdpte.page_frame_number << 12) + va.pd_index * sizeof(pde);
    if (!read_physical(pde_pa, &pde, sizeof(pde)) || !pde.present) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }

    if (pde.large_page) {
        pde.execute_disable = 0;
        if (make_writable) pde.write = 1;
        return write_physical(pde_pa, &pde, sizeof(pde))
            ? svm::svmroot_error_t::error_success
            : svm::svmroot_error_t::error_failed;
    }

    pte_64 pte{};
    auto pte_pa = (pde.page_frame_number << 12) + va.pt_index * sizeof(pte);
    if (!read_physical(pte_pa, &pte, sizeof(pte)) || !pte.present) {
        return svm::svmroot_error_t::svmroot_translate_failure;
    }

    pte.execute_disable = 0;
    if (make_writable) pte.write = 1;
    return write_physical(pte_pa, &pte, sizeof(pte))
        ? svm::svmroot_error_t::error_success
        : svm::svmroot_error_t::error_failed;
}

auto memory_access::copy_virtual_to_host(u64 cr3, u64 source_gva, void* destination, u64 size) -> bool {
    if (!destination) return false;

    auto bytes_read = 0ULL;
    auto output = static_cast<u8*>(destination);

    while (bytes_read < size) {
        u64 physical_address = 0;
        u64 remaining = 0;
        if (!translate(cr3, source_gva + bytes_read, physical_address, remaining)) {
            return false;
        }

        auto chunk = remaining < size - bytes_read ? remaining : size - bytes_read;
        if (!read_physical(physical_address, output + bytes_read, chunk)) {
            return false;
        }

        bytes_read += chunk;
    }

    return true;
}

auto memory_access::copy_host_to_virtual(u64 cr3, u64 destination_gva, const void* source, u64 size) -> bool {
    if (!source) return false;

    auto bytes_written = 0ULL;
    auto input = static_cast<const u8*>(source);

    while (bytes_written < size) {
        u64 physical_address = 0;
        u64 remaining = 0;
        if (!translate(cr3, destination_gva + bytes_written, physical_address, remaining)) {
            return false;
        }

        auto chunk = remaining < size - bytes_written ? remaining : size - bytes_written;
        if (!write_physical(physical_address, input + bytes_written, chunk)) {
            return false;
        }

        bytes_written += chunk;
    }

    return true;
}

auto memory_access::read_virtual(u64 cr3, u64 source_gva, void* destination, u64 size) -> bool {
    return copy_virtual_to_host(cr3, source_gva, destination, size);
}

auto memory_access::write_virtual(u64 cr3, u64 destination_gva, const void* source, u64 size) -> bool {
    return copy_host_to_virtual(cr3, destination_gva, source, size);
}

auto memory_access::get_process_cr3(u64 target_pid) -> u64 {
    if (!target_pid) return 0;

    PEPROCESS process = nullptr;
    auto status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(target_pid), &process);
    if (!NT_SUCCESS(status) || !process) {
        return 0;
    }

    auto cr3 = reinterpret_cast<_EPROCESS*>(process)->Pcb.DirectoryTableBase;
    ObfDereferenceObject(process);
    return cr3;
}

auto memory_access::get_process_base(u64 target_pid) -> u64 {
    if (!target_pid) return svm::svmroot_error_t::invalid_pid;

    PEPROCESS process = nullptr;
    auto status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(target_pid), &process);
    if (!NT_SUCCESS(status) || !process) {
        return svm::svmroot_error_t::error_failed;
    }

    auto base = reinterpret_cast<u64>(reinterpret_cast<_EPROCESS*>(process)->SectionBaseAddress);
    ObfDereferenceObject(process);
    return base;
}

auto memory_access::get_process_module(u64 target_pid, const wchar_t* module_name) -> u64 {
    if (!target_pid || !module_name) return 0;

    PEPROCESS process = nullptr;
    auto status = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(target_pid), &process);
    if (!NT_SUCCESS(status) || !process) {
        return 0;
    }

    if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
        ObfDereferenceObject(process);
        return 0;
    }

    auto peb_address = reinterpret_cast<u64>(PsGetProcessPeb(process));
    ObfDereferenceObject(process);
    if (!peb_address) return 0;

    auto process_cr3 = get_process_cr3(target_pid);
    if (!process_cr3) return 0;

    PEB peb = {};
    if (!read_virtual(process_cr3, peb_address, &peb, sizeof(peb)) || !peb.Ldr) {
        return 0;
    }

    PEB_LDR_DATA ldr = {};
    if (!read_virtual(process_cr3, reinterpret_cast<u64>(peb.Ldr), &ldr, sizeof(ldr)) ||
        !ldr.ModuleListLoadOrder.Flink) {
        return 0;
    }

    auto head = reinterpret_cast<u64>(ldr.ModuleListLoadOrder.Flink);
    auto current = head;

    do {
        LDR_DATA_TABLE_ENTRY entry = {};
        if (!read_virtual(process_cr3, current, &entry, sizeof(entry))) {
            break;
        }

        current = reinterpret_cast<u64>(entry.InLoadOrderModuleList.Flink);

        if (entry.BaseDllName.Length > 0 &&
            entry.BaseDllName.Length < MAX_PATH * sizeof(WCHAR) &&
            entry.BaseDllName.Buffer) {
            WCHAR name[MAX_PATH] = {};
            auto bytes = crt_min<USHORT>(
                entry.BaseDllName.Length,
                static_cast<USHORT>(MAX_PATH * sizeof(WCHAR) - sizeof(WCHAR)));

            if (read_virtual(process_cr3, reinterpret_cast<u64>(entry.BaseDllName.Buffer),
                name, bytes) &&
                crt_strcmp(name, module_name, true)) {
                return reinterpret_cast<u64>(entry.DllBase);
            }
        }
    } while (current && current != head);

    return 0;
}

auto memory_access::read_physical_memory(pvcpu_t vcpu, u64 destination_gva, u64 source_gpa, u64 size)
    -> svm::svmroot_error_t {
    UNREFERENCED_PARAMETER(vcpu);

    if (ept::get()->is_hidden_physical_range(source_gpa, size)) {
        return svm::svmroot_error_t::invalid_guest_physical;
    }

    void* source = nullptr;
    if (!physical_to_virtual(source_gpa, size, source)) {
        return svm::svmroot_error_t::invalid_guest_physical;
    }

    return copy_host_to_virtual(guest_cr3(), destination_gva, source, size)
        ? svm::svmroot_error_t::error_success
        : svm::svmroot_error_t::svmroot_translate_failure;
}

auto memory_access::write_physical_memory(pvcpu_t vcpu, u64 destination_gpa, u64 source_gva, u64 size)
    -> svm::svmroot_error_t {
    UNREFERENCED_PARAMETER(vcpu);

    u8 stack_buffer[0x1000];
    auto bytes_written = 0ULL;
    auto current_cr3 = guest_cr3();

    while (bytes_written < size) {
        auto chunk = size - bytes_written;
        if (chunk > sizeof(stack_buffer)) chunk = sizeof(stack_buffer);

        if (!copy_virtual_to_host(current_cr3, source_gva + bytes_written, stack_buffer, chunk) ||
            !write_physical(destination_gpa + bytes_written, stack_buffer, chunk)) {
            return svm::svmroot_error_t::svmroot_translate_failure;
        }

        bytes_written += chunk;
    }

    return svm::svmroot_error_t::error_success;
}

auto memory_access::read_virtual_memory(pvcpu_t vcpu, u64 process_cr3, u64 destination_gva, u64 source_gva, u64 size)
    -> svm::svmroot_error_t {
    UNREFERENCED_PARAMETER(vcpu);

    u8 stack_buffer[0x1000];
    auto bytes_read = 0ULL;
    auto current_cr3 = guest_cr3();
    if (!process_cr3) process_cr3 = current_cr3;

    while (bytes_read < size) {
        auto chunk = size - bytes_read;
        if (chunk > sizeof(stack_buffer)) chunk = sizeof(stack_buffer);

        if (!copy_virtual_to_host(process_cr3, source_gva + bytes_read, stack_buffer, chunk) ||
            !copy_host_to_virtual(current_cr3, destination_gva + bytes_read, stack_buffer, chunk)) {
            return svm::svmroot_error_t::svmroot_translate_failure;
        }

        bytes_read += chunk;
    }

    return svm::svmroot_error_t::error_success;
}

auto memory_access::write_virtual_memory(pvcpu_t vcpu, u64 process_cr3, u64 destination_gva, u64 source_gva, u64 size)
    -> svm::svmroot_error_t {
    UNREFERENCED_PARAMETER(vcpu);

    u8 stack_buffer[0x1000];
    auto bytes_written = 0ULL;
    auto current_cr3 = guest_cr3();
    if (!process_cr3) process_cr3 = current_cr3;

    while (bytes_written < size) {
        auto chunk = size - bytes_written;
        if (chunk > sizeof(stack_buffer)) chunk = sizeof(stack_buffer);

        if (!copy_virtual_to_host(current_cr3, source_gva + bytes_written, stack_buffer, chunk) ||
            !copy_host_to_virtual(process_cr3, destination_gva + bytes_written, stack_buffer, chunk)) {
            return svm::svmroot_error_t::svmroot_translate_failure;
        }

        bytes_written += chunk;
    }

    return svm::svmroot_error_t::error_success;
}

auto memory_access::get() -> memory_access* {
    static memory_access instance;
    return &instance;
}

}
