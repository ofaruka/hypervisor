#include "utilities.hpp"

namespace svm {

bool utilities::is_amd() {
    int registers[4];
    __cpuid(registers, static_cast<int>(svm::cpuid::cpu_vendor_string));
    return ((registers[1] == 'htuA') && (registers[3] == 'itne') && (registers[2] == 'DMAc'));
}

bool utilities::is_svm_supported() {
    int registers[4];
    __cpuid(registers, static_cast<int>(svm::cpuid::svm_features_ex));
    return (registers[2] & static_cast<int>(svm::cpuid::cpu_ecx_svm));
}

bool utilities::is_npt_supported() {
    int registers[4];
    __cpuid(registers, static_cast<int>(svm::cpuid::svm_features));
    return registers[3] & static_cast<int>(svm::cpuid::cpu_edx_np);
}

bool utilities::can_svm_be_enabled() {
    uint64_t vmcr;
    vmcr = __readmsr(static_cast<int>(svm::msr::svm_vm_cr));
    return !(vmcr & static_cast<int>(svm::msr::svm_vm_cr_svmdis));
}

bool utilities::check_support() {
    return is_amd() && is_svm_supported() && is_npt_supported() && can_svm_be_enabled();
}

u32 utilities::get_patch_size(PVOID code, u32 min_hook_length) {
    if (!code || !min_hook_length) {
        return 0;
    }

    u32 total_size = 0;

    while (total_size < min_hook_length) {
        PVOID current_instruction = reinterpret_cast<PVOID>(reinterpret_cast<u64>(code) + total_size);
#if defined(_WIN64)
        const u8 arch_bits = 64;
#else
        const u8 arch_bits = 32;
#endif
        u32 instruction_length = disassembler::get()->decode_length(current_instruction, arch_bits);

        if (instruction_length == 0) {
            return 0;
        }

        total_size += instruction_length;
    }

    return total_size;
}

void utilities::enable_svme() {
    svm::efer_msr msr;
    msr.value = __readmsr(svm::efer);
    msr.svme = 1;
    __writemsr(svm::efer, msr.value);
}

bool utilities::lock_pages(void* address, size_t size, PMDL* out_mdl) {
    if (!address || !size || !out_mdl || size > MAXULONG ||
        reinterpret_cast<ULONG_PTR>(address) + size < reinterpret_cast<ULONG_PTR>(address)) {
        return false;
    }

    auto mdl = IoAllocateMdl(address, static_cast<ULONG>(size), FALSE, FALSE, nullptr);

    if (!mdl) {
        return false;
    }

    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    *out_mdl = mdl;
    return true;
}

void utilities::unlock_pages(PMDL mdl) {
    if (!mdl) {
        return;
    }

    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
}

PIMAGE_SECTION_HEADER utilities::get_section(void* image_base, const char* section_name) {
    PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);
    PIMAGE_NT_HEADERS32 nt_header =
        reinterpret_cast<PIMAGE_NT_HEADERS32>(dos_header->e_lfanew + reinterpret_cast<ULONG64>(image_base));
    ULONG num_sections = nt_header->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
    STRING target_section_name;
    RtlInitString(&target_section_name, section_name);

    for (ULONG i = 0; i < num_sections; i++) {
        STRING current_section_name;
        RtlInitString(&current_section_name, reinterpret_cast<PCSZ>(section->Name));

        if (current_section_name.Length > 8)
            current_section_name.Length = 8;
        if (RtlCompareString(&current_section_name, &target_section_name, FALSE) == 0) {
            return section;
        }

        section++;
    }

    return nullptr;
}

unsigned long long utilities::get_exported_function(const unsigned long long module_address, const char* proc_name) {
    const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_address);
    const auto nt_headers =
        reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<ULONGLONG>(dos_header) + dos_header->e_lfanew);
    const auto data_directory = nt_headers->OptionalHeader.DataDirectory[0];
    const auto export_directory =
        reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(module_address + data_directory.VirtualAddress);
    const auto address_of_names = reinterpret_cast<ULONG*>(module_address + export_directory->AddressOfNames);

    for (size_t i = 0; i < export_directory->NumberOfNames; i++) {
        const auto function_name = reinterpret_cast<const char*>(module_address + address_of_names[i]);

        if (!_stricmp(function_name, proc_name)) {
            const auto name_ordinal =
                reinterpret_cast<unsigned short*>(module_address + export_directory->AddressOfNameOrdinals)[i];
            const auto function_rva =
                module_address +
                reinterpret_cast<ULONG*>(module_address + export_directory->AddressOfFunctions)[name_ordinal];
            return function_rva;
        }
    }

    return 0;
}

svm::os_version_t utilities::get_os_version() {
    RTL_OSVERSIONINFOW ver = {0};
    ver.dwOSVersionInfoSize = sizeof(ver);
    RtlGetVersion(&ver);
    svm::os_version_t os_ver = {};
    os_ver.build_number = ver.dwBuildNumber;
    os_ver.major_version = static_cast<u16>(ver.dwMajorVersion);
    os_ver.minor_version = static_cast<u16>(ver.dwMinorVersion);
    os_ver.service_version = 0;
    return os_ver;
}

void* utilities::get_process_id_by_name(const wchar_t* process_name) {
    CHAR image_name[15];
    PEPROCESS sys_process = PsInitialSystemProcess;
    PEPROCESS cur_entry = sys_process;
    do {
        RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)cur_entry + image_file_name), sizeof(image_name));

        if (crt_strcmp(image_name, process_name, true)) {
            u32 active_threads_value;
            RtlCopyMemory((PVOID)&active_threads_value, (PVOID)((uintptr_t)cur_entry + active_threads),
                          sizeof(active_threads_value));

            if (active_threads_value)
                return PsGetProcessId(cur_entry);
        }

        PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(cur_entry) + active_process_links);
        cur_entry = (PEPROCESS)((uintptr_t)list->Flink - active_process_links);
    } while (cur_entry != sys_process);
    return 0;
}

utilities* utilities::get() {
    static utilities instance;
    return &instance;
}
}
