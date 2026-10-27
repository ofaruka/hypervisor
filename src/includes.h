#pragma once
#include <ntifs.h>
#include <classpnp.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#pragma warning (disable : 4201) 
#pragma warning (disable : 4083) 
#pragma warning (disable : 4005) 
#pragma warning (disable : 4100)
#pragma warning (disable : 5040)
#pragma warning (disable : 4083)
#include <intrin.h>
#include <stdint.h>

#include "Zydis/Zydis.h"

// Debug logger
#define debug_log(text, ...) (DbgPrintEx(0, 0, "[core] " text, ##__VA_ARGS__))
#define debug_break() __debugbreak();

// Unreference Parameters/Variables
#define unref_var(x)	(x=x)
#define unref_param(x)	(x=x)

// Allocation tag
#define cv_tag 'CryHv'

// SVM
#define svm_exitinfo_reg_mask           0x0F
#define svm_intercept_popf              17
#define svm_intercept_pushf             16
#define svm_np_enable                   0

// PAGE
#define page_4kb 0x1000
#define page_2mb page_4kb * 512
#define page_1gb page_2mb * 512

// Following designation allows us to setup and dump VMCB
// data in the way that we perform on Intel VT-x driver.
#define svm_vmread8(v,o)        *(u8*)((ulong_ptr)v+o)
#define svm_vmread16(v,o)       *(u16*)((ulong_ptr)v+o)
#define svm_vmread32(v,o)       *(u32*)((ulong_ptr)v+o)
#define svm_vmread64(v,o)       *(u64*)((ulong_ptr)v+o)

#define svm_vmwrite8(v,o,d)     *(u8*)((ulong_ptr)v+o)=(u8)d
#define svm_vmwrite16(v,o,d)    *(u16*)((ulong_ptr)v+o)=(u16)d
#define svm_vmwrite32(v,o,d)    *(u32*)((ulong_ptr)v+o)=(u32)d
#define svm_vmwrite64(v,o,d)    *(u64*)((ulong_ptr)v+o)=(u64)d

#define svm_vmcopy8(d,s,o)      svm_vmwrite8(d,o,svm_vmread8(s,o))
#define svm_vmcopy16(d,s,o)     svm_vmwrite16(d,o,svm_vmread16(s,o))
#define svm_vmcopy32(d,s,o)     svm_vmwrite32(d,o,svm_vmread32(s,o))
#define svm_vmcopy64(d,s,o)     svm_vmwrite64(d,o,svm_vmread64(s,o))

#define svm_vmread      svm_vmread64
#define svm_vmwrite     svm_vmwrite64
#define svm_vmcopy      svm_vmcopy64

#define svm_attrib(a)			(u16)(((a&0xFF)|((a&0xF000)>>4))&0xfff)
#define svm_attrib_inverse(a)	(u16)(((a&0xF00)<<4)|(a&0xFF))

#define max_core_count 64

typedef union _large_integer {
	struct {
		unsigned long low_part;
		long high_part;
	} DUMMYSTRUCTNAME;
	struct {
		unsigned long low_part;
		long high_part;
	} u;
	long long quad_part;
} large_integer;

#pragma once

typedef unsigned __int8		u8;
typedef unsigned __int16	u16;
typedef unsigned __int32	u32;
typedef unsigned __int64	u64;

typedef signed __int8		i8;
typedef signed __int16		i16;
typedef signed __int32		i32;
typedef signed __int64		i64;

typedef u8* u8p;
typedef u16* u16p;
typedef u32* u32p;
typedef u64* u64p;

typedef i8* i8p;
typedef i16* i16p;
typedef i32* i32p;
typedef i64* i64p;

using guest_virt_t = u64;
using guest_phys_t = u64;
using host_virt_t = u64;
using host_phys_t = u64;

#if defined(_amd64)
typedef u64 ulong_ptr;
typedef i64 long_ptr;
#else
typedef u32 ulong_ptr;
typedef i32 long_ptr;
#endif

typedef ulong_ptr* ulong_ptr_p;
typedef long_ptr* long_ptr_p;
typedef size_t* size_p;

typedef volatile u8		u8v;
typedef volatile u16	u16v;
typedef volatile u32	u32v;
typedef volatile u64	u64v;

typedef volatile i8		i8v;
typedef volatile i16	i16v;
typedef volatile i32	i32v;
typedef volatile i64	i64v;

typedef volatile ulong_ptr	vulong_ptr;
typedef volatile long_ptr	vlong_ptr;

typedef u8v* u8vp;
typedef u16v* u16vp;
typedef u32v* u32vp;
typedef u64v* u64vp;

typedef i8v* i8vp;
typedef i16v* i16vp;
typedef i32v* i32vp;
typedef i64v* i64vp;

typedef vulong_ptr* vulong_ptr_p;
typedef vlong_ptr* vlong_ptr_p;

enum class svm_error_t
{
	error_success,
	pml4e_not_present,
	pdpte_not_present,
	pde_not_present,
	pte_not_present,
	vmxroot_translate_failure,
	invalid_self_ref_pml4e,
	invalid_mapping_pml4e,
	invalid_host_virtual,
	invalid_guest_physical,
	invalid_guest_virtual,
	page_table_init_failed
};

enum attach_option : u64 {
	no_attach,
	attach
};

// MSR definitions
enum msr_list : u32 {
	// System MSRs
	MSR_TSC = 0x00000010,
	MSR_APIC_BASE = 0x0000001B,
	MSR_IA32_FEATURE_CONTROL = 0x0000003A,
	MSR_IA32_TSC_ADJUST = 0x0000003B,
	MSR_IA32_SPEC_CTRL = 0x00000048,
	MSR_IA32_PRED_CMD = 0x00000049,
	MSR_IA32_BIOS_SIGN_ID = 0x0000008B,
	MSR_IA32_PLATFORM_INFO = 0x000000CE,
	MSR_IA32_MTRRCAP = 0x000000FE,
	MSR_IA32_ARCH_CAPABILITIES = 0x0000010A,
	MSR_IA32_MCG_CAP = 0x00000179,
	MSR_IA32_MCG_STATUS = 0x0000017A,
	MSR_IA32_MISC_ENABLE = 0x000001A0,
	MSR_PAT = 0x00000277,
	MSR_IA32_MTRR_DEF_TYPE = 0x000002FF,
	MSR_IA32_TSC_DEADLINE = 0x000006E0,
	MSR_LSTAR = 0xC0000082,
	MSR_CSTAR = 0xC0000083,
	MSR_SFMASK = 0xC0000084,
	MSR_FS_BASE = 0xC0000100,
	MSR_GS_BASE = 0xC0000101,
	MSR_KERNEL_GS_BASE = 0xC0000102,
	MSR_TSC_AUX = 0xC0000103,
	MSR_SYSENTER_CS = 0x00000174,
	MSR_SYSENTER_ESP = 0x00000175,
	MSR_SYSENTER_EIP = 0x00000176,

	// SVM MSRs
	MSR_EFER = 0xC0000080,
	MSR_STAR = 0xC0000081,
	MSR_VM_HSAVE_PA = 0xC0010117,
	MSR_VM_CR = 0xC0010114,

	// Performance MSRs
	MSR_IA32_APERF = 0x000000E8,
	MSR_IA32_MPERF = 0x000000E7,
	MSR_PERF_CTR0 = 0x000000C1,
	MSR_PERF_CTR1 = 0x000000C2,
	MSR_PERF_CTR2 = 0x000000C3,
	MSR_PERF_CTR3 = 0x000000C4,
	MSR_IA32_FIXED_CTR0 = 0x00000309,
	MSR_IA32_FIXED_CTR1 = 0x0000030A,
	MSR_IA32_FIXED_CTR2 = 0x0000030B,
	MSR_IA32_FIXED_CTR_CTRL = 0x0000038D,
	MSR_IA32_PERF_GLOBAL_CTRL = 0x0000038F,
	MSR_PERFEVTSEL0 = 0x00000186,
	MSR_PERFEVTSEL1 = 0x00000187,
	MSR_PERFEVTSEL2 = 0x00000188,
	MSR_PERFEVTSEL3 = 0x00000189,

	// System configuration MSRs
	MSR_HWCR = 0xC0010015,
	MSR_K8_SYSCFG = 0xC0010010,

	// Debug MSRs
	MSR_DEBUG_CTL = 0x000001D9,

	// Last Branch Record MSRs
	MSR_LASTBRANCHFROMIP = 0x000001DB,
	MSR_LASTBRANCHTOIP = 0x000001DC,
	MSR_LASTINTFROMIP = 0x000001DD,
	MSR_LASTINTTOIP = 0x000001DE,
	MSR_P6M_LBSTK_TOS = 0x000001C9,
	
	// Hypervisor detection MSRs
	MSR_KVM_SIGNATURE = 0x4B564D00,

};

// Hyper-V hypercall codes (decimal values as seen in securekernel)
#define HV_CALL_FLUSH_VIRTUAL_ADDRESS_SPACE  0x0002  // ShvlFlushEntireTb (code 2)
#define HV_CALL_MODIFY_VTL_PROTECTION_MASK   0x000C  // ShvlpProtectPages (code 12)
#define HV_CALL_ENABLE_PARTITION_VTL         0x000D  // ShvlpEnablePartitionVtl (code 13)
#define HV_CALL_ENABLE_VP_VTL               0x000F  // ShvlEnableVpVtl (code 15)
#define HV_CALL_GET_VP_REGISTERS             0x0050  // ShvlGetVpRegister (code 80)
#define HV_STATUS_SUCCESS                     0x0000

struct apic_bar_msr
{
	union
	{
		uint64_t value;
		struct
		{
			uint64_t reserved1 : 8;           // [0:7]
			uint64_t bootstrap_processor : 1;  // [8]
			uint64_t reserved2 : 1;           // [9]
			uint64_t x2apic_mode : 1;    // [10]
			uint64_t xapic_global : 1;   // [11]
			uint64_t apic_base : 24;           // [12:35]
		};
	};
};

extern "C" POBJECT_TYPE * IoDriverObjectType;

extern "C" {
	VOID KeFlushEntireTb(
		__in BOOLEAN Invalid,
		__in BOOLEAN AllProcessors
	);

	NTSTATUS NTAPI MmCopyVirtualMemory(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TargetProcess,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize
	);

	NTSTATUS NTAPI ZwQuerySystemInformation(
		IN size_t SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL
	);

	PPEB NTAPI PsGetProcessPeb(
		IN PEPROCESS Process
	);

	NTSTATUS ObReferenceObjectByName(IN PUNICODE_STRING ObjectName, IN ULONG Attributes, IN PACCESS_STATE PassedAccessState, IN ACCESS_MASK DesiredAccess, IN POBJECT_TYPE ObjectType, IN KPROCESSOR_MODE AccessMode, IN OUT PVOID ParseContext, OUT PVOID* Object);
}

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE {
	PVOID 	Reserved1;
	PVOID 	Reserved2;
	PVOID 	ImageBaseAddress;
	ULONG 	ImageSize;
	ULONG 	Flags;
	unsigned short 	Id;
	unsigned short 	Rank;
	unsigned short 	Unknown;
	unsigned short 	NameOffset;
	unsigned char 	Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG                       ModulesCount;
	SYSTEM_MODULE_ENTRY         Modules[1];
	ULONG                       Count;
	SYSTEM_MODULE 	            Sys_Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef VOID(WINAPI* PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;  // in bytes
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;  // LDR_*
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA64 {
	ULONG Length;
	UCHAR Initialized;
	ULONG64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY64 HashLinks;
	ULONG64 SectionPointer;
	ULONG64 CheckSum;
	ULONG64 TimeDateStamp;
	ULONG64 LoadedImports;
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
	LIST_ENTRY64 ForwarderLinks;
	LIST_ENTRY64 ServiceTagLinks;
	LIST_ENTRY64 StaticLinks;
	ULONG64 ContextInformation;
	ULONG64 OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

typedef struct _PEB64 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	UCHAR Padding0[4];
	ULONG64 Mutant;
	ULONG64 ImageBaseAddress;
	ULONG64/*PPEB_LDR_DATA64*/ Ldr;
	RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
} PEB64, * PPEB64;

typedef struct _mtrr_range_descriptor
{
	SIZE_T physical_base_address;
	SIZE_T physical_end_address;
	UCHAR  memory_type;
} mtrr_range_descriptor, * pmtrr_range_descriptor;

typedef struct _ssdt {
	LONG* ServiceTable;
	PVOID CounterTable;
	ULONG64 SyscallsNumber;
	PVOID ArgumentTable;
}_ssdt, * _pssdt;

typedef struct _syscall_info {
	SHORT syscall_number;
	const char* syscall_name;
	PVOID hook_function_address;
	PVOID* original_function_address;
}syscall_info, * psyscall_info;

inline _pssdt nt_table;
inline _pssdt win32k_table;

#define cdecl		__cdecl
#define stdcall		__stdcall
#define fastcall	__fastcall

#define align_at(n)		__declspec(align(n))

#define null	(void*)0
#define maxu8	0xff
#define maxu16	0xffff
#define maxu32	0xffffffff
#define maxu64	0xffffffffffffffff

#define windows_7 7600
#define windows_7_sp1 7601
#define windows_8 9200
#define windows_8_1 9600
#define windows_11 22000

#define windows_1803 17134
#define windows_1809 17763
#define windows_1903 18362
#define windows_1909 18363
#define windows_2004 19041
#define windows_20H2 19569
#define windows_21H1 20180

#define windows_10_version_threshold1 10240
#define windows_10_version_threshold2 10586

#define windows_10_version_redstone1 14393
#define windows_10_version_redstone2 15063
#define windows_10_version_redstone3 16299
#define windows_10_version_redstone4 17134
#define windows_10_version_redstone5 17763

#define image_file_name 0x5A8 
#define active_threads 0x5F0 
#define thread_list_head 0x5E0  
#define active_process_links 0x448

// Maximum number of loaded contexts
#define MAX_LOADED_CONTEXTS        16
#define MAX_CONTEXT_BLOB_SIZE      0x1000  // 4KB max context size

// Context blob version
#define TPM_CONTEXT_VERSION        0x0001

#define JMP_SIZE (14)
#define MAPPER_DATA_SIZE (JMP_SIZE + 7)

#define IMPLEMENTATION_PCR      24
#define SHA256_DIGEST_SIZE      32

#pragma warning (disable : 4245)
#pragma warning (disable : 4390)
#pragma warning (disable : 6011)

// Exception handlers without error code
extern "C" void divide_error_fault_handler_a(void);
extern "C" void debug_fault_trap_handler_a(void);
extern "C" void breakpoint_trap_handler_a(void);
extern "C" void overflow_trap_handler_a(void);
extern "C" void bound_range_fault_handler_a(void);
extern "C" void invalid_opcode_fault_handler_a(void);
extern "C" void device_not_available_fault_handler_a(void);
extern "C" void x87_floating_point_fault_handler_a(void);
extern "C" void machine_check_abort_handler_a(void);
extern "C" void simd_floating_point_fault_handler_a(void);

// Exception handlers with error code
extern "C" void double_fault_abort_handler_a(void);
extern "C" void invalid_tss_fault_handler_a(void);
extern "C" void segment_not_present_fault_handler_a(void);
extern "C" void stack_fault_handler_a(void);
extern "C" void general_protection_fault_handler_a(void);
extern "C" void page_fault_handler_a(void);
extern "C" void alignment_check_fault_handler_a(void);
extern "C" void control_protection_fault_handler_a(void);

extern "C" {
	uint16_t __read_cs();
	uint16_t __read_ss();
	uint16_t __read_ds();
	uint16_t __read_es();
	uint16_t __read_fs();
	uint16_t __read_gs();
	uint16_t __read_tr();
	uint16_t __read_ldtr();

	void __write_ds(uint16_t selector);
	void __write_es(uint16_t selector);
	void __write_fs(uint16_t selector);
	void __write_gs(uint16_t selector);
	void __write_tr(uint16_t selector);
	void __write_ldtr(uint16_t selector);
}

extern "C" {
	void __lgdt(const void* gdt_descriptor);
	void __lldt(uint16_t ldt_selector);
	void __ltr(uint16_t tss_selector);
	void __sgdt(void* gdt_descriptor);
	void __sldt(void* ldt_selector);
	void __str(void* tr_selector);
}

template <typename str_type, typename str_type_2>
__forceinline bool crt_strcmp(str_type str, str_type_2 in_str, bool two) {
	if (!str || !in_str)
		return false;

	wchar_t c1, c2;
#define to_lower(c_char) ((c_char >= 'A' && c_char <= 'Z') ? (c_char + 32) : c_char)

	do {
		c1 = *str++; c2 = *in_str++;
		c1 = to_lower(c1); c2 = to_lower(c2);

		if (!c1 && (two ? !c2 : 1))
			return true;

	} while (c1 == c2);

	return false;
}

template <typename T>
static auto crt_min(T A, T B)
{
	if (A < B)
		return A;

	return B;
}

template <typename T>
static auto crt_max(T A, T B)
{
	if (A > B)
		return A;

	return B;
}

#define deadloop() \
	do { \
		for (;;) { \
			_mm_pause(); \
		} \
	} while (false)

inline u64 enter_guest_time = 0;

typedef bool (*callback)(PVOID ctx);

struct page_context {
	bool is_execution;
	bool is_write;
	bool is_present;
	u64 guest_pa;
	u64 host_pa;
};

extern "C" u8 __ImageBase;

// Defines includes
#include "svm/defines_ctx/cpu.hpp"
#include "svm/defines_ctx/ntdef/def.h"
#include "svm/defines_ctx/bitset.hpp"
#include "svm/defines_ctx/memory-data.hpp"
#include "svm/defines_ctx/npt-data.hpp"
#include "svm/defines_ctx/interrupt.hpp"
#include "svm/defines_ctx/gdt-data.hpp"
#include "svm/defines_ctx/descriptors-info.hpp"
#include "svm/defines_ctx/vmcb.hpp"
#include "svm/defines_ctx/msr-data.hpp"
#include "svm/defines_ctx/vprocessor-data.hpp"
#include "svm/defines_ctx/spin-lock.hpp"
#include "svm/defines_ctx/exception-handler.hpp"

// Utilities includes
#include "svm/utilities_ctx/memory/memory.hpp"
#include "svm/utilities_ctx/memory/page_table/page_table.hpp"
#include "svm/utilities_ctx/memory/memory_access/memory_access.hpp"
#include "svm/utilities_ctx/npt/npt.hpp"
#include "svm/utilities_ctx/disassembler/disassembler.hpp"
#include "svm/utilities_ctx/debug/debug.hpp"
#include "svm/utilities_ctx/msr/msr.hpp"
#include "svm/utilities_ctx/hook/hook.hpp"
#include "svm/utilities_ctx/utilities.hpp"
#include "svm/utilities_ctx/tpm/tpm.hpp"
#include "svm/utilities_ctx/tpm/crypto/tpm_crypto.hpp"
#include "svm/utilities_ctx/memory/hide_page/hide_page.hpp"
#include "svm/utilities_ctx/logger/logger.hpp"	
#include "svm/utilities_ctx/idt/idt.hpp"
#include "svm/utilities_ctx/gdt/gdt.hpp"
#include "svm/utilities_ctx/npt/mmio/mmio_svm.hpp"

// Defines includes
#include "svm/defines_ctx/virtual-memory.hpp"
#include "svm/defines_ctx/ia32.hpp"
#include "svm/defines_ctx/amd.hpp"
#include "svm/defines_ctx/vmexit.hpp"

// Handler includes
#include "svm/handlers_ctx/msr/msr_svm.hpp"
#include "svm/handlers_ctx/efer/efer_svm.hpp"
#include "svm/handlers_ctx/npf/npf_svm.hpp"
#include "svm/handlers_ctx/cpuid/cpuid_svm.hpp"
#include "svm/handlers_ctx/vmmcall/vmmcall_svm.hpp"
#include "svm/handlers_ctx/debug_registers/dr_svm.hpp"
#include "svm/handlers_ctx/control_registers/cr_svm.hpp"
#include "svm/handlers_ctx/nmi/nmi_svm.hpp"
#include "svm/handlers_ctx/exceptions/exceptions_svm.hpp"
#include "svm/handlers_ctx/events/events_svm.hpp"
#include "svm/handlers_ctx/gif/gif_svm.hpp"
#include "svm/handlers_ctx/timing/timing_svm.hpp"
#include "svm/handlers_ctx/vmm_handlers.hpp"

#include "svm/svm.hpp"

// VTX (Intel VT-x peer to svm/)
#include "vtx/defines_ctx/intel.hpp"
#include "vtx/defines_ctx/vmcs.hpp"
#include "vtx/defines_ctx/ept.hpp"
#include "vtx/defines_ctx/vprocessor-data.hpp"
#include "vtx/utilities_ctx/utilities.hpp"
#include "vtx/utilities_ctx/vmx/vmx.hpp"
#include "vtx/utilities_ctx/ept/ept.hpp"
#include "vtx/utilities_ctx/ept/mmio/mmio_vtx.hpp"
#include "vtx/utilities_ctx/memory/memory_access_vtx.hpp"
#include "vtx/utilities_ctx/hook/hook.hpp"
#include "vtx/handlers_ctx/cache/cache_vtx.hpp"
#include "vtx/handlers_ctx/control_registers/cr_vtx.hpp"
#include "vtx/handlers_ctx/descriptors/descriptors_vtx.hpp"
#include "vtx/handlers_ctx/xcr/xcr_vtx.hpp"
#include "vtx/handlers_ctx/timing/timing_vtx.hpp"
#include "vtx/handlers_ctx/cpuid/cpuid_vtx.hpp"
#include "vtx/handlers_ctx/msr/msr_vtx.hpp"
#include "vtx/handlers_ctx/vmcall/vmcall_vtx.hpp"
#include "vtx/handlers_ctx/mtf/mtf_vtx.hpp"
#include "vtx/handlers_ctx/epv/epv_vtx.hpp"
#include "vtx/handlers_ctx/events/events_vtx.hpp"
#include "vtx/handlers_ctx/debug_registers/dr_vtx.hpp"
#include "vtx/handlers_ctx/vmm_handlers.hpp"
#include "vtx/vtx.hpp"
