#include "Driver.h"

#define to_rva(address, offset) address + (int32_t)((*(int32_t*)(address + offset) + offset) + sizeof(int32_t))

int64_t(*gre_protect_sprite_content)(int64_t, uint64_t, int32_t, char) = nullptr;

static NTSTATUS GetProcessByProcessID(__in ULONG pid, __out PEPROCESS* Win32KProcess)
{
	// Get PID offset nt!_EPROCESS.UniqueProcessId
	ULONG PID_OFFSET = HideProcess::GetUniquePIDOffSetFromEProcess();

	// Check if offset discovery was successful 
	if (PID_OFFSET == 0)
	{
		return STATUS_NOT_FOUND;
	}

	// Get LIST_ENTRY offset nt!_EPROCESS.ActiveProcessLinks
	ULONG LIST_OFFSET = PID_OFFSET;


	// Check Architecture using pointer size
	INT_PTR ptr{};

	// Ptr size 8 if compiled for a 64-bit machine, 4 if compiled for 32-bit machine
	LIST_OFFSET += sizeof(ptr);

	// Record offsets for user buffer
	KdPrint(("Found offsets: %lu & %lu", PID_OFFSET, LIST_OFFSET));

	// Get current process
	PEPROCESS CurrentEPROCESS = PsGetCurrentProcess();

	// Initialize other variables
	PLIST_ENTRY CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	PULONG CurrentPID = (PULONG)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);

	// Check self 
	if (*(ULONG*)CurrentPID == pid)
	{
		*Win32KProcess = CurrentEPROCESS;
		return STATUS_SUCCESS;
	}

	// Record the starting position
	PEPROCESS StartProcess = CurrentEPROCESS;

	// Move to next item
	CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
	CurrentPID = (PULONG)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
	CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);

	// Loop until we find the right process to remove
	// Or until we circle back
	while ((ULONG_PTR)StartProcess != (ULONG_PTR)CurrentEPROCESS)
	{

		// Check item
		if (*(ULONG*)CurrentPID == pid) {
			*Win32KProcess = CurrentEPROCESS;
			return STATUS_SUCCESS;
		}

		// Move to next item
		CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
		CurrentPID = (PULONG)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
		CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS KernelGetModuleBase(
	__in const char* ModuleName,
	__out PVOID* ImageBase)
{
	NTSTATUS status{ STATUS_UNSUCCESSFUL };
	ULONG modulesSize{ 0 };
	AUX_MODULE_EXTENDED_INFO* modules{ nullptr };

	ULONG numberOfModules{ 0 };

	if (ImageBase == nullptr)
	{
		return STATUS_INVALID_PARAMETER;
	}

	//
	// Initialze the AUX kernel library
	//
	status = AuxKlibInitialize();
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	//
	// Get the size of area needed for loaded modules
	//
	status = AuxKlibQueryModuleInformation(&modulesSize,
		sizeof(AUX_MODULE_EXTENDED_INFO),
		nullptr);
	if (!NT_SUCCESS(status) || (0 == modulesSize))
	{
		return status;
	}

	numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

	//
	// Allocate returned sized memory for the modules area
	//

	modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePool2(POOL_FLAG_PAGED, modulesSize, TAG_NET);
	if (modules == nullptr)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(modules, modulesSize);

	//
	// Request the modules array be filled with module information
	//
	status = AuxKlibQueryModuleInformation(&modulesSize,
		sizeof(AUX_MODULE_EXTENDED_INFO),
		modules);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(modules, TAG_NET);
		modules = nullptr;
		return status;
	}

	KdPrint(("[ # ] ImageBase\t\t\tImageSize\t\t\t\t\t\t  FileName  FullPathName\n"));
	for (ULONG i = 0; i < numberOfModules; i++)
	{
		KdPrint(("[%03d] %p\t", i, modules[i].BasicInfo.ImageBase)); // ImageBase
		KdPrint(("0x%08x\t", modules[i].ImageSize)); // ImageSize
		KdPrint(("%30s ", modules[i].FullPathName + modules[i].FileNameOffset)); // FileName
		KdPrint((" %s\n", modules[i].FullPathName)); // FullPathName

		if (_stricmp((const char*)(modules[i].FullPathName + modules[i].FileNameOffset), ModuleName) == 0)
		{
			*ImageBase = modules[i].BasicInfo.ImageBase;
			KdPrint(("Addresses ImageBase[%p]\n", *ImageBase));
			break;
		}
	}

	ExFreePoolWithTag(modules, TAG_NET);

	return (*ImageBase == nullptr) ? STATUS_INVALID_ADDRESS : STATUS_SUCCESS;
}

template <typename str_type, typename str_type_2>
__forceinline bool crt_strcmp(str_type str, str_type_2 in_str, bool two)
{
#define to_lower(c_char) ((c_char >= 'A' && c_char <= 'Z') ? (c_char + 32) : c_char)

	if (!str || !in_str)
		return false;

	wchar_t c1, c2;
	do
	{
		c1 = *str++; c2 = *in_str++;
		c1 = to_lower(c1); c2 = to_lower(c2);

		if (!c1 && (two ? !c2 : 1))
			return true;

	} while (c1 == c2);

	return false;
}

PIMAGE_SECTION_HEADER GetSectionHeader(const uintptr_t image_base, const char* section_name)
{
	if (!image_base || !section_name)
		return nullptr;

	const auto pimage_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);
	const auto pimage_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(image_base + pimage_dos_header->e_lfanew);

	auto psection = reinterpret_cast<PIMAGE_SECTION_HEADER>(pimage_nt_headers + 1);

	PIMAGE_SECTION_HEADER psection_hdr = nullptr;

	const auto number_of_sections = pimage_nt_headers->FileHeader.NumberOfSections;

	for (auto i = 0; i < number_of_sections; ++i)
	{
		if (crt_strcmp(reinterpret_cast<const char*>(psection->Name), section_name, false))
		{
			psection_hdr = psection;
			break;
		}

		++psection;
	}

	return psection_hdr;
}

bool data_compare(const char* pdata, const char* bmask, const char* szmask)
{
	for (; *szmask; ++szmask, ++pdata, ++bmask)
	{
		if (*szmask == 'x' && *pdata != *bmask)
			return false;
	}

	return !*szmask;
}

uintptr_t FindPattern(const uintptr_t base, const size_t size, const char* bmask, const char* szmask)
{
	for (size_t i = 0; i < size; ++i)
		if (data_compare(reinterpret_cast<const char*>(base + i), bmask, szmask))
			return base + i;

	return 0;
}

uintptr_t find_pattern_page_km(const char* szmodule, const char* szsection, const char* bmask, const char* szmask)
{
	if (!szmodule || !szsection || !bmask || !szmask)
	{
		return 0;
	}

	PVOID imageBase = nullptr;
	if (!NT_SUCCESS(KernelGetModuleBase(szmodule, &imageBase)))
	{
		return 0;
	}
	if (FALSE == MmIsAddressValid(imageBase))
	{
		return 0;
	}

	const auto  module_base = reinterpret_cast<uintptr_t>(imageBase);		// PIMAGE_DOS_HEADER
	const auto* psection = GetSectionHeader(module_base, szsection);
	return psection ? FindPattern(module_base + psection->VirtualAddress, psection->Misc.VirtualSize, bmask, szmask) : 0;
}

NTSTATUS InitFunction(_In_ ULONG pid)
{
	KAPC_STATE ApcState{};
	PEPROCESS Win32Process{};
	if (!NT_SUCCESS(GetProcessByProcessID(pid, &Win32Process)))
	{
		return STATUS_INVALID_ADDRESS;
	}
	KeStackAttachProcess(Win32Process, &ApcState);

	auto gre_protect_sprite_content_address = reinterpret_cast<PVOID>(find_pattern_page_km("win32kfull.sys", ".text",
		"\xE8\x00\x00\x00\x00\x8B\xF8\x85\xC0\x75\x0E", "x????xxxxxx"));

	if (gre_protect_sprite_content_address == 0)
	{
		KeUnstackDetachProcess(&ApcState);
		return STATUS_INVALID_ADDRESS;
	}

	gre_protect_sprite_content_address = reinterpret_cast<PVOID>(to_rva(reinterpret_cast<uintptr_t>(gre_protect_sprite_content_address), 1));

	*(PVOID*)&gre_protect_sprite_content = gre_protect_sprite_content_address;

	KeUnstackDetachProcess(&ApcState);
	return STATUS_SUCCESS;
}

NTSTATUS DisplayHook::DisableWindowCaptureprotect(pprotect_sprite_content req)
{
	if (gre_protect_sprite_content == nullptr)
	{
		if (!NT_SUCCESS(InitFunction(req->pid)))
		{
			return STATUS_UNSUCCESSFUL;
		}
	}

	if (gre_protect_sprite_content && MmIsAddressValid(gre_protect_sprite_content))
	{
		return gre_protect_sprite_content(0, req->window_handle, 1, (char)req->value) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
	}

	return STATUS_UNSUCCESSFUL;
}
