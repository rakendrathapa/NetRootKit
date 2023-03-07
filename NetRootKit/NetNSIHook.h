#pragma once
#include <wdm.h>
#include <Ntstrsafe.h>

typedef ULONG DWORD;

namespace NsiHook
{
	NTSTATUS NetHookNSIProxy();

	BOOLEAN NetNSIFreeHook();

	NTSTATUS NetNSIProxyCompletionRoutineX86(
		IN PDEVICE_OBJECT  DeviceObject,
		IN PIRP  Irp,
		IN PVOID  Context
	);

	NTSTATUS NetNSIProxyCompletionRoutine(
		IN PDEVICE_OBJECT  DeviceObject,
		IN PIRP  Irp,
		IN PVOID  Context
	);

	NTSTATUS NetNSIProxyDeviceControlHook(
		IN PDEVICE_OBJECT  DeviceObject,
		IN PIRP  Irp
	);

	extern "C" POBJECT_TYPE * IoDriverObjectType;
	extern "C" NTSYSAPI
		NTSTATUS NTAPI	ObReferenceObjectByName(
			IN PUNICODE_STRING ObjectPath,
			IN ULONG Attributes,
			IN PACCESS_STATE PassedAccessState,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_TYPE ObjectType,
			IN KPROCESSOR_MODE AccessMode,
			IN OUT PVOID ParseContext OPTIONAL,
			OUT PVOID * ObjectPtr);

	//
	// Undocumented structures. I haven't had time to reverse engineer all of them :(
	//
	//
	constexpr ULONG IOCTL_NSI_GETALLPARAM = 0x12001B;

	extern PDRIVER_OBJECT g_NetNSIProxyDriverObject;
	extern PDRIVER_DISPATCH g_NetOldNSIProxyDeviceControl;

	typedef struct _HOOKED_IO_COMPLETION {
		PIO_COMPLETION_ROUTINE OriginalCompletionRoutine;
		PVOID OriginalContext;
		LONG InvokeOnSuccess;
		PEPROCESS RequestingProcess;
	} HOOKED_IO_COMPLETION, * PHOOKED_IO_COMPLETION;

	typedef struct _INTERNAL_TCP_TABLE_SUBENTRY
	{
		char bytesfill0[2];
		USHORT Port;
		ULONG dwIP;
		char bytesfill[20];
	}INTERNAL_TCP_TABLE_SUBENTRY, * PINTERNAL_TCP_TABLE_SUBENTRY;

	typedef struct _INTERNAL_TCP_TABLE_ENTRY
	{
		INTERNAL_TCP_TABLE_SUBENTRY localEntry;
		INTERNAL_TCP_TABLE_SUBENTRY remoteEntry;

	}INTERNAL_TCP_TABLE_ENTRY, *PINTERNAL_TCP_TABLE_ENTRY;

	typedef struct _NSI_STATUS_ENTRY
	{
		ULONG dwState;
		char bytesfill[8];

	}NSI_STATUS_ENTRY, *PNSI_STATUS_ENTRY;

	typedef struct _NSI_PROCESSID_INFO
	{
		ULONG dwUdpProId;
		ULONG UnknownParam2;
		ULONG UnknownParam3;
		ULONG dwProcessId;
		ULONG UnknownParam5;
		ULONG UnknownParam6;
		ULONG UnknownParam7;
		ULONG UnknownParam8;
	}NSI_PROCESSID_INFO, * PNSI_PROCESSID_INFO;

	struct NSI_PARAM
	{
		//
		// Total 3CH size
		//
		DWORD UnknownParam1;
		DWORD UnknownParam2;
		DWORD UnknownParam3;
		DWORD UnknownParam4;
		DWORD UnknownParam5;
		DWORD UnknownParam6;
		VOID* POINTER_32 lpMem;
		DWORD UnknownParam8;
		DWORD UnknownParam9;
		DWORD UnknownParam10;
		NSI_STATUS_ENTRY* POINTER_32 lpStatus;
		DWORD UnknownParam12;
		DWORD UnknownParam13;
		DWORD UnknownParam14;
		DWORD TcpConnCount;
	};

	typedef struct _NSI_PARAM_2
	{
		//
		// Total 70H size
		//
		ULONG_PTR UnknownParam1;
		SIZE_T UnknownParam2;
		PVOID UnknownParam3;
		SIZE_T UnknownParam4;
		ULONG UnknownParam5;
		ULONG UnknownParam6;
		PVOID UnknownParam7;		// TCP_ENTRIES
		SIZE_T UnknownParam8;		// EntrySize
		PVOID UnknownParam9;
		SIZE_T UnknownParam10;
		PVOID UnknownParam11;
		SIZE_T UnknownParam12;
		PVOID UnknownParam13;
		SIZE_T UnknownParam14;
		SIZE_T ConnCount;

	}NSI_PARAM_2, * PNSI_PARAM_2;

}