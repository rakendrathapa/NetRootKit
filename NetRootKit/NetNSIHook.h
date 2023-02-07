#pragma once

#include <wdm.h>

namespace NsiHook
{
	NTSTATUS NetHookNSIProxy();

	BOOLEAN NetNSIFreeHook();

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
	typedef unsigned long       DWORD;

	extern PDRIVER_OBJECT g_NetNSIProxyDriverObject;
	extern PDRIVER_DISPATCH g_NetOldNSIProxyDeviceControl;

	typedef struct _HOOKED_IO_COMPLETION {
		PIO_COMPLETION_ROUTINE OriginalCompletionRoutine;
		PVOID OriginalContext;
		LONG InvokeOnSuccess;
		PEPROCESS RequestingProcess;
	} HOOKED_IO_COMPLETION, * PHOOKED_IO_COMPLETION;

	typedef struct _NSI_STRUCTURE_ENTRY {
		ULONG IpAddress;
		UCHAR Unknown[52];
	} NSI_STRUCTURE_ENTRY, * PNSI_STRUCTURE_ENTRY;

	typedef struct _NSI_STRUCTURE_2 {
		UCHAR Unknown[32];
		NSI_STRUCTURE_ENTRY EntriesStart[1];
	} NSI_STRUCTURE_2, * PNSI_STRUCTURE_2;

	typedef struct _NSI_STRUCTURE_1 {
		UCHAR Unknown1[40];
		PNSI_STRUCTURE_2 Entries;
		SIZE_T EntrySize;
		UCHAR Unknown2[48];
		SIZE_T NumberOfEntries;
	} NSI_STRUCTURE_1, * PNSI_STRUCTURE_1;

	typedef struct _INTERNAL_TCP_TABLE_SUBENTRY
	{
		char bytesfill0[2];
		USHORT Port;
		DWORD dwIP;
		char bytesfill[20];
	}INTERNAL_TCP_TABLE_SUBENTRY, * PINTERNAL_TCP_TABLE_SUBENTRY;

	typedef struct _INTERNAL_TCP_TABLE_ENTRY
	{
		INTERNAL_TCP_TABLE_SUBENTRY localEntry;
		INTERNAL_TCP_TABLE_SUBENTRY remoteEntry;

	}INTERNAL_TCP_TABLE_ENTRY, * PINTERNAL_TCP_TABLE_ENTRY;

	typedef struct _NSI_STATUS_ENTRY
	{
		char bytesfill[12];

	}NSI_STATUS_ENTRY, * PNSI_STATUS_ENTRY;
}