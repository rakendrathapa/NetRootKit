#pragma once
#include <wdm.h>

namespace TcpHook
{
	NTSTATUS NetHookTCPProxy();

	VOID NetTCPFreeHook();
}
