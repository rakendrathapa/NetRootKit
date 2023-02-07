#pragma once
#include <ntifs.h>

namespace IoctlHandlers
{
	NTSTATUS HandleTestConnection(_In_ PIRP Irp, _In_ const size_t BufferSize);

	NTSTATUS HandleHidePort(_In_ PIRP Irp,
		_In_ const size_t InputBufferLength);

	NTSTATUS  HandleHideIP(
		_In_ PIRP Irp, 
		_In_ const size_t InputBufferLength);

	NTSTATUS  HandleHideRemoteIP(
		_In_ PIRP Irp,
		_In_ const size_t InputBufferLength);
}