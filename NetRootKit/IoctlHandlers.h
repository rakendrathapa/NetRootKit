#pragma once

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
	
	NTSTATUS HandleHideConnectPID(
		_In_ PIRP Irp,
		_In_ const size_t InputBufferLength);

	NTSTATUS HandleHideConnectProcessName(
		_In_ PIRP Irp,
		_In_ const size_t InputBufferLength);

	NTSTATUS HandleHidePID(
		_In_ PIRP Irp,
		_In_ const size_t InputBufferLength);

	NTSTATUS DisableWindowCaptureProtect(
		_In_ PIRP Irp,
		_In_ const size_t InputBufferLength);
}