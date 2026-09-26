#include "driver_common.h"
#include <wdm.h>
#include <ntddk.h>

NTSTATUS Sign(PIRP irp, NTSTATUS status, ULONG_PTR info) {
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = info;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS IoDeviceDispatch(PDEVICE_OBJECT device_object, PIRP irp ) {
	UNREFERENCED_PARAMETER(device_object);
	UNREFERENCED_PARAMETER(irp);
	/*PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG in_buffer_len = stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG out_buffer_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
	LONG out;*/

	return STATUS_SUCCESS;
}

NTSTATUS DeviceCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	return Sign(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject)
{
	IoDeleteSymbolicLink((PUNICODE_STRING)L"\\??\\se7en");
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("SevenLamps driver unloaded\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	PDEVICE_OBJECT device = NULL;
	UNICODE_STRING device_name = RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING sym_link = RTL_CONSTANT_STRING(SYMLINK_NAME);

	//register unload routine early, so if we fail to create device or symbolic link, we can still unload the driver
	DriverObject->DriverUnload = DriverUnload;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &device);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create device: %X\n", status);
		return status;
	}
	status = IoCreateSymbolicLink(&sym_link, &device_name);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Failed to create symbolic link: %X\n", status);
		return status;
	}

	DriverObject->DeviceObject = device;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoDeviceDispatch;
	return STATUS_SUCCESS;
}