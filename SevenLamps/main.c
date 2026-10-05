#include "driver_common.h"
#include <wdm.h>
#include <ntddk.h>

NTSTATUS PsLookupProcessByProcessId(HANDLE, PEPROCESS*);

OFFSET_TABLE g_Offsets[] = {
	{ 19041, 0x7D8, 0x18, 0x1C, 0x20, 0x24, 0x28 },  // 2004
	{ 19045, 0x7D8, 0x18, 0x1C, 0x20, 0x24, 0x28 },  // 22H2
	{ 22621, 0x7D8, 0x18, 0x1C, 0x20, 0x24, 0x28 },  // Win11 22H2
};

NTSTATUS Sign(PIRP irp, NTSTATUS status, ULONG_PTR info) {
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = info;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS IoDeviceDispatch(PDEVICE_OBJECT device_object, PIRP irp) {
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	ULONG ioctl_code = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG in_buffer_len = stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG out_buffer_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
	PSEVEN_CONTEXT ctx = (PSEVEN_CONTEXT)device_object->DeviceExtension;
	LONG out;

	switch (ioctl_code) {
		case IOCTL_GET_BASE_ADDRESS:
		{
			if (in_buffer_len < sizeof(PROCESS_BASE_ADDRESS) || out_buffer_len < sizeof(PROCESS_BASE_ADDRESS)) {
				return Sign(irp, STATUS_BUFFER_TOO_SMALL, 0);
			}
			PPROCESS_BASE_ADDRESS process_base_address = (PPROCESS_BASE_ADDRESS)irp->AssociatedIrp.SystemBuffer;
			PEPROCESS target_process;
			NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)process_base_address->ProcessId, &target_process);
			if (!NT_SUCCESS(status)) {
				return Sign(irp, status, 0);
			}
			ctx->Offsets = g_Offsets[2]; // hardcoded for now, should be determined by build numberss
			ctx->TargetPid = process_base_address->ProcessId;

			ObDereferenceObject(target_process);
			out = sizeof(PROCESS_BASE_ADDRESS);
			return Sign(irp, STATUS_SUCCESS, out);
		}

		case IOCTL_INIT_MIRROR_SEC:
		{
			if (in_buffer_len < sizeof(INIT_MIRROR_SEC_BUFFER) || out_buffer_len < sizeof(INIT_MIRROR_SEC_BUFFER)) {
				return Sign(irp, STATUS_BUFFER_TOO_SMALL, 0);
			}
			INIT_MIRROR_SEC_BUFFER* section_buffer = (INIT_MIRROR_SEC_BUFFER*)irp->AssociatedIrp.SystemBuffer;
			PEPROCESS target_process;
			NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)section_buffer->ProcessId, &target_process);
			if (!NT_SUCCESS(status)) {
				return Sign(irp, status, 0);
			}

			//walk vad tree
			OFFSET_TABLE offsets = ctx->Offsets; // hardcoded for now, should be determined by build number
			PRTL_AVL_TABLE vad = (PRTL_AVL_TABLE)((PUCHAR)target_process + offsets.VadRootOffset); // get vad root from offsets

			if (!vad->BalancedRoot.RightChild) {
				return Sign(irp, STATUS_UNSUCCESSFUL, 0);
			}
			PRTL_BALANCED_LINKS links[1024] = { 0 };
			INT stack_ptr = 0;
			ULONG64 lowest_va = MAXULONG64;
			ULONG64 highest_va = 0;
			links[stack_ptr++] = vad->BalancedRoot.RightChild;


			while (stack_ptr > 0) {
				PRTL_BALANCED_LINKS current_link = links[--stack_ptr];
				if (!current_link) {
					continue;
				}

				PMMVAD_SHORT node = (PMMVAD_SHORT)current_link;
				ULONG64 start_vpn = ((ULONG64)node->StartingVpnHigh << 32) | node->StartingVpn;
				ULONG64 end_vpn = ((ULONG64)node->EndingVpnHigh << 32) | node->EndingVpn;
				ULONG64 start_va = start_vpn << PAGE_SHIFT;
				ULONG64 end_va = (end_vpn << PAGE_SHIFT) | (PAGE_SIZE - 1);
				SIZE_T  region_size = end_va - start_va + 1;
				if (start_va < lowest_va)  lowest_va = start_va;
				if (end_va > highest_va) highest_va = end_va;

				DbgPrint("VAD Node: Start VA: %llx, End VA: %llx, Size: %llx\n", start_va, end_va, region_size);

				PRTL_BALANCED_LINKS left_child = current_link->LeftChild;
				PRTL_BALANCED_LINKS right_child = current_link->RightChild;
				if (left_child) {
					links[stack_ptr++] = left_child;
				}
				if (right_child) {
					links[stack_ptr++] = right_child;
				}
			}

			SIZE_T section_size = highest_va - lowest_va + 1;

			ctx->ProcessBase = lowest_va;
			ctx->ProcessTop = highest_va;
			ctx->SectionSize = section_size;

			ObDereferenceObject(target_process);
			out = sizeof(INIT_MIRROR_SEC_BUFFER);
			return Sign(irp, STATUS_SUCCESS, out);
		}

		default:
		{
			return Sign(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
		}
	}
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
	
	PSEVEN_CONTEXT ctx = (PSEVEN_CONTEXT)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(SEVEN_CONTEXT),
		'xtCS'
	);
	if (!ctx) {
		DbgPrint("Failed to allocate context\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(ctx, sizeof(SEVEN_CONTEXT));
	DriverObject->DeviceObject = device;
	DriverObject->DeviceObject->DeviceExtension = ctx;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoDeviceDispatch;
	return STATUS_SUCCESS;
}