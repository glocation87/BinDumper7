#include "driver_common.h"
#include <wdm.h>
#include <ntddk.h>

NTSTATUS PsLookupProcessByProcessId(HANDLE, PEPROCESS*);

OFFSET_TABLE g_Offsets[] = {
	{ 19041, 0x7D8, 0x18, 0x1C, 0x20, 0x24, 0x28 },  // 2004
	{ 19045, 0x7E0, 0x18, 0x1C, 0x20, 0x24, 0x28 },  // 22H2
	{ 22621, 0x7E0, 0x18, 0x1C, 0x20, 0x24, 0x28 },  // Win11 22H2
	{ 28000, 0x558, 0x018, 0x01C, 0x020, 0x021 },// Windows 11 26H1 - Build 28000
};

NTSTATUS Sign(PIRP irp, NTSTATUS status, ULONG_PTR info) {
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = info;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

//stole these routines here: https://github.com/0xMastEB/manual-pte-walk/blob/main/main.c
ULONG64 ReadPhysical(ULONG64 PhysAddr)
{
	ULONG64 value = 0;
	MM_COPY_ADDRESS addr;
	SIZE_T bytesRead = 0;
	addr.PhysicalAddress.QuadPart = PhysAddr;
	MmCopyMemory(&value, addr, sizeof(ULONG64), MM_COPY_MEMORY_PHYSICAL, &bytesRead);
	return value;
}

ULONG64 WalkPageTables(ULONG64 cr3, ULONG64 VirtualAddress)
{
	ULONG64 pml4Phys = cr3 & 0xFFFFFFFFF000;
	ULONG64 physAddr;
	ULONG64 pml4e = ReadPhysical(pml4Phys + PML4_INDEX(VirtualAddress) * 8);
	if (!(pml4e & 1)) { DbgPrint("[Walk] PML4E Not Present!\n"); return 0; }

	ULONG64 pdpte = ReadPhysical((pml4e & 0xFFFFFFFFF000) + PDPT_INDEX(VirtualAddress) * 8);
	if (!(pdpte & 1)) { DbgPrint("[Walk] PDPTE not present!\n"); return 0; }

	ULONG64 pde = ReadPhysical((pdpte & 0xFFFFFFFFF000) + PD_INDEX(VirtualAddress) * 8);
	if (!(pde & 1)) { DbgPrint("[Walk] PDE not present!\n"); return 0; }

	if (pde & 0x80) {
		return 0;
	}

	ULONG64 pte = ReadPhysical((pde & 0xFFFFFFFFF000) + PT_INDEX(VirtualAddress) * 8);
	if (!(pte & 1)) { DbgPrint("[Walk] PTE not present!\n"); return 0; }

	physAddr = (pte & 0xFFFFFFFFF000) | ((ULONG64)VirtualAddress & 0xFFF);
	DbgPrint("[Walk] Physical Address: 0x%llX\n", physAddr);

	return physAddr;
}

NTSTATUS PopulateSectionMirror(PSEVEN_CONTEXT ctx, PVOID user_base)
{
	PEPROCESS target_process = ctx->TargetProcess;
	ULONG64 dtb = *(ULONG64*)((PUCHAR)target_process + KPROCESS_DTB_OFFSET);
	ULONG64 udirbase = *(ULONG64*)((PUCHAR)target_process + KPROCESS_UDIRBASE_OFFSET);
	ULONG64 cr3 = udirbase ? udirbase : dtb;
	DbgPrint("EPROCESS: 0x%llX\n", (ULONG64)target_process);
	DbgPrint("CR3 from UDTB: 0x%llX\n", udirbase);
	DbgPrint("CR3 from DTB: 0x%llX\n", dtb); 
	DbgPrint("CR3: 0x%llX\n", cr3);

	for (ULONG i = 0; i < ctx->RegionCount; i++) {
		VAD_REGION* region = &ctx->Regions[i];

		for (ULONG64 va = region->StartVa; va < region->StartVa + region->Size; va += PAGE_SIZE) {
			ULONG64 phys = WalkPageTables(cr3, va);
			if (!phys) continue;

			ULONG64 sec_offset = region->Offset + (va - region->StartVa);
			PVOID dest = (PUCHAR)user_base + sec_offset;

			MM_COPY_ADDRESS src;
			src.PhysicalAddress.QuadPart = phys;
			SIZE_T copied = 0;
			MmCopyMemory(dest, src, PAGE_SIZE,
				MM_COPY_MEMORY_PHYSICAL, &copied);
		}
	}
	
	return STATUS_SUCCESS;
}

NTSTATUS CreateSectionMirror(PSEVEN_CONTEXT ctx, SIZE_T size) {
	LARGE_INTEGER max_size;
	max_size.QuadPart = (LONGLONG)size;

	HANDLE section_handle;
	NTSTATUS status = ZwCreateSection(
		&section_handle,
		SECTION_ALL_ACCESS,
		NULL,
		&max_size,
		PAGE_READWRITE,
		SEC_RESERVE,
		NULL
	);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	DbgPrint("[CreateSectionMirror] Section created successfully\n");

	SIZE_T view_size = size;
	ctx->SectionHandle = section_handle;
	ctx->SectionSize = view_size;

	return STATUS_SUCCESS;
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
			ctx->Offsets = g_Offsets[3]; // 26h1
			ctx->TargetPid = process_base_address->ProcessId;
			ctx->TargetProcess = target_process;

			ObDereferenceObject(target_process);
			out = sizeof(PROCESS_BASE_ADDRESS);
			return Sign(irp, STATUS_SUCCESS, out);
			break;
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
			PRTL_AVL_TREE vad = (PRTL_AVL_TREE)((PUCHAR)target_process + offsets.VadRootOffset); // get vad root from offsets

			if (!vad->Root) {
				ObDereferenceObject(target_process);
				return Sign(irp, STATUS_UNSUCCESSFUL, 0);
			}

			ctx->Regions = ExAllocatePool2(POOL_FLAG_NON_PAGED,
				sizeof(VAD_REGION) * 1024, 'gdAV');
			ctx->RegionCount = 0;

			PRTL_BALANCED_NODE nodes[1024] = { 0 };
			INT stack_ptr = 0;
			ULONG64 lowest_va = MAXULONG64;
			ULONG64 highest_va = 0;
			nodes[stack_ptr++] = vad->Root; //stack_ptr++ is the same as links[0 && ++stack_ptr] if it could hold expressions
			INT node_count = 0;
			ULONG64 bytes = 0;
			ULONG64 current_offset = 0;


			while (stack_ptr > 0) {
				//--stack_ptr is the same as links[stack-ptr - 1 = 0] because stack_ptr++ increments the value at stack_ptr memory address by unit amount
				PRTL_BALANCED_NODE current_link = nodes[--stack_ptr];
				if (!current_link) {
					continue;
				}

				PMMVAD_SHORT node = (PMMVAD_SHORT)current_link;
				ULONG64 start_vpn;
				ULONG64 end_vpn;
				__try {
					// If the MMU is modifying this node @ rt and the
					// address temporarily becomes invalid, this faults and
					// EXCEPTION_EXECUTE_HANDLER catches it instead of bugchecking (BSOD)
					start_vpn = ((ULONG64)node->StartingVpnHigh << 32) | node->StartingVpn;
					end_vpn = ((ULONG64)node->EndingVpnHigh << 32) | node->EndingVpn;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					continue;
				}
				
				ULONG64 start_va = start_vpn << PAGE_SHIFT;
				ULONG64 end_va = (end_vpn << PAGE_SHIFT) | (PAGE_SIZE - 1);
				SIZE_T region_size = end_va - start_va + 1;
				if (start_va < lowest_va)  lowest_va = start_va;
				if (end_va > highest_va) highest_va = end_va;

				ctx->Regions[node_count].StartVa = start_va;
				ctx->Regions[node_count].Size = region_size;
				ctx->Regions[node_count].Offset = current_offset;
				ctx->RegionCount++;

				current_offset += region_size;
				bytes += region_size;
				node_count++;

				
				PRTL_BALANCED_NODE left_child = (PRTL_BALANCED_NODE)((ULONG_PTR)current_link->Left & ~3ULL);
				PRTL_BALANCED_NODE right_child = (PRTL_BALANCED_NODE)((ULONG_PTR)current_link->Right & ~3ULL);
				if (left_child) {
					nodes[stack_ptr++] = left_child;
				}
				if (right_child) {
					nodes[stack_ptr++] = right_child;
				}
			}

			//SIZE_T section_size = highest_va - lowest_va + 1;

			if (!NT_SUCCESS(CreateSectionMirror(ctx, (SIZE_T)bytes)))
			{	
				ObDereferenceObject(target_process);
				return Sign(irp, STATUS_UNSUCCESSFUL, 0);
			}

			ctx->ProcessBase = lowest_va;
			ctx->ProcessTop = highest_va;
			ctx->Initialized = TRUE;

			section_buffer->Flag = 0x1; // initialized

			ObDereferenceObject(target_process);
			out = sizeof(INIT_MIRROR_SEC_BUFFER);
			return Sign(irp, STATUS_SUCCESS, out);
		}
		case IOCTL_GET_SECTION_HANDLE:
		{
			if (!ctx->Initialized) {
				return Sign(irp, STATUS_UNSUCCESSFUL, 0);
			}
			if (out_buffer_len < sizeof(SECTION_VIEW_INFO)) {
				return Sign(irp, STATUS_BUFFER_TOO_SMALL, 0);
			}

			PVOID user_base = NULL;
			SIZE_T view_size = 0;

			NTSTATUS status = ZwMapViewOfSection(
				ctx->SectionHandle,
				ZwCurrentProcess(),  // caller's usermode process
				&user_base,
				0, 0, NULL,
				&view_size,
				ViewUnmap,
				0,
				PAGE_READWRITE
			);

			if (!NT_SUCCESS(status)) {
				DbgPrint("[GetSectionHandle] ZwMapViewOfSection failed: 0x%X\n", status);
				return Sign(irp, status, 0);
			}

			DbgPrint("[GetSectionHandle] Mapped at usermode: 0x%p\n", user_base);

			PopulateSectionMirror(ctx, user_base);

			PSECTION_VIEW_INFO info = (PSECTION_VIEW_INFO)irp->AssociatedIrp.SystemBuffer;
			info->MirrorBase = user_base;
			info->MirrorSize = ctx->SectionSize;
			info->ProcessBase = (PVOID)ctx->ProcessBase;
			info->RegionCount = ctx->RegionCount;

			out = sizeof(SECTION_VIEW_INFO);
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
	DbgPrint("[DriverUnload] Starting driver unload\n");
	PSEVEN_CONTEXT ctx = (PSEVEN_CONTEXT)DriverObject->DeviceObject->DeviceExtension;
	
	if (ctx && ctx->Initialized) {
		if (ctx->SectionHandle) {
			ZwClose(ctx->SectionHandle);
			ctx->SectionHandle = NULL;
		}
		if (ctx->Regions) {
			ExFreePool(ctx->Regions);
			ctx->Regions = NULL;
		}
	}
	
	IoDeleteSymbolicLink((PUNICODE_STRING)L"\\??\\se7en");
	DbgPrint("[DriverUnload] Symbolic link deleted\n");
	
	if (ctx) {
		ExFreePool(ctx);
	}
	
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("[DriverUnload] Device deleted\n");
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
	
	NTSTATUS status = IoCreateDevice(DriverObject, sizeof(SEVEN_CONTEXT), &device_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &device);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	
	status = IoCreateSymbolicLink(&sym_link, &device_name);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	
	PSEVEN_CONTEXT ctx = (PSEVEN_CONTEXT)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(SEVEN_CONTEXT),
		'xtCS'
	);
	if (!ctx) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	RtlZeroMemory(ctx, sizeof(SEVEN_CONTEXT));
	
	DriverObject->DeviceObject = device;
	DriverObject->DeviceObject->DeviceExtension = ctx;
	
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoDeviceDispatch;
	
	return STATUS_SUCCESS;
}