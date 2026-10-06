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

	ULONG64 pml4e = ReadPhysical(pml4Phys + PML4_INDEX(VirtualAddress) * 8);
	DbgPrint("[Walk] PML4E: 0x%llX (index %llu)\n", pml4e, PML4_INDEX(VirtualAddress));
	if (!(pml4e & 1)) { DbgPrint("[Walk] PML4E Not Present!\n"); return 0; }

	ULONG64 pdpte = ReadPhysical((pml4e & 0xFFFFFFFFF000) + PDPT_INDEX(VirtualAddress) * 8);
	DbgPrint("[Walk] PDPTE: 0x%llX (index %llu)\n", pdpte, PDPT_INDEX(VirtualAddress));
	if (!(pdpte & 1)) { DbgPrint("[Walk] PDPTE not present!\n"); return 0; }

	ULONG64 pde = ReadPhysical((pdpte & 0xFFFFFFFFF000) + PD_INDEX(VirtualAddress) * 8);
	DbgPrint("[Walk] PDE: 0x%llX (index %llu)\n", pde, PD_INDEX(VirtualAddress));
	if (!(pde & 1)) { DbgPrint("[Walk] PDE not present!\n"); return 0; }

	if (pde & 0x80) {
		ULONG64 physAddr = (pde & 0xFFFFFE00000) | ((ULONG64)VirtualAddress & 0x1FFFFF);
		DbgPrint("[Walk] 2MB Large Page! Physical: 0x%llX\n", physAddr);
		return 0;
	}

	ULONG64 pte = ReadPhysical((pde & 0xFFFFFFFFF000) + PT_INDEX(VirtualAddress) * 8);
	DbgPrint("[Walk] PTE: 0x%llX (index %llu)\n", pte, PT_INDEX(VirtualAddress));
	if (!(pte & 1)) { DbgPrint("[Walk] PTE not present!\n"); return 0; }

	ULONG64 physAddr = (pte & 0xFFFFFFFFF000) | ((ULONG64)VirtualAddress & 0xFFF);
	DbgPrint("[Walk] Physical Address: 0x%llX\n", physAddr);

	return physAddr;
}

NTSTATUS PopulateSectionMirror(PSEVEN_CONTEXT ctx)
{
	PEPROCESS target_process = ctx->TargetProcess;
	KPROCESS* kprocess = (KPROCESS*)(target_process);
	ULONG64 cr3 = kprocess->DirectoryTableBase;
	
	DbgPrint("EPROCESS: 0x%llX\n", (ULONG64)target_process);
	DbgPrint("CR3 from DTB: 0x%llX\n", cr3);
	DbgPrint("UserDTB: 0x%llX\n", *(ULONG64*)((PUCHAR)target_process + 0x28 + 8));

	
	//iterate cached regions and populate the section mirror with their contents
	for (ULONG region_idx = 0; region_idx < ctx->RegionCount; region_idx++ ) {
		
		VAD_REGION* region = &ctx->Regions[region_idx];
		//iterate every va within region
		for (ULONG64 va = region->StartVa; va < region->StartVa + region->Size; va += PAGE_SIZE) {

			// Walk PT for this VA, get physical address
			// Copy physical page into section at region->Offset + (va - region->StartVa)
			ULONG64 phys_mem = WalkPageTables(cr3, va);
			ULONG64 section_offset = region->Offset + (va - region->StartVa);
			PVOID   dest = (PUCHAR)ctx->SectionBase + section_offset;

			LARGE_INTEGER low_sec_off;
			low_sec_off.QuadPart = section_offset;

			PVOID page_view = NULL;
			SIZE_T page_size = PAGE_SIZE;
			DbgBreakPoint();
			ZwMapViewOfSection(ctx->SectionHandle, ZwCurrentProcess(),
				&page_view, 0, PAGE_SIZE, &low_sec_off,
				&page_size, ViewUnmap, 0, PAGE_READWRITE);


			MM_COPY_ADDRESS src;
			src.PhysicalAddress.QuadPart = phys_mem;
			SIZE_T bytes_copied;
			MmCopyMemory(dest, src, PAGE_SIZE, MM_COPY_MEMORY_PHYSICAL, &bytes_copied);


			ZwUnmapViewOfSection(ZwCurrentProcess(), page_view);
			DbgPrint("[PopulateSectionMirror] Copied 0x%llX bytes from physical 0x%llX to section offset 0x%llX\n", bytes_copied, phys_mem, section_offset);
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
	DbgBreakPoint();
	SIZE_T view_size = size;
	ctx->SectionHandle = section_handle;
	ctx->SectionSize = view_size;

	if (!NT_SUCCESS(PopulateSectionMirror(ctx))) {
		DbgPrint("[CreateSectionMirror] Failed to populate section mirror\n");
		ZwClose(section_handle);
		ctx->SectionHandle = NULL;
		ctx->SectionSize = 0;
		ctx->SectionBase = NULL;
		return STATUS_UNSUCCESSFUL;
	}
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