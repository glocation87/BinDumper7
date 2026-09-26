#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>   // kernel types
#else
#include <Windows.h> // user-mode types
#include <winioctl.h>
#endif

#define DEVICE_NAME  L"\\Device\\Se7en"
#define SYMLINK_NAME L"\\??\\Se7en"

#define SE7EN_DEVICE_TYPE 0x8239
#define GET_BASE_ADDRESS_CODE 0x800

#define IOCTL_GET_BASE_ADDRESS CTL_CODE(SE7EN_DEVICE_TYPE, GET_BASE_ADDRESS_CODE, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PROCESS_BASE_ADDRESS {
#ifdef _KERNEL_MODE
    ULONG ProcessId;
    PVOID BaseAddress;
#else
    DWORD ProcessId;
    PVOID BaseAddress;
#endif
} PROCESS_BASE_ADDRESS, * PPROCESS_BASE_ADDRESS;
