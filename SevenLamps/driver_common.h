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
#define GET_IMAGE_MIRROR_CODE 0x801
#define GET_IMAGE_SECTION_CODE 0x802

#define IOCTL_GET_BASE_ADDRESS CTL_CODE(SE7EN_DEVICE_TYPE, GET_BASE_ADDRESS_CODE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INIT_MIRROR_SEC CTL_CODE(SE7EN_DEVICE_TYPE, GET_IMAGE_MIRROR_CODE, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MIRROR_SEC CTL_CODE(SE7EN_DEVICE_TYPE, GET_IMAGE_SECTION_CODE, METHOD_BUFFERED, FILE_ANY_ACCESS)

#ifdef _KERNEL_MODE
#define WORD USHORT
#define PML4_INDEX(va) (((va) >> 39) & 0x1FF)  // 0x1FF = 511 in decimal 111111111.
#define PDPT_INDEX(va) (((va) >> 30) & 0x1FF)
#define PD_INDEX(va)   (((va) >> 21) & 0x1FF)
#define PT_INDEX(va)   (((va) >> 12) & 0X1FF) 

    typedef struct _MMVAD_SHORT {
        RTL_BALANCED_NODE   VadNode;        // offset 0x00       
        ULONG               StartingVpn;    // offset 0x18
        ULONG               EndingVpn;      // offset 0x1C
        UCHAR               StartingVpnHigh;// offset 0x20 
        UCHAR               EndingVpnHigh;  // offset 0x21
    } MMVAD_SHORT, * PMMVAD_SHORT;

    typedef struct _RTL_AVL_TREE {
        PRTL_BALANCED_NODE Root;   // direct pointer to root node, NULL if empty
    } RTL_AVL_TREE, * PRTL_AVL_TREE;

    typedef struct _VAD_REGION {
        ULONG64 StartVa;
        SIZE_T  Size;
        ULONG64 Offset;
    } VAD_REGION, * PVAD_REGION;

    typedef struct _VAD_CONTEXT {
        VAD_REGION* Regions;
        ULONG       Count;
        ULONG64     LowestVa;
        ULONG64     HighestVa;
    } VAD_CONTEXT;

    typedef struct _OFFSET_TABLE {
        ULONG BuildNumber;
        ULONG VadRootOffset;
        ULONG StartingVpnOffset;
        ULONG EndingVpnOffset;
        ULONG StartingVpnHighOffset;
        ULONG EndingVpnHighOffset;
        ULONG VadFlagsOffset;
    } OFFSET_TABLE;
    typedef struct _KGDTENTRY
    {
        WORD LimitLow;
        WORD BaseLow;
        ULONG HighWord;
    } KGDTENTRY, * PKGDTENTRY;
    typedef struct _KIDTENTRY
    {
        WORD Offset;
        WORD Selector;
        WORD Access;
        WORD ExtendedOffset;
    } KIDTENTRY, * PKIDTENTRY;
    typedef struct _KEXECUTE_OPTIONS
    {
        ULONG ExecuteDisable : 1;
        ULONG ExecuteEnable : 1;
        ULONG DisableThunkEmulation : 1;
        ULONG Permanent : 1;
        ULONG ExecuteDispatchEnable : 1;
        ULONG ImageDispatchEnable : 1;
        ULONG Spare : 2;
    } KEXECUTE_OPTIONS, * PKEXECUTE_OPTIONS;

    typedef struct _SEVEN_CONTEXT {
        // Target info
        ULONG           TargetPid;
        PEPROCESS       TargetProcess;   

        // Section mirror
        HANDLE          SectionHandle;
        PVOID           SectionBase;    
        SIZE_T          SectionSize;

        // VA layout from VAD walk
        ULONG64         ProcessBase;      
        ULONG64         ProcessTop;       

        // VAD region list (built during walk)
        PVAD_REGION     Regions;          
        ULONG           RegionCount;

        // Offset table (resolved at init from build number)
        OFFSET_TABLE    Offsets;

        // State
        BOOLEAN         Initialized;
        PDEVICE_OBJECT  DeviceObject;

    } SEVEN_CONTEXT, * PSEVEN_CONTEXT;

    typedef struct _KPROCESS
    {
        DISPATCHER_HEADER Header;
        LIST_ENTRY ProfileListHead;
        ULONG DirectoryTableBase;
        ULONG Unused0;
        KGDTENTRY LdtDescriptor;
        KIDTENTRY Int21Descriptor;
        WORD IopmOffset;
        UCHAR Iopl;
        UCHAR Unused;
        ULONG ActiveProcessors;
        ULONG KernelTime;
        ULONG UserTime;
        LIST_ENTRY ReadyListHead;
        SINGLE_LIST_ENTRY SwapListEntry;
        PVOID VdmTrapcHandler;
        LIST_ENTRY ThreadListHead;
        ULONG ProcessLock;
        ULONG Affinity;
#pragma warning(push)
#pragma warning(disable: 4201)  // nameless struct/union
        union UnioneOne
        {
            ULONG AutoAlignment : 1;
            ULONG DisableBoost : 1;
            ULONG DisableQuantum : 1;
            ULONG ReservedFlags : 29;
            LONG ProcessFlags;
        };
#pragma warning(pop)
        CHAR BasePriority;
        CHAR QuantumReset;
        UCHAR State;
        UCHAR ThreadSeed;
        UCHAR PowerState;
        UCHAR IdealNode;
        UCHAR Visited;
#pragma warning(push)
#pragma warning(disable: 4201)  // nameless struct/union
        union UnionTwo
        {
            KEXECUTE_OPTIONS Flags;
            UCHAR ExecuteOptions;
        };
#pragma warning(pop)
        ULONG StackCount;
        LIST_ENTRY ProcessListEntry;
        UINT64 CycleTime;
    } KPROCESS, * PKPROCESS;

#endif

typedef struct _SEC_VIEW {
    #ifdef _KERNEL_MODE
    PVOID ViewBase;
	SIZE_T ViewSize;
    #else
    PVOID ViewBase;
    SIZE_T ViewSize;
    #endif
} SEC_VIEW, * PSEC_VIEW;
typedef struct _INIT_MIRROR_SEC_BUFFER {
#ifdef _KERNEL_MODE
    ULONG ProcessId;
    USHORT Flag;
#else
    DWORD ProcessId;
    WORD Flag;
#endif
} INIT_MIRROR_SEC_BUFFER;
typedef struct _PROCESS_BASE_ADDRESS {
#ifdef _KERNEL_MODE
    ULONG ProcessId;
    PVOID BaseAddress;

#else
    DWORD ProcessId;
    PVOID BaseAddress;
#endif
} PROCESS_BASE_ADDRESS, * PPROCESS_BASE_ADDRESS;
