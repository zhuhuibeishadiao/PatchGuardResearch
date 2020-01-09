#ifndef _PG_STRUCT_H_
#define _PG_STRUCT_H_

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

typedef struct _SYSTEM_POOL_INFO
{
    union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
}SYSTEM_POOL_INFO, *PSYSTEM_POOL_INFO;

#define PXE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PDE_PER_PAGE 512
#define PTE_PER_PAGE 512
#define PTE_PER_PAGE_BITS 10    // This handles the case where the page is full

#if PTE_PER_PAGE_BITS > 32
error - too many bits to fit into MMPTE_SOFTWARE or MMPFN.u1
#endif

typedef struct _MMPTE_SOFTWARE {
    ULONGLONG Valid : 1;
    ULONGLONG PageFileLow : 4;
    ULONGLONG Protection : 5;
    ULONGLONG Prototype : 1;
    ULONGLONG Transition : 1;
    ULONGLONG UsedPageTableEntries : PTE_PER_PAGE_BITS;
    ULONGLONG Reserved : 20 - PTE_PER_PAGE_BITS;
    ULONGLONG PageFileHigh : 32;
} MMPTE_SOFTWARE;

typedef struct _MMPTE_TRANSITION {
    ULONGLONG Valid : 1;
    ULONGLONG Write : 1;
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Protection : 5;
    ULONGLONG Prototype : 1;
    ULONGLONG Transition : 1;
    ULONGLONG PageFrameNumber : 28;
    ULONGLONG Unused : 24;
} MMPTE_TRANSITION;

typedef struct _MMPTE_PROTOTYPE {
    ULONGLONG Valid : 1;
    ULONGLONG Unused0 : 7;
    ULONGLONG ReadOnly : 1;
    ULONGLONG Unused1 : 1;
    ULONGLONG Prototype : 1;
    ULONGLONG Protection : 5;
    LONGLONG ProtoAddress : 48;
} MMPTE_PROTOTYPE;

typedef struct _MMPTE_SUBSECTION {
    ULONGLONG Valid : 1;
    ULONGLONG Unused0 : 4;
    ULONGLONG Protection : 5;
    ULONGLONG Prototype : 1;
    ULONGLONG Unused1 : 5;
    LONGLONG SubsectionAddress : 48;
} MMPTE_SUBSECTION;

typedef struct _MMPTE_LIST {
    ULONGLONG Valid : 1;
    ULONGLONG OneEntry : 1;
    ULONGLONG filler0 : 3;

    //
    // Note the Prototype bit must not be used for lists like freed nonpaged
    // pool because lookaside pops can legitimately reference bogus addresses
    // (since the pop is unsynchronized) and the fault handler must be able to
    // distinguish lists from protos so a retry status can be returned (vs a
    // fatal bugcheck).
    //
    // The same caveat applies to both the Transition and the Protection
    // fields as they are similarly examined in the fault handler and would
    // be misinterpreted if ever nonzero in the freed nonpaged pool chains.
    //

    ULONGLONG Protection : 5;
    ULONGLONG Prototype : 1;        // MUST BE ZERO as per above comment.
    ULONGLONG Transition : 1;

    ULONGLONG filler1 : 20;
    ULONGLONG NextEntry : 32;
} MMPTE_LIST;

typedef struct _MMPTE_HIGHLOW {
    ULONG LowPart;
    ULONG HighPart;
} MMPTE_HIGHLOW;


typedef struct _MMPTE_HARDWARE_LARGEPAGE {
    ULONGLONG Valid : 1;
    ULONGLONG Write : 1;
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Accessed : 1;
    ULONGLONG Dirty : 1;
    ULONGLONG LargePage : 1;
    ULONGLONG Global : 1;
    ULONGLONG CopyOnWrite : 1; // software field
    ULONGLONG Prototype : 1;   // software field
    ULONGLONG reserved0 : 1;   // software field
    ULONGLONG PAT : 1;
    ULONGLONG reserved1 : 8;   // software field
    ULONGLONG PageFrameNumber : 19;
    ULONGLONG reserved2 : 24;   // software field
} MMPTE_HARDWARE_LARGEPAGE, *PMMPTE_HARDWARE_LARGEPAGE;

//
// A Page Table Entry on AMD64 has the following definition.
// Note the MP version is to avoid stalls when flushing TBs across processors.
//

//
// Uniprocessor version.
//

#define _HARDWARE_PTE_WORKING_SET_BITS  11

typedef struct _HARDWARE_PTE {
    ULONG64 Valid : 1;
    ULONG64 Write : 1;                // UP version
    ULONG64 Owner : 1;
    ULONG64 WriteThrough : 1;
    ULONG64 CacheDisable : 1;
    ULONG64 Accessed : 1;
    ULONG64 Dirty : 1;
    ULONG64 LargePage : 1;
    ULONG64 Global : 1;
    ULONG64 CopyOnWrite : 1;          // software field
    ULONG64 Prototype : 1;            // software field
    ULONG64 reserved0 : 1;            // software field
    ULONG64 PageFrameNumber : 28;
    ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS + 1);
    ULONG64 SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
    ULONG64 NoExecute : 1;
} HARDWARE_PTE, *PHARDWARE_PTE;

typedef struct _MMPTE_HARDWARE {
    ULONGLONG Valid : 1;
#if defined(NT_UP)
    ULONGLONG Write : 1;        // UP version
#else
    ULONGLONG Writable : 1;        // changed for MP version
#endif
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Accessed : 1;
    ULONGLONG Dirty : 1;
    ULONGLONG LargePage : 1;
    ULONGLONG Global : 1;
    ULONGLONG CopyOnWrite : 1; // software field
    ULONGLONG Prototype : 1;   // software field
#if defined(NT_UP)
    ULONGLONG reserved0 : 1;  // software field
#else
    ULONGLONG Write : 1;       // software field - MP change
#endif
    ULONGLONG PageFrameNumber : 28;
    ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS + 1);
    ULONGLONG SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
    ULONG64 NoExecute : 1;
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;

typedef struct _MMPTE {
    union {
        ULONG_PTR Long;
        MMPTE_HARDWARE Hard;
        MMPTE_HARDWARE_LARGEPAGE HardLarge;
        HARDWARE_PTE Flush;
        MMPTE_PROTOTYPE Proto;
        MMPTE_SOFTWARE Soft;
        MMPTE_TRANSITION Trans;
        MMPTE_SUBSECTION Subsect;
        MMPTE_LIST List;
    } u;
} MMPTE;

typedef MMPTE *PMMPTE;

typedef struct _MI_SYSTEM_PTE_TYPE
{
    RTL_BITMAP Bitmap;
    PMMPTE BasePte;
}MI_SYSTEM_PTE_TYPE, *PMI_SYSTEM_PTE_TYPE;

#define PTE_PER_PAGE 512
#define PDE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PXE_PER_PAGE 512

#define PPI_MASK (PPE_PER_PAGE - 1)
#define PXI_MASK (PXE_PER_PAGE - 1)

#ifndef PTE_SHIFT
#define PTE_SHIFT 3
#endif
#ifndef PTI_SHIFT
#define PTI_SHIFT 12
#endif
#ifndef PDI_SHIFT
#define PDI_SHIFT 21
#endif
#ifndef PPI_SHIFT
#define PPI_SHIFT 30
#endif
#ifndef PXI_SHIFT
#define PXI_SHIFT 39
#endif

#define MM_PTE_VALID_MASK         0x1
#define MM_PTE_WRITE_MASK         0x800
#define MM_PTE_OWNER_MASK         0x4
#define MM_PTE_WRITE_THROUGH_MASK 0x8
#define MM_PTE_CACHE_DISABLE_MASK 0x10
#define MM_PTE_ACCESS_MASK        0x20
#define MM_PTE_DIRTY_MASK         0x42
#define MM_PTE_LARGE_PAGE_MASK    0x80
#define MM_PTE_GLOBAL_MASK        0x100
#define MM_PTE_COPY_ON_WRITE_MASK 0x200
#define MM_PTE_PROTOTYPE_MASK     0x400
#define MM_PTE_TRANSITION_MASK    0x800

#define MiGetPxeOffset(va) \
    ((ULONG)(((ULONG_PTR)(va) >> PXI_SHIFT) & PXI_MASK))

#define MiGetPxeAddress(va)   \
    ((PMMPTE)PXE_BASE + MiGetPxeOffset(va))

#define MiGetPpeAddress(va)   \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PPI_SHIFT) << PTE_SHIFT) + PPE_BASE))

#define MiGetPdeAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) << PTE_SHIFT) + PDE_BASE))

#define MiGetPteAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + PTE_BASE))

#define VA_SHIFT (63 - 47)              // address sign extend shift count

#define MiGetVirtualAddressMappedByPte(PTE) \
    ((PVOID)((LONG_PTR)(((LONG_PTR)(PTE) - PTE_BASE) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT))

#define MI_IS_PHYSICAL_ADDRESS(Va) \
    ((MiGetPxeAddress(Va)->u.Hard.Valid == 1) && \
     (MiGetPpeAddress(Va)->u.Hard.Valid == 1) && \
     ((MiGetPdeAddress(Va)->u.Long & 0x81) == 0x81) || (MiGetPteAddress(Va)->u.Hard.Valid == 1))

#ifndef PXE_BASE
#define PXE_BASE    0xFFFFF6FB7DBED000UI64
#endif
#ifndef PXE_SELFMAP
#define PXE_SELFMAP 0xFFFFF6FB7DBEDF68UI64
#endif
#ifndef PPE_BASE
#define PPE_BASE    0xFFFFF6FB7DA00000UI64
#endif
#ifndef PDE_BASE
#define PDE_BASE    0xFFFFF6FB40000000UI64
#endif
#ifndef PTE_BASE
#define PTE_BASE    0xFFFFF68000000000UI64
#endif

#define PXE_TOP           0xFFFFF6FB7DBEDFFFUI64
#define PPE_TOP           0xFFFFF6FB7DBFFFFFUI64
#define PDE_TOP           0xFFFFF6FB7FFFFFFFUI64
#define PTE_TOP           0xFFFFF6FFFFFFFFFFUI64

#define PHYSICAL_ADDRESS_BITS 40

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)

#ifndef _WIN64
#define DUMP_BLOCK_SIZE 0x20000
#else
#define DUMP_BLOCK_SIZE 0x40000
#endif // !_WIN64

//
// DO NOT ADD OR REMOVE FIELDS FROM THE MIDDLE OF THIS STRUCTURE!!!
//
// If you remove a field, replace it with an "unused" placeholder.
// Do not reuse fields until there has been enough time for old debuggers
// and extensions to age out.
//

    //
// This structure is used by the debugger for all targets
// It is the same size as DBGKD_DATA_HEADER on all systems
//
typedef struct _DBGKD_DEBUG_DATA_HEADER64 {

    //
    // Link to other blocks
    //

    LIST_ENTRY64 List;

    //
    // This is a unique tag to identify the owner of the block.
    // If your component only uses one pool tag, use it for this, too.
    //

    ULONG           OwnerTag;

    //
    // This must be initialized to the size of the data block,
    // including this structure.
    //

    ULONG           Size;

} DBGKD_DEBUG_DATA_HEADER64, *PDBGKD_DEBUG_DATA_HEADER64;


typedef struct _KDDEBUGGER_DATA64 {

    DBGKD_DEBUG_DATA_HEADER64 Header;

    //
    // Base address of kernel image
    //

    ULONG64   KernBase;

    //
    // DbgBreakPointWithStatus is a function which takes an argument
    // and hits a breakpoint.  This field contains the address of the
    // breakpoint instruction.  When the debugger sees a breakpoint
    // at this address, it may retrieve the argument from the first
    // argument register, or on x86 the eax register.
    //

    ULONG64   BreakpointWithStatus;       // address of breakpoint

    //
    // Address of the saved context record during a bugcheck
    //
    // N.B. This is an automatic in KeBugcheckEx's frame, and
    // is only valid after a bugcheck.
    //

    ULONG64   SavedContext;

    //
    // help for walking stacks with user callbacks:
    //

    //
    // The address of the thread structure is provided in the
    // WAIT_STATE_CHANGE packet.  This is the offset from the base of
    // the thread structure to the pointer to the kernel stack frame
    // for the currently active usermode callback.
    //

    USHORT  ThCallbackStack;            // offset in thread data

    //
    // these values are offsets into that frame:
    //

    USHORT  NextCallback;               // saved pointer to next callback frame
    USHORT  FramePointer;               // saved frame pointer

    //
    // pad to a quad boundary
    //
    USHORT  PaeEnabled;

    //
    // Address of the kernel callout routine.
    //

    ULONG64   KiCallUserMode;             // kernel routine

    //
    // Address of the usermode entry point for callbacks.
    //

    ULONG64   KeUserCallbackDispatcher;   // address in ntdll


    //
    // Addresses of various kernel data structures and lists
    // that are of interest to the kernel debugger.
    //

    ULONG64   PsLoadedModuleList;
    ULONG64   PsActiveProcessHead;
    ULONG64   PspCidTable;

    ULONG64   ExpSystemResourcesList;
    ULONG64   ExpPagedPoolDescriptor;
    ULONG64   ExpNumberOfPagedPools;

    ULONG64   KeTimeIncrement;
    ULONG64   KeBugCheckCallbackListHead;
    ULONG64   KiBugcheckData;

    ULONG64   IopErrorLogListHead;

    ULONG64   ObpRootDirectoryObject;
    ULONG64   ObpTypeObjectType;

    ULONG64   MmSystemCacheStart;
    ULONG64   MmSystemCacheEnd;
    ULONG64   MmSystemCacheWs;

    ULONG64   MmPfnDatabase;
    ULONG64   MmSystemPtesStart;
    ULONG64   MmSystemPtesEnd;
    ULONG64   MmSubsectionBase;
    ULONG64   MmNumberOfPagingFiles;

    ULONG64   MmLowestPhysicalPage;
    ULONG64   MmHighestPhysicalPage;
    ULONG64   MmNumberOfPhysicalPages;

    ULONG64   MmMaximumNonPagedPoolInBytes;
    ULONG64   MmNonPagedSystemStart;
    ULONG64   MmNonPagedPoolStart;
    ULONG64   MmNonPagedPoolEnd;

    ULONG64   MmPagedPoolStart;
    ULONG64   MmPagedPoolEnd;
    ULONG64   MmPagedPoolInformation;
    ULONG64   MmPageSize;

    ULONG64   MmSizeOfPagedPoolInBytes;

    ULONG64   MmTotalCommitLimit;
    ULONG64   MmTotalCommittedPages;
    ULONG64   MmSharedCommit;
    ULONG64   MmDriverCommit;
    ULONG64   MmProcessCommit;
    ULONG64   MmPagedPoolCommit;
    ULONG64   MmExtendedCommit;

    ULONG64   MmZeroedPageListHead;
    ULONG64   MmFreePageListHead;
    ULONG64   MmStandbyPageListHead;
    ULONG64   MmModifiedPageListHead;
    ULONG64   MmModifiedNoWritePageListHead;
    ULONG64   MmAvailablePages;
    ULONG64   MmResidentAvailablePages;

    ULONG64   PoolTrackTable;
    ULONG64   NonPagedPoolDescriptor;

    ULONG64   MmHighestUserAddress;
    ULONG64   MmSystemRangeStart;
    ULONG64   MmUserProbeAddress;

    ULONG64   KdPrintCircularBuffer;
    ULONG64   KdPrintCircularBufferEnd;
    ULONG64   KdPrintWritePointer;
    ULONG64   KdPrintRolloverCount;

    ULONG64   MmLoadedUserImageList;

    // NT 5.1 Addition

    ULONG64   NtBuildLab;
    ULONG64   KiNormalSystemCall;

    // NT 5.0 hotfix addition

    ULONG64   KiProcessorBlock;
    ULONG64   MmUnloadedDrivers;
    ULONG64   MmLastUnloadedDriver;
    ULONG64   MmTriageActionTaken;
    ULONG64   MmSpecialPoolTag;
    ULONG64   KernelVerifier;
    ULONG64   MmVerifierData;
    ULONG64   MmAllocatedNonPagedPool;
    ULONG64   MmPeakCommitment;
    ULONG64   MmTotalCommitLimitMaximum;
    ULONG64   CmNtCSDVersion;

    // NT 5.1 Addition

    ULONG64   MmPhysicalMemoryBlock;
    ULONG64   MmSessionBase;
    ULONG64   MmSessionSize;
    ULONG64   MmSystemParentTablePage;

    // Server 2003 addition

    ULONG64   MmVirtualTranslationBase;

    USHORT    OffsetKThreadNextProcessor;
    USHORT    OffsetKThreadTeb;
    USHORT    OffsetKThreadKernelStack;
    USHORT    OffsetKThreadInitialStack;

    USHORT    OffsetKThreadApcProcess;
    USHORT    OffsetKThreadState;
    USHORT    OffsetKThreadBStore;
    USHORT    OffsetKThreadBStoreLimit;

    USHORT    SizeEProcess;
    USHORT    OffsetEprocessPeb;
    USHORT    OffsetEprocessParentCID;
    USHORT    OffsetEprocessDirectoryTableBase;

    USHORT    SizePrcb;
    USHORT    OffsetPrcbDpcRoutine;
    USHORT    OffsetPrcbCurrentThread;
    USHORT    OffsetPrcbMhz;

    USHORT    OffsetPrcbCpuType;
    USHORT    OffsetPrcbVendorString;
    USHORT    OffsetPrcbProcStateContext;
    USHORT    OffsetPrcbNumber;

    USHORT    SizeEThread;

    ULONG64   KdPrintCircularBufferPtr;
    ULONG64   KdPrintBufferSize;

    ULONG64   KeLoaderBlock;

    USHORT    SizePcr;
    USHORT    OffsetPcrSelfPcr;
    USHORT    OffsetPcrCurrentPrcb;
    USHORT    OffsetPcrContainedPrcb;

    USHORT    OffsetPcrInitialBStore;
    USHORT    OffsetPcrBStoreLimit;
    USHORT    OffsetPcrInitialStack;
    USHORT    OffsetPcrStackLimit;

    USHORT    OffsetPrcbPcrPage;
    USHORT    OffsetPrcbProcStateSpecialReg;
    USHORT    GdtR0Code;
    USHORT    GdtR0Data;

    USHORT    GdtR0Pcr;
    USHORT    GdtR3Code;
    USHORT    GdtR3Data;
    USHORT    GdtR3Teb;

    USHORT    GdtLdt;
    USHORT    GdtTss;
    USHORT    Gdt64R3CmCode;
    USHORT    Gdt64R3CmTeb;

    ULONG64   IopNumTriageDumpDataBlocks;
    ULONG64   IopTriageDumpDataBlocks;

    // Longhorn addition

    ULONG64   VfCrashDataBlock;
    ULONG64   MmBadPagesDetected;
    ULONG64   MmZeroedPageSingleBitErrorsDetected;

    // Windows 7 addition

    ULONG64   EtwpDebuggerData;
    USHORT    OffsetPrcbContext;

    // Windows 8 addition

    USHORT    OffsetPrcbMaxBreakpoints;
    USHORT    OffsetPrcbMaxWatchpoints;

    ULONG     OffsetKThreadStackLimit;
    ULONG     OffsetKThreadStackBase;
    ULONG     OffsetKThreadQueueListEntry;
    ULONG     OffsetEThreadIrpList;

    USHORT    OffsetPrcbIdleThread;
    USHORT    OffsetPrcbNormalDpcState;
    USHORT    OffsetPrcbDpcStack;
    USHORT    OffsetPrcbIsrStack;

    USHORT    SizeKDPC_STACK_FRAME;

    // Windows 8.1 Addition

    USHORT    OffsetKPriQueueThreadListHead;
    USHORT    OffsetKThreadWaitReason;

    // Windows 10 RS1 Addition

    USHORT    Padding;
    ULONG64   PteBase;

    // Windows 10 RS5 Addition

    ULONG64 RetpolineStubFunctionTable;
    ULONG RetpolineStubFunctionTableSize;
    ULONG RetpolineStubOffset;
    ULONG RetpolineStubSize;

} KDDEBUGGER_DATA64, *PKDDEBUGGER_DATA64;

typedef struct _DUMP_HEADER {
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG_PTR DirectoryTableBase;
    ULONG_PTR PfnDataBase;
    PLIST_ENTRY PsLoadedModuleList;
    PLIST_ENTRY PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG NumberProcessors;
    ULONG BugCheckCode;
    ULONG_PTR BugCheckParameter1;
    ULONG_PTR BugCheckParameter2;
    ULONG_PTR BugCheckParameter3;
    ULONG_PTR BugCheckParameter4;
    CHAR VersionUser[32];

#ifndef _WIN64
    ULONG PaeEnabled;
#endif // !_WIN64

    struct _KDDEBUGGER_DATA64 * KdDebuggerDataBlock;
} DUMP_HEADER, *PDUMP_HEADER;

#ifndef _WIN64
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, Signature) == 0);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, ValidDump) == 4);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, MajorVersion) == 8);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, MinorVersion) == 0xc);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, DirectoryTableBase) == 0x10);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, PfnDataBase) == 0x14);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, PsLoadedModuleList) == 0x18);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, PsActiveProcessHead) == 0x1c);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, MachineImageType) == 0x20);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, NumberProcessors) == 0x24);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckCode) == 0x28);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter1) == 0x2c);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter2) == 0x30);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter3) == 0x34);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter4) == 0x38);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, PaeEnabled) == 92);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, KdDebuggerDataBlock) == 96);
#else
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, Signature) == 0);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, ValidDump) == 4);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, MajorVersion) == 8);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, MinorVersion) == 0xc);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, DirectoryTableBase) == 0x10);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, PfnDataBase) == 0x18);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, PsLoadedModuleList) == 0x20);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, PsActiveProcessHead) == 0x28);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, MachineImageType) == 0x30);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, NumberProcessors) == 0x34);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckCode) == 0x38);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter1) == 0x40);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter2) == 0x48);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter3) == 0x50);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter4) == 0x58);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, KdDebuggerDataBlock) == 0x80);
#endif // !_WIN64

#ifndef _WIN64
#define KDDEBUGGER_DATA_OFFSET 0x1068
#else
#define KDDEBUGGER_DATA_OFFSET 0x2080
#endif // !_WIN64

#endif