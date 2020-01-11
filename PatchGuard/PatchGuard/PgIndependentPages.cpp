#include "pch.h"

typedef struct _PG_IDDP_INFO
{
    SHORT BuildNumber;
    DWORD Valid;
    PMI_SYSTEM_PTE_TYPE SystemPteInfo;
    FNMiDeterminePoolType MiDeterminePoolType;
#ifdef _WIN64
    PMMPTE PxeBase;
    PMMPTE PxeTop;

    PMMPTE PpeBase;
    PMMPTE PpeTop;
#endif // _WIN64

    PMMPTE PdeBase;
    PMMPTE PdeTop;

    PMMPTE PteBase;
    PMMPTE PteTop;
    KDDEBUGGER_DATA64 DebuggerDataBlock;
}PG_IDDP_INFO, *PPG_IDDP_INFO;

#define IDDP_INFO_INIT_SUCCESS 0x8888

PG_IDDP_INFO g_Iddp = { 0 };

PMMPTE
NTAPI
GetPxeAddress(
    __in PVOID VirtualAddress
)
{
    return g_Iddp.PxeBase + MiGetPxeOffset(VirtualAddress);
}

PMMPTE
NTAPI
GetPpeAddress(
    __in PVOID VirtualAddress
)
{
    return (PMMPTE)
        (((((LONGLONG)VirtualAddress &
            VIRTUAL_ADDRESS_MASK) >> PPI_SHIFT) << PTE_SHIFT) + (LONGLONG)g_Iddp.PpeBase);
}

PMMPTE
NTAPI
GetPdeAddress(
    __in PVOID VirtualAddress
)
{
    return (PMMPTE)
        (((((LONGLONG)VirtualAddress &
            VIRTUAL_ADDRESS_MASK) >> PDI_SHIFT) << PTE_SHIFT) + (LONGLONG)g_Iddp.PdeBase);
}

PMMPTE
NTAPI
GetPteAddress(
    __in PVOID VirtualAddress
)
{
    return (PMMPTE)
        (((((LONGLONG)VirtualAddress &
            VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + (LONGLONG)g_Iddp.PteBase);
}

PVOID
NTAPI
GetVirtualAddressMappedByPte(
    __in PMMPTE Pte
)
{
    return (PVOID)((((LONGLONG)Pte - (LONGLONG)g_Iddp.PteBase) <<
        (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT);
}

PVOID
NTAPI
GetVirtualAddressMappedByPde(
    __in PMMPTE Pde
)
{
    return GetVirtualAddressMappedByPte((PMMPTE)GetVirtualAddressMappedByPte(Pde));
}

PVOID
NTAPI
GetVirtualAddressMappedByPpe(
    __in PMMPTE Ppe
)
{
    return GetVirtualAddressMappedByPte((PMMPTE)GetVirtualAddressMappedByPde(Ppe));
}

PVOID
NTAPI
GetVirtualAddressMappedByPxe(
    __in PMMPTE Pxe
)
{
    return GetVirtualAddressMappedByPde((PMMPTE)GetVirtualAddressMappedByPde(Pxe));
}

VOID PgIdpInitializeSystemSpace(
    __inout PPG_IDDP_INFO Block
)
{
    if (Block->BuildNumber > 10586) {
        Block->PteBase = (PMMPTE)Block->DebuggerDataBlock.PteBase;

        Block->PteTop = (PMMPTE)
            ((LONGLONG)Block->PteBase |
            (((((LONGLONG)1 << (VIRTUAL_ADDRESS_BITS + 1)) >> PTI_SHIFT) << PTE_SHIFT) - 1));

        Block->PdeBase = (PMMPTE)
            (((LONGLONG)Block->PteBase & ~(((LONGLONG)1 << (PHYSICAL_ADDRESS_BITS - 1)) - 1)) |
            (((LONGLONG)Block->PteBase >> 9) & (((LONGLONG)1 << (PHYSICAL_ADDRESS_BITS - 1)) - 1)));

        Block->PdeTop = (PMMPTE)
            ((LONGLONG)Block->PdeBase |
            (((((LONGLONG)1 << (VIRTUAL_ADDRESS_BITS + 1)) >> PDI_SHIFT) << PTE_SHIFT) - 1));

        Block->PpeBase = (PMMPTE)
            (((LONGLONG)Block->PdeBase & ~(((LONGLONG)1 << (PHYSICAL_ADDRESS_BITS - 1)) - 1)) |
            (((LONGLONG)Block->PdeBase >> 9) & (((LONGLONG)1 << (PHYSICAL_ADDRESS_BITS - 1)) - 1)));

        Block->PpeTop = (PMMPTE)
            ((LONGLONG)Block->PpeBase |
            (((((LONGLONG)1 << (VIRTUAL_ADDRESS_BITS + 1)) >> PPI_SHIFT) << PTE_SHIFT) - 1));

        Block->PxeBase = (PMMPTE)
            (((LONGLONG)Block->PpeBase & ~(((LONGLONG)1 << (PHYSICAL_ADDRESS_BITS - 1)) - 1)) |
            (((LONGLONG)Block->PpeBase >> 9) & (((LONGLONG)1 << (PHYSICAL_ADDRESS_BITS - 1)) - 1)));

        Block->PxeTop = (PMMPTE)
            ((LONGLONG)Block->PxeBase |
            (((((LONGLONG)1 << (VIRTUAL_ADDRESS_BITS + 1)) >> PXI_SHIFT) << PTE_SHIFT) - 1));
    }
    else {
        Block->PteBase = (PMMPTE)PTE_BASE;
        Block->PteTop = (PMMPTE)PTE_TOP;
        Block->PdeBase = (PMMPTE)PDE_BASE;
        Block->PdeTop = (PMMPTE)PDE_TOP;
        Block->PpeBase = (PMMPTE)PPE_BASE;
        Block->PpeTop = (PMMPTE)PPE_TOP;
        Block->PxeBase = (PMMPTE)PXE_BASE;
        Block->PxeTop = (PMMPTE)PXE_TOP;
    }
}

NTSTATUS PgIdpInitialization()
{
    CONTEXT context = { 0 };

    if (g_Iddp.Valid == IDDP_INFO_INIT_SUCCESS)
        return STATUS_SUCCESS;

    RtlZeroMemory(&g_Iddp, sizeof(PG_IDDP_INFO));

    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);

    PDUMP_HEADER dumpHeader = (PDUMP_HEADER)ExAllocatePoolWithTag(NonPagedPool, DUMP_BLOCK_SIZE, 'pmud');

    if (dumpHeader == NULL)
        return STATUS_NO_MEMORY;

    RtlZeroMemory(dumpHeader, DUMP_BLOCK_SIZE);

    KeCapturePersistentThreadState(&context, NULL, 0, 0, 0, 0, 0, dumpHeader);

    /*
    这里不能直接用dumpheader中的,在非调试模式是加密的
    反汇编KeCapturePersistentThreadState . KdpDataBlockEncoded引用的地方KdEncodeDataBlock
    */
    RtlCopyMemory(&g_Iddp.DebuggerDataBlock, (PUCHAR)dumpHeader + KDDEBUGGER_DATA_OFFSET, sizeof(g_Iddp.DebuggerDataBlock));

    g_Iddp.BuildNumber = (SHORT)dumpHeader->MinorVersion;

    //typedef struct _MI_VISIBLE_STATE                         // 26 elements, 0xC40 bytes (sizeof) 
        //{
        //    /*0x000*/     struct _MI_SPECIAL_POOL SpecialPool;                 // 4 elements, 0x40 bytes (sizeof)   
        //    /*0x040*/     struct _LIST_ENTRY SessionWsList;                    // 2 elements, 0x10 bytes (sizeof)   
        //    /*0x050*/     struct _RTL_BITMAP* SessionIdBitmap;
        //    /*0x058*/     struct _MM_PAGED_POOL_INFO PagedPoolInfo;            // 6 elements, 0x38 bytes (sizeof)   
        //    /*0x090*/     UINT64       MaximumNonPagedPoolInPages;
        //    /*0x098*/     UINT64       SizeOfPagedPoolInPages;
        //    /*0x0A0*/     struct _MI_SYSTEM_PTE_TYPE SystemPteInfo;            // 13 elements, 0x60 bytes (sizeof)  
        //                  ........................
        //    DebuggerDataBlock.MmPagedPoolCommit = &MiState->vs.PagedPoolInfo.AllocatedPagedPool((PCHAR)& +0x18 = struct _MI_SYSTEM_PTE_TYPE)  MiState is struct _MI_SYSTEM_INFORMATION
        //}MI_VISIBLE_STATE, *PMI_VISIBLE_STATE;
    if(g_Iddp.DebuggerDataBlock.MmPagedPoolCommit && MmIsAddressValid((PVOID)g_Iddp.DebuggerDataBlock.MmPagedPoolCommit))
        g_Iddp.SystemPteInfo = (PMI_SYSTEM_PTE_TYPE)(g_Iddp.DebuggerDataBlock.MmPagedPoolCommit + 0x18);
    else
    {
        UNICODE_STRING us = RTL_CONSTANT_STRING(L"MmAllocateMappingAddress");

        auto p = PgHelperGetUndocumentFunctionAddress(&us, NULL, (UCHAR*)"\x48\x8d\x0d", 3, 0x300, 0xcc, 3, TRUE);

        if (p != NULL && MmIsAddressValid(p))
        {
            g_Iddp.SystemPteInfo = (PMI_SYSTEM_PTE_TYPE)RvaToVa(p);
        }
        
        if (g_Iddp.SystemPteInfo == NULL || !MmIsAddressValid(g_Iddp.SystemPteInfo))
        {
            DPRINT("pte Initialization : SystemPteInfo is null.\r\n");
            ExFreePoolWithTag(dumpHeader, 'pmud');
            return STATUS_NOT_FOUND;
        }
    }

    g_Iddp.MiDeterminePoolType = (FNMiDeterminePoolType)0xfffff80119042830;
    PgIdpInitializeSystemSpace(&g_Iddp);

    ExFreePoolWithTag(dumpHeader, 'pmud');

    g_Iddp.Valid = IDDP_INFO_INIT_SUCCESS;

    return STATUS_SUCCESS;
}

BOOLEAN PgIdpMmIsAccessibleAddress(PVOID Address)
{
    auto pxe = GetPxeAddress(Address);

    if (!pxe->u.Hard.Valid)
        return false;

    auto ppe = GetPpeAddress(Address);

    if (!ppe->u.Hard.Valid)
        return false;

    auto pde = GetPdeAddress(Address);

    if (!pde->u.Hard.Valid)
        return false;

    auto pte = GetPteAddress(Address);

    if ((!pde->u.Hard.LargePage && (!pte || !pte->u.Hard.Valid)))
        return false;

    return true;
}

BOOLEAN PgIdpMmIsExecutebleAddress(PVOID Address)
{
    if (!PgIdpMmIsAccessibleAddress(Address))
        return false;

    auto pde = GetPdeAddress(Address);
    auto pte = GetPteAddress(Address);

    if (pde->u.Hard.NoExecute || (!pde->u.Hard.LargePage && (!pte || pte->u.Hard.NoExecute))) {
        return false;
    }

    return true;
}

void PgIdpInsertSort(PVOID* R, int n)
{
    int i, j;
    for (i = 1; i < n; i++)
    {
        auto t = R[i];

        for (j = i - 1; j >= 0 && t < R[j]; j--)
        {
            R[j + 1] = R[j];
        }

        R[j + 1] = t;
    }
}

NTSTATUS PgIdpEnumPhysicalMemory(ENUMPHYSICALCALLBACK callback, PVOID context)
{
    if (callback == NULL)
        return STATUS_INVALID_PARAMETER;

    auto PhysicalMemoryBlock = MmGetPhysicalMemoryRanges();

    if (PhysicalMemoryBlock == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    auto NumberOfPtes = g_Iddp.SystemPteInfo->Bitmap.SizeOfBitMap * 8;

    PVOID* ptr = (PVOID*)ExAllocatePoolWithTag(NonPagedPool, NumberOfPtes, 'pdig');

    if (ptr == NULL)
    {
        ExFreePool(PhysicalMemoryBlock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ptr, NumberOfPtes);
    auto Count = 0;

    auto i = 0;
    while (PhysicalMemoryBlock[i].NumberOfBytes.QuadPart != 0)
    {
        PHYSICAL_ADDRESS BaseAddress = PhysicalMemoryBlock[i].BaseAddress;
        LARGE_INTEGER NumberOfBytes = PhysicalMemoryBlock[i].NumberOfBytes;

        while (NumberOfBytes.QuadPart > 0)
        {
            auto MapAddress = MmGetVirtualForPhysical(BaseAddress);
            if (MapAddress && (ULONG_PTR)MapAddress > (ULONG_PTR)MmSystemRangeStart)
            {
                if (PgIdpMmIsExecutebleAddress(MapAddress))
                {
                    PVOID ImageBase = nullptr;

                    RtlPcToFileHeader(MapAddress, &ImageBase);

                    if (!ImageBase)
                    {
                        ptr[Count] = MapAddress;
                        Count++;
                    }
                }
            }

            BaseAddress.QuadPart += PAGE_SIZE;
            NumberOfBytes.QuadPart -= PAGE_SIZE;
        }
        i++;
    }

    ExFreePool(PhysicalMemoryBlock);
    PgIdpInsertSort(ptr, Count);
    
    for (i = 0; i < Count; i++)
    {
        if (ptr[i] && MmIsAddressValid(ptr[i]))
        {
            if (!callback(ptr[i], PAGE_SIZE, context))
                break;
            LOGF_DEBUG("%p    %p\r\n", ptr[i], GetPteAddress(ptr[i]));
        }
    }

    ExFreePoolWithTag(ptr, 'pdig');

    return STATUS_SUCCESS;
}

BOOLEAN PgIdpMemoryIsExist(PVOID* ptr, DWORD cbPtr, PVOID target)
{
    if (ptr == nullptr || cbPtr == 0 || target == nullptr)
        return false;

    for (size_t i = 0; i < cbPtr; i++)
    {
        if (ptr[i] == target)
            return true;
    }

    return false;
}

SIZE_T PgIdpGetMemorySize(PVOID* ptr, DWORD cbPtr, PVOID target, DWORD targetIndex, PVOID* lpBase, SIZE_T* lpsize)
{
    if (ptr == nullptr || cbPtr == 0 || target == nullptr || lpBase == nullptr || lpsize == nullptr)
        return 0;

    /*
    1909 offset:1bb44
    1903 offset:1b4f3
    1803 offset:1a2b1
    */

    //SIZE_T Fmax = 0x1f; // 0x1f * PAGE_SIZE = 0x1F000
    SIZE_T FMin = 0x10; // 0x10 * PAGE_SIZE = 0x10000
    PVOID base = nullptr;
    PVOID end = nullptr;

    for (size_t Fmax = 0x1e; Fmax > FMin; Fmax--)
    {
        auto p = (PVOID)((PCHAR)target - Fmax * PAGE_SIZE);

        if (PgIdpMemoryIsExist(ptr, cbPtr, p))
        {
            base = p;
            break;
        }
    }

    if (base == nullptr)
        return 0;

    for (size_t i = 0; i < cbPtr - targetIndex; i++)
    {
        auto p = (PVOID)((PCHAR)target + i * PAGE_SIZE);

        if (!PgIdpMemoryIsExist(ptr, cbPtr, p))
        {
            end = (PVOID)((PCHAR)p - PAGE_SIZE);
            break;
        }
    }

    SIZE_T size = (ULONG64)end - (ULONG64)base;

    if (size > 0x95000)
        size = 0x86000;

    *lpBase = base;
    *lpsize = size;

    return size;
}

NTSTATUS PgIdpEnumPhysicalMemoryEx(PPG_OPERATION_CALLBACKS callbacks, PVOID context)
{
    if (callbacks == NULL)
        return STATUS_INVALID_PARAMETER;

    auto PhysicalMemoryBlock = MmGetPhysicalMemoryRanges();

    if (PhysicalMemoryBlock == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    auto NumberOfPtes = g_Iddp.SystemPteInfo->Bitmap.SizeOfBitMap * 8;

    PVOID* ptr = (PVOID*)ExAllocatePoolWithTag(NonPagedPool, NumberOfPtes, 'pdig');

    if (ptr == NULL)
    {
        ExFreePool(PhysicalMemoryBlock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ptr, NumberOfPtes);
    auto Count = 0;

    auto i = 0;
    while (PhysicalMemoryBlock[i].NumberOfBytes.QuadPart != 0)
    {
        PHYSICAL_ADDRESS BaseAddress = PhysicalMemoryBlock[i].BaseAddress;
        LARGE_INTEGER NumberOfBytes = PhysicalMemoryBlock[i].NumberOfBytes;

        while (NumberOfBytes.QuadPart > 0)
        {
            auto MapAddress = MmGetVirtualForPhysical(BaseAddress);
            if (MapAddress && (ULONG_PTR)MapAddress > (ULONG_PTR)MmSystemRangeStart)
            {
                if (PgIdpMmIsExecutebleAddress(MapAddress))
                {
                    PVOID ImageBase = nullptr;

                    RtlPcToFileHeader(MapAddress, &ImageBase);

                    if (!ImageBase)
                    {
                        ptr[Count] = MapAddress;
                        Count++;
                    }
                }
            }

            BaseAddress.QuadPart += PAGE_SIZE;
            NumberOfBytes.QuadPart -= PAGE_SIZE;
        }
        i++;
    }

    ExFreePool(PhysicalMemoryBlock);
    PgIdpInsertSort(ptr, Count);

    for (i = 0; i < Count; i++)
    {
        if (ptr[i] && MmIsAddressValid(ptr[i]))
        {
            PVOID PostContext = nullptr;
            auto pgStatus = callbacks->PreCallBack(ptr[i], PAGE_SIZE, context, &PostContext);

            if (pgStatus == PG_PREOP_CALL_POST_AND_FIND_SIZE)
            {
                SIZE_T size = 0;
                PVOID base = nullptr;
                PgIdpGetMemorySize(ptr, Count, ptr[i], i, &base, &size);

                auto poolType = g_Iddp.MiDeterminePoolType(ptr[i]);

                LOGF_DEBUG("base:%p    size:%p    type:%d\r\n", base, size, poolType);

                if (size == 0 || base == nullptr)
                    continue;

                if (!callbacks->PostCallBack(base, size, context, PostContext))
                    break;
            }
        }
    }

    ExFreePoolWithTag(ptr, 'pdig');

    return STATUS_SUCCESS;
}

SIZE_T PgIdpGetPhysicalMemoryBlockSize(PVOID Va)
{
    if (Va == NULL)
        return 0;

    if (!MmIsAddressValid(Va))
        return 0;

    if (MmGetPhysicalAddress(Va).QuadPart == 0)
        return 0;

    if (!PgIdpMmIsAccessibleAddress(Va))
        return 0;

    PCHAR p = nullptr;

    size_t i = 0;

    for (i = 0; i < 0x95; i++)
    {
        p = (PCHAR)Va + PAGE_SIZE * i;

        if (!MmIsAddressValid(p))
            break;

        auto phy = MmGetPhysicalAddress(p);

        if (phy.QuadPart == 0)
            break;

        if (!PgIdpMmIsAccessibleAddress(p))
            break;
    }

    if (i == 0)
        return 0;

    return i * PAGE_SIZE;
}

VOID
NTAPI
PgIdpInitializeSystemPtesBitMap(
    __inout PMMPTE BasePte,
    __in PFN_NUMBER NumberOfPtes,
    __out PRTL_BITMAP BitMap
)
{
    /*PMMPTE PointerPxe = NULL;
    PMMPTE PointerPpe = NULL;
    PMMPTE PointerPde = NULL;
    PMMPTE PointerPte = NULL;*/
    PVOID PointerAddress = NULL;
    ULONG BitNumber = 0;
    PVOID BeginAddress = NULL;
    PVOID EndAddress = NULL;

    /*
    PatchGuard Context pages allocate by MmAllocateIndependentPages
    PTE field like this
    nt!_MMPTE
    [+0x000] Long             : 0x2da963 [Type: unsigned __int64]
    [+0x000] VolatileLong     : 0x2da963 [Type: unsigned __int64]
    [+0x000] Hard             [Type: _MMPTE_HARDWARE]
    [+0x000 ( 0: 0)] Valid            : 0x1     [Type: unsigned __int64] <- MM_PTE_VALID_MASK
    [+0x000 ( 1: 1)] Dirty1           : 0x1     [Type: unsigned __int64] <- MM_PTE_DIRTY_MASK
    [+0x000 ( 2: 2)] Owner            : 0x0     [Type: unsigned __int64]
    [+0x000 ( 3: 3)] WriteThrough     : 0x0     [Type: unsigned __int64]
    [+0x000 ( 4: 4)] CacheDisable     : 0x0     [Type: unsigned __int64]
    [+0x000 ( 5: 5)] Accessed         : 0x1     [Type: unsigned __int64] <- MM_PTE_ACCESS_MASK
    [+0x000 ( 6: 6)] Dirty            : 0x1     [Type: unsigned __int64] <- MM_PTE_DIRTY_MASK
    [+0x000 ( 7: 7)] LargePage        : 0x0     [Type: unsigned __int64]
    [+0x000 ( 8: 8)] Global           : 0x1     [Type: unsigned __int64] <- MM_PTE_GLOBAL_MASK
    [+0x000 ( 9: 9)] CopyOnWrite      : 0x0     [Type: unsigned __int64]
    [+0x000 (10:10)] Unused           : 0x0     [Type: unsigned __int64]
    [+0x000 (11:11)] Write            : 0x1     [Type: unsigned __int64] <- MM_PTE_WRITE_MASK
    [+0x000 (47:12)] PageFrameNumber  : 0x2da   [Type: unsigned __int64] <- pfndata index
    [+0x000 (51:48)] reserved1        : 0x0     [Type: unsigned __int64]
    [+0x000 (62:52)] SoftwareWsIndex  : 0x0     [Type: unsigned __int64]
    [+0x000 (63:63)] NoExecute        : 0x0     [Type: unsigned __int64] <- page can executable
    [+0x000] Flush            [Type: _HARDWARE_PTE]
    [+0x000] Proto            [Type: _MMPTE_PROTOTYPE]
    [+0x000] Soft             [Type: _MMPTE_SOFTWARE]
    [+0x000] TimeStamp        [Type: _MMPTE_TIMESTAMP]
    [+0x000] Trans            [Type: _MMPTE_TRANSITION]
    [+0x000] Subsect          [Type: _MMPTE_SUBSECTION]
    [+0x000] List             [Type: _MMPTE_LIST]
    */

#define VALID_PTE_SET_BITS \
            ( MM_PTE_VALID_MASK | MM_PTE_DIRTY_MASK | MM_PTE_WRITE_MASK | MM_PTE_ACCESS_MASK)

#define VALID_PTE_UNSET_BITS \
            ( MM_PTE_WRITE_THROUGH_MASK | MM_PTE_CACHE_DISABLE_MASK | MM_PTE_COPY_ON_WRITE_MASK )

    BeginAddress = GetVirtualAddressMappedByPte(BasePte);
    EndAddress = GetVirtualAddressMappedByPte(BasePte + NumberOfPtes);
    DPRINT("bit:%p    ~    %p\n", BeginAddress, EndAddress);

    PointerAddress = BeginAddress;
    //DbgBreakPoint();

    do {

        auto pte = GetPteAddress(PointerAddress);

        if (PgIdpMmIsAccessibleAddress(PointerAddress))
        {
            pte = GetPteAddress(PointerAddress);

            if (pte->u.Hard.Valid)
            {
                BitNumber = (ULONG)(pte - BasePte);
                RtlSetBit(BitMap, BitNumber);
                //DbgBreakPoint();
            }

            PointerAddress = GetVirtualAddressMappedByPte(pte + 1);

        }
        else
        {
            PointerAddress = GetVirtualAddressMappedByPte(pte + 1);
        }

    } while ((ULONG_PTR)PointerAddress < (ULONG_PTR)EndAddress);
}

NTSTATUS PgIdpEnumIndependentPages(ENUMMEMORYCALLBACK callback, PVOID context)
{
    auto status = STATUS_SUCCESS;

    if (g_Iddp.Valid != IDDP_INFO_INIT_SUCCESS)
    {
        status = PgIdpInitialization();

        if (!NT_SUCCESS(status))
            return status;
    }

    PRTL_BITMAP BitMap = NULL;
    ULONG BitMapSize = 0;
    PFN_NUMBER NumberOfPtes = 0;
    ULONG HintIndex = 0;
    ULONG StartingRunIndex = 0;

    NumberOfPtes = g_Iddp.SystemPteInfo->Bitmap.SizeOfBitMap * 8;

    BitMapSize =
        sizeof(RTL_BITMAP) + (ULONG)((((NumberOfPtes + 1) + 31) / 32) * 4);

    BitMap = (PRTL_BITMAP)ExAllocatePool(NonPagedPool, BitMapSize);

    if (NULL != BitMap) {
        RtlInitializeBitMap(
            BitMap,
            (PULONG)(BitMap + 1),
            (ULONG)(NumberOfPtes + 1));

        RtlClearAllBits(BitMap);

        PgIdpInitializeSystemPtesBitMap(
            g_Iddp.SystemPteInfo->BasePte,
            NumberOfPtes,
            BitMap);

        do {
            HintIndex = RtlFindSetBits(
                BitMap,
                1,
                HintIndex);

            if (MAXULONG != HintIndex) {
                RtlFindNextForwardRunClear(
                    BitMap,
                    HintIndex,
                    &StartingRunIndex);

                RtlClearBits(BitMap, HintIndex, StartingRunIndex - HintIndex);

                //if (StartingRunIndex -
                //    HintIndex >= BYTES_TO_PAGES(PgBlock->SizeINITKDBG)) {

                //    /*PgCompareFields(
                //        PgBlock,
                //        PgSystemPtes,
                //        GetVirtualAddressMappedByPte(PgBlock->BasePte + HintIndex),
                //        (StartingRunIndex - HintIndex) * PAGE_SIZE);*/
                //        //ULONG RegionSize = (StartingRunIndex - HintIndex) * PAGE_SIZE;

                //    DPRINT("%p    0x%x    0x%x    0x%x\n", GetVirtualAddressMappedByPte(PgBlock->PteSystem->BasePte + HintIndex), (StartingRunIndex - HintIndex) * PAGE_SIZE, StartingRunIndex, HintIndex);
                //}

                /*if (!callback(TRUE, GetVirtualAddressMappedByPte(g_Iddp.SystemPteInfo->BasePte + HintIndex), (StartingRunIndex - HintIndex) * PAGE_SIZE, (PUCHAR)'pddi', context))
                    break;*/

                auto p = GetVirtualAddressMappedByPte(g_Iddp.SystemPteInfo->BasePte + HintIndex);
                size_t size = (StartingRunIndex - HintIndex) * PAGE_SIZE;
                DPRINT("%p    0x%p\n", p, size);

                /*if (MmIsAddressValid(p) || MmIsAddressValid((PCHAR)p + size - 1))
                {
                    if (!callback(true, p, size, (PUCHAR)'pddi', context))
                        break;
                }*/

                if (PgIdpMmIsAccessibleAddress(p) && PgIdpMmIsAccessibleAddress((PCHAR)p + size - PAGE_SIZE))
                {
                    if (!callback(true, p, size, (PUCHAR)'pddi', context))
                        break;
                }

                HintIndex = StartingRunIndex;
            }
        } while (HintIndex < NumberOfPtes);

        ExFreePool(BitMap);

        //DbgBreakPoint();

        return STATUS_SUCCESS;
    }

    return STATUS_NO_MEMORY;
}
