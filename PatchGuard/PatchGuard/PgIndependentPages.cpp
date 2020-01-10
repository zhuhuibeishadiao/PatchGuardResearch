#include "pch.h"

typedef struct _PG_IDDP_INFO
{
    SHORT BuildNumber;
    DWORD Valid;
    PMI_SYSTEM_PTE_TYPE SystemPteInfo;
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

void insert_sort(PVOID* R, int n)
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
                        /*if (!callback(MapAddress, PAGE_SIZE, context))
                            break;*/
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
    insert_sort(ptr, Count);
    
    for (i = 0; i < Count; i++)
    {
        if (ptr[i] && MmIsAddressValid(ptr[i]))
        {
            if (!callback(ptr[i], PAGE_SIZE, context))
                break;
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
