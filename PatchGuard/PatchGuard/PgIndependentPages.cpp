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
    if (g_Iddp.DebuggerDataBlock.MmPagedPoolCommit && MmIsAddressValid((PVOID)g_Iddp.DebuggerDataBlock.MmPagedPoolCommit))
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

    PUCHAR ptr = nullptr;
    PgHelperScanSection(".text", PgHelperGetNtosBase(), (UCHAR*)"\xb8\x21\x00\x00\x00\xeb", 6, 0xcc, 0, (PVOID*)&ptr);

    if (ptr == nullptr)
        PgHelperScanSection(".text", PgHelperGetNtosBase(), (UCHAR*)"\xb8\x21\x00\x00\x00\xc3", 6, 0xcc, 0, (PVOID*)&ptr);

    if (ptr == nullptr)
    {
        DPRINT("Get MiDeterminePoolType faild.\n");
        ExFreePoolWithTag(dumpHeader, 'pmud');
        return STATUS_NOT_FOUND;
    }

    for (size_t i = 0; i < 0x100; i++)
    {
        ptr--;
        if (*ptr == 0xcc)
        {
            ptr++;
            g_Iddp.MiDeterminePoolType = (FNMiDeterminePoolType)ptr;
            break;
        }
    }

    if (g_Iddp.MiDeterminePoolType == nullptr)
    {
        DPRINT("Get MiDeterminePoolType faild cc.\n");
        ExFreePoolWithTag(dumpHeader, 'pmud');
        return STATUS_NOT_FOUND;
    }

    LOGF_DEBUG("MiDeterminePoolType:%p\n", g_Iddp.MiDeterminePoolType);

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

PHASHTABLE PgIdpGetPhysicalMmeory()
{
    auto PhysicalMemoryBlock = MmGetPhysicalMemoryRanges();

    if (PhysicalMemoryBlock == NULL)
        return nullptr;

    auto pHashTable = HbInitializeTable(0x200);

    if (pHashTable == nullptr)
        return nullptr;

    auto NumberOfPtes = g_Iddp.SystemPteInfo->Bitmap.SizeOfBitMap * 8;

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
                        DATA data;
                        RtlZeroMemory(&data, sizeof(data));
                        data.Va = (ULONG_PTR)MapAddress;
                        data.poolType = g_Iddp.MiDeterminePoolType(MapAddress);
                        data.size = PAGE_SIZE;
                        HbInsert(data.Va, &data, pHashTable);
                    }
                }
            }

            BaseAddress.QuadPart += PAGE_SIZE;
            NumberOfBytes.QuadPart -= PAGE_SIZE;
        }
        i++;
    }

    ExFreePool(PhysicalMemoryBlock);

    return pHashTable;
}

NTSTATUS PgIdpMarkNonPageMemory(PHASHTABLE pHashTable)
{
    PSYSTEM_BIGPOOL_INFORMATION pBigPoolInfo = nullptr;

    auto status = PgHelperEnumBigPool(nullptr, nullptr, (PVOID*)&pBigPoolInfo);

    if (!NT_SUCCESS(status) || pBigPoolInfo == nullptr)
    {
        HbDestroyTable(pHashTable);
        return status;
    }

    for (ULONG i = 0; i < pBigPoolInfo->Count; i++)
    {
        SYSTEM_BIGPOOL_ENTRY poolEntry = pBigPoolInfo->AllocatedInfo[i];

        BOOLEAN bNonPaged = (poolEntry.NonPaged == 1);
        PVOID p = poolEntry.VirtualAddress;

        PSYSTEM_POOL_INFO pp = (PSYSTEM_POOL_INFO)&p;

        pp->NonPaged = 0;

        auto pData = HbFindHashTable((ULONG_PTR)pp->VirtualAddress, pHashTable);

        if (pData)
        {
            pData->base = (ULONG_PTR)pp->VirtualAddress;
            pData->size = poolEntry.SizeInBytes;
            
            if (bNonPaged)
                pData->poolType = NonPagedPool;

            for (size_t k = 1; k < pData->size / PAGE_SIZE - 1; k++)
            {
                auto tmpKey = pData->base + k * PAGE_SIZE;

                HbRemove(tmpKey, pHashTable);

            }
        }
    }

    ExFreePool(pBigPoolInfo);

    //DumpTable(pHashTable);

    return STATUS_SUCCESS;
}

void PgIdpEnumHashTable(PHASHTABLE pHashTable, PPG_OPERATION_CALLBACKS Callbacks, PVOID context)
{
    PTWOWAY pNode = NULL;
    PLIST_ENTRY pListHead = NULL;
    PLIST_ENTRY pListLink = NULL;
    unsigned int i;

    for (i = 0; i < pHashTable->tableSize; i++)
    {
        pListHead = pListLink = pHashTable->pListHeads[i];
        if (pListHead == NULL)
        {
            DPRINT("pListHead is NULL!\n");
            continue;
        }
        if (!IsListEmpty(pListHead))
        {
            do
            {
                pNode = CONTAINING_RECORD(pListLink, TWOWAY, linkfield);
                pListLink = pListLink->Flink;
                if (pNode->key != 0)
                {

                    if (MmIsAddressValid((PVOID)pNode->data.Va))
                    {
                        PVOID postContext = nullptr;
                        if (Callbacks->PreCallBack((PVOID)pNode->data.Va, pNode->data.size, context, &postContext) == PG_PREOP_CALL_POST_AND_FIND_SIZE)
                        {
                            LOGF_DEBUG("key:%p    base:%p    Va:%p    size:%p    type:%d\n", pNode->key, pNode->data.base, pNode->data.Va, pNode->data.size, pNode->data.poolType);
                            if (!Callbacks->PostCallBack((PVOID)(pNode->data.base ? pNode->data.base : pNode->data.Va), pNode->data.size, context, postContext, pHashTable))
                                break;
                        }
                    }
                    

                }
            } while (pListLink != pListHead);
        }
    }

}

NTSTATUS PgIdpEnumPhysicalMemoryEx(PPG_OPERATION_CALLBACKS callbacks, PVOID context)
{
    if (callbacks == NULL)
        return STATUS_INVALID_PARAMETER;

    auto p = PgIdpGetPhysicalMmeory();

    if (p)
    {
        PgIdpMarkNonPageMemory(p);
        PgIdpEnumHashTable(p, callbacks, context);
        HbDestroyTable(p);
        return STATUS_SUCCESS;
    }
    else
    {
        //DbgBreakPoint();
        DPRINT("GetPhysicalMmeory faild.\r\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}