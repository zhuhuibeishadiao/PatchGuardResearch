#include "pch.h"

enum PG_SCAN_TYPE
{
    PgScanType_Unknow = 0,
    PgScanType_c3,
    PgScanType_Routine,
    PgScanType_Fileds
};

typedef struct _PG_PRE_POST_CONTEXT
{
    PG_SCAN_TYPE ScanType;
    PVOID        ScanedAddress;
}PG_PRE_POST_CONTEXT, *PPG_PRE_POST_CONTEXT;

ULONG PgCoreGetCodeSize(PVOID VirtualAddress, LDE_DISASM Lde)
{
    if (Lde == NULL || VirtualAddress == NULL || !MmIsAddressValid(VirtualAddress))
        return 0;

    PUCHAR p = (PUCHAR)VirtualAddress;

    ULONG len = 0;
    ULONG size = 0;

    __try {
        while (true)
        {
            len = Lde(p, 64);
            size = size + len;

            if (len == 1 && *p == 0xc3)
            {
                break;
            }

            p = p + len;

            if (size > 0x2000)
                return 0;
        }
    }
    __except (1)
    {
        return 0;
    }

    return size;
}

NTSTATUS PgCoreinitialization(PPG_CORE_INFO pgCoreInfo)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    PVOID pMappedNtos = NULL;

    DWORD64 Key = 0x4808588948c48b48; // pg entry point code
    /*
    INIT:00000001408A9CFF 48 31 84 CA C0 00 00 00                       xor     [rdx+rcx*8+0C0h], rax
    INIT:00000001408A9D07 48 D3 C8                                      ror     rax, cl
    INIT:00000001408A9D0A 48 0F BB C0                                   btc     rax, rax
    */
    DWORD64 CmpAppendDllSectionKey = 0x000000c0ca843148;
    
    do
    {
        if (pgCoreInfo == NULL)
            break;

        RtlZeroMemory(pgCoreInfo, sizeof(PG_CORE_INFO));

        pgCoreInfo->LdeAsm = (LDE_DISASM)PgHelperGetLDE();

        if (pgCoreInfo->LdeAsm == NULL)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        status = PgHelperMapFile(L"\\SystemRoot\\System32\\ntoskrnl.exe", &pMappedNtos);

        if (!NT_SUCCESS(status))
        {
            LOGF_ERROR("Map ntos faild : %p\r\n", status);
            break;
        }

        PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(pMappedNtos);

        if (pHdr == NULL)
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            LOGF_ERROR("get nt header faild : %p\r\n", status);
            break;
        }

        pgCoreInfo->NtosBase = (ULONG64)PgHelperGetNtosBase();

        if (pgCoreInfo->NtosBase == 0)
        {
            status = STATUS_INVALID_IMAGE_FORMAT;
            LOGF_ERROR("get ntos base : %p\r\n", status);
            break;
        }

        pgCoreInfo->NtosEnd = pgCoreInfo->NtosBase + pHdr->OptionalHeader.SizeOfImage;

        LOGF_DEBUG("ntos base:%p    size:%p\r\n", pgCoreInfo->NtosBase, pHdr->OptionalHeader.SizeOfImage);

        auto pInitDBGSection = PgHelperGetSection("INITKDBG", pMappedNtos);

        if (pInitDBGSection == NULL)
        {
            LOGF_ERROR("Get INITKDBG section faild.\r\n");
            status = STATUS_NOT_FOUND;
            break;
        }

        pgCoreInfo->NtosInitSizeOfRawData = pInitDBGSection->SizeOfRawData;

        PCHAR ptr = NULL;

        status = PgHelperScanSection("INITKDBG", pMappedNtos, (PUCHAR)&Key, 8, 0xcc, 0, (PVOID*)&ptr);

        if (!NT_SUCCESS(status))
        {
            DPRINT("Scan pgEntry code faild %p\r\n", status);
            break;
        }

        RtlCopyMemory(pgCoreInfo->PgEntryPointFiled, ptr, sizeof(pgCoreInfo->PgEntryPointFiled));

        for (size_t i = 0; i < sizeof(pgCoreInfo->PgEntryPointFiled) / 8; i++)
        {
            DPRINT("PgEntryPointFiled[%d]   %p\r\n", i, pgCoreInfo->PgEntryPointFiled[i]);
        }

        status = PgHelperScanSection("INIT", pMappedNtos, (PUCHAR)&CmpAppendDllSectionKey, 8, 0xcc, 0, (PVOID*)&ptr);

        if (!NT_SUCCESS(status))
        {
            DPRINT("Scan CmpAppendDllSection faild %p\r\n", status);
            break;
        }

        /*
        //            INIT:00000001408A9D10 8B 82 88 06 00 00                             mov     eax, [rdx+688h]
        //            */

        size_t scaned = 0;

        while (true)
        {
            auto len = pgCoreInfo->LdeAsm(ptr, 64);

            scaned = scaned + len;

            if (len == 6)
            {
                pgCoreInfo->PgEntryPointRVA = *(ULONG*)(ptr + 2);
                LOGF_DEBUG("PgEntryPointRVA:%p\r\n", pgCoreInfo->PgEntryPointRVA);

                status = STATUS_SUCCESS;

                break;
            }

            if (scaned > 0x100)
            {
                status = STATUS_NOT_FOUND;
                break;
            }

            ptr = ptr + len;
        }

        if (!NT_SUCCESS(status))
        {
            DPRINT("Get PgEntry RVA faild.\r\n");
            break;
        }

        /*
        RtlMinimalBarrier pg最后一个函数的这个 并且貌似最后的ret不加密
        1803 指向pg最后未加密的数据的偏移 0x6A8

        TKDBG:0000000140369F1D F3 90                                         pause
        INITKDBG:0000000140369F1F
        INITKDBG:0000000140369F1F                               loc_140369F1F:                          ; CODE XREF: RtlMinimalBarrier+1D↑j
        INITKDBG:0000000140369F1F 8B 01                                         mov     eax, [rcx]
        INITKDBG:0000000140369F21 41 23 C1                                      and     eax, r9d
        INITKDBG:0000000140369F24 41 3B C0                                      cmp     eax, r8d
        INITKDBG:0000000140369F27 75 F4                                         jnz     short loc_140369F1D
        INITKDBG:0000000140369F29 0F BA E2 10                                   bt      edx, 10h
        INITKDBG:0000000140369F2D 73 09                                         jnb     short loc_140369F38
        INITKDBG:0000000140369F2F B8 01 00 00 00                                mov     eax, 1
        INITKDBG:0000000140369F34 F0 01 41 04                                   lock add [rcx+4], eax
        INITKDBG:0000000140369F38
        INITKDBG:0000000140369F38                               loc_140369F38:                          ; CODE XREF: RtlMinimalBarrier+45↑j
        INITKDBG:0000000140369F38 32 C0                                         xor     al, al
        INITKDBG:0000000140369F3A C3                                            retn
        INITKDBG:0000000140369F3A                               RtlMinimalBarrier endp

        */

        pgCoreInfo->PgRtlMinimalBarrierFiled[0] = 0x0001b8097310e2ba;
        pgCoreInfo->PgRtlMinimalBarrierFiled[1] = 0xc032044101f00000;
        // retn

        /*
            INIT:00000001409ABA8F                               loc_1409ABA8F:                          ; CODE XREF: CmpAppendDllSection+8E↓j
            INIT:00000001409ABA8F 48 31 84 CA C0 00 00 00                       xor     [rdx+rcx*8+0C0h], rax
            INIT:00000001409ABA97 48 D3 C8                                      ror     rax, cl
            INIT:00000001409ABA9A 48 0F BB C0                                   btc     rax, rax
            INIT:00000001409ABA9E E2 EF                                         loop    loc_1409ABA8F

            0: kd> ?a3a00b5ab0c9b857-A3A03F5891C8B4E8
            Evaluate expression: -57165494549649 = ffffcc02`1f01036f
            0: kd> dps ffffcc02`1f01036f L120
            ffffcc02`1f01036f  903d3204`e5cc5ce4
            .................
            .................
            offset:0xc0
            ffffcc02`1f010437  00000000`00000000                                                        rcx = 1
            ffffcc02`1f01043f  00000000`00000000                                                        rcx = 2
            ffffcc02`1f010447  00000000`00000000                                                        rcx = 3
            ffffcc02`1f01044f  00000000`00000000                                                        rcx = 4
            ffffcc02`1f010457  fffff807`3162ce00 nt!ExAcquireResourceSharedLite                         rcx = 5
            ffffcc02`1f01045f  fffff807`3162ca20 nt!ExAcquireResourceExclusiveLite                      rcx = 6
            ffffcc02`1f010467  fffff807`3196a010 nt!ExAllocatePoolWithTag                               rcx = 7
            ffffcc02`1f01046f  fffff807`3196a0a0 nt!ExFreePool                                          rcx = 8
            ffffcc02`1f010477  fffff807`31c299e0 nt!ExMapHandleToPointer
            ffffcc02`1f01047f  fffff807`316b0060 nt!ExQueueWorkItem
                                                                                                        rcx = (offset-0xc0) / 8     offset != 0xc0
           */

        pgCoreInfo->PgContextFiled[0] = PgHelperGetRoutineName(L"ExAcquireResourceSharedLite");
        pgCoreInfo->PgContextFiled[1] = PgHelperGetRoutineName(L"ExAcquireResourceExclusiveLite");
        pgCoreInfo->PgContextFiled[2] = PgHelperGetRoutineName(L"ExAllocatePoolWithTag");
        pgCoreInfo->PgContextFiled[3] = PgHelperGetRoutineName(L"ExFreePool");

        auto p = PgHelperGetRoutineName(L"DbgBreakPointWithStatus");

        /*
        ffffbd07`c170e959  fffff802`d544d810 hal!HalReturnToFirmware+0xa0
        ffffbd07`c170e961  00000000`000000ae
        ffffbd07`c170e969  fffff802`d563f650 nt!KeBugCheckEx
        ffffbd07`c170e971  00000000`00000120
        ffffbd07`c170e979  fffff802`d56f7660 nt!KeBugCheck2
        ffffbd07`c170e981  00000000`00000de0
        ffffbd07`c170e989  fffff802`d56f87a0 nt!KiBugCheckDebugBreak
        ffffbd07`c170e991  00000000`000000b5
        ffffbd07`c170e999  fffff802`d564b080 nt!KiDebugTrapOrFault
        ffffbd07`c170e9a1  00000000`0000043f
        ffffbd07`c170e9a9  fffff802`d5648470 nt!DbgBreakPointWithStatus
        ffffbd07`c170e9b1  00000000`00000002
        ffffbd07`c170e9b9  fffff802`d5648610 nt!RtlCaptureContext
        ffffbd07`c170e9c1  00000000`00000137
        ffffbd07`c170e9c9  fffff802`d566144c nt!KeQueryCurrentStackInformation+0x1a906c
        ffffbd07`c170e9d1  00000000`00000074
        ffffbd07`c170e9d9  fffff802`d54b83e0 nt!KeQueryCurrentStackInformation
        ffffbd07`c170e9e1  00000000`0000018a
        ffffbd07`c170e9e9  fffff802`d563f9a0 nt!KiSaveProcessorControlState
        ffffbd07`c170e9f1  00000000`00000172
        ffffbd07`c170e9f9  fffff802`d56534c0 nt!memcpy
        ffffbd07`c170ea01  00000000`00000339
        ffffbd07`c170ea09  fffff802`d56e8710 nt!IoSaveBugCheckProgress
        ffffbd07`c170ea11  00000000`0000003d
        ffffbd07`c170ea19  fffff802`d553b240 nt!KeIsEmptyAffinityEx
        ffffbd07`c170ea21  00000000`00000029
        ffffbd07`c170ea29  fffff802`d5ccdb50 nt!VfNotifyVerifierOfEvent
        ffffbd07`c170ea31  00000000`00000120
        ffffbd07`c170ea39  fffff802`d5648e30 nt!guard_check_icall
        ffffbd07`c170ea41  00000000`0000004a
        ffffbd07`c170ea49  fffff802`d579e7d0 nt!KeGuardDispatchICall
        ffffbd07`c170ea51  00000000`00000006
        ffffbd07`c170ea59  fffff802`d58506b8 nt!HalPrivateDispatchTable+0x48
        ffffbd07`c170ea61  00000000`00000008
        */
        pgCoreInfo->PgDbgBreakPointWithStatusFiled[0] = p;
        pgCoreInfo->PgDbgBreakPointWithStatusFiled[1] = 2; // sizeof(DbgBreakPointWithStatus);

        if (p)
            LOGF_DEBUG("size:%p\r\n", PgCoreGetCodeSize((PVOID)p, pgCoreInfo->LdeAsm));

        p = PgHelperGetRoutineName(L"RtlCaptureContext");

        if (p)
            LOGF_DEBUG("size:%p\r\n", PgCoreGetCodeSize((PVOID)p, pgCoreInfo->LdeAsm));

        p = PgHelperGetRoutineName(L"memcpy");

        if (p)
            LOGF_DEBUG("size:%p\r\n", PgCoreGetCodeSize((PVOID)p, pgCoreInfo->LdeAsm));

        p = PgHelperGetRoutineName(L"KeIsEmptyAffinityEx");

        if (p)
            LOGF_DEBUG("size:%p\r\n", PgCoreGetCodeSize((PVOID)p, pgCoreInfo->LdeAsm));

        p = PgHelperGetRoutineName(L"KeBugCheckEx");

        if (p)
            LOGF_DEBUG("size:%p\r\n", PgCoreGetCodeSize((PVOID)p, pgCoreInfo->LdeAsm));

        status = STATUS_SUCCESS;

        for (size_t i = 0; i < sizeof(pgCoreInfo->PgContextFiled) / 8; i++)
        {
            if (pgCoreInfo->PgContextFiled[i] == 0)
            {
                status = STATUS_UNSUCCESSFUL;
                break;
            }
        }

    } while (false);

    if (pMappedNtos)
        ZwUnmapViewOfSection(ZwCurrentProcess(), pMappedNtos);

    if (!NT_SUCCESS(status))
    {
        if (pgCoreInfo->LdeAsm)
            ExFreePoolWithTag(pgCoreInfo->LdeAsm, 'edlk');

        pgCoreInfo->LdeAsm = NULL;
    }

    return status;
}

void PgCoreDumpPgContext(PVOID pgContext, SIZE_T size)
{
    PULONG64 p = (PULONG64)pgContext;

    for (size_t i = 0; i < size / 8 - 1; i++)
    {
        if (i < 0x19) // 0xc8 / 8 rcx = 1
            LOGF_INFO("%p   %p    rcx:%p    offset:%p\r\n", &p[i], p[i], 0, i * 8);
        else
            LOGF_INFO("%p   %p    rcx:%p    offset:%p\r\n", &p[i], p[i], i - 0x18, i * 8);
    }
}

BOOLEAN PgCoreGetFirstRorKeyAndOffsetByC3(ULONG64* lpRorKey, ULONG64* lpOffset, PVOID pgContext, SIZE_T ContextSize, PPG_CORE_INFO pgCore)
{
    if (lpRorKey == NULL || lpOffset == NULL || pgContext == NULL || ContextSize == 0 || pgCore == NULL)
        return false;

    PULONG64 p = (PULONG64)pgContext;
    ULONG64 offset = 0;

    /*
    12:51:27.723	INF	FFFFD10B69E1A665   F73B466650BD8B99    rcx:000000000000343B    offset:000000000001A298
    12:51:27.723	INF	FFFFD10B69E1A66D   AFCD4B3315AF2611    rcx:000000000000343C    offset:000000000001A2A0
    12:51:27.723	INF	FFFFD10B69E1A675   B5CB9B264D27F895    rcx:000000000000343D    offset:000000000001A2A8
    12:51:27.723	INF	FFFFD10B69E1A67D   00000000000000C3    rcx:000000000000343E    offset:000000000001A2B0
    */
    for (size_t i = 0; i < ContextSize / 8 - 1 - 1; i++)
    {
        if (*p == 0x00000000000000C3)
        {
            p = p - 2;
            offset = (ULONG64)p - (ULONG64)pgContext;
            break;
        }

        p++;
    }

    if (offset <= 0xc0)
    {
        LOGF_ERROR("not find 0x00000000000000C3\r\n");
        return false;
    }

    LOGF_INFO("GetKeyAndOffset -> offset:%p    p:%p\r\n", offset, p);

    ULONG64 rorKey = p[1] ^ pgCore->PgRtlMinimalBarrierFiled[1];
    ULONG64 rcx = (offset - 0xc0) / 8 + 1;

    rorKey = __ror64(rorKey, rcx);
    rorKey = __btc64(rorKey, rorKey);

    if ((rorKey ^ p[0]) == pgCore->PgRtlMinimalBarrierFiled[0])
    {
        LOGF_INFO("get first rorkey success -> rcx:%p    offset:%p    rorkey:%p\r\n", rcx, offset + 8, p[1] ^ pgCore->PgRtlMinimalBarrierFiled[1]);
    }
    else
    {
        LOGF_ERROR("Get first check faild.\r\n");
        return false;
    }

    /*p = &p[1];
    rorKey = *p ^ pgCore->PgRtlMinimalBarrierFiled[1];
    offset = (ULONG64)p - (ULONG64)pgContext;

    while (offset > 0xc0)
    {
        rcx = (offset - 0xc0) / 8;

        auto Decryptd = *p ^ rorKey;

        LOGF_INFO("offset:%p    rcx:%p    encrypted:%p    decrypted:%p    rorkey:%p\r\n", offset, rcx, *p, Decryptd, rorKey);

        rorKey = __ror64(rorKey, rcx);
        rorKey = __btc64(rorKey, rorKey);

        p--;
        offset = offset - 8;
    }*/

    return true;
}

BOOLEAN PgCoreDecrytionPartDump(PULONG64 pgContext, SIZE_T ContextSize, PPG_CORE_INFO pCore)
{
    if (pCore->PgDbgBreakPointWithStatusFiled[0] == NULL)
        return false;

    BOOLEAN bFindDecryRorKey = false;
    ULONG64 rorkey = 0;
    size_t rcx = 0;

    size_t i = 0;
    ULONG64 lastRorkey = 0;
    ULONG64 offset = 0;

    for (i = 0; i < ContextSize / 8 - 1; i++)
    {
        offset = (ULONG64)&pgContext[i] - (ULONG64)pgContext;

        if (offset <= 0xc0)
            continue;

        rcx = (offset - 0xc0) / 8;

        rorkey = pgContext[i] ^ pCore->PgDbgBreakPointWithStatusFiled[1];
        lastRorkey = rorkey;

        rorkey = __ror64(rorkey, rcx);
        rorkey = __btc64(rorkey, rorkey);

        if ((rorkey ^ pgContext[i - 1]) == pCore->PgDbgBreakPointWithStatusFiled[0])
        {
            LOGF_INFO("hit key rcx:%p    offset:%p\r\n", rcx, offset);
            bFindDecryRorKey = true;
            break;
        }
    }



    if (bFindDecryRorKey == false)
    {
        LOGF_ERROR("not hit decrypt rorkey :<\r\n");
        return false;
    }

    PULONG64 p = (PULONG64)(offset + (ULONG64)pgContext);
    rorkey = lastRorkey;

    while (offset > 0xc0)
    {
        rcx = (offset - 0xc0) / 8;

        auto Decryptd = *p ^ rorkey;

        LOGF_INFO("offset:%p    rcx:%p    encrypted:%p    decrypted:%p    rorkey:%p\r\n", offset, rcx, *p, Decryptd, rorkey);

        rorkey = __ror64(rorkey, rcx);
        rorkey = __btc64(rorkey, rorkey);

        p--;
        offset = offset - 8;
    }

    return true;

}

BOOLEAN PgCoreCompareFilelds(PULONG64 pg, ULONG64 pFilelds[4], ULONG rcx)
{
    auto rorkey = pg[3] ^ pFilelds[3];
    
    rorkey = __ror64(rorkey, rcx);

    rorkey = __btc64(rorkey, rorkey);

    if ((rorkey ^ pg[2]) == pFilelds[2])
    {
        rcx--;
        rorkey = __ror64(rorkey, rcx);
        rorkey = __btc64(rorkey, rorkey);

        if ((rorkey ^ pg[1]) == pFilelds[1])
        {
            rcx--;

            rorkey = __ror64(rorkey, rcx);
            rorkey = __btc64(rorkey, rorkey);

            if ((rorkey ^ pg[0]) == pFilelds[0])
                return true;
        }
    }

    return false;
}

BOOLEAN NTAPI PgCorePoolCallback(BOOLEAN bNonPagedPool, PVOID Va, SIZE_T size, UCHAR tag[4], PVOID context)
{
    if (bNonPagedPool == false)
        return true;

    if (size > 0x95000)
        return true;

    if (context == NULL)
        return false;

    PPG_CORE_INFO pCoreInfo = reinterpret_cast<PPG_CORE_INFO>(context);

    if (size < pCoreInfo->NtosInitSizeOfRawData)
        return true;
    
    PCHAR p = (PCHAR)Va;

    PCHAR pEnd = p + size - 0x8 * 4;
    
    ULONG offsetHeader = 0;

    PULONG64 CompareFields = NULL;

    /*
            rs1
            INIT:00000001409ABA8F                               loc_1409ABA8F:                          ; CODE XREF: CmpAppendDllSection+8E↓j
            INIT:00000001409ABA8F 48 31 84 CA C0 00 00 00                       xor     [rdx+rcx*8+0C0h], rax
            INIT:00000001409ABA97 48 D3 C8                                      ror     rax, cl
            INIT:00000001409ABA9A 48 0F BB C0                                   btc     rax, rax
            INIT:00000001409ABA9E E2 EF                                         loop    loc_1409ABA8F

            0: kd> ?a3a00b5ab0c9b857-A3A03F5891C8B4E8
            Evaluate expression: -57165494549649 = ffffcc02`1f01036f
            0: kd> dps ffffcc02`1f01036f L120
            ffffcc02`1f01036f  903d3204`e5cc5ce4
            .................
            .................
            offset:0xc8
            ffffcc02`1f010437  00000000`00000000                                                        rcx = 1
            ffffcc02`1f01043f  00000000`00000000                                                        rcx = 2
            ffffcc02`1f010447  00000000`00000000                                                        rcx = 3
            ffffcc02`1f01044f  00000000`00000000                                                        rcx = 4
            ffffcc02`1f010457  fffff807`3162ce00 nt!ExAcquireResourceSharedLite                         rcx = 5
            ffffcc02`1f01045f  fffff807`3162ca20 nt!ExAcquireResourceExclusiveLite                      rcx = 6
            ffffcc02`1f010467  fffff807`3196a010 nt!ExAllocatePoolWithTag                               rcx = 7
            ffffcc02`1f01046f  fffff807`3196a0a0 nt!ExFreePool                                          rcx = 8
            ffffcc02`1f010477  fffff807`31c299e0 nt!ExMapHandleToPointer
            ffffcc02`1f01047f  fffff807`316b0060 nt!ExQueueWorkItem
                                                                                                        rcx = (offset-0xc0) / 8
                                                                                                        // offset = rcx * 8 + 0xc0;
            rs5.
            ffff8183`c20a0014  daa1c838`0103c62e
            .................
            .................
            offset:0xc8
            ffff8183`c20a00dc  00000000`00000000                                                        rcx = 1
            ffff8183`c20a00e4  00000000`00000000                                                        rcx = 2
            ffff8183`c20a00ec  00000000`00000000                                                        rcx = 3
            ffff8183`c20a00f4  fffff802`472b6350 nt!ExAcquireResourceSharedLite                         rcx = 4
            ffff8183`c20a00fc  fffff802`472b60e0 nt!ExAcquireResourceExclusiveLite                      rcx = 5
            ffff8183`c20a0104  fffff802`4755c030 nt!ExAllocatePoolWithTag                               rcx = 6
            ffff8183`c20a010c  fffff802`4755c010 nt!ExFreePool                                          rcx = 7
           
           */
    do
    {
        CompareFields = (PULONG64)p;

        if (!PgIdpMmIsAccessibleAddress(CompareFields) || !PgIdpMmIsAccessibleAddress(CompareFields + 4))
            break;

        size_t rcx = 8;
        // 用ExFreePool开始碰撞
        BOOLEAN bFouned = PgCoreCompareFilelds(CompareFields, pCoreInfo->PgContextFiled, rcx);

        if (!bFouned)
        {
            rcx = 7;
            bFouned = PgCoreCompareFilelds(CompareFields, pCoreInfo->PgContextFiled, rcx);
        }

        if (bFouned)
        {
            if (rcx == 8)
                offsetHeader = 0x1d; // offset ExAcquireResourceSharedLite - 0xe8 = pg context    0x1d = e8 / 8
            else
                offsetHeader = 0x1c; // offset ExAcquireResourceSharedLite - 0xe0 = pg context    0x1c = e0 / 8

            auto PgContext = CompareFields - offsetHeader;
            auto PgContextSize = size - ((ULONG64)PgContext - (ULONG64)Va);

            LOGF_INFO("Tag: %.*s, Address: 0x%p, Size: 0x%p\r\n", 4, tag, Va, size);

            auto rdtsc = __rdtsc();

            LOGF_INFO("PgContext:%p    size:%p    rcx:%p    rdtsc:%p    %lld\r\n", PgContext, PgContextSize, rcx, rdtsc, rdtsc);

            //PgCoreDumpPgContext(PgContext, PgContextSize);
            ULONG64 offset = 0;
            ULONG64 rorkey = 0;
            // 解密c8~第二部分结束
            PgCoreGetFirstRorKeyAndOffsetByC3(&rorkey, &offset, PgContext, PgContextSize, (PPG_CORE_INFO)context);
            // 解密c8~0x988
            //PgCoreDecrytionPartDump(PgContext, PgContextSize, (PPG_CORE_INFO)context);

            return true;
        }

        p++;
    } while ((ULONG64)p < (ULONG64)pEnd);

    return true;
}

PG_PREOP_CALLBACK_STATUS NTAPI PgCorePreCallback(PVOID Va, SIZE_T size, PVOID CallbackContext, PVOID* PostContext)
{
    if (!MmIsAddressValid(Va) || !MmIsAddressValid((PCHAR)Va + size - 1))
        return PG_PREOP_NOT_CALL_POST;

    if (size > 0x95000)
        return PG_PREOP_NOT_CALL_POST;

    if (CallbackContext == NULL)
        return PG_PREOP_BREAK;

    PPG_CORE_INFO pCoreInfo = reinterpret_cast<PPG_CORE_INFO>(CallbackContext);

    PCHAR p = (PCHAR)Va;

    PCHAR pEnd = p + size - 0x8 * 8;

    //ULONG offsetHeader = 0;

    PULONG64 CompareFields = NULL;

    /*
            rs1
            INIT:00000001409ABA8F                               loc_1409ABA8F:                          ; CODE XREF: CmpAppendDllSection+8E↓j
            INIT:00000001409ABA8F 48 31 84 CA C0 00 00 00                       xor     [rdx+rcx*8+0C0h], rax
            INIT:00000001409ABA97 48 D3 C8                                      ror     rax, cl
            INIT:00000001409ABA9A 48 0F BB C0                                   btc     rax, rax
            INIT:00000001409ABA9E E2 EF                                         loop    loc_1409ABA8F

            0: kd> ?a3a00b5ab0c9b857-A3A03F5891C8B4E8
            Evaluate expression: -57165494549649 = ffffcc02`1f01036f
            0: kd> dps ffffcc02`1f01036f L120
            ffffcc02`1f01036f  903d3204`e5cc5ce4
            .................
            .................
            offset:0xc8
            ffffcc02`1f010437  00000000`00000000                                                        rcx = 1
            ffffcc02`1f01043f  00000000`00000000                                                        rcx = 2
            ffffcc02`1f010447  00000000`00000000                                                        rcx = 3
            ffffcc02`1f01044f  00000000`00000000                                                        rcx = 4
            ffffcc02`1f010457  fffff807`3162ce00 nt!ExAcquireResourceSharedLite                         rcx = 5
            ffffcc02`1f01045f  fffff807`3162ca20 nt!ExAcquireResourceExclusiveLite                      rcx = 6
            ffffcc02`1f010467  fffff807`3196a010 nt!ExAllocatePoolWithTag                               rcx = 7
            ffffcc02`1f01046f  fffff807`3196a0a0 nt!ExFreePool                                          rcx = 8
            ffffcc02`1f010477  fffff807`31c299e0 nt!ExMapHandleToPointer
            ffffcc02`1f01047f  fffff807`316b0060 nt!ExQueueWorkItem
                                                                                                        rcx = (offset-0xc0) / 8
                                                                                                        // offset = rcx * 8 + 0xc0;
            rs5.
            ffff8183`c20a0014  daa1c838`0103c62e
            .................
            .................
            offset:0xc8
            ffff8183`c20a00dc  00000000`00000000                                                        rcx = 1
            ffff8183`c20a00e4  00000000`00000000                                                        rcx = 2
            ffff8183`c20a00ec  00000000`00000000                                                        rcx = 3
            ffff8183`c20a00f4  fffff802`472b6350 nt!ExAcquireResourceSharedLite                         rcx = 4
            ffff8183`c20a00fc  fffff802`472b60e0 nt!ExAcquireResourceExclusiveLite                      rcx = 5
            ffff8183`c20a0104  fffff802`4755c030 nt!ExAllocatePoolWithTag                               rcx = 6
            ffff8183`c20a010c  fffff802`4755c010 nt!ExFreePool                                          rcx = 7

           */
    do
    {
        CompareFields = (PULONG64)p;

        if (!PgIdpMmIsAccessibleAddress(CompareFields) || !PgIdpMmIsAccessibleAddress(CompareFields + 6))
            break;

        /*
            xxxxxxxxxxxxxxxxx  xxxxxxxxxxxxxxxxx 可能是全加密 半加密 最后一个字节未加密
            ffffa38a`2cf1dc45  00000000`00000000
            ffffa38a`2cf1dc4d  fffff806`20cbe8c7 nt!ExQueueWorkItem+0x7
            ffffa38a`2cf1dc55  56d15c8b`00000010
            ffffa38a`2cf1dc5d  00000000`00000001
            ffffa38a`2cf1dc65  00000000`00000000
            ffffa38a`2cf1dc6d  00000000`00000000
            ffffa38a`2cf1dc75  00000000`00000000
            ffffa38a`2cf1dc7d  fffff806`20cbe8d7 nt!ExQueueWorkItem+0x17
            ffffa38a`2cf1dc85  2ecc050e`0000008a

            c3下面的0可能是用于对齐?

            剩下的结构体
            _struct xxxxx
            {
                PVOID routine;
                ULONG checksum?;
                ULONG routineCodeSize;
                PVOID unknow;(一直为1)
                PVOID Fileds[3];
            }

        */

        // 扫出来的可能不是第一个 在PostCallback中做判断
        if (CompareFields[0] > pCoreInfo->NtosBase && CompareFields[0] < pCoreInfo->NtosEnd)
        {
            if (CompareFields[2] == 0x0000000000000001)
            {
                if (CompareFields[3] == 0 && CompareFields[4] == 0 && CompareFields[5] == 0)
                {
                    if (CompareFields[6] > pCoreInfo->NtosBase && CompareFields[6] < pCoreInfo->NtosEnd)
                    {
                        PPG_PRE_POST_CONTEXT PreContext = (PPG_PRE_POST_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, sizeof(PG_PRE_POST_CONTEXT), 'tsoP');

                        if (PreContext == nullptr)
                        {
                            LOGF_ERROR("%s:Alloc Context faild.\r\n", __FUNCDNAME__);
                            return PG_PREOP_BREAK;
                        }

                        RtlZeroMemory(PreContext, sizeof(PG_PRE_POST_CONTEXT));

                        PreContext->ScanType = PgScanType_Routine;
                        PreContext->ScanedAddress = CompareFields - 1; // -1 这是第二部分加密的结尾

                        *PostContext = PreContext;
                        LOGF_DEBUG("PgCorePhysicalMemoryCallbackEx hit pg by Routine -> %p    %p\r\n", Va, CompareFields);
                        return PG_PREOP_CALL_POST_AND_FIND_SIZE;
                    }
                }
            }
        }

        p++;
    } while ((ULONG64)p < (ULONG64)pEnd);

    return PG_PREOP_NOT_CALL_POST;
}

BOOLEAN NTAPI PgCorePostCallback(PVOID Va, SIZE_T size, PVOID CallbackContext, PVOID PostContext, PHASHTABLE pHashTable)
{
    if (Va == nullptr || size > 0x95000 || CallbackContext == nullptr || PostContext == nullptr)
    {
        if (PostContext)
            ExFreePoolWithTag(PostContext, 'tsoP');

        return false;
    }

    PPG_PRE_POST_CONTEXT PreContext = (PPG_PRE_POST_CONTEXT)PostContext;

    LOGF_DEBUG("PgCorePostCallback -> base:%p    size:%p    PreContext:%p    ScanType:%s\r\n", Va, size, PreContext->ScanedAddress, PreContext->ScanType == PgScanType_c3 ? "c3" : "routine");

    if (size == PAGE_SIZE)
    {
        LOGF_WARN("PgCorePostCallback -> size is PAGE_SIZE\r\n");
        /*
        10:45:31.298	DBG	-----[PgCore] Find PgContext in physical.-----
        10:45:31.345	DBG	PgCorePhysicalMemoryCallbackEx hit pg by c3 -> FFFFBC01A693A000    FFFFBC01A693A40B
        10:45:31.363	DBG	key:FFFFBC01A693A000    base:0000000000000000    Va:FFFFBC01A693A000    size:0000000000001000    type:32
        10:45:31.363	WRN	PgCorePostCallback -> size is PAGE_SIZE
        10:45:31.383	DBG	PgCorePostCallback -> base:FFFFBC01A693A000    size:0000000000001000    PreContext:FFFFBC01A693A40B    ScanType:c3
        10:45:31.407	DBG	PgCorePhysicalMemoryCallbackEx hit pg by c3 -> FFFFAA82BC29C000    FFFFAA82BC2B6359
        10:45:31.407	DBG	key:FFFFAA82BC29C000    base:FFFFAA82BC29C000    Va:FFFFAA82BC29C000    size:0000000000068000    type:0
        10:45:31.431	DBG	PgCorePostCallback -> base:FFFFAA82BC29C000    size:0000000000068000    PreContext:FFFFAA82BC2B6359    ScanType:c3
        10:45:31.455	DBG	-----[PgCore] Find PgContext in physical end.-----

        WRN:NonPagedPoolSession PAGE_SIZE 命中
        查看后发现pg正在解密 还没解密完?

        ffffbc01`a69209f3  e7d54562`876622b7
        ffffbc01`a69209fb  fc0785a8`60e3055d
        ffffbc01`a6920a03  95e784c0`f128a1e1
        ffffbc01`a6920a0b  60abbf80`f0b50c1c
        ffffbc01`a6920a13  1a1704c6`da8b8ed1
        ffffbc01`a6920a1b  1838c157`7f004aeb
        ffffbc01`a6920a23  5dfc0785`a860e305
        ffffbc01`a6920a2b  2d430718`2aefe03c
        ffffbc01`a6920a33  82aefe03`c2d43071
        ffffbc01`a6920a3b  785a860e`3055dfc0
        ffffbc01`a6920a43  8c1577f0`1e16a183
        ffffbc01`a6920a4b  0f0b50c1`c60abbf8
        kd>
        ffffbc01`a6920a53  c60abbf8`0f0b50c1
        ffffbc01`a6920a5b  1e16a183`8c1577f0
        ffffbc01`a6920a63  3055dfc0`785a860e
        ffffbc01`a6920a6b  c2d43071`82aefe03
        ffffbc01`a6920a73  2aefe03c`2d431467
        ffffbc01`a6920a7b  a860e305`5dfc0785
        ffffbc01`a6920a83  00000005`00000011
        ffffbc01`a6920a8b  fffff803`3c5ab810
        ffffbc01`a6920a93  00000000`000000ae
        ffffbc01`a6920a9b  fffff803`3bdac650 nt!KeBugCheckEx
        ffffbc01`a6920aa3  00000000`00000120
        ffffbc01`a6920aab  fffff803`3be64660 nt!KeBugCheck2
        ffffbc01`a6920ab3  00000000`00000de0
        ffffbc01`a6920abb  fffff803`3be657a0 nt!KiBugCheckDebugBreak
        ffffbc01`a6920ac3  00000000`000000b5
        ffffbc01`a6920acb  fffff803`3bdb8080 nt!KiDebugTrapOrFault
        kd>
        ffffbc01`a6920ad3  00000000`0000043f
        ffffbc01`a6920adb  fffff803`3bdb5470 nt!DbgBreakPointWithStatus
        ffffbc01`a6920ae3  00000000`00000002
        ffffbc01`a6920aeb  fffff803`3bdb5610 nt!RtlCaptureContext
        ffffbc01`a6920af3  00000000`00000137
        ffffbc01`a6920afb  fffff803`3bdce44c nt!KeQueryCurrentStackInformation+0x1a906c
        ffffbc01`a6920b03  00000000`00000074
        ffffbc01`a6920b0b  fffff803`3bc253e0 nt!KeQueryCurrentStackInformation
        ffffbc01`a6920b13  00000000`0000018a
        ffffbc01`a6920b1b  fffff803`3bdac9a0 nt!KiSaveProcessorControlState
        ffffbc01`a6920b23  00000000`00000172
        ffffbc01`a6920b2b  fffff803`3bdc04c0 nt!memcpy
        ffffbc01`a6920b33  00000000`00000339
        ffffbc01`a6920b3b  fffff803`3be55710 nt!IoSaveBugCheckProgress

        */
    }
    else
    {
         /*
         xxxxxxxxxxxxxxxxx  xxxxxxxxxxxxxxxxx 可能是全加密 半加密 最后一个字节未加密
            ffffa38a`2cf1dc45  00000000`00000000
            ffffa38a`2cf1dc4d  fffff806`20cbe8c7 nt!ExQueueWorkItem+0x7
            ffffa38a`2cf1dc55  56d15c8b`00000010
            ffffa38a`2cf1dc5d  00000000`00000001
            ffffa38a`2cf1dc65  00000000`00000000
            ffffa38a`2cf1dc6d  00000000`00000000
            ffffa38a`2cf1dc75  00000000`00000000
            ffffa38a`2cf1dc7d  fffff806`20cbe8d7 nt!ExQueueWorkItem+0x17
            ffffa38a`2cf1dc85  2ecc050e`0000008a

            c3下面的0可能是用于对齐?

            剩下的结构体
            _struct xxxxx
            {
                PVOID routine;
                ULONG checksum?;
                ULONG routineCodeSize;
                PVOID unknow;(一直为1)
                PVOID Fileds[3];
            }
         */
        PULONG64 pEndOfPgVContext = (PULONG64)PreContext->ScanedAddress;

        do
        {
            if (*(pEndOfPgVContext - 1) == 0)
            {
                DPRINT("The address of the hit point is not the first:%p\r\n", pEndOfPgVContext);
                break;
            }

            PUCHAR pRtlMinimalBarrier = (PUCHAR)pEndOfPgVContext - 1;

            /*
                INITKDBG:0000000140349D3D 0F BA E2 10                                   bt      edx, 10h
                INITKDBG:0000000140349D41 73 09                                         jnb     short loc_140349D4C
                INITKDBG:0000000140349D43 B8 01 00 00 00                                mov     eax, 1
                INITKDBG:0000000140349D48 F0 01 41 04                                   lock add [rcx+4], eax
                INITKDBG:0000000140349D4C
                INITKDBG:0000000140349D4C                               loc_140349D4C:                          ; CODE XREF: RtlMinimalBarrier+45j
                INITKDBG:0000000140349D4C 32 C0                                         xor     al, al
                INITKDBG:0000000140349D4E C3                                            retn
                INITKDBG:0000000140349D4E                               RtlMinimalBarrier endp
            */

            static UCHAR RtlMinimalBarrier[8] = {0xc3, 0xc0, 0x32, 0x04, 0x41, 0x01, 0xf0, 0x00};

            size_t i = 0;
            for (i = 0; i < sizeof(RtlMinimalBarrier); i++)
            {
                pRtlMinimalBarrier = pRtlMinimalBarrier - i;

                if (*pRtlMinimalBarrier != RtlMinimalBarrier[i])
                    break;
            }

            if (i == 0)
            {
                DPRINT("pg alignment.\r\n");
            }

            if (i == sizeof(RtlMinimalBarrier))
            {
                DPRINT("pg Decryption in progress or completed.\r\n");
                DbgBreakPoint();
                break;
            }

            pEndOfPgVContext = (PULONG64)(pRtlMinimalBarrier - 7);

            // 这里我们通过碰撞offset来撞即可
            DPRINT("pgVContext:%p\r\n", pEndOfPgVContext);

        } while (false);
            
    }

    ExFreePoolWithTag(PostContext, 'tsoP');

    return true;
}

BOOLEAN NTAPI PgCorePoolCallbackEx(BOOLEAN bNonPagedPool, PVOID Va, SIZE_T size, UCHAR tag[4], PVOID context)
{
    if (bNonPagedPool == false)
        return true;

    if (size > 0x95000)
        return true;

    if (context == NULL)
        return false;

    PPG_CORE_INFO pCoreInfo = reinterpret_cast<PPG_CORE_INFO>(context);

    if (size < pCoreInfo->NtosInitSizeOfRawData)
        return true;

    PCHAR p = (PCHAR)Va;

    PCHAR pEnd = p + size - 0x8 * 8;

    //ULONG offsetHeader = 0;

    PULONG64 CompareFields = NULL;

    /*
            rs1
            INIT:00000001409ABA8F                               loc_1409ABA8F:                          ; CODE XREF: CmpAppendDllSection+8E↓j
            INIT:00000001409ABA8F 48 31 84 CA C0 00 00 00                       xor     [rdx+rcx*8+0C0h], rax
            INIT:00000001409ABA97 48 D3 C8                                      ror     rax, cl
            INIT:00000001409ABA9A 48 0F BB C0                                   btc     rax, rax
            INIT:00000001409ABA9E E2 EF                                         loop    loc_1409ABA8F

            0: kd> ?a3a00b5ab0c9b857-A3A03F5891C8B4E8
            Evaluate expression: -57165494549649 = ffffcc02`1f01036f
            0: kd> dps ffffcc02`1f01036f L120
            ffffcc02`1f01036f  903d3204`e5cc5ce4
            .................
            .................
            offset:0xc8
            ffffcc02`1f010437  00000000`00000000                                                        rcx = 1
            ffffcc02`1f01043f  00000000`00000000                                                        rcx = 2
            ffffcc02`1f010447  00000000`00000000                                                        rcx = 3
            ffffcc02`1f01044f  00000000`00000000                                                        rcx = 4
            ffffcc02`1f010457  fffff807`3162ce00 nt!ExAcquireResourceSharedLite                         rcx = 5
            ffffcc02`1f01045f  fffff807`3162ca20 nt!ExAcquireResourceExclusiveLite                      rcx = 6
            ffffcc02`1f010467  fffff807`3196a010 nt!ExAllocatePoolWithTag                               rcx = 7
            ffffcc02`1f01046f  fffff807`3196a0a0 nt!ExFreePool                                          rcx = 8
            ffffcc02`1f010477  fffff807`31c299e0 nt!ExMapHandleToPointer
            ffffcc02`1f01047f  fffff807`316b0060 nt!ExQueueWorkItem
                                                                                                        rcx = (offset-0xc0) / 8
                                                                                                        // offset = rcx * 8 + 0xc0;
            rs5.
            ffff8183`c20a0014  daa1c838`0103c62e
            .................
            .................
            offset:0xc8
            ffff8183`c20a00dc  00000000`00000000                                                        rcx = 1
            ffff8183`c20a00e4  00000000`00000000                                                        rcx = 2
            ffff8183`c20a00ec  00000000`00000000                                                        rcx = 3
            ffff8183`c20a00f4  fffff802`472b6350 nt!ExAcquireResourceSharedLite                         rcx = 4
            ffff8183`c20a00fc  fffff802`472b60e0 nt!ExAcquireResourceExclusiveLite                      rcx = 5
            ffff8183`c20a0104  fffff802`4755c030 nt!ExAllocatePoolWithTag                               rcx = 6
            ffff8183`c20a010c  fffff802`4755c010 nt!ExFreePool                                          rcx = 7

            1909 offset:1bb44
            1903 offset:1b4f3
            1803 offset:1a2b1
           */
    do
    {
        CompareFields = (PULONG64)p;

        if (!PgIdpMmIsAccessibleAddress(CompareFields) || !PgIdpMmIsAccessibleAddress(CompareFields + 6))
            break;

        if (CompareFields[0] > pCoreInfo->NtosBase && CompareFields[0] < pCoreInfo->NtosEnd)
        {
            if (CompareFields[2] == 0x0000000000000001)
            {
                if (CompareFields[3] == 0 && CompareFields[4] == 0 && CompareFields[5] == 0)
                {
                    if (CompareFields[6] > pCoreInfo->NtosBase && CompareFields[6] < pCoreInfo->NtosEnd)
                    {
                        LOGF_INFO("PgCorePoolCallbackEx: Tag: %.*s, Address: 0x%p, Size: 0x%p\r\n", 4, tag, Va, size);
                        LOGF_DEBUG("PgCorePoolCallbackEx hot pg -> %p    %p\r\n", Va, CompareFields);
                        return true;
                    }
                }
            }

        }

        p++;
    } while ((ULONG64)p < (ULONG64)pEnd);

    return true;
}

NTSTATUS PgCoreFindPgContext(PPG_CORE_INFO pgCoreInfo)
{
    LOGF_DEBUG("-----[PgCore] Find PgContext in pool.-----\r\n");
    PgHelperEnumBigPool(PgCorePoolCallback, pgCoreInfo, NULL);
    //PgHelperEnumBigPool(PgCorePoolCallbackEx, pgCoreInfo, NULL);
    LOGF_DEBUG("-----[PgCore] Find PgContext in pool end.-----\r\n");

    LOGF_DEBUG("-----[PgCore] Find PgContext in physical.-----\r\n");

    PG_OPERATION_CALLBACKS callbacks;
    callbacks.PreCallBack = PgCorePreCallback;
    callbacks.PostCallBack = PgCorePostCallback;
    PgIdpEnumPhysicalMemoryEx(&callbacks, pgCoreInfo);
    
    LOGF_DEBUG("-----[PgCore] Find PgContext in physical end.-----\r\n");

    auto status = STATUS_SUCCESS;

    if(!NT_SUCCESS(status))
        LOGF_ERROR("[PgCore] Enum Physical Memory return 0x%x\r\n", status);

    return status;
}