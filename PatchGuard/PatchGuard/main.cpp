#include "pch.h"

HANDLE g_hLoopFindThread = NULL;
BOOLEAN g_bEndLoopFindThread = false;

PG_CORE_INFO g_pgCoreInfo = { 0 };

void LoopFindPgRoutine(_In_ PVOID StartContext)
{
    while (!g_bEndLoopFindThread)
    {
        PgCoreFindPgContext(&g_pgCoreInfo);

        PgHelperSleep(30 * 1000);
    }

    LOGF_DEBUG("Loop Find Thread exit.\r\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

void WaitLoopFindPgRoutine()
{
    if (g_hLoopFindThread == NULL)
        return;

    PETHREAD pThread = NULL;
    OBJECT_HANDLE_INFORMATION handleInfo = { 0 };

    auto status = ObReferenceObjectByHandle(g_hLoopFindThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pThread, &handleInfo);

    if (NT_SUCCESS(status))
    {
        g_bEndLoopFindThread = true;
        KeWaitForSingleObject(pThread, Executive, KernelMode, TRUE, NULL);
    }

    if (pThread)
        ObDereferenceObject(pThread);

    ZwClose(g_hLoopFindThread);

    g_hLoopFindThread = NULL;
}

void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    WaitLoopFindPgRoutine();

    if (g_pgCoreInfo.LdeAsm)
        ExFreePoolWithTag(g_pgCoreInfo.LdeAsm, 'edlk');

    g_pgCoreInfo.LdeAsm = NULL;

    LogTermination();
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegisterPath)
{
    pDriverObject->DriverUnload = DriverUnload;

    auto status = LogInitialize();

    if (!NT_SUCCESS(status))
    {
        DPRINT("LogInitialize faild : 0x%x\r\n", status);
        return status;
    }

    status = PgCoreinitialization(&g_pgCoreInfo);

    if (!NT_SUCCESS(status))
    {
        LOGF_ERROR("PgCoreinitialization faild : 0x%x\r\n", status);
        LogTermination();
        return status;
    }

    LOGF_DEBUG("PgCoreinitialization success.\r\n");

    status = PsCreateSystemThread(&g_hLoopFindThread, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, LoopFindPgRoutine, nullptr);

    if (!NT_SUCCESS(status))
    {
        LOGF_ERROR("Create Loop Find Routine faild.\r\n");
        LogTermination();
        return status;
    }

    return STATUS_SUCCESS;
}