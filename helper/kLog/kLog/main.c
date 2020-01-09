#include "pch.h"

void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    LogTermination();
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegisterPath)
{
    DPRINT("driver loaded.\n");

    if (!NT_SUCCESS(LogInitialize()))
        DPRINT("LogInitialize faild.\n");

    LOGF_INFO("driver loaded.");

    pDriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}