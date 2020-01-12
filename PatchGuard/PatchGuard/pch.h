#ifndef _PCH_H_
#define _PCH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#include "../../helper/kLog/kLogLib/Log.h"

#include "PgStruct.h"
#include "hash.h"
#include "asm.h"
#include "PgHelper.h"
#include "PgIndependentPages.h"

#include "PgCore.h"

    NTSYSAPI
        NTSTATUS
        NTAPI
        ZwQuerySystemInformation(
            IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
            OUT PVOID                   SystemInformation,
            IN ULONG                    Length,
            OUT PULONG                  ReturnLength
        );

    NTSYSAPI
        PIMAGE_NT_HEADERS
        NTAPI
        RtlImageNtHeader(PVOID Base);

    NTSYSAPI
        ULONG
        NTAPI
        KeCapturePersistentThreadState(
            __in PCONTEXT Context,
            __in_opt PKTHREAD Thread,
            __in ULONG BugCheckCode,
            __in ULONG_PTR BugCheckParameter1,
            __in ULONG_PTR BugCheckParameter2,
            __in ULONG_PTR BugCheckParameter3,
            __in ULONG_PTR BugCheckParameter4,
            __in PDUMP_HEADER DumpHeader
        );

    NTSYSAPI PVOID RtlPcToFileHeader(
        PVOID PcValue,
        PVOID *BaseOfImage
    );

#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif