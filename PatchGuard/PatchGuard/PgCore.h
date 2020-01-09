#ifndef _PG_CORE_H_
#define _PG_CORE_H_

typedef struct _PG_CORE_INFO
{
    ULONG NtosInitSizeOfRawData;
    ULONG PgEntryPointRVA;
    ULONG64 PgContextFiled[4];
    ULONG64 PgEntryPointFiled[4];
    ULONG64 PgDbgBreakPointWithStatusFiled[2];
    ULONG64 PgRtlMinimalBarrierFiled[2];
    LDE_DISASM LdeAsm;
}PG_CORE_INFO, *PPG_CORE_INFO;

NTSTATUS PgCoreFindPgContext(PPG_CORE_INFO pgCoreInfo);

NTSTATUS PgCoreinitialization(PPG_CORE_INFO pgCoreInfo);

#endif