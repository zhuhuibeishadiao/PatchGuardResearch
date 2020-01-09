#ifndef _PG_INDEPENDENT_PAGES_H_
#define _PG_INDEPENDENT_PAGES_H_

typedef BOOLEAN(NTAPI *ENUMPHYSICALCALLBACK)(PVOID Va, SIZE_T size, PVOID context);

NTSTATUS PgIdpInitialization();

BOOLEAN PgIdpMmIsExecutebleAddress(PVOID Address);

BOOLEAN PgIdpMmIsAccessibleAddress(PVOID Address);

NTSTATUS PgIdpEnumPhysicalMemory(ENUMPHYSICALCALLBACK callback, PVOID context);

#endif
