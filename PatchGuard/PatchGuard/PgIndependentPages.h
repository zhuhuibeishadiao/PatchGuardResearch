#ifndef _PG_INDEPENDENT_PAGES_H_
#define _PG_INDEPENDENT_PAGES_H_

NTSTATUS PgIdpEnumIndependentPages(ENUMMEMORYCALLBACK callback, PVOID context);

NTSTATUS PgIdpInitialization();

#endif
