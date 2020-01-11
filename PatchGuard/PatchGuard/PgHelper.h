#ifndef _PG_HELPER_H_
#define _PG_HELPER_H_

typedef BOOLEAN(NTAPI *ENUMMEMORYCALLBACK)(BOOLEAN bNonPagedPool, PVOID Va, SIZE_T size, UCHAR tag[4], PVOID context);

typedef int(*LDE_DISASM)(void *p, int dw);

PVOID PgHelperGetSystemInformation(SYSTEM_INFORMATION_CLASS InfoClass);

NTSTATUS PgHelperEnumBigPool(ENUMMEMORYCALLBACK callback, PVOID context, PVOID* lpPoolInfo);

ULONG_PTR PgHelperGetRoutineName(wchar_t* szName);

void PgHelperSleep(LONG msec);

PVOID PgHelperGetLDE();

PIMAGE_SECTION_HEADER PgHelperGetSection(PCCHAR sectionName, PVOID base);

//  π”√ZwUnmapViewOfSection Õ∑≈ ZwCurrentProcess
NTSTATUS PgHelperMapFile(wchar_t* szFileName, PVOID* lpMapped);

NTSTATUS PgHelperScanSection(IN PCCHAR sectionName,
    IN PVOID base,
    IN UCHAR* pFeatureCode,
    IN ULONG FeatureCodeNum,
    IN UCHAR SegCode,
    IN LONG AddNum,
    __in_opt PVOID* ptr);

PVOID PgHelperGetUndocumentFunctionAddress(
    IN PUNICODE_STRING pFunName,
    IN PUCHAR pStartAddress,
    IN UCHAR* pFeatureCode,
    IN ULONG FeatureCodeNum,
    ULONG SerSize,
    UCHAR SegCode,
    LONG AddNum,
    BOOLEAN ByName);

PVOID PgHelperGetNtosBase();

#ifndef RvaToVa
#define RvaToVa(p) \
            ((PVOID)((PCHAR)(ULONG_PTR)(p) + \
                *(PLONG)(ULONG_PTR)(p) + \
                sizeof(LONG)))
#endif // !RvaToVa

#endif