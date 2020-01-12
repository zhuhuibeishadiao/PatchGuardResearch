#ifndef _Hash_H
#define _Hash_H

typedef unsigned char BYTE;
typedef unsigned long DWORD;
typedef unsigned short WORD;

typedef struct _DATA
{
    POOL_TYPE poolType;
    SIZE_T size;
    ULONG_PTR Va;
    ULONG_PTR base;
} DATA, *PDATA;

typedef struct _TWOWAY
{
    ULONG_PTR key;
    DATA data;
    LIST_ENTRY linkfield;
} TWOWAY, *PTWOWAY;

typedef struct _HASHTABLE
{
    unsigned int tableSize;
    PLIST_ENTRY *pListHeads;
} HASHTABLE, *PHASHTABLE;

PHASHTABLE HbInitializeTable(unsigned int tableSize);

void HbInsert(ULONG_PTR key, PDATA pData, PHASHTABLE pHashTable);

void HbRemove(ULONG_PTR key, PHASHTABLE pHashTable);

void HbDestroyTable(PHASHTABLE pHashTable);

ULONG HbDumpTable(PHASHTABLE pHashTable);

PDATA HbFindHashTable(ULONG_PTR key, PHASHTABLE pHashTable);


#endif // _Hash_H