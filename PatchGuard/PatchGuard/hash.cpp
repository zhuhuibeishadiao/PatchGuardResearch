#include "pch.h"

#define DRIVERTAG1 'HSAH'

PNPAGED_LOOKASIDE_LIST pLookasideList_TWOWAY = NULL;

/* Return next prime; assume N >= 10 */
static unsigned int HbNextPrime(int N)
{
    int i;


    if (N % 2 == 0)
        N++;
    for (; ; N += 2)
    {
        for (i = 3; i * i <= N; i += 2)
            if (N % i == 0)
                goto ContOuter;  /* Sorry about this! */
        return N;
    ContOuter:;
    }
}

unsigned int HbHash(ULONG_PTR key, unsigned int tableSize)
{
    return key % tableSize;
}

PHASHTABLE HbInitializeTable(unsigned int tableSize)
{
    PHASHTABLE pHashTable = NULL;
    PTWOWAY pNode = NULL;
    unsigned int i;


    // Allocate space for the hashtable
    pHashTable = (PHASHTABLE)ExAllocatePoolWithTag(NonPagedPool, sizeof(HASHTABLE), DRIVERTAG1);
    if (pHashTable == NULL)
    {
        DPRINT("ExAllocatePoolWithTag returned NULL!\n");
        return NULL;
    }


    pHashTable->tableSize = HbNextPrime(tableSize);


    // Allocate array of pointers to linkedlists 
    pHashTable->pListHeads = (PLIST_ENTRY*)ExAllocatePoolWithTag(NonPagedPool, sizeof(PLIST_ENTRY) * pHashTable->tableSize, DRIVERTAG1);
    if (pHashTable->pListHeads == NULL)
    {
        DPRINT("ExAllocatePoolWithTag returned NULL!\n");
        return NULL;
    }


    // Allocate space for the lookaside list for the TWOWAY-structures.
    pLookasideList_TWOWAY = (PNPAGED_LOOKASIDE_LIST)ExAllocatePoolWithTag(NonPagedPool, sizeof(NPAGED_LOOKASIDE_LIST), DRIVERTAG1);
    if (pLookasideList_TWOWAY == NULL)
    {
        DPRINT("ExAllocatePoolWithTag returned NULL!\n");
        return NULL;
    }


    // Initialize the lookaside list.
    ExInitializeNPagedLookasideList(
        pLookasideList_TWOWAY,
        NULL,
        NULL,
        0,
        sizeof(TWOWAY),
        DRIVERTAG1,
        0);


    // Allocate empty nodes for the each linked list.
    for (i = 0; i < pHashTable->tableSize; i++)
    {
        pNode = (PTWOWAY)ExAllocateFromNPagedLookasideList(pLookasideList_TWOWAY);
        if (pNode == NULL)
        {
            DPRINT("ExAllocateFromNPagedLookasideList returned NULL!\n");
            return NULL;
        }
        else
        {
            pNode->key = 0x00000000;
            RtlZeroMemory(&pNode->data, sizeof(DATA));
            InitializeListHead(&pNode->linkfield);
        }
        pHashTable->pListHeads[i] = &pNode->linkfield;
    }


    return pHashTable;
}

PTWOWAY HbFind(ULONG_PTR key, PHASHTABLE pHashTable)
{
    PTWOWAY pNode = NULL;
    PLIST_ENTRY pListHead = NULL;
    PLIST_ENTRY pListLink = NULL;


    pListHead = pListLink = pHashTable->pListHeads[HbHash(key, pHashTable->tableSize)];
    if (pListHead == NULL)
    {
        DPRINT("pListHead is NULL!\n");
        return NULL;
    }


    if (!IsListEmpty(pListHead))
    {
        do
        {
            pNode = CONTAINING_RECORD(pListLink, TWOWAY, linkfield);
            if (pNode->key == key)
            {
                return pNode;
            }
            pListLink = pListLink->Flink;
        } while (pListLink != pListHead);
    }


    return NULL;
}

PDATA HbFindHashTable(ULONG_PTR key, PHASHTABLE pHashTable)
{
    auto p = HbFind(key, pHashTable);

    if (p == nullptr)
        return nullptr;

    return &p->data;
}

void HbInsert(ULONG_PTR key, PDATA pData, PHASHTABLE pHashTable)
{
    PTWOWAY pNode = NULL;
    PTWOWAY pNewNode = NULL;
    PLIST_ENTRY pListHead = NULL;


    pNode = HbFind(key, pHashTable);
    // The node with the given key was not found.
    if (pNode == NULL)
    {
        pNewNode = (PTWOWAY)ExAllocateFromNPagedLookasideList(pLookasideList_TWOWAY);
        if (pNewNode == NULL)
        {
            DPRINT("ExAllocateFromNPagedLookasideList returned NULL!\n");
            return;
        }

        // Insert the data to the node.
        pNewNode->key = key;
        pNewNode->data.base = pData->base;
        pNewNode->data.poolType = pData->poolType;
        pNewNode->data.Va = pData->Va;
        pNewNode->data.size = pData->size;


        // Insert the node to the doubly-linked list.
        pListHead = pHashTable->pListHeads[HbHash(key, pHashTable->tableSize)];
        InsertTailList(pListHead, &pNewNode->linkfield);
    }
}

void HbRemove(ULONG_PTR key, PHASHTABLE pHashTable)
{
    PTWOWAY pNode = NULL;
    PLIST_ENTRY pListHead = NULL;

    pNode = HbFind(key, pHashTable);
    // The node with the given key was found.
    if (pNode != NULL)
    {
        RemoveEntryList(&pNode->linkfield);
        ExFreeToNPagedLookasideList(pLookasideList_TWOWAY, pNode);
    }
}

void HbDestroyTable(PHASHTABLE pHashTable)
{
    PTWOWAY pNode = NULL;
    PTWOWAY pTmpNode = NULL;
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
                ExFreeToNPagedLookasideList(pLookasideList_TWOWAY, pNode);
            } while (pListLink != pListHead);
        }
        else
        {
            pNode = CONTAINING_RECORD(pListHead, TWOWAY, linkfield);
            ExFreeToNPagedLookasideList(pLookasideList_TWOWAY, pNode);
        }
    }


    ExDeleteNPagedLookasideList(pLookasideList_TWOWAY);
    ExFreePoolWithTag(pLookasideList_TWOWAY, DRIVERTAG1);
    ExFreePoolWithTag(pHashTable->pListHeads, DRIVERTAG1);
    ExFreePoolWithTag(pHashTable, DRIVERTAG1);
}


ULONG HbDumpTable(PHASHTABLE pHashTable)
{
    PTWOWAY pNode = NULL;
    PLIST_ENTRY pListHead = NULL;
    PLIST_ENTRY pListLink = NULL;
    unsigned int i;
    ULONG total = 0;


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
                    LOGF_DEBUG("key:%p    base:%p    Va:%p    size:%p    type:%d\n", pNode->key, pNode->data.base, pNode->data.Va, pNode->data.size, pNode->data.poolType);
                    total++;
                }
            } while (pListLink != pListHead);
        }
    }
    return total;
}
