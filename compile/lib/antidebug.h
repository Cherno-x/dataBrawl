#pragma once
#include <Windows.h>
#include <winternl.h>
#include "iatobfus.h"

typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

BOOL NtQIPDebuggerCheck() {

	NTSTATUS						STATUS						= 0;
	fnNtQueryInformationProcess		pNtQueryInformationProcess	= NULL;
	DWORD_PTR 						dwIsDebuggerPresent			= 0;
	DWORD_PTR 						hProcessDebugObject			= 0;

	// getting NtQueryInformationProcess address
	pNtQueryInformationProcess = (fnNtQueryInformationProcess)MyGetProcAddress(MyGetModuleHandle(L"NTDLL.DLL"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		return FALSE;
	}

	// calling NtQueryInformationProcess with the 'ProcessDebugPort' flag
	STATUS = pNtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessDebugPort,
		&dwIsDebuggerPresent,
		sizeof(DWORD64),
		NULL
	);

	// if STATUS is not
	if (STATUS != 0x0) {
		return FALSE;
	}

	// if NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
	if (dwIsDebuggerPresent != 0) {
		//printf("\n\t[i] NtQueryInformationProcess [1] - ProcessDebugPort Detected A Debugger \n");
		return TRUE;
	}

	// calling NtQueryInformationProcess with the 'ProcessDebugObjectHandle' flag
	STATUS = pNtQueryInformationProcess(
		GetCurrentProcess(),
		(PROCESSINFOCLASS)30,
		&hProcessDebugObject,
		sizeof(DWORD64),
		NULL
	);

	// if STATUS is not 0 and not 0xC0000353 (that is 'STATUS_PORT_NOT_SET')
	if (STATUS != 0x0 && STATUS != 0xC0000353) {
		//printf("\n\t[!] NtQueryInformationProcess [2] Failed With Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// if NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
	if (hProcessDebugObject != 0) {
		//printf("\n\t[i] NtQueryInformationProcess [w] - hProcessDebugObject Detected A Debugger \n");
		return TRUE;
	}

	return FALSE;
}
