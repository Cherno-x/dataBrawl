#pragma once
#include <Windows.h>
#include <stdio.h>

#define TMPFILE	L"temp.tmp"

#define SECTOSTRESS(i)( (int)i * 196 )


BOOL ApiHammering(DWORD dwStress) {

	WCHAR		szPath						[MAX_PATH * 2],
				szTmpPath					[MAX_PATH];

	HANDLE		hRFile						= INVALID_HANDLE_VALUE,
				hWFile						= INVALID_HANDLE_VALUE;
	
	DWORD		dwNumberOfBytesRead			= 0,
				dwNumberOfBytesWritten		= 0;
	
	PBYTE		pRandBuffer					= NULL;
	SIZE_T		sBufferSize					= 0xFFFFF;	// 1048575 byte
	
	INT			Random						= 0;

	// getting the tmp folder path
	if (!GetTempPathW(MAX_PATH, szTmpPath)) {
		return FALSE;
	}

	for (SIZE_T i = 0; i < dwStress; i++){

		// creating the file in write mode
		if ((hWFile = CreateFileW(szPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL)) == INVALID_HANDLE_VALUE) {
			return FALSE;
		}

		// allocating a buffer and filling it with a random value
		pRandBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBufferSize);
		Random = rand() % 0xFF;
		memset(pRandBuffer, Random, sBufferSize);

		// writing the random data into the file
		if (!WriteFile(hWFile, pRandBuffer, sBufferSize, &dwNumberOfBytesWritten, NULL) || dwNumberOfBytesWritten != sBufferSize) {
			return FALSE;
		}

		// clearing the buffer & closing the handle of the file
		RtlZeroMemory(pRandBuffer, sBufferSize);
		CloseHandle(hWFile);

		// opennig the file in read mode & delete when closed
		if ((hRFile = CreateFileW(szPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
			return FALSE;
		}

		// reading the random data written before 	
		if (!ReadFile(hRFile, pRandBuffer, sBufferSize, &dwNumberOfBytesRead, NULL) || dwNumberOfBytesRead != sBufferSize) {
			return FALSE;
		}

		// clearing the buffer & freeing it
		RtlZeroMemory(pRandBuffer, sBufferSize);
		HeapFree(GetProcessHeap(), 0, pRandBuffer);

		// closing the handle of the file - deleting it
		CloseHandle(hRFile);
	}


	return TRUE;
}

