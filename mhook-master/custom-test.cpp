/*#include <windows.h>
#include <stdio.h>
#include <psapi.h>*/
#include <tchar.h>
#include "stdafx.h"
#include "mhook-lib/mhook.h"

//define structure required to interface with OpenProcess and properly provide params
typedef struct _CLIENT_ID {
	DWORD_PTR UniqueProcess;
	DWORD_PTR UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
//typedef the signature of to-hook fxn
typedef ULONG (WINAPI* _NtOpenProcess)(OUT PHANDLE ProcessHandle, 
		 IN ACCESS_MASK AccessMask, IN PVOID ObjectAttributes, 
		 IN PCLIENT_ID ClientId );
//get process address of OpenProcess, cast to custom signature fxn ptr type
_NtOpenProcess TrueNtOpenProcess = (_NtOpenProcess) GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess");
//define hook fxn to overwrite OpenProcess
	//WINAPI is a macro for Windows compilers indicating the call standard to use (since non-UNIX, esp Windows, systems frequently feature multiple competing call standards)
	//this is a compiler hint, and not part of the C(PP) PL
ULONG WINAPI NTOProcHook1(OUT PHANDLE ProcessHandle, IN ACCESS_MASK AccessMask, IN PVOID ObjectAttributes, IN PCLIENT_ID ClientId ) {
	ULONG ret;
	printf("Intercepted NtOpenProcess with ObjectAttributes @%lx\n", ObjectAttributes);
	//unhook, passthru, rehook
	Mhook_Unhook((PVOID*)&TrueNtOpenProcess);
	ret = TrueNtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);
	Mhook_SetHook((PVOID*)&TrueNtOpenProcess, NTOProcHook1);
	return ret;
}
ULONG WINAPI NTOProcHook2(OUT PHANDLE ProcessHandle, IN ACCESS_MASK AccessMask, IN PVOID ObjectAttributes, IN PCLIENT_ID ClientId ) {
	ULONG ret;
	printf("Intercepted NtOpenProcess with ObjectAttributes @%lx\n", ObjectAttributes);
	//direct passthru, no hook management
	ret = TrueNtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);
	return ret;
}

/*
//credit https://gist.github.com/baiyanhuang/902894
HANDLE GetProcessByName(const TCHAR* szProcessName) {
		if(szProcessName == NULL) return NULL;

		DWORD aProcesses[1024], cbNeeded, cProcesses;
		if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
				return NULL;

		// Calculate how many process identifiers were returned.
		cProcesses = cbNeeded / sizeof(DWORD);

		// Print the name and process identifier for each process.
		for ( unsigned int i = 0; i < cProcesses; i++ ) {
				DWORD dwProcessID = aProcesses[i];
				// Get a handle to the process.
				HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessID );

				// Get the process name.
				TCHAR szEachProcessName[MAX_PATH];
				if (NULL != hProcess) {
						HMODULE hMod;
						DWORD cbNeeded;

						if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
								GetModuleBaseName( hProcess, hMod, szEachProcessName, sizeof(szEachProcessName)/sizeof(TCHAR) );
						}
				}

				if (!_tcscmp(szProcessName, szEachProcessName)) return hProcess;

				CloseHandle( hProcess );
		}

		return NULL;
}
*/
int wmain(int argc, WCHAR* argv[]) {
	HANDLE hProc = NULL;
	ULONG true_ntoproc, curr_ntoproc;
	UCHAR i;
	
	if ((argc < 2) || wcstol(argv[1],0,10)==1) {
//Test1
	//Hook1
	//set the hook
	Mhook_SetHook((PVOID*)&TrueNtOpenProcess, NTOProcHook1);
	//examine addresses of TrueNtOpenProcess, current address found when resolving NtOpenProcess, and address of NTOProcHook
	true_ntoproc = (ULONG) TrueNtOpenProcess;
	curr_ntoproc = (ULONG) GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess"); //casting FARPROC to ULONG, probably fine
	printf("True NtOpenProcess: %lx\nCurrent NtOpenProcess: %lx\nNtOProc_Hook1: %lx\n", true_ntoproc, curr_ntoproc, (ULONG)NTOProcHook1);
	//get proc handle, which should see OpenProcess calling our now-hooked NtOpenProcess -> NTOProcHook1
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	//hProc = GetProcessByName((TCHAR*)"Notepad.exe"); //will call OpenProcess multiple times
	//optional: use handle
	printf("PID: %d\n", GetProcessId(hProc));
	//close handle, unset hook
	CloseHandle(hProc);
	Mhook_Unhook((PVOID*)&TrueNtOpenProcess);

	//Hook2
	//set hook, this time to NTOProcHook2
	Mhook_SetHook((PVOID*)&TrueNtOpenProcess, NTOProcHook2);
	//examine
	true_ntoproc = (ULONG) TrueNtOpenProcess;
	curr_ntoproc = (ULONG) GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess"); //casting FARPROC to ULONG, probably fine
	printf("True NtOpenProcess: %lx\nCurrent NtOpenProcess: %lx\nNtOProc_Hook2: %lx\n", true_ntoproc, curr_ntoproc, (ULONG)NTOProcHook2);
	//use new hook
	hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, 1340);
	//hProc = GetProcessByName((TCHAR*)"Notepad.exe"); //will call OpenProcess multiple times
	//optional: use handle
	printf("PID: %d\n", GetProcessId(hProc));
	//close handle, unset hook
	CloseHandle(hProc);
	Mhook_Unhook((PVOID*)&TrueNtOpenProcess);
	
	} else {
//Test2
	//I see movement, so let's see if there's some kind of degradation that takes place across multiple rehooks
	//none apparent in where GetProcAddress will resolve the fxn address during or after rehooks
	//BUT we do see a change, (iterative or first-time-only), between the true original address and the during&post-hook address

	//pre-hook
	true_ntoproc = (ULONG) TrueNtOpenProcess;
	curr_ntoproc = (ULONG) GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess");
	printf("*Pre-Hook*\nTrue NtOpenProcess: %lx\nCurrent NtOpenProcess: %lx\n", true_ntoproc, curr_ntoproc);

	//first hook
	Mhook_SetHook((PVOID*)&TrueNtOpenProcess, NTOProcHook2);
	curr_ntoproc = (ULONG) GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess");
	printf("*First Hook*\nTrueNtOpenProcess: %lx\nCurrent NtOpenProcess: %lx\n", true_ntoproc, curr_ntoproc);
	//use
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	curr_ntoproc = (ULONG) GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess");
	printf("*First Hook, Post-Use*\nTrueNtOpenProcess: %lx\nCurrent NtOpenProcess: %lx\n", true_ntoproc, curr_ntoproc);

	//post-hook
	Mhook_Unhook((PVOID*)&TrueNtOpenProcess);
	curr_ntoproc = (ULONG) GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess");
	printf("*Post-Hook*\nTrueNtOpenProcess: %lx\nCurrent NtOpenProcess: %lx\n", true_ntoproc, curr_ntoproc);
	//use
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());

	//rehooking
	printf("*Rehooking (Showing Post-Rehook)*\n");
	for (i=0; i<10; i++) {
		Mhook_SetHook((PVOID*)&TrueNtOpenProcess, NTOProcHook2);
		//printf("Current (while hooked) NtOpenProcess: %lx\n", (ULONG) GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess"));
		Mhook_Unhook((PVOID*)&TrueNtOpenProcess);
		//printf("Current (post-hook) NtOpenProcess: %lx\n", (ULONG) GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess"));
		curr_ntoproc = (ULONG) GetProcAddress(GetModuleHandle(L"ntdll"), "NtOpenProcess");
		printf("TrueNtOpenProcess: %lx, Current NtOpenProcess: %lx\n", true_ntoproc, curr_ntoproc);
	}

	printf("done\n");

	}
}

