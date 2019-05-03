#include <stdio.h>
#include <Windows.h>

#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#pragma comment(linker, "/ENTRY:wmainCRTStartup /SUBSYSTEM:Windows")

int wmain(int argc, wchar_t **argv)
{
	if (argc != 2)
		return -1;

	WCHAR lpPath[260] = { 0 };
	GetModuleFileName(NULL, lpPath, 260);
	PathRemoveFileSpec(lpPath);
	lstrcat(lpPath, L"\\Hooker.dll");

	DWORD dwCache;
	STARTUPINFO Si = { sizeof(Si) };
	PROCESS_INFORMATION Pi = { 0 };
	CreateProcess(argv[1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi);
	auto lpAddr = VirtualAllocEx(Pi.hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(Pi.hProcess, lpAddr, lpPath, 520, &dwCache);
	HANDLE hThread = CreateRemoteThread(Pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, lpAddr, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	ResumeThread(Pi.hThread);
	return 0;
}