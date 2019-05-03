#include <stdio.h>
#include <Windows.h>

#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#include "detours.h"
#pragma comment(lib, "detours.lib")

HRSRC(WINAPI *TrueFindResourceA)(HMODULE hModule, LPCSTR lpName, LPCSTR lpType) = FindResourceA;
typedef BOOL(*DecryptFunc)(LPVOID u1, LPVOID lpBuff, LPVOID lpData, DWORD uSize);
BOOL HookDecryptFunc(LPVOID u1, LPVOID lpBuff, LPVOID lpData, DWORD uSize);

DecryptFunc TrueDecryptFunc;

void DumpAndRestore(LPVOID lpBuff, DWORD uSize)
{
	WCHAR pBuff[260];
	GetModuleFileName(NULL, pBuff, 260);
	PathRemoveExtension(pBuff);
	StrCat(pBuff, L"_dump.exe");

	DWORD uCache;
	HANDLE hFile = CreateFile(pBuff, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	WriteFile(hFile, lpBuff, uSize - 16, &uCache, NULL);
	CloseHandle(hFile);

	MessageBox(NULL, L"íÒéÊäÆê¨ÅCë¶õíåãë©íˆéÆÅB", L"", MB_ICONINFORMATION | MB_TOPMOST);
	ExitProcess(0);
}

BOOL HookDecryptFunc(LPVOID u1, LPVOID lpBuff, LPVOID lpData, DWORD uSize)
{
	TrueDecryptFunc(u1, lpBuff, lpData, uSize);
	DumpAndRestore(lpBuff, uSize);
	return TRUE;
}

HRSRC WINAPI HookFindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType)
{
	if (lpName == (LPCSTR)202)
	{
		auto hBase = (PBYTE)GetModuleHandle(NULL);
		MEMORY_BASIC_INFORMATION pMemInfo;
		VirtualQuery(hBase + 0x1000, &pMemInfo, sizeof(pMemInfo));
		for (size_t i = 0; i < pMemInfo.RegionSize; i++) {
			if (memcmp(hBase + i, "\x8B\x44\x24\x04\x8B\x48\x08\x51\x8B\x4C\x24\x14", 12) == 0) {
				TrueDecryptFunc = (DecryptFunc)(hBase + i);
				DetourTransactionBegin();
				DetourAttach(&(LPVOID&)TrueDecryptFunc, HookDecryptFunc);
				DetourDetach(&(LPVOID&)TrueFindResourceA, HookFindResourceA);
				DetourTransactionCommit();
				break;
			}
		}
	}
	return TrueFindResourceA(hModule, lpName, lpType);
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DetourTransactionBegin();
		DetourAttach(&(LPVOID&)TrueFindResourceA, HookFindResourceA);
		DetourTransactionCommit();
	}
	return TRUE;
}