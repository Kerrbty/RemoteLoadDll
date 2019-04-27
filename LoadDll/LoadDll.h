#ifndef _LOAD_MY_DLL_HEADER_H_
#define _LOAD_MY_DLL_HEADER_H_
#include <Windows.h>
#include <tchar.h>

BOOL WINAPI RemoteInertDllFromFileW(HANDLE hProcess, LPWSTR DllPathName);
BOOL WINAPI RemoteInertDllFromFileA(HANDLE hProcess, LPSTR DllPathName);
BOOL WINAPI RemoteInertDllFromMemory(HANDLE hProcess, LPBYTE DllBuffer, DWORD dwDllSize);

#endif