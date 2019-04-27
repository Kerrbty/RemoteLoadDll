#include <Windows.h>
#include <tchar.h>
#include <string.h>
#include <Tlhelp32.h>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

typedef BOOL (WINAPI* PRemoteInertDllW)(HANDLE hProcess, LPWSTR DllPathName);
typedef BOOL (WINAPI* PRemoteInertDllFromMemory)(HANDLE hProcess, LPBYTE DllBuffer, DWORD dwDllSize);

typedef VOID (* READINFO)(DWORD PID);

BOOL EnableDebugPrivilege(BOOL bEnable = TRUE) 
{ 

    BOOL fOK = FALSE;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) //打开进程访问令牌
    { 
        //试图修改“调试”特权
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        fOK = (GetLastError() == ERROR_SUCCESS);
        CloseHandle(hToken); 
    } 
    return fOK; 
}

VOID pInsertDll(DWORD PID)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    HMODULE hSDll = LoadLibrary(TEXT("LoadDll.dll"));

#if   0
    PRemoteInertDllW remoteloadfile = (PRemoteInertDllW)GetProcAddress(hSDll, "RemoteInertDllFromFileW");
    if (hProcess != NULL && remoteloadfile != NULL)
    {
        WCHAR FileName[512] = {0};
        GetModuleFileNameW(NULL, FileName, MAX_PATH);
        PathRemoveFileSpecW(FileName);
        wcscat(FileName, L"\\Test.dll");
        remoteloadfile(hProcess, FileName);
        CloseHandle(hProcess);
    }
#else
    PRemoteInertDllFromMemory remoteloadmemory = (PRemoteInertDllFromMemory)GetProcAddress(hSDll, "RemoteInertDllFromMemory");
    if (hProcess != NULL && remoteloadmemory != NULL)
    {
        WCHAR FileName[512] = {0};
        GetModuleFileNameW(NULL, FileName, MAX_PATH);
        PathRemoveFileSpecW(FileName);
        wcscat(FileName, L"\\Test.dll");

        HANDLE hDllFile = CreateFileW(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDllFile != INVALID_HANDLE_VALUE)
        {
            DWORD dwBytes = 0;
            DWORD dwDllSzie = GetFileSize(hDllFile, NULL);
            LPBYTE lpDllBuf = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDllSzie);
            if (lpDllBuf != NULL)
            {
                SetFilePointer(hDllFile, 0, NULL, FILE_BEGIN);
                ReadFile(hDllFile, lpDllBuf, dwDllSzie, &dwBytes, NULL);
                CloseHandle(hDllFile);

                remoteloadmemory(hProcess, lpDllBuf, dwDllSzie);

                HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, lpDllBuf);
            }
        }
        CloseHandle(hProcess);
    }
#endif

    FreeLibrary(hSDll);
}

DWORD processNameToId(LPCTSTR lpszProcessName, READINFO CallBackFunc)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe)) 
    {
        return -1;
    }

    while (Process32Next(hSnapshot, &pe)) {
        if (!_tcsicmp(lpszProcessName, pe.szExeFile)) {
            CallBackFunc(pe.th32ProcessID);
        }
    }
    CloseHandle(hSnapshot);
    return 0;
}

typedef HMODULE (WINAPI* PLoadDllFromFileW)(PWSTR szFileName);
int main()
{
    EnableDebugPrivilege();
    processNameToId(TEXT("notepad.exe"), pInsertDll);
    return 0;
}