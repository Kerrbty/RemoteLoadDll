#pragma once

#include "ApiInit.h"

#define USE_VIRTUAL_MEMORY   

#ifdef USE_VIRTUAL_MEMORY
#define AllocMemory(_size)  pRealVirtualAllocEx(pRealGetCurrentProcess(), NULL, _size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
#define FreeMemory(_addr)   pRealVirtualFreeEx(pRealGetCurrentProcess(), _addr, 0, MEM_RELEASE);
#else
#define AllocMemory(_size)  pRealHeapAlloc(pRealGetProcessHeap(), HEAP_ZERO_MEMORY, _size)
#define FreeMemory(_addr)   pRealHeapFree(pRealGetProcessHeap(), HEAP_NO_SERIALIZE, _addr)
#endif

#define DeleteHandle(_a) {if(_a != INVALID_HANDLE_VALUE) { pRealCloseHandle(_a); _a = INVALID_HANDLE_VALUE;}}
#define FileOpenA(_name, _openf, _sharef, _createf)  pRealCreateFileA(_name, _openf, _sharef, NULL, _createf, FILE_ATTRIBUTE_NORMAL, NULL)
#define FileOpenW(_name, _openf, _sharef, _createf)  pRealCreateFileW(_name, _openf, _sharef, NULL, _createf, FILE_ATTRIBUTE_NORMAL, NULL)
// #define CreateKeyEx(_hkey, _lpSubKey, _samDesired, _phkResult, _lpdwDisposition)  pOldRegCreateKeyEx(_hkey, _lpSubKey, 0, NULL, 0, _samDesired, NULL, _phkResult, _lpdwDisposition)


#ifdef _UNICODE
#define FileOpen FileOpenW
#else
#define FileOpen FileOpenA
#endif


#if _MSC_VER < 1400 
extern "C" BOOL WINAPI GetFileSizeEx(HANDLE, PLARGE_INTEGER);
extern "C" BOOL WINAPI SetFilePointerEx(HANDLE, LARGE_INTEGER, PLARGE_INTEGER,DWORD);
#endif


// 多字节转宽字节，内存需要自行释放
__forceinline static PWSTR MulToWide( LPCSTR str )
{
    PWSTR  pElementText;
    int    iTextLen;

    iTextLen = pRealMultiByteToWideChar( CP_ACP,
        0,
        (PCHAR)str,
        -1,
        NULL,
        0 );

    pElementText = (PWSTR)AllocMemory((iTextLen+1)*sizeof(WCHAR));

    pRealMultiByteToWideChar( CP_ACP,
        0,
        (PCHAR)str,
        -1,
        pElementText,
        iTextLen );

    return pElementText;
}

__forceinline static PSTR WideToMul( LPCWSTR str )
{
    PSTR  pElementText;
    int    iTextLen;

    iTextLen = pRealWideCharToMultiByte( CP_ACP,
        0,
        str,
        -1,
        NULL,
        0,
        NULL,
        NULL);

    pElementText = (PSTR)AllocMemory(iTextLen+1 );

    pRealWideCharToMultiByte( CP_ACP,
        0,
        str,
        -1,
        pElementText,
        iTextLen,
        NULL,
        NULL);

    return pElementText;
}