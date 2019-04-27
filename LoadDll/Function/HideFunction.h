#ifndef _HIDE_FUNCTION_IN_ANVIRUS_HEADER_H_
#define _HIDE_FUNCTION_IN_ANVIRUS_HEADER_H_
#include <Windows.h>
#include <tchar.h>

#define  KERNEL32    0x52E7FDC2    // "Kernel32.dll" 
#define  USER32      0x66268A98    // "User32.dll" 
#define  NTDLL       0x71435F4E    // "ntdll.dll" 
#define  SHLWAPI     0x77C88702    // "shlwapi.dll"
#define  ADVAPI32    0x47D7425E    // "Advapi32.dll"
#define  GDI32       0x4c68253f    // "Gdi32.dll 
#define  SHELL32     0x43cf1b57    // "Shell32.dll"
#define  VERSION     0x7f077b4a    // "Version.dll"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void SetZero(PVOID pAddr, int sz);

DWORD GetStringHash(PSTR FuncName);

PVOID GetProcAddr(HMODULE hmodule, DWORD hash);

HMODULE LoadDll(DWORD hash);




#ifdef __cplusplus
};
#endif // __cplusplus

#endif  // _HIDE_FUNCTION_IN_ANVIRUS_HEADER_H_ 