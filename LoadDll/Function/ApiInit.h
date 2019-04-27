#ifndef __API_HEADER_FILE_HEADER_HH_H__
#define __API_HEADER_FILE_HEADER_HH_H__
#include <Windows.h>
#include <tchar.h>
#define EXT_FUNC(_fnc)  extern P##_fnc pReal##_fnc

// Kernel32.dll
typedef HMODULE (WINAPI* PGetModuleHandleA)( LPCSTR );
typedef HMODULE (WINAPI* PGetModuleHandleW)( LPCWSTR );
typedef BOOL (WINAPI* PTerminateProcess)(HANDLE, UINT);
typedef VOID (WINAPI* PExitProcess)(UINT);
typedef HANDLE (WINAPI* PGetProcessHeap)(VOID);
typedef LPVOID (WINAPI* PHeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL (WINAPI* PHeapFree)(HANDLE, DWORD,  LPVOID);
typedef BOOL (WINAPI* PCloseHandle)(  HANDLE );
typedef HANDLE (WINAPI* PCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI* PCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD (WINAPI* PGetFileSize)(HANDLE, LPDWORD);
typedef BOOL (WINAPI* PGetFileSizeEx)(HANDLE, LARGE_INTEGER);
typedef LPSTR (WINAPI* PGetCommandLineA)(VOID);
typedef LPWSTR (WINAPI* PGetCommandLineW)(VOID);
typedef VOID (WINAPI* PExitProcess)(UINT);
typedef FARPROC (WINAPI* PGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI* PLoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI* PLoadLibraryW)(LPCWSTR);
typedef HANDLE (WINAPI* PGetCurrentProcess)(VOID);
typedef DWORD (WINAPI* PGetModuleFileNameA)(HMODULE, LPSTR, DWORD);
typedef DWORD (WINAPI* PGetModuleFileNameW)(HMODULE, LPWSTR, DWORD);
typedef int (WINAPI* PMultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
typedef int (WINAPI* PWideCharToMultiByte)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBYTE);
typedef DWORD (WINAPI* PSetFilePointer)(HANDLE, LONG, PLONG, DWORD);
typedef BOOL (WINAPI* PReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef DWORD (WINAPI* PExpandEnvironmentStringsA)(LPCSTR, LPSTR, DWORD);
typedef DWORD (WINAPI* PExpandEnvironmentStringsW)(LPCWSTR, LPWSTR, DWORD);
typedef LPVOID (WINAPI* PVirtualAllocEx)(HANDLE , LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* PVirtualFreeEx)( HANDLE, LPVOID, SIZE_T, DWORD);
typedef HANDLE (WINAPI* PCreateFileMappingA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef HANDLE (WINAPI* PCreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID (WINAPI* PMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL (WINAPI *PUnmapViewOfFile)(LPVOID);
typedef BOOL (WINAPI* PVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI* PCreateThread)(LPSECURITY_ATTRIBUTES, DWORD, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD (WINAPI* PWaitForSingleObject)(HANDLE, DWORD);
typedef HANDLE (WINAPI* POpenProcess)(DWORD, BOOL, DWORD);
typedef HANDLE (WINAPI* PCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI* PGetModuleHandleExA)(DWORD, LPCSTR, HMODULE*);
typedef BOOL (WINAPI* PGetModuleHandleExW)(DWORD, LPCWSTR, HMODULE*);
typedef BOOL (WINAPI* PWriteProcessMemory)(HANDLE, LPVOID, LPVOID, DWORD, LPDWORD);

// User32.dll 
typedef int (WINAPI* PMessageBoxA)( HWND, LPCTSTR, LPCSTR, UINT );
typedef int (WINAPI* PMessageBoxW)( HWND, LPCTSTR, LPCWSTR, UINT );
typedef INT (WINAPI* PDialogBoxParamA)( HINSTANCE, LPCSTR, HWND, DLGPROC, LPARAM);
typedef INT (WINAPI* PDialogBoxParamW)( HINSTANCE, LPCWSTR, HWND, DLGPROC, LPARAM);
typedef BOOL (WINAPI* PSetWindowTextA)(HWND, LPCSTR);
typedef BOOL (WINAPI* PSetWindowTextW)(HWND, LPCWSTR);
typedef LONG (WINAPI* PGetWindowLongA)(HWND, int);
typedef LONG (WINAPI* PGetWindowLongW)(HWND, int);
typedef LONG (WINAPI* PSetWindowLongA)(HWND, int, LONG);
typedef LONG (WINAPI* PSetWindowLongW)(HWND, int, LONG);
typedef BOOL (WINAPI* PSetLayeredWindowAttributes)(HWND, COLORREF, BYTE, DWORD);
typedef HANDLE (WINAPI* PLoadImageA)(HINSTANCE, LPCSTR, UINT, int, int, UINT);
typedef HANDLE (WINAPI* PLoadImageW)(HINSTANCE, LPCWSTR, UINT, int, int, UINT);
typedef HDC (WINAPI* PGetDC)(HWND);
typedef int (WINAPI* PReleaseDC)(HWND, HDC hDC);
typedef LRESULT (WINAPI* PSendMessageA)(HWND, UINT, WPARAM, LPARAM);
typedef LRESULT (WINAPI* PSendMessageW)(HWND, UINT, WPARAM, LPARAM);
typedef HWND (WINAPI* PGetDlgItem)(HWND, int);
typedef BOOL (WINAPI* PEndDialog)(HWND, INT_PTR);
typedef BOOL (WINAPI* PInvalidateRect)(HWND, CONST RECT *,BOOL);
typedef BOOL (WINAPI* PGetClientRect)(HWND, LPRECT);
typedef HBITMAP (WINAPI* PLoadBitmapA)(HINSTANCE, LPCSTR);
typedef HBITMAP (WINAPI* PLoadBitmapW)(HINSTANCE, LPCWSTR);


// Gdi32.dll
typedef HDC (WINAPI* PCreateCompatibleDC)(HDC);
typedef HGDIOBJ (WINAPI* PSelectObject)(HDC, HGDIOBJ);
typedef int (WINAPI* PGetObjectA)(HGDIOBJ, int, LPVOID);
typedef int (WINAPI* PGetObjectW)(HGDIOBJ, int, LPVOID);
typedef BOOL (WINAPI* PDeleteDC)(HDC);
typedef int (WINAPI* PSetStretchBltMode)(HDC, int);
typedef BOOL (WINAPI* PStretchBlt)(HDC, int, int, int, int, HDC, int, int, int, int, DWORD);
typedef BOOL (WINAPI* PTextOutA)(HDC, int, int, LPCSTR, int);
typedef BOOL (WINAPI* PTextOutW)(HDC, int, int, LPCWSTR, int);
typedef HGDIOBJ (WINAPI* PGetStockObject)(int);


// ADVAPI32.DLL
typedef BOOL (WINAPI* PAllocateAndInitializeSid)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID*);
typedef BOOL (WINAPI* PCheckTokenMembership)(HANDLE, PSID, PBOOL );
typedef PVOID (WINAPI* PFreeSid)(PSID);
typedef BOOL (WINAPI* PGetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef BOOL (WINAPI* POpenProcessToken)(HANDLE, DWORD, PHANDLE);

// Shell32.dll
typedef BOOL (WINAPI* PShellExecuteExA)(LPSHELLEXECUTEINFOA);
typedef BOOL (WINAPI* PShellExecuteExW)(LPSHELLEXECUTEINFOW);


// Version.dll
typedef DWORD (WINAPI* PGetFileVersionInfoSizeA)(LPSTR, LPDWORD);
typedef DWORD (WINAPI* PGetFileVersionInfoSizeW)(LPWSTR, LPDWORD);
typedef BOOL (WINAPI* PGetFileVersionInfoA)(LPSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI* PGetFileVersionInfoW)(LPWSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI* PVerQueryValueA)(const LPVOID, LPTSTR, LPVOID *, PUINT);
typedef BOOL (WINAPI* PVerQueryValueW)(const LPVOID, LPTSTR, LPVOID *, PUINT);


// Kernel32.dll
EXT_FUNC(GetModuleHandleA);
EXT_FUNC(GetModuleHandleW);
EXT_FUNC(TerminateProcess);
EXT_FUNC(ExitProcess);
EXT_FUNC(GetProcessHeap);
EXT_FUNC(HeapAlloc);
EXT_FUNC(HeapFree);
EXT_FUNC(CloseHandle);
EXT_FUNC(CreateFileA);
EXT_FUNC(CreateFileW);
EXT_FUNC(GetFileSize);
EXT_FUNC(GetFileSizeEx);
EXT_FUNC(GetCommandLineA);
EXT_FUNC(GetCommandLineW);
EXT_FUNC(GetProcAddress);
EXT_FUNC(LoadLibraryA);
EXT_FUNC(LoadLibraryW);
EXT_FUNC(GetCurrentProcess);
EXT_FUNC(GetModuleFileNameA);
EXT_FUNC(GetModuleFileNameW);
EXT_FUNC(MultiByteToWideChar);
EXT_FUNC(WideCharToMultiByte);
EXT_FUNC(SetFilePointer);
EXT_FUNC(ReadFile);
EXT_FUNC(ExpandEnvironmentStringsA);
EXT_FUNC(ExpandEnvironmentStringsW);
EXT_FUNC(VirtualAllocEx);
EXT_FUNC(VirtualFreeEx);
EXT_FUNC(CreateFileMappingA);
EXT_FUNC(CreateFileMappingW);
EXT_FUNC(MapViewOfFile);
EXT_FUNC(UnmapViewOfFile);
EXT_FUNC(VirtualProtect);
EXT_FUNC(CreateThread);
EXT_FUNC(WaitForSingleObject);
EXT_FUNC(OpenProcess);
EXT_FUNC(CreateRemoteThread);
EXT_FUNC(GetModuleHandleExA);
EXT_FUNC(GetModuleHandleExW);
EXT_FUNC(WriteProcessMemory);

// user32.dll 
EXT_FUNC(MessageBoxA);
EXT_FUNC(MessageBoxW);
EXT_FUNC(DialogBoxParamA);
EXT_FUNC(DialogBoxParamW);
EXT_FUNC(SetWindowTextA);
EXT_FUNC(SetWindowTextW);
EXT_FUNC(GetWindowLongA);
EXT_FUNC(GetWindowLongW);
EXT_FUNC(SetWindowLongA);
EXT_FUNC(SetWindowLongW);
EXT_FUNC(SetLayeredWindowAttributes);
EXT_FUNC(LoadImageA);
EXT_FUNC(LoadImageW);
EXT_FUNC(GetDC);
EXT_FUNC(ReleaseDC);
EXT_FUNC(SendMessageA);
EXT_FUNC(SendMessageW);
EXT_FUNC(GetDlgItem);
EXT_FUNC(EndDialog);
EXT_FUNC(InvalidateRect);
EXT_FUNC(GetClientRect);
EXT_FUNC(LoadBitmapA);
EXT_FUNC(LoadBitmapW);



// GDi32
EXT_FUNC(CreateCompatibleDC);
EXT_FUNC(SelectObject);
EXT_FUNC(GetObjectA);
EXT_FUNC(GetObjectW);
EXT_FUNC(DeleteDC);
EXT_FUNC(SetStretchBltMode);
EXT_FUNC(StretchBlt);
EXT_FUNC(TextOutA);
EXT_FUNC(TextOutW);
EXT_FUNC(GetStockObject);


// ADVAPI32.DLL
EXT_FUNC(AllocateAndInitializeSid);
EXT_FUNC(CheckTokenMembership);
EXT_FUNC(FreeSid);
EXT_FUNC(GetTokenInformation);
EXT_FUNC(OpenProcessToken);


// Shell32.dll
EXT_FUNC(ShellExecuteExA);
EXT_FUNC(ShellExecuteExW);


// Version.dll
EXT_FUNC(GetFileVersionInfoSizeA);
EXT_FUNC(GetFileVersionInfoSizeW);
EXT_FUNC(GetFileVersionInfoA);
EXT_FUNC(GetFileVersionInfoW);
EXT_FUNC(VerQueryValueA);
EXT_FUNC(VerQueryValueW);

#ifdef _UNICODE
#define pRealSendMessage pRealSendMessageW
#define pRealTextOut pRealTextOutW
#define pRealMessageBox pRealMessageBoxW
#define pReadDialogBoxParam DialogBoxParamW
#define pRealGetModuleHandle pRealGetModuleHandleW
#define PGetCommandLine PGetCommandLineW
#define pRealGetCommandLine pRealGetCommandLineW
#define pRealSetWindowText pRealSetWindowTextW
#define pRealSetWindowLong pRealSetWindowLongW
#define pRealLoadImage pRealLoadImageW
#define pRealGetWindowLong pRealGetWindowLongW
#define pRealGetObject pRealGetObjectW
#define pRealDialogBoxParam pRealDialogBoxParamW
#define pRealLoadBitmap pRealLoadBitmapW
#define pRealGetModuleFileName pRealGetModuleFileNameW
#define pRealShellExecuteEx pRealShellExecuteExW
#define pRealGetFileVersionInfoSize pRealGetFileVersionInfoSizeW
#define pRealGetFileVersionInfo pRealGetFileVersionInfoW
#define pRealVerQueryValue pRealVerQueryValueW
#define pRealExpandEnvironmentStrings pRealExpandEnvironmentStringsW
#define pRealCreateFileMapping pRealCreateFileMappingW
#define pRealCreateFile pRealCreateFileW
#define pRealGetModuleHandleEx pRealGetModuleHandleExW
#else
#define pRealSendMessage pRealSendMessageA
#define pRealTextOut pRealTextOutA
#define pRealMessageBox pRealMessageBoxA
#define pReadDialogBoxParam DialogBoxParamA
#define pRealGetModuleHandle pRealGetModuleHandleA
#define PGetCommandLine PGetCommandLineA
#define pRealGetCommandLine pRealGetCommandLineA
#define pRealSetWindowText pRealSetWindowTextA
#define pRealSetWindowLong pRealSetWindowLongA
#define pRealLoadImage pRealLoadImageA
#define pRealGetWindowLong pRealGetWindowLongA
#define pRealGetObject pRealGetObjectA
#define pRealDialogBoxParam pRealDialogBoxParamA
#define pRealLoadBitmap pRealLoadBitmapA
#define pRealGetModuleFileName pRealGetModuleFileNameA
#define pRealShellExecuteEx pRealShellExecuteExA
#define pRealGetFileVersionInfoSize pRealGetFileVersionInfoSizeA
#define pRealGetFileVersionInfo pRealGetFileVersionInfoA
#define pRealVerQueryValue pRealVerQueryValueA
#define pRealExpandEnvironmentStrings pRealExpandEnvironmentStringsA
#define pRealCreateFileMapping pRealCreateFileMappingA
#define pRealCreateFile pRealCreateFileA
#define pRealGetModuleHandleEx pRealGetModuleHandleExA
#endif

BOOL InitAll(LPVOID lpNoUse = NULL);

#endif  // __API_HEADER_FILE_HEADER_HH_H__