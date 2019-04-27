#include "ApiInit.h"
#include "HideFunction.h"
#ifdef _USRDLL
#pragma comment(linker, "/entry:dllstart")
#else
#pragma comment(linker, "/entry:start")
#endif


#define  DEFFUC(_na)   P##_na pReal##_na = NULL;
#define  GETPROC(_na, _hmd, _hs)  pReal##_na = (P##_na)GetProcAddr(_hmd, _hs); if (pReal##_na == NULL) { return FALSE;}

// Kernel32.dll 
DEFFUC(GetModuleHandleA);
DEFFUC(GetModuleHandleW);
DEFFUC(TerminateProcess);
DEFFUC(ExitProcess);
DEFFUC(GetProcessHeap);
DEFFUC(HeapAlloc);
DEFFUC(HeapFree);
DEFFUC(CloseHandle);
DEFFUC(CreateFileA);
DEFFUC(CreateFileW);
DEFFUC(GetFileSize);
DEFFUC(GetFileSizeEx);
DEFFUC(GetCommandLineA);
DEFFUC(GetCommandLineW);
DEFFUC(GetProcAddress);
DEFFUC(LoadLibraryA);
DEFFUC(LoadLibraryW);
DEFFUC(GetCurrentProcess);
DEFFUC(GetModuleFileNameA);
DEFFUC(GetModuleFileNameW);
DEFFUC(MultiByteToWideChar);
DEFFUC(WideCharToMultiByte);
DEFFUC(SetFilePointer);
DEFFUC(ReadFile);
DEFFUC(ExpandEnvironmentStringsA);
DEFFUC(ExpandEnvironmentStringsW);
DEFFUC(VirtualAllocEx);
DEFFUC(VirtualFreeEx);
DEFFUC(CreateFileMappingA);
DEFFUC(CreateFileMappingW);
DEFFUC(MapViewOfFile);
DEFFUC(UnmapViewOfFile);
DEFFUC(VirtualProtect);
DEFFUC(CreateThread);
DEFFUC(WaitForSingleObject);
DEFFUC(OpenProcess);
DEFFUC(CreateRemoteThread);
DEFFUC(GetModuleHandleExA);
DEFFUC(GetModuleHandleExW);
DEFFUC(WriteProcessMemory);

// User32.dll 
DEFFUC(MessageBoxA);
DEFFUC(MessageBoxW);
DEFFUC(DialogBoxParamA);
DEFFUC(DialogBoxParamW);
DEFFUC(SetWindowTextA);
DEFFUC(SetWindowTextW);
DEFFUC(GetWindowLongA);
DEFFUC(GetWindowLongW);
DEFFUC(SetWindowLongA);
DEFFUC(SetWindowLongW);
DEFFUC(SetLayeredWindowAttributes);
DEFFUC(LoadImageA);
DEFFUC(LoadImageW);
DEFFUC(GetDC);
DEFFUC(ReleaseDC);
DEFFUC(SendMessageA);
DEFFUC(SendMessageW);
DEFFUC(GetDlgItem);
DEFFUC(EndDialog);
DEFFUC(InvalidateRect);
DEFFUC(GetClientRect);
DEFFUC(LoadBitmapA);
DEFFUC(LoadBitmapW);

// Gdi32.dll
DEFFUC(CreateCompatibleDC);
DEFFUC(SelectObject);
DEFFUC(GetObjectA);
DEFFUC(GetObjectW);
DEFFUC(DeleteDC);
DEFFUC(SetStretchBltMode);
DEFFUC(StretchBlt);
DEFFUC(TextOutA);
DEFFUC(TextOutW);
DEFFUC(GetStockObject);

// ADVAPI32.dll
DEFFUC(AllocateAndInitializeSid);
DEFFUC(CheckTokenMembership);
DEFFUC(FreeSid);
DEFFUC(GetTokenInformation);
DEFFUC(OpenProcessToken);


// Shell32.dll
DEFFUC(ShellExecuteExA);
DEFFUC(ShellExecuteExW);

// Version
DEFFUC(GetFileVersionInfoSizeA);
DEFFUC(GetFileVersionInfoSizeW);
DEFFUC(GetFileVersionInfoA);
DEFFUC(GetFileVersionInfoW);
DEFFUC(VerQueryValueA);
DEFFUC(VerQueryValueW);

BOOL InitAll(LPVOID lpNoUse)
{
    HMODULE hKernelModule;
    HMODULE hUserModule;
    HMODULE hGDiModule;
    HMODULE hAdavapiModule;
    HMODULE hShellModule;
    HMODULE hVersionModule;

    hKernelModule = LoadDll(KERNEL32);
    GETPROC(GetModuleHandleA, hKernelModule, 0x3777cccb);
    GETPROC(GetModuleHandleW, hKernelModule, 0x3777cce1);
    GETPROC(TerminateProcess, hKernelModule, 0x4beac1b0);
    GETPROC(ExitProcess,hKernelModule, 0x672f331f);  // GetStringHash("ExitProcess") 
    GETPROC(GetProcessHeap, hKernelModule, 0x4fe490b7);
    GETPROC(HeapAlloc, hKernelModule, 0x6e4de02d);
    GETPROC(HeapFree, hKernelModule, 0x51d5bbee);
    GETPROC(CloseHandle, hKernelModule, 0x70ebfb28);
    GETPROC(CreateFileA, hKernelModule, 0x4e1e0843);
    GETPROC(CreateFileW, hKernelModule, 0x4e1e0859);
    GETPROC(GetFileSize, hKernelModule, 0x1a693447);
    GETPROC(GetFileSizeEx, hKernelModule, 0x11f6b1a6);
    GETPROC(GetCommandLineA, hKernelModule, 0x51a3c442);
    GETPROC(GetCommandLineW, hKernelModule, 0x51a3c458);
    GETPROC(GetProcAddress, hKernelModule, 0x6a6f5696);
    GETPROC(LoadLibraryA, hKernelModule, 0x094c4c32);
    GETPROC(LoadLibraryW, hKernelModule, 0x094c4c48);
    GETPROC(GetCurrentProcess, hKernelModule, 0x5f1121c0);
    GETPROC(GetModuleFileNameA, hKernelModule, 0x660c1c02);
    GETPROC(GetModuleFileNameW, hKernelModule, 0x660c1c18);
    GETPROC(MultiByteToWideChar, hKernelModule, 0x2502909d);
    GETPROC(WideCharToMultiByte, hKernelModule, 0x1495a57f);
    GETPROC(SetFilePointer, hKernelModule, 0x450e36a1);
    GETPROC(ReadFile, hKernelModule, 0x4588b716);
    GETPROC(ExpandEnvironmentStringsA, hKernelModule, 0x609e6f8c);
    GETPROC(ExpandEnvironmentStringsW, hKernelModule, 0x609e6fa2);
    GETPROC(VirtualAllocEx, hKernelModule, 0x1c29179f);
    GETPROC(VirtualFreeEx, hKernelModule, 0x1702ac12);
    GETPROC(CreateFileMappingA, hKernelModule, 0x22c9ce0b);
    GETPROC(CreateFileMappingW, hKernelModule, 0x22c9ce21);
    GETPROC(MapViewOfFile, hKernelModule, 0x683bea5e);
    GETPROC(UnmapViewOfFile, hKernelModule, 0x27d95fff);
    GETPROC(VirtualProtect, hKernelModule, 0x339ed8ee);
    GETPROC(CreateThread, hKernelModule, 0x149b8638);
    GETPROC(WaitForSingleObject, hKernelModule, 0x3282227b);
    GETPROC(OpenProcess, hKernelModule, 0x34102a7f);
    GETPROC(CreateRemoteThread, hKernelModule, 0x2c7f4aee);
    GETPROC(GetModuleHandleExA, hKernelModule, 0x556bccb2);
    GETPROC(GetModuleHandleExW, hKernelModule, 0x556bccc8);
    GETPROC(WriteProcessMemory, hKernelModule, 0x6328d74d);

    hUserModule = LoadDll(USER32);
    GETPROC(MessageBoxA, hUserModule, 0x574311f3);
    GETPROC(MessageBoxW, hUserModule, 0x57431209);
    GETPROC(DialogBoxParamA, hUserModule, 0x375966a1);
    GETPROC(DialogBoxParamW, hUserModule, 0x375966b7);
    GETPROC(SetWindowTextA, hUserModule, 0x71382638);
    GETPROC(SetWindowTextW, hUserModule, 0x7138264e);
    GETPROC(GetWindowLongA, hUserModule, 0x667ef1ed);
    GETPROC(GetWindowLongW, hUserModule, 0x667ef203);
    GETPROC(SetWindowLongA, hUserModule, 0x1f0e4ce1);
    GETPROC(SetWindowLongW, hUserModule, 0x1f0e4cf7);
    GETPROC(SetLayeredWindowAttributes, hUserModule, 0x6ec1140d);
    GETPROC(LoadImageA, hUserModule, 0x7d1b9b72);
    GETPROC(LoadImageW, hUserModule, 0x7d1b9b88);
    GETPROC(GetDC, hUserModule, 0x2ec0c445);
    GETPROC(ReleaseDC, hUserModule, 0x43098fc6);
    GETPROC(SendMessageA, hUserModule, 0x63683dd2);
    GETPROC(SendMessageW, hUserModule, 0x63683de8);
    GETPROC(GetDlgItem, hUserModule, 0x59d8722e);
    GETPROC(EndDialog, hUserModule, 0x7c6b19f1);
    GETPROC(InvalidateRect, hUserModule, 0x052de971);
    GETPROC(GetClientRect, hUserModule, 0x480b9971);
    GETPROC(LoadBitmapA, hUserModule, 0x151cba26);
    GETPROC(LoadBitmapW, hUserModule, 0x151cba3c);

    hGDiModule = LoadDll(GDI32);
    GETPROC(CreateCompatibleDC, hGDiModule, 0x664f2ec7);
    GETPROC(SelectObject, hGDiModule, 0x2324162f);
    GETPROC(GetObjectA, hGDiModule, 0x72beda22);
    GETPROC(GetObjectW, hGDiModule, 0x72beda38);
    GETPROC(DeleteDC, hGDiModule, 0x5fcce556);
    GETPROC(SetStretchBltMode, hGDiModule, 0x3c656e6c);
    GETPROC(StretchBlt, hGDiModule, 0x21f9b8c3);
    GETPROC(TextOutA, hGDiModule, 0x0987a5ea);
    GETPROC(TextOutW, hGDiModule, 0x0987a600);
    GETPROC(GetStockObject, hGDiModule, 0x332ec96b);

    hAdavapiModule = LoadDll(ADVAPI32);
    GETPROC(AllocateAndInitializeSid, hAdavapiModule, 0x52d03ab0);
    GETPROC(CheckTokenMembership, hAdavapiModule, 0x1e8dc88d);
    GETPROC(FreeSid, hAdavapiModule, 0x5ff18806);
    GETPROC(GetTokenInformation, hAdavapiModule, 0x580127b9);
    GETPROC(OpenProcessToken, hAdavapiModule, 0x77f4b262);


    hShellModule =  LoadDll(SHELL32);
    GETPROC(ShellExecuteExA, hShellModule, 0x51c78d37);
    GETPROC(ShellExecuteExW, hShellModule, 0x51c78d4d);

    hVersionModule = LoadDll(VERSION);
    GETPROC(GetFileVersionInfoSizeA, hVersionModule, 0x65d7b8e6);
    GETPROC(GetFileVersionInfoSizeW, hVersionModule, 0x65d7b8fc);
    GETPROC(GetFileVersionInfoA, hVersionModule, 0x36b57d69);
    GETPROC(GetFileVersionInfoW, hVersionModule, 0x36b57d7f);
    GETPROC(VerQueryValueA, hVersionModule, 0x480bd59f);
    GETPROC(VerQueryValueW, hVersionModule, 0x480bd5b5);

    return TRUE;
}

extern "C" void _except_handler3(unsigned int cookie)
{
    return ;
}

#ifdef _USRDLL
extern BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID);
BOOL WINAPI dllstart(HINSTANCE hModule, DWORD dwReason, LPVOID lpvReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        if ( !InitAll() )
        {
#ifdef _DEBUG
            pRealMessageBox(NULL, TEXT("有函数的hash值写错了"), NULL, NULL);
#endif
            return FALSE;
        }
    }
    return DllMain(hModule, dwReason, lpvReserved);
}

#else
extern BOOL WINAPI _tWinMain(HINSTANCE, HINSTANCE, LPTSTR, int);
void start()
{
    int val = 0;
    if ( !InitAll() )
    {
#ifdef _DEBUG
        pRealMessageBox(NULL, TEXT("有函数的hash值写错了"), NULL, NULL);
#endif
        return;
    }
#ifdef _WINDOWS
    val = _tWinMain(pRealGetModuleHandle(NULL), NULL, pRealGetCommandLine(), SW_SHOW);
#else  // _CONSOLE
//     val = _tmain();
#endif // _WINDOWS
    pRealExitProcess(val);
}

#endif

