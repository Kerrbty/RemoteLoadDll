#include "LoadModel.h"
#include "Function/defs.h"
#include "LoadDll.h"
#include <shlwapi.h>
#pragma comment(lib, "shlwapi")


BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, 
                        LPVOID lpvReserved)
{
    switch( dwReason ) {
        case DLL_PROCESS_ATTACH:
#ifdef _DEBUG
            pRealMessageBoxA(NULL, NULL, NULL, NULL);
#endif
            break;

        case DLL_PROCESS_DETACH:
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        default:
            break;
    }
    return TRUE;
}


BOOL WINAPI RemoteInertDllFromMemory(HANDLE hProcess, LPBYTE DllBuffer, DWORD dwDllSize)
{
    // 打开当前模块写入远程进程，然后展开注入  
    DWORD dwBytes = 0;
    BOOL InsertSuccess = FALSE;
    HMODULE hModule = NULL;
    LPWSTR szThisDllPath = (LPWSTR)AllocMemory(MAX_PATH*sizeof(WCHAR));
    pRealGetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)RemoteInertDllFromFileW, &hModule);
    pRealGetModuleFileNameW(hModule, szThisDllPath, MAX_PATH);
    HANDLE hDllFile = FileOpenW(szThisDllPath, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    if (hDllFile != INVALID_HANDLE_VALUE)
    {
        // 读入文件 
        DWORD dwDllSzie = pRealGetFileSize(hDllFile, NULL);
        LPBYTE lpDllBuf = (LPBYTE)AllocMemory(dwDllSzie);
        if (lpDllBuf != NULL)
        {
            pRealSetFilePointer(hDllFile, 0, NULL, FILE_BEGIN);
            pRealReadFile(hDllFile, lpDllBuf, dwDllSzie, &dwBytes, NULL);
            pRealCloseHandle(hDllFile);

            // 按区块写入进程  
            PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)lpDllBuf;
            PIMAGE_NT_HEADERS peheader = 
                (PIMAGE_NT_HEADERS)((DWORD)Header + Header->e_lfanew);

            DWORD dwsizeOfImage = peheader->OptionalHeader.SizeOfImage;
            LPVOID lpDllRemoteAddress = pRealVirtualAllocEx(hProcess, NULL, dwsizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (lpDllRemoteAddress != NULL)
            {
                WORD SectionNum = peheader->FileHeader.NumberOfSections; // 节数目
                PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)( (DWORD)peheader + 
                    sizeof(peheader->FileHeader) + 
                    sizeof(peheader->Signature) +
                    peheader->FileHeader.SizeOfOptionalHeader ); // 节表项的开始

                pRealWriteProcessMemory(hProcess, (LPBYTE)lpDllRemoteAddress, (LPBYTE)Header, 0x1000, &dwBytes);
                for (WORD i=0; i<SectionNum; i++) // 将节一个个复制到内存中
                {
                    DWORD ulsize = SectionHeader[i].Misc.VirtualSize;
                    if ( ulsize > SectionHeader[i].SizeOfRawData )
                    {
                        ulsize = SectionHeader[i].SizeOfRawData;
                    }
                    pRealWriteProcessMemory(hProcess,
                        (LPVOID)((LPBYTE)lpDllRemoteAddress + SectionHeader[i].VirtualAddress), 
                        (LPVOID)((LPBYTE)Header + SectionHeader[i].PointerToRawData), 
                        ulsize,
                        &dwBytes); 


                } 

                // 需要 重定位
                LPBYTE lpRelocAddr = (LPBYTE)pRealGetProcAddress(hModule, "RelocAddr");
                lpRelocAddr = lpRelocAddr - (LPBYTE)hModule + (LPBYTE)lpDllRemoteAddress;
                HANDLE hRelocThread = pRealCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpRelocAddr, (LPVOID)lpDllRemoteAddress, 0, NULL);
                pRealWaitForSingleObject(hRelocThread, INFINITE);
                pRealCloseHandle(hRelocThread);

                // 远程初始化函数地址 
                LPBYTE lpInitAddr = (LPBYTE)pRealGetProcAddress(hModule, "InitAll");
                lpInitAddr = lpInitAddr - (LPBYTE)hModule + (LPBYTE)lpDllRemoteAddress;
                HANDLE hInitThread = pRealCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpInitAddr, NULL, 0, NULL);
                pRealWaitForSingleObject(hInitThread, INFINITE);
                pRealCloseHandle(hInitThread);

                // 远程申请内存， 写入dll内存
                LPVOID lpDllNameAddr = pRealVirtualAllocEx(hProcess, NULL, dwDllSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                pRealWriteProcessMemory(hProcess, (LPBYTE)lpDllNameAddr, DllBuffer, dwDllSize, &dwBytes);
                // 开始动态加载其他dll 
                LPBYTE lpLoadDllAddr = (LPBYTE)pRealGetProcAddress(hModule, "LoadDllFromMemory");
                lpLoadDllAddr = lpLoadDllAddr - (LPBYTE)hModule + (LPBYTE)lpDllRemoteAddress;
                HANDLE hLoadDllThread = pRealCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadDllAddr, lpDllNameAddr, 0, NULL);
                pRealWaitForSingleObject(hLoadDllThread, INFINITE);
                pRealCloseHandle(hLoadDllThread);
                pRealVirtualFreeEx(hProcess, lpDllNameAddr, dwDllSize, MEM_RELEASE);

                // 这里其实顺便可以释放这个dll了
                // pRealVirtualFreeEx(hProcess, lpDllRemoteAddress, dwsizeOfImage, MEM_RELEASE);

                InsertSuccess = TRUE;
            }
            FreeMemory(lpDllBuf);
        }
    }
    return InsertSuccess;
}

BOOL WINAPI RemoteInertDllFromFileW(HANDLE hProcess, LPWSTR DllPathName)
{
    // 打开当前模块写入远程进程，然后展开注入  
    DWORD dwBytes = 0;
    BOOL InsertSuccess = FALSE;
    HMODULE hModule = NULL;

    // 如果此dll无模块的话，这里代码需要更改 
    LPWSTR szThisDllPath = (LPWSTR)AllocMemory(MAX_PATH*sizeof(WCHAR));
    pRealGetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)RemoteInertDllFromFileW, &hModule);
    pRealGetModuleFileNameW(hModule, szThisDllPath, MAX_PATH);
    HANDLE hDllFile = FileOpenW(szThisDllPath, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    if (hDllFile != INVALID_HANDLE_VALUE)
    {
        // 读入文件 
        DWORD dwDllSzie = pRealGetFileSize(hDllFile, NULL);
        LPBYTE lpDllBuf = (LPBYTE)AllocMemory(dwDllSzie);
        if (lpDllBuf != NULL)
        {
            pRealSetFilePointer(hDllFile, 0, NULL, FILE_BEGIN);
            pRealReadFile(hDllFile, lpDllBuf, dwDllSzie, &dwBytes, NULL);
            pRealCloseHandle(hDllFile);

            // 按区块写入进程  
            PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)lpDllBuf;
            PIMAGE_NT_HEADERS peheader = 
                (PIMAGE_NT_HEADERS)((DWORD)Header + Header->e_lfanew);

            DWORD dwsizeOfImage = peheader->OptionalHeader.SizeOfImage;
            LPVOID lpDllRemoteAddress = pRealVirtualAllocEx(hProcess, NULL, dwsizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (lpDllRemoteAddress != NULL)
            {
                WORD SectionNum = peheader->FileHeader.NumberOfSections; // 节数目
                PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)( (DWORD)peheader + 
                                                        sizeof(peheader->FileHeader) + 
                                                        sizeof(peheader->Signature) +
                                                        peheader->FileHeader.SizeOfOptionalHeader ); // 节表项的开始

                pRealWriteProcessMemory(hProcess, (LPBYTE)lpDllRemoteAddress, (LPBYTE)Header, 0x1000, &dwBytes);
                for (WORD i=0; i<SectionNum; i++) // 将节一个个复制到内存中
                {
                    DWORD ulsize = SectionHeader[i].Misc.VirtualSize;
                    if ( ulsize > SectionHeader[i].SizeOfRawData )
                    {
                        ulsize = SectionHeader[i].SizeOfRawData;
                    }
                    pRealWriteProcessMemory(hProcess,
                                        (LPVOID)((LPBYTE)lpDllRemoteAddress + SectionHeader[i].VirtualAddress), 
                                        (LPVOID)((LPBYTE)Header + SectionHeader[i].PointerToRawData), 
                                        ulsize,
                                        &dwBytes); 
                    

                } 

                // 需要 重定位
                LPBYTE lpRelocAddr = (LPBYTE)pRealGetProcAddress(hModule, "RelocAddr");
                lpRelocAddr = lpRelocAddr - (LPBYTE)hModule + (LPBYTE)lpDllRemoteAddress;
                HANDLE hRelocThread = pRealCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpRelocAddr, (LPVOID)lpDllRemoteAddress, 0, NULL);
                pRealWaitForSingleObject(hRelocThread, INFINITE);
                pRealCloseHandle(hRelocThread);

                // 远程初始化函数地址 
                LPBYTE lpInitAddr = (LPBYTE)pRealGetProcAddress(hModule, "InitAll");
                lpInitAddr = lpInitAddr - (LPBYTE)hModule + (LPBYTE)lpDllRemoteAddress;
                HANDLE hInitThread = pRealCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpInitAddr, NULL, 0, NULL);
                pRealWaitForSingleObject(hInitThread, INFINITE);
                pRealCloseHandle(hInitThread);


                // 写入dll名称
                LPVOID lpDllNameAddr = pRealVirtualAllocEx(hProcess, NULL, MAX_PATH*sizeof(WCHAR), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                pRealWriteProcessMemory(hProcess, (LPBYTE)lpDllNameAddr, DllPathName, MAX_PATH*sizeof(WCHAR), &dwBytes);
                // 开始动态加载其他dll 
                LPBYTE lpLoadDllAddr = (LPBYTE)pRealGetProcAddress(hModule, "LoadDllFromFileW");
                lpLoadDllAddr = lpLoadDllAddr - (LPBYTE)hModule + (LPBYTE)lpDllRemoteAddress;
                HANDLE hLoadDllThread = pRealCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadDllAddr, lpDllNameAddr, 0, NULL);
                pRealWaitForSingleObject(hLoadDllThread, INFINITE);
                pRealCloseHandle(hLoadDllThread);
                pRealVirtualFreeEx(hProcess, lpDllNameAddr, MAX_PATH*sizeof(WCHAR), MEM_RELEASE);

                // 这里其实顺便可以释放这个dll了
                // pRealVirtualFreeEx(hProcess, lpDllRemoteAddress, dwsizeOfImage, MEM_RELEASE);

                InsertSuccess = TRUE;
            }
            FreeMemory(lpDllBuf);
        }
    }
    return InsertSuccess;
}

BOOL WINAPI RemoteInertDllFromFileA(HANDLE hProcess, LPSTR DllPathName)
{
    LPWSTR wsDllPathName = MulToWide(DllPathName);
    if (wsDllPathName != NULL)
    {
        RemoteInertDllFromFileW(hProcess, wsDllPathName);
        FreeMemory(wsDllPathName);
        return TRUE;
    }
    return FALSE;
}
