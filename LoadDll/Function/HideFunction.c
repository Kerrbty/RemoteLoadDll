#include "HideFunction.h"
#include <intrin.h>
#pragma comment(lib, "memset.lib")

struct  
{
    DWORD hash;
    LPCSTR DllName;
} DllHash[] = {
    {KERNEL32 , "TZMQZS,-1[SS" },  // "Kernel32" 
    {USER32   , "JLZM,-1[SS"   },  // "User32"
    {NTDLL    , "QK[SS1[SS"    },  // "ntdll"
    {SHLWAPI  , "LWSH^OV1[SS"  },  // "shlwapi"
    {ADVAPI32 , "^[I^OV,-1[SS" },   // "Advapi32"
    {GDI32    , "X[V,-1[SS"   },   // "Gdi32" 
    {SHELL32  ,  "LWZSS,-1[SS"},    // "Shell32"
    {VERSION  ,  "IZMLVPQ1[SS"},    // "Version"
};

HANDLE hKernel32;

#pragma data_seg("text")
#pragma comment(linker,"/SECTION:text,RWE")
char GetKernelHandle[]={"PYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIshatoQVP30WpwpLKqPDLlKW05LNkEPLKQPVhKsAA"};
#pragma data_seg()

typedef HMODULE (WINAPI* PLoadLibraryExA)( LPCSTR, DWORD , DWORD );

DWORD GetStringHash(PSTR FuncName) // 0x00401070
{
    DWORD dw1 = 0x5C6B7;
    DWORD dw2 = 0xF8C9;
    DWORD dw3 = 0;
    while(*FuncName)
    {
        if (*FuncName >= 'A' && *FuncName <= 'Z')
        {
            dw3 = *FuncName + dw3*dw2 + 0x20;
        }
        else
        {
            dw3 = *FuncName + dw3*dw2;
        }
        dw2 = dw2*dw1;

        FuncName++;
    }

    return dw3&0x7FFFFFFF;
}

HMODULE WINAPI GetKernelBase()
{
// #ifndef _DEBUG
    DWORD dwPEB = __readfsdword(0x30); 
    DWORD peb_ldr_data = *(PDWORD)((PBYTE)dwPEB+0xC);
    DWORD InInitializationOrderLinks = *(*(PDWORD*)((PBYTE)peb_ldr_data+0x1C));
    return (HMODULE)(*(PDWORD)((PBYTE)InInitializationOrderLinks+0x8));
// #else // _DEBUG 
//     return (*(HANDLE(*)())&GetKernelHandle)();
// #endif // _DEBUG  
}

PVOID GetProcAddr(HMODULE hmodule, DWORD hash) // 0x00401100
{
    PIMAGE_DOS_HEADER Header;
    PIMAGE_NT_HEADERS peheader;
    PIMAGE_EXPORT_DIRECTORY pExportDir;

    LPBYTE pExportAddr;
    DWORD dwExportSize;
    PDWORD NameRVA;
    PDWORD FuncAddr;
    PWORD Ordinal;
    PBYTE pFuncAddr;

    DWORD i;

    if (hmodule == NULL)
    {
        return NULL;
    }
    
    Header = (PIMAGE_DOS_HEADER)hmodule;
    peheader = (PIMAGE_NT_HEADERS)((DWORD)Header + Header->e_lfanew);

    if ( (Header->e_magic != IMAGE_DOS_SIGNATURE) ||  (peheader->Signature != IMAGE_NT_SIGNATURE) )
    {
        return NULL;
    }

    // 导出表地址
    pExportDir = (PIMAGE_EXPORT_DIRECTORY)  // (pRELOADTABLE)
        ( (LPBYTE)Header + peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // IAT地址
    pExportAddr = (LPBYTE)hmodule + peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    dwExportSize = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    NameRVA = (PDWORD)((LPBYTE)hmodule + pExportDir->AddressOfNames );
    FuncAddr = (PDWORD)((LPBYTE)hmodule + pExportDir->AddressOfFunctions);
    Ordinal = (PWORD)((LPBYTE)hmodule + pExportDir->AddressOfNameOrdinals);

    // 遍历以名称导出的函数
    pFuncAddr = NULL;
    for (i=0; i<pExportDir->NumberOfNames; i++)
    {
        LPSTR tmpfunname = (PSTR)((DWORD)NameRVA[i]+(LPBYTE)hmodule);

        if (hash == GetStringHash(tmpfunname))
        {
            WORD Hint = Ordinal[i];
            pFuncAddr = (PBYTE)hmodule + FuncAddr[Hint];
            break;
        }
    }
    if (pFuncAddr != NULL)
    {
        if ( ((pFuncAddr[0]|0x20) >= 'a' && (pFuncAddr[0]|0x20) <= 'z') &&
            ((pFuncAddr[1]|0x20) >= 'a' && (pFuncAddr[1]|0x20) <= 'z') &&
            ((pFuncAddr[2]|0x20) >= 'a' && (pFuncAddr[2]|0x20) <= 'z') &&
            ((pFuncAddr[3]|0x20) >= 'a' && (pFuncAddr[3]|0x20) <= 'z') 
            )
        {
            char DllName[260] = {0};
            PLoadLibraryExA loadlibexA;

            if (hKernel32 == NULL)
            {
                hKernel32 = GetKernelBase();
            }
            loadlibexA = (PLoadLibraryExA)GetProcAddr(hKernel32, 0x835D0A3);  // 
            if (loadlibexA != NULL)
            {
                HMODULE hNewModule;
                char* pName = (char*)pFuncAddr;
                int i=0;
                while(*pName != '.' && *pName != '\0')
                {
                    DllName[i++] = *pName++;
                }
                if (*pName == '.')
                {
                    DllName[i++] = *pName++;
                    DllName[i++] = 'D';
                    DllName[i++] = 'L';
                    DllName[i++] = 'L';
                    DllName[i++] = '\0';
                }
                hNewModule = loadlibexA(DllName, 0, 0);
                pFuncAddr = GetProcAddr(hNewModule, GetStringHash(pName));
            }
        }
    }

    return pFuncAddr;
}

char* DecrdeDllName(char* saveName, const char* encryName)
{
    const char* p = encryName;
    char* q = saveName;
    while(*p != '\0')
    {
        *q++ = *p++ ^ 0x1F;
    }
    *q = '\0';
    return saveName;
}

HMODULE LoadDll(DWORD hash)
{
    int i = 0;
    char buf[30] = {0};

    for (i=0; i<sizeof(DllHash)/sizeof(DllHash[0]); i++)
    {
        if (hash == DllHash[i].hash)
        {
            PLoadLibraryExA loadlibexA;
            if (hKernel32 == NULL)
            {
                hKernel32 = GetKernelBase();
            }
            loadlibexA = (PLoadLibraryExA)GetProcAddr(hKernel32, 0x835D0A3); 
            if (loadlibexA != NULL)
            {
                DecrdeDllName(buf, DllHash[i].DllName);
                return loadlibexA(buf, 0, 0);
            }
        }
    }
    return NULL;
}