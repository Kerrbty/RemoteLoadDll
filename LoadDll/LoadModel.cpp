#include "LoadModel.h"
#include "Function/ApiInit.h"
#include "Function/defs.h"

#pragma pack(push, 1)
BOOL copy_memory(DWORD DstAddr, DWORD SrcAddr, size_t dwsize);

// �ض�λ��ṹ
typedef struct _OffTable{
	USHORT addr:12;
	USHORT flags:4;
}OffTable, *pOffTable;

typedef struct _RELOADTABLE{
	DWORD StartVirtualAddress;
	DWORD size;
	OffTable Table[1];
}RELOADTABLE, *pRELOADTABLE;



// �����ṹ
typedef struct _HintName
{
	WORD Hint;
	CHAR Name[1];
}HintName, *PHintName;

typedef struct _DllMainCall 
{
	HMODULE hmodule;
	DWORD reasons;
}DllMainCall, *pDllMainCall;

#pragma pack(pop)


HMODULE MapThePeFile(LPVOID pMemAddr); // ��Ⲣӳ���ļ�
DWORD WINAPI DllInit(LPVOID hModule); // ��ʼ��(����)DllMain
BOOL FixIMPORT(HMODULE hModule); // ��䵼���
BOOL isPEFile(LPVOID pFileMap); // �ж��ļ��Ƿ���PE�ļ�

HMODULE G_This_LoadDll_Module = NULL;
WCHAR   G_This_LoadDll_Name[MAX_PATH];


typedef BOOL (APIENTRY* pDllMain)(  HINSTANCE hModule, 
								  DWORD  ul_reason_for_call, 
									LPVOID lpReserved);


int __cdecl mystrcmp(const char * _Str1, const char * _Str2)
{
    while(*_Str1 != '\0' || *_Str2 != '\0')
    {
        if (*_Str1 > *_Str2)
        {
            return 1;
        }
        else if (*_Str1 < *_Str2)
        {
            return -1;
        }
        else
        {
            _Str1++;
            _Str2++;
        }
    }
    return 0;
}

char* __cdecl mystrcat(char* str1, const char* str2)
{
    char *p = str1;
    while(*p != '\0')
    {
        p++;
    }
    while(*str2 != '\0')
    {
        *p++ = *str2++;
    }
    *p = '\0';
    return str1;
}

void * __cdecl mymemcpy(void * _Dst, const void * _Src, size_t _Size)
{
    PBYTE src = (PBYTE)_Src;
    PBYTE dst = (PBYTE)_Dst;
    for (size_t i=0; i<_Size; i++)
    {
        dst[i] = src[i];
    }
    return dst;
}

// �޸��ض�λ�� hmodule ���صĵ�ַ
// BaseAddress ��Ҫ�ض�λ�ĵ�ַ���������HOOK���߻ָ�hookʱ����
BOOL WINAPI RelocAddr( HMODULE hModule )
{
	if (hModule == NULL)
	{
		return false;
	}

	LPBYTE BaseAddress = (LPBYTE)hModule;

	PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS peheader = 
		(PIMAGE_NT_HEADERS)((LPBYTE)Header + Header->e_lfanew);

	DWORD dwsizeOfImage = peheader->OptionalHeader.SizeOfImage;
	LPBYTE dwAddress = (LPBYTE)peheader->OptionalHeader.ImageBase;

	if ( dwAddress == (LPBYTE)hModule )
	{
		// ���ص������ַ,����Ҫ�ض�λ
		return TRUE;
	}

	// PE ͷ offset 0x98
	if (peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0)
    {
        // û���ض�λ��
        return FALSE;
    }
	pRELOADTABLE  reloadaddr = (pRELOADTABLE)
		( (LPBYTE)hModule + peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) ;

	if ( (LPBYTE)reloadaddr < (LPBYTE)hModule || 
		 (LPBYTE)reloadaddr > (LPBYTE)hModule+dwsizeOfImage )
	{
		// ����������ļ���,�ض�λ�����
		return false;
	}

	// �����ض�λ��
	while ( reloadaddr->StartVirtualAddress != NULL && reloadaddr->size != NULL )
	{
		for (DWORD i=0; i<(reloadaddr->size-8)/2 ; i++)
		{
			__try
			{
				if ( reloadaddr->Table[i].flags == IMAGE_REL_BASED_HIGHLOW )
				{
					PDWORD* OffsetAddress = (PDWORD*)(reloadaddr->Table[i].addr + (LPBYTE)hModule + reloadaddr->StartVirtualAddress);
					// �����µ�ƫ���� = ԭʼֵ - ԭʼ���ص�ַ + �µļ��ص�ַ
					*OffsetAddress = (LPDWORD)((LPBYTE)(*OffsetAddress) - dwAddress + BaseAddress);
				}
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				continue;
			}
		}
		reloadaddr = (pRELOADTABLE) ((DWORD)reloadaddr  + reloadaddr->size );
	}


	return true; 
}

typedef DWORD (WINAPI* PGetModuleFileNameA)(HMODULE, LPSTR, DWORD);
DWORD WINAPI MyGetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
    if (hModule == G_This_LoadDll_Module)
    {
        return pRealWideCharToMultiByte(CP_ACP, 0, G_This_LoadDll_Name, -1, lpFilename, nSize, NULL, NULL);
    }
    PGetModuleFileNameA realfunc = (PGetModuleFileNameA)pRealGetProcAddress(pRealLoadLibraryA("Kernel32.dll"), "GetModuleFileNameA");
    return realfunc(hModule, lpFilename, nSize);
}


// ��䵼���
BOOL FixIMPORT(HMODULE hModule) 
{
	if (hModule == NULL)
	{
		return false;
	}
	
	PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS peheader = 
		(PIMAGE_NT_HEADERS)((LPBYTE)Header + Header->e_lfanew);

	// IAT��ַ
	PIMAGE_IMPORT_DESCRIPTOR pImpDescript = (PIMAGE_IMPORT_DESCRIPTOR) (pRELOADTABLE)
		( (LPBYTE)hModule + peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// ������2ָ����ַ���ָ���޸���1ָ����ڴ��(��1ָ��IMPORT table)
	while (pImpDescript->Name != NULL)
	{
		PDWORD ImportApiName = (PDWORD)((LPBYTE)hModule + pImpDescript->OriginalFirstThunk); // ���뺯����������
		// ��Ҫ�޸��ĵ�����ַ , �� IMAGE_DIRECTORY_ENTRY_IAT ����
		LPDWORD* FixTable = (PDWORD*)((LPBYTE)hModule + pImpDescript->FirstThunk); 
		
		// �õ�����dll��ַ
		HMODULE impDllModule = pRealGetModuleHandleA( (char*)((LPBYTE)hModule + pImpDescript->Name) );
		if (impDllModule == NULL)
		{
			impDllModule = pRealLoadLibraryA( (char*)((LPBYTE)hModule + pImpDescript->Name) );
		}

		// �޸�
		if (impDllModule)
		{
			for (int i=0; ImportApiName[i]!=NULL ; i++)
			{
				__try
				{
                    //////////////////////////////////////////////////////////////////////////
                    //  ��IMAGE_THUNK_DATA�����λ�������1����Ordinal���������AddressOfData
                    //////////////////////////////////////////////////////////////////////////
                    if ( IMAGE_SNAP_BY_ORDINAL(ImportApiName[i]) )
                    {
                        FixTable[i] = (LPDWORD)pRealGetProcAddress(impDllModule, (PSTR)(ImportApiName[i]&0x7FFFFFFF));
                    }
                    else
                    {
                        PHintName imputhint = (PHintName)( ImportApiName[i] + (LPBYTE)hModule );
                        if (imputhint->Name[0] != '\0')
                        {
                            // ���� GetModuleFileNameA �������MFC������ 
                            if ( mystrcmp( imputhint->Name, "GetModuleFileNameA") == 0 )
                            {
                                FixTable[i] = (LPDWORD)MyGetModuleFileNameA;
                            }
                            else
                            {
                                FixTable[i] = (LPDWORD)pRealGetProcAddress(impDllModule, imputhint->Name);
                            }
                            
                        }
                        else
                        {
                            FixTable[i] = (LPDWORD)pRealGetProcAddress(impDllModule, (PSTR)imputhint->Hint);
                        }
                    }
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					continue;
				}
				
			}
		}
		pImpDescript++;
	}

	return TRUE;
}


// ����TLS
bool ExecuteTLS(HMODULE hModule)
{
	if (hModule == NULL)
	{
		return false;
	}

	PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS peheader = 
		(PIMAGE_NT_HEADERS)((LPBYTE)Header + Header->e_lfanew);
	
	// IAT��ַ
	PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY) (pRELOADTABLE)
		( (LPBYTE)hModule + peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

    if ( (LPBYTE)tls > (LPBYTE)hModule) {
        PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;
        if (callback) 
		{
            while (*callback) 
			{
                (*callback)((LPVOID)hModule, DLL_PROCESS_ATTACH, NULL);
                callback++;
            }
        }
    }
	return true;
}


/////////////////////////////////////////////////////////////////////////////////////////////////
// ��Ⲣӳ���ļ�
// ���ӳ����̿��� ntdll ������ 
// ZwOpenFile(ZwCreateFile)\ ZwCreateSection \ ZwMapViewOfSection 
// ȡ��
/////////////////////////////////////////////////////////////////////////////////////////////////
HMODULE MapThePeFile(LPVOID pMemAddr)
{
	PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)pMemAddr;
	PIMAGE_NT_HEADERS peheader = 
		(PIMAGE_NT_HEADERS)((LPBYTE)Header + Header->e_lfanew);
	
	// �����ļ���¼�Ĵ�С�����ڴ�
	DWORD dwsizeOfImage = peheader->OptionalHeader.SizeOfImage;
    LPVOID DllAddress = AllocMemory(dwsizeOfImage);
	
	if (DllAddress == NULL)
	{
		return NULL;
	}
	DWORD oldprotect;
	pRealVirtualProtect(DllAddress, dwsizeOfImage, PAGE_EXECUTE_READWRITE, &oldprotect);

	mymemcpy(DllAddress, Header, peheader->OptionalHeader.SizeOfHeaders); // ��PEͷ���ƹ�ȥ,���Ҫ��ȷ������VMP������  

	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)( (DWORD)peheader + 
											sizeof(peheader->FileHeader) + 
											sizeof(peheader->Signature) +
											peheader->FileHeader.SizeOfOptionalHeader ); // �ڱ���Ŀ�ʼ

	WORD SectionNum = peheader->FileHeader.NumberOfSections; // ����Ŀ
	for (WORD i=0; i<SectionNum; i++) // ����һ�������Ƶ��ڴ���
	{
		DWORD ulsize = SectionHeader[i].Misc.VirtualSize;
		if ( ulsize > SectionHeader[i].SizeOfRawData )
		{
			ulsize = SectionHeader[i].SizeOfRawData;
		}
		mymemcpy(	(LPVOID)((DWORD)DllAddress + SectionHeader[i].VirtualAddress), 
				(LPVOID)((DWORD)Header + SectionHeader[i].PointerToRawData), 
				ulsize ); 
	} 

	return (HMODULE)DllAddress;
}

// �ж�PE�ļ��Ƿ�Ϸ�
BOOL isPEFile(LPVOID pFileMap)
{
	PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)pFileMap;

	if( Header->e_magic != 'ZM' )
	{
		return FALSE;
	}

	if ( Header->e_lfanew > 0x1000 || Header->e_lfanew < 0 )
	{
		return FALSE;
	}

	PIMAGE_NT_HEADERS peheader = 
		(PIMAGE_NT_HEADERS)((LPBYTE)Header + Header->e_lfanew);

	if (peheader->Signature != 'EP' || 
		peheader->FileHeader.Machine != 0x014C &&  // x86
		peheader->FileHeader.Machine != 0x8664 )   // x64
//		peheader->OptionalHeader.SectionAlignment != PAGE_SIZE) // �ڴ��ж�������
	{
		return FALSE;
	}

	return TRUE;
}


// ����DLLMain
DWORD WINAPI DllInit(LPVOID lpwparam)
{
	pDllMainCall dllcall = (pDllMainCall)lpwparam;
	if (dllcall == NULL || dllcall->hmodule == NULL)
	{
		return -1;
	}

	PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)dllcall->hmodule;
	PIMAGE_NT_HEADERS peheader = 
		(PIMAGE_NT_HEADERS)((LPBYTE)Header + Header->e_lfanew);
	
	DWORD dwAddress = peheader->OptionalHeader.AddressOfEntryPoint;

	// ���ô�˵�е�DllMain
	pDllMain dllini = (pDllMain)( (LPBYTE)dllcall->hmodule + dwAddress) ;
	
	__try{
		if ( !dllini((HINSTANCE)dllcall->hmodule, dllcall->reasons, NULL) )
		{
			return -1;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return -1;
	}
	
	return 0;
}


// ����ϵͳ��ȫ�����ݵ�
BOOL CopyModuleSection(HMODULE SrcHmod, HMODULE DstHmod)
{
	PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)SrcHmod;
	PIMAGE_NT_HEADERS peheader = 
		(PIMAGE_NT_HEADERS)((DWORD)Header + Header->e_lfanew);
	ULONG check_number = 0 ;

	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)( (DWORD)peheader + 
		sizeof(peheader->FileHeader) + 
		sizeof(peheader->Signature) +
		peheader->FileHeader.SizeOfOptionalHeader ); // �ڱ���Ŀ�ʼ

	DWORD SectionNum = peheader->FileHeader.NumberOfSections; // ����Ŀ

	for (DWORD i=0; i<SectionNum; i++) // ����һ�������Ƶ��ڴ���
	{
		if ( !(SectionHeader[i].Characteristics&0x20000000) && // ����Ϊ��ִ�д���
			!(SectionHeader[i].Characteristics&0x20)  // ��������ִ�д���
			)
		{
			DWORD ulsize = SectionHeader[i].Misc.VirtualSize ;
			if ( ulsize > SectionHeader[i].SizeOfRawData )
			{
				ulsize = SectionHeader[i].SizeOfRawData;
			}
			copy_memory( (DWORD)DstHmod + SectionHeader[i].VirtualAddress,
				(DWORD)SrcHmod + SectionHeader[i].VirtualAddress,
				ulsize);
		}
	}
	return true;
}

HMODULE WINAPI LoadDllFromMemory(LPVOID pMemAddr)
{
    HMODULE hModule = MapThePeFile(pMemAddr);
    if (hModule == NULL)
    {
        return NULL;
    }

    // ˢд�ض�λ��
    if ( !RelocAddr(hModule) )
    {
        FreeMemory(hModule);
        return NULL;
    }

    // ˢ�µ����
    // �������ĸ��ʱȽϸ�,ץȡ���쳣
    FixIMPORT(hModule);

    // ˢ����ʱ����� , �ȿ��Ű�, �Ժ�ʵ��
    // 	if ( !DelayImport)
    // 	{
    //      FreeMemory(hModule);
    // 		return NULL;
    // 	}

    // ָ��TLS����
    //	ExecuteTLS(hModule);

    // ����һ���߳�, ����DLLMain (ͬ��)

    DllMainCall dllcall;
    dllcall.hmodule = hModule;
    dllcall.reasons = DLL_PROCESS_ATTACH;
    HANDLE handle = pRealCreateThread(NULL, 0, DllInit, (LPVOID)&dllcall, 0, NULL);
    if (handle != NULL)
    {
        pRealWaitForSingleObject(handle, INFINITE);
        pRealCloseHandle(handle);
    }

    return hModule;
}

// ����DLL����
HMODULE WINAPI LoadDllFromFileW(PWSTR szFileName)
{
    HMODULE hModule = NULL;
    HANDLE handle = FileOpenW(szFileName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    if (handle == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    // ӳ���ļ�
    HANDLE pWrite = pRealCreateFileMapping(handle,
        NULL,  
        PAGE_READONLY,  
        0,  
        0,  
        NULL);  
    pRealCloseHandle(handle);
    if (pWrite == NULL)
    {
        return NULL;
    }

    LPVOID pFile = pRealMapViewOfFile(pWrite, 
        FILE_MAP_READ,  
        0,  
        0,  
        0);  
    if (pFile == NULL || !isPEFile(pFile))
    {
        pRealCloseHandle(pWrite);
        return NULL;
    }
    hModule = LoadDllFromMemory(pFile);

    pRealUnmapViewOfFile(pFile);
    pRealCloseHandle(pWrite);

    G_This_LoadDll_Module = hModule;
    mymemcpy(G_This_LoadDll_Name, szFileName, MAX_PATH*sizeof(WCHAR));

    return hModule;
}

HMODULE WINAPI LoadDllFromFileA(PSTR szFileName)
{
    LPWSTR lpwzFileName = MulToWide(szFileName);
    HMODULE hModule = LoadDllFromFileW(lpwzFileName);
    FreeMemory(lpwzFileName);
    return hModule;
}


////////////////////////////////////////////////////////
// ��������������ַ
////////////////////////////////////////////////////////
LPVOID WINAPI MyGetProcAddress(HMODULE hmodule, PSTR szFuncName) 
{
    DWORD i = 0;
    // szFuncName == NULL ��ʱ��֪���Ǵ��ĺ�����,���Ǵ��ĺ���hintֵ
    if (hmodule == NULL || szFuncName == NULL)
    {
        return NULL;
    }
    
    PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)hmodule;
    PIMAGE_NT_HEADERS peheader = 
        (PIMAGE_NT_HEADERS)((DWORD)Header + Header->e_lfanew);
    
    // �������ַ
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY) // (pRELOADTABLE)
        ( (LPBYTE)hmodule + peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    // IAT��ַ
    LPBYTE pExportAddr = (LPBYTE)hmodule + peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD dwExportSize = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    
    PDWORD NameRVA = (PDWORD)((LPBYTE)hmodule + pExportDir->AddressOfNames );
    PDWORD FuncAddr = (PDWORD)((LPBYTE)hmodule + pExportDir->AddressOfFunctions);
    PWORD Ordinal = (PWORD)((LPBYTE)hmodule + pExportDir->AddressOfNameOrdinals);
    
    // ���������Ƶ����ĺ���
    LPBYTE funaddr = 0;
    if ( HIWORD(szFuncName) > 0 )
    {
//         OutputDebugStringA(szFuncName);
// 		OutputDebugStringA("\r\n");
        __try
        {
            for (i=0; i<pExportDir->NumberOfNames; i++)
            {
// 				char buf[8];
// 				wsprintfA(buf, "%d:\t", i);
// 				OutputDebugStringA(buf);
// 				OutputDebugStringA((PSTR)((DWORD)NameRVA[i]+(LPBYTE)hmodule));
// 				OutputDebugStringA("\r\n");
				LPSTR tmpfunname = (PSTR)((DWORD)NameRVA[i]+(LPBYTE)hmodule);
                if( mystrcmp( tmpfunname, szFuncName) == 0)
                {
                    WORD Hint = Ordinal[i];
                    funaddr = (LPBYTE)hmodule+FuncAddr[Hint];
                    break;
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return NULL;
        }
        
    }
    else
    {
        // ��������ŵ����ĺ���
//         OutputDebugStringA("orider");
        DWORD firstOrd = pExportDir->Base;
        PDWORD FuncAddr = (PDWORD)((LPBYTE)hmodule + pExportDir->AddressOfFunctions); 
        //////////////////////////////////////////////////////////////////////////
        //     �����������ֻ��������������Ordinal��һ����2��һ����8
        // ��NumberOfFunctions����Ϊ7����8-2+1��, firstOrd Ϊ 2
        //////////////////////////////////////////////////////////////////////////
        if (firstOrd+pExportDir->NumberOfFunctions > LOWORD(szFuncName))
        {
            funaddr = (LPBYTE)hmodule+FuncAddr[LOWORD(szFuncName)-firstOrd];
        }
    }
    
    // ����Ǻ���ת���򣬼�����
    PCHAR filename = (PCHAR)funaddr;
    if (funaddr != NULL && pExportAddr <= (LPBYTE)funaddr && pExportAddr+dwExportSize >= (LPBYTE)funaddr &&
        (filename[0]|0x20) >= 'a' && (filename[0]|0x20) <= 'z' &&
        (filename[1]|0x20) >= 'a' && (filename[1]|0x20) <= 'z' 
        )
    {
//         OutputDebugStringA("Next Stepped!");
        DWORD szlen = 0;
        char DllName[MAX_PATH] = {0};
        while(*funaddr != '.')
        {
            DllName[szlen] = *funaddr;
            funaddr++;
            szlen++;
        }
        funaddr++;
        DllName[szlen] = '\0';
        mystrcat(DllName, ".dll");
        HMODULE dllhmodule = pRealGetModuleHandleA(DllName);
        return MyGetProcAddress(dllhmodule, (LPSTR)funaddr);
    }
    
    return funaddr;
}

BOOL WINAPI FreeMyDlls(HMODULE hModule, BOOL bCallDllMain)
{
	if (!bCallDllMain)
	{
        return FreeMemory(hModule);
	}

	DllMainCall dllcall;
	if (hModule == NULL)
	{
		return FALSE;
	}
	dllcall.hmodule = hModule;
	dllcall.reasons = DLL_PROCESS_DETACH;
	HANDLE handle = pRealCreateThread(NULL, 0, DllInit, (LPVOID)&dllcall, 0, NULL);
	if (handle != NULL)
	{
		pRealWaitForSingleObject(handle, INFINITE);
		pRealCloseHandle(handle);
	}
    return FreeMemory(hModule);
}

// �޸�DstAddr��ַ���ڴ�����
BOOL copy_memory(DWORD DstAddr, DWORD SrcAddr, size_t dwsize)
{
	// 
	__try
	{
		DWORD OldProtect;
		pRealVirtualProtect((LPVOID)DstAddr, dwsize, PAGE_EXECUTE_READWRITE, &OldProtect);
		mymemcpy((LPVOID)DstAddr, (LPVOID)SrcAddr, dwsize);
		pRealVirtualProtect((LPVOID)DstAddr, dwsize, OldProtect, &OldProtect);
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		return false;
	}
	return true;
}