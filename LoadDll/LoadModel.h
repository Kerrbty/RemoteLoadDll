#ifndef _RELOAD_MYSELF_DLL_MODEL_
#define _RELOAD_MYSELF_DLL_MODEL_

#include <windows.h>
#include <tchar.h>
#define PAGE_SIZE 0x1000

HMODULE WINAPI LoadMyDllsA( PSTR szFileName); // ����DLL�ļ�
HMODULE WINAPI LoadMyDllsW( PWSTR szFileName); // ����DLL�ļ�
BOOL WINAPI RelocAddr( HMODULE hModule ); // �޸��ض�λ��
LPVOID WINAPI MyGetProcAddress(HMODULE hmodule, PSTR szFuncName); // �õ�����������ַ or Orid 
BOOL WINAPI FreeMyDlls(HMODULE hmodule, BOOL bCallDllMain = TRUE); // ж��dll


#endif  // _RELOAD_MYSELF_DLL_MODEL_