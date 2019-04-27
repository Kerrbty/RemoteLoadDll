#ifndef _RELOAD_MYSELF_DLL_MODEL_
#define _RELOAD_MYSELF_DLL_MODEL_

#include <windows.h>
#include <tchar.h>
#define PAGE_SIZE 0x1000

HMODULE WINAPI LoadMyDllsA( PSTR szFileName); // 加载DLL文件
HMODULE WINAPI LoadMyDllsW( PWSTR szFileName); // 加载DLL文件
BOOL WINAPI RelocAddr( HMODULE hModule ); // 修改重定位表
LPVOID WINAPI MyGetProcAddress(HMODULE hmodule, PSTR szFuncName); // 得到导出函数地址 or Orid 
BOOL WINAPI FreeMyDlls(HMODULE hmodule, BOOL bCallDllMain = TRUE); // 卸载dll


#endif  // _RELOAD_MYSELF_DLL_MODEL_