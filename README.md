# SysRDL

SysRDL is a simple reflective DLL loader that maps a DLL into the current process using direct syscalls.  
It includes custom implementations of `LoadLibraryW` and `GetProcAddress` (implemented in C and MASM) and supports RC4 encryption for the loaded dll.

**NOTE:** SysRDL does **not** perform remote injection. If you need remote injection, implement the injector inside your DLL.

## How to Use it ?
this project is created for learning direct syscalls in windows & about windows loader.
to compile & run this project  you need first to modify Syscalls_10_0_Build_26100.asm file cause is generated for my current build and syscalls numbers change accross windows builds a simple way to achive that just use my tool [sharpsyscall](https://github.com/Abdelhadi963/sharpsyscall) as follow.

```powershell
.\sharpsyscall.exe 
```
<img width="769" height="155" alt="image" src="https://github.com/user-attachments/assets/9a977431-8d87-402b-a83d-40d69cd58b17" />

it's will generate some default stubs but it's enought feel free to remove inused assembly stubs check  [sharpsyscall](https://github.com/Abdelhadi963/sharpsyscall) repo on how to add your generated MASM file to your project & then you can build it simply.

## Usage 
It's so Simple as you can see in the help menu, just pass the dll file path use `-k` flag to provide RC4 encryption key if your dll is encrypted.
```
sysrdl.exe <path_to_dll> [-k <decryption_key>]
```
for the seek of our demo we can create a simple `MessageBoxDLL`, just create a C++ dynamic library project in visual studeo and past thr following code as you which, but the entry point should be `DLLMain` cause am calling this entry point, Fell free to change the entry point calling logic as you want.
```C
#include "pch.h"
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		MessageBox(NULL, L"MessageBoxDLL loaded!", L"Info", MB_OK);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
we can test that this DLL is working befor loading it to the current process, Simply using `rundll32.exe`.
```
Rundll32.exe MessageBoxDll.dll,DLLMain
```
## Windows API references
- `LoadLibraryW` — official Microsoft documentation: [LoadLibraryW (libloaderapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw). :contentReference[oaicite:0]{index=0}  
- `GetProcAddress` — official Microsoft documentation: [GetProcAddress (libloaderapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress). :contentReference[oaicite:1]{index=1}


