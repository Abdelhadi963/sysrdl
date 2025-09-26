# SysRDL

SysRDL is a simple reflective DLL loader that maps a DLL into the current process using direct syscalls.  
It includes custom implementations of `GetModuleHandleW` ,`LoadLibraryW` and `GetProcAddress` To resolve nested import and forwraded APIs and supports RC4 encryption for the loaded dll.
It include a simple assembly implementation for `GetImageBase` API via PEB parsing check `RDLStub.asm` file.

If you see `GetModuleHandleW` in the import table is just used internal by C runtime in my guess & we didn't called it any where, C run time use alot of windows APIs naturaly for some threading and trick we can compile the file staticly to avoid this but i want to keep it simple and use Visual Studio Compiler & Build Linker, It's harmless ( Defender will not catch Us!! ).
<img width="1402" height="688" alt="image" src="https://github.com/user-attachments/assets/bfe9b2a5-63ba-4142-be45-547f5f43653f" />

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
<img width="1371" height="235" alt="image" src="https://github.com/user-attachments/assets/4b436855-d8c9-4d22-960a-ad9caab7e251" />

### load an uncrypted DLL 
we can load it (i copied the same dll to my sysrdl project).
```
.\sysrdl.exe .\MessageBoxDLL.dll
```
<img width="1683" height="986" alt="image" src="https://github.com/user-attachments/assets/fb6a53e9-687b-4897-9afe-83337f7e6cc4" />

### load an encrypted DLL

i added a `rc4_encryptor.py` file in scripts folder you can simply use it to encrypt your DLL.
```powershell
python3 ..\..\scripts\rc4_encryptor.py -i .\MessageBoxDLL.dll -o .\MessageBoxDLL.bin -k ippyokai
[+] Encrypted .\MessageBoxDLL.dll -> .\MessageBoxDLL.bin (10752 bytes)
```
loading it using our key
```
.\sysrdl.exe .\MessageBoxDLL.bin -k ippyokai
```
<img width="1742" height="972" alt="image" src="https://github.com/user-attachments/assets/b6109c3f-dba1-48ce-9ad4-00a4a1708531" />

## Using Reflective DLL
in this section we can give a real example using a `meterprter` dll.
as we know our code inject to the current process but we can use a meterpreter dll that it self has a reflective loader stub that inject it's self to another process (rundll32.exe) to spawn meterpreter session.

generate a simple x64 dll & encode it using the same script.

load it we can spot the remote injection pattern from the resolved APIs.
<img width="1281" height="648" alt="image" src="https://github.com/user-attachments/assets/76ba04d1-a7f5-463e-8327-72e0495b68e8" />

check our metasploit console we can see that we have got the callback ( remember defender is fully working but not catching us)
<img width="1731" height="751" alt="image" src="https://github.com/user-attachments/assets/ed97cad7-7110-4e54-894c-753b6ef23297" />

Now it's easy to check is injected to `Rundll32.exe` just use `getpid` grap your pid in meterprter session then we can get the process name using powershell as follow.
```powershell
 Get-CimInstance Win32_Process -Filter "ProcessId=<your pid from getpid>" | Select-Object ProcessId, ProcessName
```
<img width="1577" height="127" alt="image" src="https://github.com/user-attachments/assets/294f5169-38f4-49a9-9ebe-c133ae3509eb" />

To make sure just use process explorer and kill rundll32.exe :) and session will die.
# How it's Work !!
this section will be added soon on how i implimented `GetModuleHandleW` ,`LoadLibraryW` and `GetProcAddress` & how the reloaction and every thing else works.

## Windows API references
- `LoadLibraryW` — official Microsoft documentation: [LoadLibraryW (libloaderapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw).
- `GetProcAddress` — official Microsoft documentation: [GetProcAddress (libloaderapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).

