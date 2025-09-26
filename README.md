# SysRDL

SysRDL is a simple reflective DLL loader that maps a DLL into the current process using direct syscalls.  
It includes custom implementations of `LoadLibraryW` and `GetProcAddress` (implemented in C and MASM) and supports RC4 encryption for the loaded dll.

**NOTE:** SysRDL does **not** perform remote injection. If you need remote injection, implement the injector inside the DLL you load into the target process.

## How to Use it ?
this project is created for learning direct syscalls in windows & about windows loader.
to compile & run this project  you need first to modify Syscalls_10_0_Build_26100.asm file cause is generated for my current build and syscalls numbers change accross windows builds a simple way to achive that just use my tool [sharpsyscall](https://github.com/Abdelhadi963/sharpsyscall) as follow.

```

```


## Windows API references
- `LoadLibraryW` — official Microsoft documentation: [LoadLibraryW (libloaderapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw). :contentReference[oaicite:0]{index=0}  
- `GetProcAddress` — official Microsoft documentation: [GetProcAddress (libloaderapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress). :contentReference[oaicite:1]{index=1}


