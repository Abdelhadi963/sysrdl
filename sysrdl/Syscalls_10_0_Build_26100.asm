; ============================================================
;  Syscall Stubs for Windows 10.0 (Build 26100)
;  ------------------------------------------------------------
;  These syscall numbers are specific to this Windows build.
;  Syscall numbers often change across builds, so regenerate
;  this file when targeting a different Windows version.
; ============================================================

.code

    ; NtOpenProcess - Syscall Number: 38
    SysNtOpenProcess proc
         mov r10, rcx
         mov eax, 26h
         syscall
         ret
    SysNtOpenProcess endp

    ; ZwOpenProcess - Syscall Number: 38
    SysZwOpenProcess proc
         mov r10, rcx
         mov eax, 26h
         syscall
         ret
    SysZwOpenProcess endp

    ; NtWriteVirtualMemory - Syscall Number: 58
    SysNtWriteVirtualMemory proc
         mov r10, rcx
         mov eax, 3Ah
         syscall
         ret
    SysNtWriteVirtualMemory endp

    ; ZwWriteVirtualMemory - Syscall Number: 58
    SysZwWriteVirtualMemory proc
         mov r10, rcx
         mov eax, 3Ah
         syscall
         ret
    SysZwWriteVirtualMemory endp

    ; NtProtectVirtualMemory - Syscall Number: 80
    SysNtProtectVirtualMemory proc
         mov r10, rcx
         mov eax, 50h
         syscall
         ret
    SysNtProtectVirtualMemory endp

    ; ZwProtectVirtualMemory - Syscall Number: 80
    SysZwProtectVirtualMemory proc
         mov r10, rcx
         mov eax, 50h
         syscall
         ret
    SysZwProtectVirtualMemory endp

    ; NtCreateThreadEx - Syscall Number: 201
    SysNtCreateThreadEx proc
         mov r10, rcx
         mov eax, 0C9h
         syscall
         ret
    SysNtCreateThreadEx endp

    ; ZwCreateThreadEx - Syscall Number: 201
    SysZwCreateThreadEx proc
         mov r10, rcx
         mov eax, 0C9h
         syscall
         ret
    SysZwCreateThreadEx endp

    ; NtClose - Syscall Number: 15
    SysNtClose proc
         mov r10, rcx
         mov eax, 0Fh
         syscall
         ret
    SysNtClose endp

    ; ZwClose - Syscall Number: 15
    SysZwClose proc
         mov r10, rcx
         mov eax, 0Fh
         syscall
         ret
    SysZwClose endp

    ; NtQueryInformationProcess - Syscall Number: 25
    SysNtQueryInformationProcess proc
         mov r10, rcx
         mov eax, 19h
         syscall
         ret
    SysNtQueryInformationProcess endp

    ; ZwQueryInformationProcess - Syscall Number: 25
    SysZwQueryInformationProcess proc
         mov r10, rcx
         mov eax, 19h
         syscall
         ret
    SysZwQueryInformationProcess endp

    ; NtAllocateVirtualMemory - Syscall Number: 24
    SysNtAllocateVirtualMemory proc
         mov r10, rcx
         mov eax, 18h
         syscall
         ret
    SysNtAllocateVirtualMemory endp

    ; ZwAllocateVirtualMemory - Syscall Number: 24
    SysZwAllocateVirtualMemory proc
         mov r10, rcx
         mov eax, 18h
         syscall
         ret
    SysZwAllocateVirtualMemory endp

    ; ZwQuerySystemInformation - Syscall Number: 54
    SysZwQuerySystemInformation proc
         mov r10, rcx
         mov eax, 36h
         syscall
         ret
    SysZwQuerySystemInformation endp

    ; NtFreeVirtualMemory - Syscall Number: 30
    SysNtFreeVirtualMemory proc
         mov r10, rcx
         mov eax, 1Eh
         syscall
         ret
    SysNtFreeVirtualMemory endp

    ; ZwFreeVirtualMemory - Syscall Number: 30
    SysZwFreeVirtualMemory proc
         mov r10, rcx
         mov eax, 1Eh
         syscall
         ret
    SysZwFreeVirtualMemory endp

    ; NtOpenThread - Syscall Number: 57
    SysNtOpenThread proc
         mov r10, rcx
         mov eax, 39h
         syscall
         ret
    SysNtOpenThread endp

    ; ZwOpenThread - Syscall Number: 57
    SysZwOpenThread proc
         mov r10, rcx
         mov eax, 39h
         syscall
         ret
    SysZwOpenThread endp

    ; NtResumeThread - Syscall Number: 82
    SysNtResumeThread proc
         mov r10, rcx
         mov eax, 52h
         syscall
         ret
    SysNtResumeThread endp

    ; ZwResumeThread - Syscall Number: 82
    SysZwResumeThread proc
         mov r10, rcx
         mov eax, 52h
         syscall
         ret
    SysZwResumeThread endp

    ; NtSuspendThread - Syscall Number: 207
    SysNtSuspendThread proc
         mov r10, rcx
         mov eax, 0CFh
         syscall
         ret
    SysNtSuspendThread endp

    ; ZwSuspendThread - Syscall Number: 207
    SysZwSuspendThread proc
         mov r10, rcx
         mov eax, 0CFh
         syscall
         ret
    SysZwSuspendThread endp

    ; NtCreateFile - Syscall Number: 85
    SysNtCreateFile proc
         mov r10, rcx
         mov eax, 55h
         syscall
         ret
    SysNtCreateFile endp

    ; ZwCreateFile - Syscall Number: 85
    SysZwCreateFile proc
         mov r10, rcx
         mov eax, 55h
         syscall
         ret
    SysZwCreateFile endp

    ; NtOpenFile - Syscall Number: 51
    SysNtOpenFile proc
         mov r10, rcx
         mov eax, 33h
         syscall
         ret
    SysNtOpenFile endp

    ; ZwOpenFile - Syscall Number: 51
    SysZwOpenFile proc
         mov r10, rcx
         mov eax, 33h
         syscall
         ret
    SysZwOpenFile endp

    ; NtReadFile - Syscall Number: 6
    SysNtReadFile proc
         mov r10, rcx
         mov eax, 06h
         syscall
         ret
    SysNtReadFile endp

    ; ZwReadFile - Syscall Number: 6
    SysZwReadFile proc
         mov r10, rcx
         mov eax, 06h
         syscall
         ret
    SysZwReadFile endp

    ; NtWriteFile - Syscall Number: 8
    SysNtWriteFile proc
         mov r10, rcx
         mov eax, 08h
         syscall
         ret
    SysNtWriteFile endp

    ; ZwWriteFile - Syscall Number: 8
    SysZwWriteFile proc
         mov r10, rcx
         mov eax, 08h
         syscall
         ret
    SysZwWriteFile endp

    ; NtQueryInformationFile - Syscall Number: 17
    SysNtQueryInformationFile proc
         mov r10, rcx
         mov eax, 11h
         syscall
         ret
    SysNtQueryInformationFile endp

    ; ZwQueryInformationFile - Syscall Number: 17
    SysZwQueryInformationFile proc
         mov r10, rcx
         mov eax, 11h
         syscall
         ret
    SysZwQueryInformationFile endp

    ; NtQueryDirectoryFile - Syscall Number: 53
    SysNtQueryDirectoryFile proc
         mov r10, rcx
         mov eax, 35h
         syscall
         ret
    SysNtQueryDirectoryFile endp

    ; ZwQueryDirectoryFile - Syscall Number: 53
    SysZwQueryDirectoryFile proc
         mov r10, rcx
         mov eax, 35h
         syscall
         ret
    SysZwQueryDirectoryFile endp

    ; NtQueryAttributesFile - Syscall Number: 61
    SysNtQueryAttributesFile proc
         mov r10, rcx
         mov eax, 3Dh
         syscall
         ret
    SysNtQueryAttributesFile endp

    ; ZwQueryAttributesFile - Syscall Number: 61
    SysZwQueryAttributesFile proc
         mov r10, rcx
         mov eax, 3Dh
         syscall
         ret
    SysZwQueryAttributesFile endp

    ; NtSetInformationFile - Syscall Number: 39
    SysNtSetInformationFile proc
         mov r10, rcx
         mov eax, 27h
         syscall
         ret
    SysNtSetInformationFile endp

    ; ZwSetInformationFile - Syscall Number: 39
    SysZwSetInformationFile proc
         mov r10, rcx
         mov eax, 27h
         syscall
         ret
    SysZwSetInformationFile endp

    ; NtDeleteFile - Syscall Number: 219
    SysNtDeleteFile proc
         mov r10, rcx
         mov eax, 0DBh
         syscall
         ret
    SysNtDeleteFile endp

    ; ZwDeleteFile - Syscall Number: 219
    SysZwDeleteFile proc
         mov r10, rcx
         mov eax, 0DBh
         syscall
         ret
    SysZwDeleteFile endp

    ; NtCreateSection - Syscall Number: 74
    SysNtCreateSection proc
         mov r10, rcx
         mov eax, 4Ah
         syscall
         ret
    SysNtCreateSection endp

    ; ZwCreateSection - Syscall Number: 74
    SysZwCreateSection proc
         mov r10, rcx
         mov eax, 4Ah
         syscall
         ret
    SysZwCreateSection endp

    ; NtMapViewOfSection - Syscall Number: 40
    SysNtMapViewOfSection proc
         mov r10, rcx
         mov eax, 28h
         syscall
         ret
    SysNtMapViewOfSection endp

    ; ZwMapViewOfSection - Syscall Number: 40
    SysZwMapViewOfSection proc
         mov r10, rcx
         mov eax, 28h
         syscall
         ret
    SysZwMapViewOfSection endp

    ; NtUnmapViewOfSection - Syscall Number: 42
    SysNtUnmapViewOfSection proc
         mov r10, rcx
         mov eax, 2Ah
         syscall
         ret
    SysNtUnmapViewOfSection endp

    ; ZwUnmapViewOfSection - Syscall Number: 42
    SysZwUnmapViewOfSection proc
         mov r10, rcx
         mov eax, 2Ah
         syscall
         ret
    SysZwUnmapViewOfSection endp

end
