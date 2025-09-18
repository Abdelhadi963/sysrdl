#pragma once
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// -----------------------------------------------------------
// Constants
// -----------------------------------------------------------
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L) 

// -----------------------------------------------------------
// Structures
// -----------------------------------------------------------
typedef CLIENT_ID* PCLIENT_ID;
typedef struct _FILE_NETWORK_OPEN_INFORMATION* PFILE_NETWORK_OPEN_INFORMATION;
typedef int SECTION_INHERIT;


// -----------------------------------------------------------
// Helper macro for initializing OBJECT_ATTRIBUTES
// -----------------------------------------------------------
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
    }

// -----------------------------------------------------------
// Minimal inline version of RtlInitUnicodeString 
// -----------------------------------------------------------
static inline void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (DestinationString) {
        DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR));
        DestinationString->MaximumLength = DestinationString->Length + sizeof(WCHAR);
        DestinationString->Buffer = (PWSTR)SourceString;
    }
}
#ifdef __cplusplus
extern "C" {
#endif

    // ------------------- Process / Memory / Thread -------------------

    NTSTATUS SysNtOpenProcess(
        _Out_ PHANDLE ProcessHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ PCLIENT_ID ClientId
    );
    NTSTATUS SysQuerySystemInformation(
        _In_ ULONG SystemInformationClass,
        _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
        _In_ ULONG SystemInformationLength,
        _Out_opt_ PULONG ReturnLength
	);

    NTSTATUS SysNtWriteVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _In_ PVOID BaseAddress,
        _In_reads_bytes_(BufferSize) PVOID Buffer,
        _In_ SIZE_T BufferSize,
        _Out_opt_ PSIZE_T NumberOfBytesWritten
    );

    NTSTATUS SysNtProtectVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _Inout_ PVOID* BaseAddress,
        _Inout_ PSIZE_T NumberOfBytesToProtect,
        _In_ ULONG NewAccessProtection,
        _Out_ PULONG OldAccessProtection
    );

    NTSTATUS SysNtCreateThreadEx(
        _Out_ PHANDLE ThreadHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_ HANDLE ProcessHandle,
        _In_ PVOID StartRoutine,
        _In_opt_ PVOID Argument,
        _In_ ULONG CreateFlags,
        _In_ SIZE_T ZeroBits,
        _In_ SIZE_T StackSize,
        _In_ SIZE_T MaximumStackSize,
        _In_opt_ PVOID AttributeList
    );

    NTSTATUS SysNtClose(
        _In_ HANDLE Handle
    );

    NTSTATUS SysNtQueryInformationProcess(
        _In_ HANDLE ProcessHandle,
        _In_ PROCESSINFOCLASS ProcessInformationClass,
        _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
        _In_ ULONG ProcessInformationLength,
        _Out_opt_ PULONG ReturnLength
    );

    NTSTATUS SysNtAllocateVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _Inout_ PVOID* BaseAddress,
        _In_ ULONG_PTR ZeroBits,
        _Inout_ PSIZE_T RegionSize,
        _In_ ULONG AllocationType,
        _In_ ULONG Protect
    );

    NTSTATUS SysNtFreeVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _Inout_ PVOID* BaseAddress,
        _Inout_ PSIZE_T RegionSize,
        _In_ ULONG FreeType
    );

    NTSTATUS SysNtOpenThread(
        _Out_ PHANDLE ThreadHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ PCLIENT_ID ClientId
    );

    NTSTATUS SysNtResumeThread(
        _In_ HANDLE ThreadHandle,
        _Out_opt_ PULONG PreviousSuspendCount
    );

    NTSTATUS SysNtSuspendThread(
        _In_ HANDLE ThreadHandle,
        _Out_opt_ PULONG PreviousSuspendCount
    );

    // ------------------- File / Filesystem -------------------

    NTSTATUS SysNtCreateFile(
        _Out_ PHANDLE FileHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_opt_ PLARGE_INTEGER AllocationSize,
        _In_ ULONG FileAttributes,
        _In_ ULONG ShareAccess,
        _In_ ULONG CreateDisposition,
        _In_ ULONG CreateOptions,
        _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
        _In_ ULONG EaLength
    );

    NTSTATUS SysNtOpenFile(
        _Out_ PHANDLE FileHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_ ULONG ShareAccess,
        _In_ ULONG OpenOptions
    );

    NTSTATUS SysNtReadFile(
        _In_ HANDLE FileHandle,
        _In_opt_ HANDLE Event,
        _In_opt_ PIO_APC_ROUTINE ApcRoutine,
        _In_opt_ PVOID ApcContext,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _Out_writes_bytes_to_(Length, *ByteCount) PVOID Buffer,
        _In_ ULONG Length,
        _In_opt_ PLARGE_INTEGER ByteOffset,
        _In_opt_ PULONG Key
    );

    NTSTATUS SysNtWriteFile(
        _In_ HANDLE FileHandle,
        _In_opt_ HANDLE Event,
        _In_opt_ PIO_APC_ROUTINE ApcRoutine,
        _In_opt_ PVOID ApcContext,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_reads_bytes_(Length) PVOID Buffer,
        _In_ ULONG Length,
        _In_opt_ PLARGE_INTEGER ByteOffset,
        _In_opt_ PULONG Key
    );

    NTSTATUS SysNtQueryInformationFile(
        _In_ HANDLE FileHandle,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _Out_writes_bytes_(Length) PVOID FileInformation,
        _In_ ULONG Length,
        _In_ FILE_INFORMATION_CLASS FileInformationClass
    );

    NTSTATUS SysNtQueryDirectoryFile(
        _In_ HANDLE FileHandle,
        _In_opt_ HANDLE Event,
        _In_opt_ PIO_APC_ROUTINE ApcRoutine,
        _In_opt_ PVOID ApcContext,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _Out_writes_bytes_(Length) PVOID FileInformation,
        _In_ ULONG Length,
        _In_ FILE_INFORMATION_CLASS FileInformationClass,
        _In_ BOOLEAN ReturnSingleEntry,
        _In_opt_ PUNICODE_STRING FileName,
        _In_ BOOLEAN RestartScan
    );

    NTSTATUS SysNtQueryAttributesFile(
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PFILE_NETWORK_OPEN_INFORMATION FileInformation
    );

    NTSTATUS SysNtSetInformationFile(
        _In_ HANDLE FileHandle,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_reads_bytes_(Length) PVOID FileInformation,
        _In_ ULONG Length,
        _In_ FILE_INFORMATION_CLASS FileInformationClass
    );

    NTSTATUS SysNtDeleteFile(
        _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

    // ------------------- Section / Mapping -------------------

    NTSTATUS SysNtCreateSection(
        _Out_ PHANDLE SectionHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
        _In_opt_ PLARGE_INTEGER MaximumSize,
        _In_ ULONG SectionPageProtection,
        _In_ ULONG AllocationAttributes,
        _In_opt_ HANDLE FileHandle
    );

    NTSTATUS SysNtMapViewOfSection(
        _In_ HANDLE SectionHandle,
        _In_ HANDLE ProcessHandle,
        _Inout_ PVOID* BaseAddress,
        _In_ ULONG_PTR ZeroBits,
        _In_ SIZE_T CommitSize,
        _Inout_opt_ PLARGE_INTEGER SectionOffset,
        _Inout_ PSIZE_T ViewSize,
        _In_ SECTION_INHERIT InheritDisposition,
        _In_ ULONG AllocationType,
        _In_ ULONG Win32Protect
    );

    NTSTATUS SysNtUnmapViewOfSection(
        _In_ HANDLE ProcessHandle,
        _In_ PVOID BaseAddress
    );

#ifdef __cplusplus
}
#endif
