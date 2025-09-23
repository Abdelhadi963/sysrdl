#include "prototype.h"
#include "MyGetProcAddressNFW.h"
#include <winternl.h>
#include <stdarg.h>

#define NTSTATUS_INVALID_PARAMETER      0xC000000D
#define NTSTATUS_SUCCESS                0x00000000
#define NTSTATUS_INVALID_BUFFER_LENGTH  0xC0000023
#define NTSTATUS_DLL_NOT_FOUND          0xC0000135


// -----------------------------------------------------------
// Get current PEB
// -----------------------------------------------------------
PEB* GetCurrentPEB() {
#ifdef _WIN64
    return (PEB*)__readgsqword(0x60);
#else
    return (PEB*)__readfsdword(0x30);
#endif
}

// -----------------------------------------------------------
// Custom GetModuleHandleW via PEB
// -----------------------------------------------------------
HMODULE MyGetModuleHandleW(LPCWSTR lpModuleName) {
    PPEB peb = GetCurrentPEB();
    if (!peb || !peb->Ldr) return NULL;

    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current = head->Flink;

    // If lpModuleName is NULL, return first entry (main executable)
    if (!lpModuleName) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        return (HMODULE)module->DllBase;
    }

    while (current != head) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (module->FullDllName.Buffer) {
            wchar_t* fileName = wcsrchr(module->FullDllName.Buffer, L'\\');
            if (fileName) fileName++;
            else fileName = module->FullDllName.Buffer;

            if (_wcsicmp(fileName, lpModuleName) == 0) {
                /*wprintf(L"[+] Found module %s at: %p\n", lpModuleName, module->DllBase);*/
                return (HMODULE)module->DllBase;
            }
        }
        current = current->Flink;
    }

    wprintf(L"[!] Module %s not found\n", lpModuleName);
    return NULL;
}

// -----------------------------------------------------------
// LdrLoadDll prototype
// -----------------------------------------------------------
typedef NTSTATUS(NTAPI* pfnLdrLoadDll)(
    PCWSTR DllPath,
    PULONG DllCharacteristics,
    PUNICODE_STRING DllName,
    PVOID* DllHandle
    );

// -----------------------------------------------------------
// Wrapper for LdrLoadDll using MyGetModuleHandleW + MyGetProcAddress
// -----------------------------------------------------------
NTSTATUS FMyLdrLoadDll(PUNICODE_STRING DestinationPath, PVOID* BaseAddress) {
    HMODULE hNtdll = MyGetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        wprintf(L"[!] Failed to find ntdll.dll\n");
        return NTSTATUS_DLL_NOT_FOUND;
    }

    pfnLdrLoadDll pLdrLoadDll = (pfnLdrLoadDll)MyGetProcAddressNFW(hNtdll, "LdrLoadDll");
    if (!pLdrLoadDll) {
        wprintf(L"[!] Failed to resolve LdrLoadDll\n");
        return NTSTATUS_DLL_NOT_FOUND;
    }

    return pLdrLoadDll(NULL, NULL, DestinationPath, BaseAddress);
}

// -----------------------------------------------------------
// Wrapper for LoadLibraryW Around LdrLoader NT API
// -----------------------------------------------------------
NTSTATUS MyLoadLibraryW(LPCWSTR dllPath) {
    if (!dllPath) {
        wprintf(L"[!] Invalid dllPath pointer\n");
        return NTSTATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING DestinationPath;
    RtlInitUnicodeString(&DestinationPath, dllPath);

    if (DestinationPath.Length == 0) {
        wprintf(L"[!] Zero-length dllPath\n");
        return NTSTATUS_INVALID_BUFFER_LENGTH;
    }

    // Trim trailing spaces
    while (DestinationPath.Length >= sizeof(WCHAR) &&
        DestinationPath.Buffer[(DestinationPath.Length / sizeof(WCHAR)) - 1] == L' ') {
        DestinationPath.Length -= sizeof(WCHAR);
    }

    PVOID baseAddress = NULL;
    NTSTATUS status = FMyLdrLoadDll(&DestinationPath, &baseAddress);
    if (status == NTSTATUS_SUCCESS) {
        /*wprintf(L"[+] DLL loaded at %p\n", baseAddress);*/
    }
    else {
        wprintf(L"[!] LdrLoadDll failed with 0x%08X\n", status);
    }

    return status;
}

