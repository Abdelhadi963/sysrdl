#pragma once
#include <windows.h>
#include <stdio.h>

// -----------------------------
// GetProcAddress Implimentation without Fowarder
// -----------------------------
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)

static FARPROC MyGetProcAddressNFW(HMODULE hModule, LPCSTR lpProcName) {
    if (hModule == NULL || lpProcName == NULL)
        return NULL;

    UINT_PTR uiLibraryAddress = (UINT_PTR)hModule;
    FARPROC fpResult = NULL;

    __try {
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
        PIMAGE_DATA_DIRECTORY pDataDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

        UINT_PTR uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);
        UINT_PTR uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);
        UINT_PTR uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

        // Check if import by ordinal
        if (((DWORD_PTR)lpProcName & 0xFFFF0000) == 0x00000000) {
            DWORD ordinal = IMAGE_ORDINAL((DWORD)lpProcName);
            DWORD index = ordinal - pExportDirectory->Base;

            if (index >= pExportDirectory->NumberOfFunctions)
                return NULL;

            DWORD functionRVA = DEREF_32(uiAddressArray + index * sizeof(DWORD));
            if (functionRVA == 0) return NULL;

            fpResult = (FARPROC)(uiLibraryAddress + functionRVA);
            printf("[+]      Ordinal %d -> %p\n", ordinal, fpResult);
        }
        else {
            // Import by name
            DWORD dwCounter = pExportDirectory->NumberOfNames;
            while (dwCounter--) {
                char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));

                if (strcmp(cpExportedFunctionName, lpProcName) == 0) {
                    WORD nameOrdinal = DEREF_16(uiNameOrdinals);
                    DWORD functionRVA = DEREF_32(uiLibraryAddress + pExportDirectory->AddressOfFunctions + (nameOrdinal * sizeof(DWORD)));

                    if (functionRVA == 0) return NULL;

                    fpResult = (FARPROC)(uiLibraryAddress + functionRVA);
                    printf("[+]      %s -> %p\n", cpExportedFunctionName, fpResult);
                    break;
                }

                uiNameArray += sizeof(DWORD);
                uiNameOrdinals += sizeof(WORD);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[ERROR] Exception in MyGetProcAddress for %s\n", lpProcName);
        fpResult = NULL;
    }

    return fpResult;
}