#pragma once
#include <windows.h>
#include <stdio.h>
#include "MyLoadLibraryW.h"

#define MAX_FORWARDER_CHAIN 10


// -----------------------------
// GetProcAddress Implimentation Inspired By @stephenfewer Impelemetation
// -----------------------------
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)

static FARPROC MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName, int chainDepth) {
    UINT_PTR uiLibraryAddress = 0;
    FARPROC fpResult = NULL;
    NTSTATUS status;

    if (hModule == NULL || lpProcName == NULL)
        return NULL;

    if (chainDepth > MAX_FORWARDER_CHAIN + 2 ) {
        printf("[ERROR] Forwarder chain too deep: %d\n", chainDepth);
        return NULL;
    }

    // Module handle is really its base address
    uiLibraryAddress = (UINT_PTR)hModule;

    __try
    {
        UINT_PTR uiAddressArray = 0;
        UINT_PTR uiNameArray = 0;
        UINT_PTR uiNameOrdinals = 0;
        PIMAGE_NT_HEADERS pNtHeaders = NULL;
        PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
        PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

        // Get the VA of the modules NT Header
        pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
        pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        // Get the VA of the export directory
        pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

        // Get the VA for the array of addresses
        uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);
        // Get the VA for the array of name pointers
        uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);
        // Get the VA for the array of name ordinals
        uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

        // Test if we are importing by name or by ordinal
        if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
        {
            // Import by ordinal
            DWORD ordinal = IMAGE_ORDINAL((DWORD)lpProcName);
            DWORD index = ordinal - pExportDirectory->Base;

            if (index >= pExportDirectory->NumberOfFunctions) {
                return NULL;
            }

            // Use the import ordinal (- export ordinal base) as an index into the array of addresses
            uiAddressArray += (index * sizeof(DWORD));
            DWORD functionRVA = DEREF_32(uiAddressArray);

            if (functionRVA == 0) {
                return NULL;
            }

            // Check if this is a forwarder (RVA points within export directory)
            if (functionRVA >= pDataDirectory->VirtualAddress &&
                functionRVA < pDataDirectory->VirtualAddress + pDataDirectory->Size)
            {
                // This is a forwarder
                char* forwarderString = (char*)(uiLibraryAddress + functionRVA);
                /*printf("[DEBUG] Ordinal %d forwarded to: %s\n", ordinal, forwarderString);*/

                char forwarder[256] = { 0 };
                strncpy_s(forwarder, sizeof(forwarder), forwarderString, _TRUNCATE);

                char* dot = strchr(forwarder, '.');
                if (!dot) return NULL;
                *dot = '\0';
                char* funcName = dot + 1;

                // Ensure forwarder module name ends with ".dll"
                char forwarderModule[MAX_PATH] = { 0 };
                strncpy_s(forwarderModule, sizeof(forwarderModule), forwarder, _TRUNCATE);

                // Append ".dll" if not present
                if (_stricmp(forwarderModule + strlen(forwarderModule) - 4, ".dll") != 0) {
                    strcat_s(forwarderModule, sizeof(forwarderModule), ".dll");
                }

                
                wchar_t wForwarder[MAX_PATH] = { 0 };
                size_t converted = 0;
                mbstowcs_s(&converted, wForwarder, MAX_PATH, forwarderModule, _TRUNCATE);

         
                status = MyLoadLibraryW(wForwarder);
                if (status != NTSTATUS_SUCCESS) {
                    wprintf(L"[!] Failed to load %ls: 0x%08X\n", wForwarder, status);
                }

                // Retrieve the module handle after loading
                HMODULE hForward = MyGetModuleHandleW(wForwarder);

                
                if (!hForward) return NULL;

                // Check if funcName is an ordinal
                if ((uintptr_t)funcName <= 0xFFFF) {
                    return MyGetProcAddress(hForward, funcName, chainDepth + 1);
                }
                else {
                    return MyGetProcAddress(hForward, funcName, chainDepth + 1);
                }
            }

            // Resolve the address for this imported function
            fpResult = (FARPROC)(uiLibraryAddress + functionRVA);
            printf("[+]      Ordinal %d -> %p\n", ordinal, fpResult);
        }
        else
        {
            // Import by name
            DWORD dwCounter = pExportDirectory->NumberOfNames;
            while (dwCounter--)
            {
                char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));

                // Test if we have a match
                if (strcmp(cpExportedFunctionName, lpProcName) == 0)
                {
                    // Use the functions name ordinal as an index into the array of addresses
                    WORD nameOrdinal = DEREF_16(uiNameOrdinals);
                    DWORD functionRVA = DEREF_32(uiLibraryAddress + pExportDirectory->AddressOfFunctions + (nameOrdinal * sizeof(DWORD)));

                    if (functionRVA == 0) {
                        return NULL;
                    }

                    // Check if this is a forwarder (RVA points within export directory)
                    if (functionRVA >= pDataDirectory->VirtualAddress &&
                        functionRVA < pDataDirectory->VirtualAddress + pDataDirectory->Size)
                    {
                        // This is a forwarder
                        char* forwarderString = (char*)(uiLibraryAddress + functionRVA);
                        /*printf("[DEBUG] %s forwarded to: %s\n", lpProcName, forwarderString);*/

                        char forwarder[256] = { 0 };
                        strncpy_s(forwarder, sizeof(forwarder), forwarderString, _TRUNCATE);

                        char* dot = strchr(forwarder, '.');
                        if (!dot) return NULL;
                        *dot = '\0';
                        char* funcName = dot + 1;

                        // Ensure forwarder module name ends with ".dll"
                        char forwarderModule[MAX_PATH] = { 0 };
                        strncpy_s(forwarderModule, sizeof(forwarderModule), forwarder, _TRUNCATE);

                        // Append ".dll" if not present
                        if (_stricmp(forwarderModule + strlen(forwarderModule) - 4, ".dll") != 0) {
                            strcat_s(forwarderModule, sizeof(forwarderModule), ".dll");
                        }

                        
                        wchar_t wForwarder[MAX_PATH] = { 0 };
                        size_t converted = 0;
                        mbstowcs_s(&converted, wForwarder, MAX_PATH, forwarderModule, _TRUNCATE);

                        
                        status = MyLoadLibraryW(wForwarder);
                        if (status != NTSTATUS_SUCCESS) {
                            wprintf(L"[!] Failed to load %ls: 0x%08X\n", wForwarder, status);
                        }

                        
                        HMODULE hForward = MyGetModuleHandleW(wForwarder);

                        if (!hForward) return NULL;

                        // Simple infinite loop prevention: if same module and same name, fail !!
                        if (hForward == hModule && strcmp(funcName, lpProcName) == 0) {
                            printf("[ERROR] Circular forwarder detected: %s\n", lpProcName);
                            return NULL;
                        }

                        // Check if funcName is an ordinal
                        if ((uintptr_t)funcName <= 0xFFFF) {
                            return MyGetProcAddress(hForward, funcName, chainDepth + 1);
                        }
                        else {
                            return MyGetProcAddress(hForward, funcName, chainDepth + 1);
                        }
                    }

                    // Calculate the virtual address for the function
                    fpResult = (FARPROC)(uiLibraryAddress + functionRVA);
                    printf("[+]      %s -> %p\n", cpExportedFunctionName, fpResult);
                    break;
                }

                // Get the next exported function name
                uiNameArray += sizeof(DWORD);
                // Get the next exported function name ordinal
                uiNameOrdinals += sizeof(WORD);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("[ERROR] Exception in MyGetProcAddress for %s\n", lpProcName);
        fpResult = NULL;
    }

    return fpResult;
}
