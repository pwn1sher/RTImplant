#pragma once
#include <stdint.h>
#include "shellcode.h"


typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;


// Struct Defenitions

typedef uint64_t* PQWORD;

typedef struct _REAL_DISPLAY_DEVICE
{
	DWORD cb;
	TCHAR DeviceName[32];
	TCHAR DeviceString[128];
	DWORD StateFlags;
	TCHAR DeviceID[128];
	TCHAR DeviceKey[128];
} REAL_DISPLAY_DEVICE;

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

// Other internal function declarations

VOID    PreChecks();
BOOL    EnvChecks();
VOID    AmIDebugged();
CHAR* GetDynamicMutex();
PWSTR   ReadEnvValue(PWSTR);
FARPROC GetFuncAddr(PVOID, DWORD);
DWORD   compute_hash(const void*, UINT32);
