#pragma once

#include <Windows.h>
#include <iostream>

#define NF_GET_PROCESS_ID CTL_CODE(FILE_DEVICE_UNKNOWN, 0xf9000, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define NF_GET_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0xf9001, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define NF_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0xf9002, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define NF_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0xf9003, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define NF_MOUSE_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0xf9004, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _NF_PROCESS_ID_REQUEST
{
	ULONG process_id;
	char process_name[64];
}NF_PROCESS_ID_REQUEST, * PNF_PROCESS_ID_REQUEST;

typedef struct _NF_MODULE_REQUEST
{
	ULONG process_id;
	ULONG address;
	wchar_t module_name[64];
}NF_MODULE_REQUEST, * PNF_MODULE_REQUEST;

typedef struct _NF_READ_REQUEST
{
	ULONG process_id;
	ULONG address;
	ULONG buffer;
	ULONG size;
}NF_READ_REQUEST, * PNF_READ_REQUEST;

typedef struct _NF_WRITE_REQUEST
{
	ULONG process_id;
	ULONG address;
	ULONG buffer;
	ULONG size;
}NF_WRITE_REQUEST, * PNF_WRITE_REQUEST;

typedef struct _NF_MOUSE_REQUEST
{
	long x;
	long y;
	unsigned short button_flags;
}NF_MOUSE_REQUEST, * PNF_MOUSE_REQUEST;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;