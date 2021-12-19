# Background

This repo started off as my endeavour into finding a way to bypass BattleEyes exploit detection methods. The purpose of this was to learn more about cheat development, reverse engineering and areas of code that stray away from the usualy enterprise code that I'm more used to.

# Library

This is a very simple and lazily written library that allows me to utilize the driver mentioned below in a generic way to perform read and write memory operations from the kernel as opposed to userland. Utilizing the `DllImport attribute` and `extern keyword`, we can utilize the functions exposed on the C++ DLL in this C# library. Furthermore, this library was written to be easily ported into new projects as it deals with generic concepts such as processes, modules and offsets.

# Driver

This is a very hacky driver: It leverages an EFI driver loaded at runtime which patches out the native SetVariable function so that if a specific hard-coded variable is passed up it knows to run our patched code as opposed to the generic SetVariable implementation. This effectively gives us acces to read and write memory operations from a kernel level.

### Challenge: Walking the PEB

As this set-up above purely allows us to utilize read and write memory operations, there are still a lot of short-comings: For example, what happens if a process, I.E BattleEye, strips the process handle from the process we intend to read and write from? We have the process id, but since we can't obtain a handle to it, it's *verrrry hard* to figure out where in memory to read and write from and what to offset to find certain modules within the process.

Enter the `PEB`.

The PEB, or Process Environment Block, is a partially undocumented Windows NT data structure that details information regarding a given process. Every process has a PEB. It contains a lot of useful info, such as whether the process is being debugged, or maybe the base address of the process. This is how we leverage our ability to read data unrestricted, by bruteforcing our way up the PEB:

We define a lot of different structs based on documentation explaining how the PEB is set-up and it's offsets and fields, and then we load some NT API functions and use them to get some basic information on the process. From there we obtain the base address and use the `LDR` structure within the PEB to find the module we're looking for. The `LDR` structure is basically a doubly linked list of all the loaded modules within the process and the base address for each module.

This is how, in let's say, Escape From Tarkov, we're able to simply pass in the Process ID, the name of the module and any given offset we may require, and get the modules base address back, even if the process handle was stripped.

```
extern "C"
{
	uintptr_t Driver::GetModuleBaseAddress(DWORD procId, const char* nameAsChar, uintptr_t offset)
	{
		BOOL  bReturnStatus = TRUE;
		DWORD dwSize = 0;
		DWORD dwSizeNeeded = 0;
		DWORD dwBytesRead = 0;
		DWORD dwBufferSize = 0;
		HANDLE hHeap = 0;
		WCHAR* pwszBuffer = NULL;

		smPPROCESS_BASIC_INFORMATION pbi = NULL;

		smPEB peb = { 0 };
		smPEB_LDR_DATA peb_ldr = { 0 };
		smRTL_USER_PROCESS_PARAMETERS peb_upp = { 0 };

		ZeroMemory(&peb, sizeof(peb));
		ZeroMemory(&peb_ldr, sizeof(peb_ldr));
		ZeroMemory(&peb_upp, sizeof(peb_upp));

		// Attempt to access process
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION , FALSE, procId);
		if (hProcess == INVALID_HANDLE_VALUE) {
			return FALSE;
		}

		// Try to allocate buffer 
		hHeap = GetProcessHeap();
		dwSize = sizeof(smPROCESS_BASIC_INFORMATION);
		pbi = (smPPROCESS_BASIC_INFORMATION)HeapAlloc(hHeap,
			HEAP_ZERO_MEMORY,
			dwSize);
		// Did we successfully allocate memory
		if (!pbi) {
			CloseHandle(hProcess);
			return FALSE;
		}

		HMODULE hNtDll = LoadLibrary((L"ntdll.dll"));
		gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll,"NtQueryInformationProcess");

		// Attempt to get basic info on process
		NTSTATUS dwStatus = gNtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, dwSize, &dwSizeNeeded);

		// If we had error and buffer was too small, try again
		// with larger buffer size (dwSizeNeeded)
		if (dwStatus >= 0 && dwSize < dwSizeNeeded)
		{
			if (pbi)
				HeapFree(hHeap, 0, pbi);
			pbi = (smPPROCESS_BASIC_INFORMATION)HeapAlloc(hHeap,
				HEAP_ZERO_MEMORY,
				dwSizeNeeded);
			if (!pbi) {
				CloseHandle(hProcess);
				return FALSE;
			}
			dwStatus = gNtQueryInformationProcess(hProcess,
				ProcessBasicInformation,
				pbi, dwSizeNeeded, &dwSizeNeeded);
		}

		LIST_ENTRY currEntry = {};
		LIST_ENTRY* currEntryFlink = {};

		if (dwStatus >= 0)
		{
			if (pbi->PebBaseAddress)
			{
				Driver::initialize();
				if (Driver::read_memory(procId, reinterpret_cast<uintptr_t>(pbi->PebBaseAddress), reinterpret_cast<uintptr_t>(&peb), sizeof(peb)) == 0) {
					if (Driver::read_memory(procId, reinterpret_cast<uintptr_t>(peb.Ldr), reinterpret_cast<uintptr_t>(&peb_ldr), sizeof(peb_ldr)) == 0) {
						Driver::read_memory(procId, reinterpret_cast<uintptr_t>(peb_ldr.InMemoryOrderModuleList.Flink), reinterpret_cast<uintptr_t>(&currEntry), sizeof(currEntry));
						while (currEntryFlink != peb_ldr.InMemoryOrderModuleList.Flink) {
							Driver::read_memory(procId, reinterpret_cast<uintptr_t>(currEntry.Flink), reinterpret_cast<uintptr_t>(&currEntryFlink), sizeof(currEntryFlink));
							nLDR_DATA_TABLE_ENTRY* modPtr = (nLDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(currEntryFlink, nLDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
							nLDR_DATA_TABLE_ENTRY mod = {};
							Driver::read_memory(procId, reinterpret_cast<uintptr_t>(modPtr), reinterpret_cast<uintptr_t>(&mod), sizeof(nLDR_DATA_TABLE_ENTRY));

							std::string nameAsString = std::string(nameAsChar);
							std::wstring widestr = std::wstring(nameAsString.begin(), nameAsString.end());
							const wchar_t* name = widestr.c_str();

							std::wstring buffer(mod.BaseDllName.Length / sizeof(wchar_t), 0);
							if (Driver::read_memory(procId, reinterpret_cast<uintptr_t>(mod.BaseDllName.Buffer), reinterpret_cast<uintptr_t>(&buffer[0]), mod.BaseDllName.Length)) {
								auto error = GetLastError();
								std::cout << "readprocmemory failed uni.buff " << error << std::endl;
							}
							const wchar_t* name2 = buffer.c_str();

							if (_wcsicmp(name, name2) == 0)
							{
								return reinterpret_cast<uintptr_t>(mod.DllBase) + offset;
							}
							else {
								LIST_ENTRY nextEntry = {};
								Driver::read_memory(procId, reinterpret_cast<uintptr_t>(currEntry.Flink), reinterpret_cast<uintptr_t>(&nextEntry), sizeof(nextEntry));
								currEntry = nextEntry;
							}
						}
					}
				}
			}
		}
		return 0;
	}
}
```