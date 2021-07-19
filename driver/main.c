#include "stdafx.h"

INT64(NTAPI *EnumerateDebuggingDevicesOriginal)(PVOID, PVOID);

PMMVAD(*MiAllocateVad)(UINT_PTR start, UINT_PTR end, LOGICAL deletable);
NTSTATUS(*MiInsertVadCharges)(PMMVAD vad, PEPROCESS process);
VOID(*MiInsertVad)(PMMVAD vad, PEPROCESS process);

INT64 NTAPI EnumerateDebuggingDevicesHook(PREQUEST_DATA data, PINT64 status) {
	if (ExGetPreviousMode() != UserMode || !data) {
		return EnumerateDebuggingDevicesOriginal(data, status);
	}

	// Can't use inline SEH for safe dereferences cause PG
	REQUEST_DATA safeData = { 0 };
	if (!SafeCopy(&safeData, data, sizeof(safeData)) || safeData.Unique != DATA_UNIQUE) {
		return EnumerateDebuggingDevicesOriginal(data, status);
	}
	
	switch (safeData.Type) {
		HANDLE_REQUEST(Extend, REQUEST_EXTEND);
		HANDLE_REQUEST(Write, REQUEST_WRITE);
		HANDLE_REQUEST(Read, REQUEST_READ);
		HANDLE_REQUEST(Protect, REQUEST_PROTECT);
		HANDLE_REQUEST(Alloc, REQUEST_ALLOC);
		HANDLE_REQUEST(Free, REQUEST_FREE);
		HANDLE_REQUEST(Module, REQUEST_MODULE);
	}

	*status = STATUS_NOT_IMPLEMENTED;
	return 0;
}

NTSTATUS Main() {
	PCHAR base = GetKernelBase();
	if (!base) {
		printf("! failed to get ntoskrnl base !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	// MiAllocateVad
	PBYTE addr = (PBYTE)FindPatternImage(base, "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x30\x48\x8B\xE9\x41\x8B\xF8\xB9\x00\x00\x00\x00\x48\x8B\xF2\x8B\xD1\x41\xB8\x00\x00\x00\x00", "xxxx?xxxx?xxxx?xxxxxxxxxxxx????xxxxxxx????");
	if (!addr) 
	{
		DbgPrintEx(0, 0, "[driver] MiAllocateVad not found!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
 
	*(PVOID*)&MiAllocateVad = addr;
 
	// MiInsertVadCharges
	addr = FindPatternImage(base, "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x8B\x41\x18\x48\x8B\xD9\x44\x0F\xB6\x71\x00\x45\x33\xE4", "xxxx?xxxx?xxxx?xxxxxxxxxxxxxxxxxxxxxxx?xxx");
	if (!addr) 
	{
		DbgPrintEx(0, 0, "[driver] MiInsertVadCharges not found!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
 
	*(PVOID*)&MiInsertVadCharges = addr;
 
	// MiInsertVad
	addr = FindPatternImage(base, "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x8B\x41\x1C\x33\xED\x0F\xB6\x59\x21", "xxxx?xxxx?xxxx?xxxxxxxxxxxxxxxxxxxxxx");
	if (!addr) 
	{
		DbgPrintEx(0, 0, "[driver] MiInsertVad not found!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
 
	*(PVOID*)&MiInsertVad = addr;

	// Intended be manually mapped
	addr = FindPatternImage(base, "\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\x85\xC0\x78\x40", "xxx????x????xxxxxx");
	if (!addr) {
		printf("! failed to find xKdEnumerateDebuggingDevices  !\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	*(PVOID *)&EnumerateDebuggingDevicesOriginal = InterlockedExchangePointer(RELATIVE_ADDR(addr, 7), (PVOID)EnumerateDebuggingDevicesHook);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registryPath);

	return Main();
}