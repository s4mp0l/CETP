#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// -----------------------
// Structures
// -----------------------

typedef struct _NTOS_INFO
{
    ULONG_PTR uBase;
    ULONG_PTR uSize;
    WCHAR     wszPath[MAX_PATH];
} NTOS_INFO, * PNTOS_INFO;

// -----------------------
// Functions
// -----------------------

// Fills pInfo with ntoskrnl kernel base, size, and on-disk path via
// NtQuerySystemInformation(SystemModuleInformation).
BOOL GetNtoskrnlInfo(
    _Out_ PNTOS_INFO pInfo
);

// Returns the kernel VA of an ntoskrnl export given a user-mode mapping
// of the file (loaded with DONT_RESOLVE_DLL_REFERENCES).
ULONG_PTR GetExportKernelVA(
    _In_ HMODULE   hNtosUser,
    _In_ ULONG_PTR uKernelBase,
    _In_ LPCSTR    pszExport
);

// Walks the CallbackList of every targeted _OBJECT_TYPE (Process, Thread)
// and unlinks every OB_CALLBACK_ENTRY registered via ObRegisterCallbacks.
BOOL RemoveObCallbacks(
    _In_ HANDLE   hDev,
    _In_ HMODULE  hNtosUser,
    _In_ PNTOS_INFO pNtos
);
