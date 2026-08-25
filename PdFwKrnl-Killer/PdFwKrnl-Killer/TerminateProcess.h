#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// -----------------------
// Globals
// -----------------------

// Processes to strip PPL from and terminate on detection.
extern LPCWSTR      g_TargetProcessNames[];
extern const DWORD  g_TargetProcessCount;

// -----------------------
// Functions
// -----------------------

// Strips EPROCESS.Protection from dwPid via the PdFwKrnl write primitive,
// then terminates the process. Attempts a direct TerminateProcess first;
// falls back to PPL removal if access is denied.
BOOL RemovePPLAndKill(
    _In_ HANDLE  hDev,
    _In_ DWORD   dwPid,
    _In_ LPCWSTR pwszName
);

// Polls all running processes every 500 ms and calls RemovePPLAndKill for
// every process whose name appears in g_TargetProcessNames. Does not return.
VOID MonitorAndKillLoop(
    _In_ HANDLE hDev
);
