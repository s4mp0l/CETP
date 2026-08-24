#pragma once

#include <Windows.h>
#include <stdio.h>

#define PRINTA(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define PRINTW(fmt, ...) wprintf(fmt, ##__VA_ARGS__)

// -----------------------
// From Etw.c
// -----------------------

BOOL EtwPatching(
    _In_ HANDLE hProcess
);

// -----------------------
// From Amsi.c
// -----------------------

HANDLE SetupAmsiBypass(VOID);

// -----------------------
// From CLR.cpp
// -----------------------

#ifdef __cplusplus
extern "C" {
#endif

HRESULT DotnetExecute(
    _In_     PBYTE  pbAssembly,
    _In_     ULONG  cbAssembly,
    _In_     PWSTR  pwszAppDomain,
    _In_opt_ PWSTR* ppwszArgv,
    _In_     INT    nArgc
);

#ifdef __cplusplus
}
#endif
