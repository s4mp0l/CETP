#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// -----------------------
// Functions
// -----------------------

// Zeroes EPROCESS.Protection for dwPid via the PdFwKrnl kernel write primitive.
// Works against PPL processes; does NOT terminate the process.
// Returns TRUE on success, including when the process was not PPL-protected.
BOOL RemovePPL(
    _In_ HANDLE hDev,
    _In_ DWORD  dwPid
);
