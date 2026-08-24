#pragma once

// Minimal CLR 4.x hosting interface declarations.
// Replaces the missing metahost.h from the .NET Framework SDK.

#include <Windows.h>
#include <objbase.h>

// ---- CLSIDs ----
EXTERN_C const CLSID CLSID_CLRMetaHost;
EXTERN_C const CLSID CLSID_CorRuntimeHost;

// ---- IIDs ----
EXTERN_C const IID IID_ICLRMetaHost;
EXTERN_C const IID IID_ICLRRuntimeInfo;
EXTERN_C const IID IID_ICorRuntimeHost;

// ---- CLRCreateInstance function pointer type ----
typedef HRESULT(WINAPI* pfnCLRCreateInstance)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);

// ============================================================
// ICLRMetaHost
// {D332DB9E-B9B3-4125-8207-A14884F53216}
// ============================================================
struct __declspec(uuid("D332DB9E-B9B3-4125-8207-A14884F53216")) ICLRMetaHost : IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE GetRuntime(
        LPCWSTR  pwzVersion,
        REFIID   riid,
        LPVOID* ppRuntime) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetVersionFromFile(
        LPCWSTR  pwzFilePath,
        LPWSTR   pwzBuffer,
        DWORD* pcchBuffer) = 0;

    virtual HRESULT STDMETHODCALLTYPE EnumerateInstalledRuntimes(
        IUnknown** ppEnumerator) = 0;

    virtual HRESULT STDMETHODCALLTYPE EnumerateLoadedRuntimes(
        HANDLE   hndProcess,
        IUnknown** ppEnumerator) = 0;

    virtual HRESULT STDMETHODCALLTYPE RequestRuntimeLoadedNotification(
        IUnknown* pCallbackFunction) = 0;

    virtual HRESULT STDMETHODCALLTYPE QueryLegacyV2RuntimeBinding(
        REFIID   riid,
        LPVOID* ppUnk) = 0;

    virtual HRESULT STDMETHODCALLTYPE ExitProcess(
        INT32 iExitCode) = 0;
};

// ============================================================
// ICLRRuntimeInfo
// {BD39D1D2-BA2F-486A-89B0-B4B0CB466891}
// ============================================================
struct __declspec(uuid("BD39D1D2-BA2F-486A-89B0-B4B0CB466891")) ICLRRuntimeInfo : IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE GetVersionString(
        LPWSTR  pwzBuffer,
        DWORD* pcchBuffer) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetRuntimeDirectory(
        LPWSTR  pwzBuffer,
        DWORD* pcchBuffer) = 0;

    virtual HRESULT STDMETHODCALLTYPE IsLoaded(
        HANDLE  hndProcess,
        BOOL* pbLoaded) = 0;

    virtual HRESULT STDMETHODCALLTYPE LoadErrorString(
        UINT    iResourceID,
        LPWSTR  pwzBuffer,
        DWORD* pcchBuffer,
        LONG    iLocaleID) = 0;

    virtual HRESULT STDMETHODCALLTYPE LoadLibrary(
        LPCWSTR  pwzDllName,
        HMODULE* phndModule) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetProcAddress(
        LPCSTR  pszProcName,
        LPVOID* ppProc) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetInterface(
        REFCLSID rclsid,
        REFIID   riid,
        LPVOID* ppUnk) = 0;

    virtual HRESULT STDMETHODCALLTYPE IsLoadable(
        BOOL* pbLoadable) = 0;

    virtual HRESULT STDMETHODCALLTYPE SetDefaultStartupFlags(
        DWORD   dwStartupFlags,
        LPCWSTR pwzHostConfigFile) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetDefaultStartupFlags(
        DWORD* pdwStartupFlags,
        LPWSTR  pwzHostConfigFile,
        DWORD* pcchHostConfigFile) = 0;

    virtual HRESULT STDMETHODCALLTYPE BindAsLegacyV2Runtime() = 0;

    virtual HRESULT STDMETHODCALLTYPE IsStarted(
        BOOL* pbStarted,
        DWORD* pdwStartupFlags) = 0;
};

// HDOMAINENUM is an opaque handle used by ICorRuntimeHost (not in current SDK headers)
typedef void* HDOMAINENUM;

// ============================================================
// ICorRuntimeHost  (interface IID = CB2F6722, CoClass CLSID = CB2F6723)
// ============================================================
struct __declspec(uuid("CB2F6722-AB3A-11D2-9C40-00C04FA30A3E")) ICorRuntimeHost : IUnknown
{
    virtual HRESULT STDMETHODCALLTYPE CreateLogicalThreadState() = 0;
    virtual HRESULT STDMETHODCALLTYPE DeleteLogicalThreadState() = 0;
    virtual HRESULT STDMETHODCALLTYPE SwitchInLogicalThreadState(DWORD* pFiberCookie) = 0;
    virtual HRESULT STDMETHODCALLTYPE SwitchOutLogicalThreadState(DWORD** ppFiberCookie) = 0;
    virtual HRESULT STDMETHODCALLTYPE LocksHeldByLogicalThread(DWORD* pCount) = 0;
    virtual HRESULT STDMETHODCALLTYPE MapFile(HANDLE hFile, HMODULE* hMapAddress) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetConfiguration(IUnknown** pConfiguration) = 0;

    virtual HRESULT STDMETHODCALLTYPE Start() = 0;
    virtual HRESULT STDMETHODCALLTYPE Stop() = 0;

    virtual HRESULT STDMETHODCALLTYPE CreateDomain(
        LPCWSTR   pwzFriendlyName,
        IUnknown* pIdentityArray,
        IUnknown** pAppDomain) = 0;

    virtual HRESULT STDMETHODCALLTYPE GetDefaultDomain(IUnknown** pAppDomain) = 0;
    virtual HRESULT STDMETHODCALLTYPE EnumDomains(HDOMAINENUM* hEnum) = 0;
    virtual HRESULT STDMETHODCALLTYPE NextDomain(HDOMAINENUM hEnum, IUnknown** pAppDomain) = 0;
    virtual HRESULT STDMETHODCALLTYPE CloseEnum(HDOMAINENUM hEnum) = 0;

    virtual HRESULT STDMETHODCALLTYPE CreateDomainEx(
        LPCWSTR   pwzFriendlyName,
        IUnknown* pSetup,
        IUnknown* pEvidence,
        IUnknown** pAppDomain) = 0;

    virtual HRESULT STDMETHODCALLTYPE CreateDomainSetup(IUnknown** pAppDomainSetup) = 0;
    virtual HRESULT STDMETHODCALLTYPE CreateEvidence(IUnknown** pEvidence) = 0;
    virtual HRESULT STDMETHODCALLTYPE UnloadDomain(IUnknown* pAppDomain) = 0;
    virtual HRESULT STDMETHODCALLTYPE CurrentDomain(IUnknown** pAppDomain) = 0;
};

// ============================================================
// GUID definitions (definitions, not just declarations)
// Put in a header guard so they're defined only once
// ============================================================
#ifdef METAHOST_DEFINE_GUIDS

const CLSID CLSID_CLRMetaHost = { 0x9280188d, 0x0e8e, 0x4867, { 0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde } };
const CLSID CLSID_CorRuntimeHost = { 0xcb2f6723, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };
const IID   IID_ICLRMetaHost = { 0xd332db9e, 0xb9b3, 0x4125, { 0x82, 0x07, 0xa1, 0x48, 0x84, 0xf5, 0x32, 0x16 } };
const IID   IID_ICLRRuntimeInfo = { 0xbd39d1d2, 0xba2f, 0x486a, { 0x89, 0xb0, 0xb4, 0xb0, 0xcb, 0x46, 0x68, 0x91 } };
const IID   IID_ICorRuntimeHost = { 0xcb2f6722, 0xab3a, 0x11d2, { 0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e } };

#endif // METAHOST_DEFINE_GUIDS
