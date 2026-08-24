#include <Windows.h>
#include <objbase.h>
#include <stdio.h>
#define METAHOST_DEFINE_GUIDS

#include "metahost.h"
#include "Common.h"

namespace mscorlib {
#include "mscorlib.h"
}

// -----------------------
// Functions
// -----------------------

extern "C" HRESULT DotnetExecute(
    _In_     PBYTE  pbAssembly,
    _In_     ULONG  cbAssembly,
    _In_     PWSTR  pwszAppDomain,
    _In_opt_ PWSTR* ppwszArgv,
    _In_     INT    nArgc
)
{
    HRESULT                hResult          = S_OK;
    ICLRMetaHost*          pMetaHost        = NULL;
    ICLRRuntimeInfo*       pRuntimeInfo     = NULL;
    ICorRuntimeHost*       pRuntimeHost     = NULL;
    IUnknown*              pAppDomainThunk  = NULL;
    mscorlib::_AppDomain*  pAppDomain       = NULL;
    mscorlib::_Assembly*   pAssembly        = NULL;
    mscorlib::_MethodInfo* pMethodInfo      = NULL;
    SAFEARRAYBOUND         SafeArrayBound   = {};
    SAFEARRAY*             pSafeAssembly    = NULL;
    SAFEARRAY*             pSafeExpected    = NULL;
    SAFEARRAY*             pSafeArguments   = NULL;
    VARIANT                varArgv          = {};
    BOOL                   bIsLoadable      = FALSE;
    HMODULE                hMscoree         = NULL;
    pfnCLRCreateInstance   pCLRCreateInstance = NULL;
    LONG                   iIndex           = 0;

    hMscoree = LoadLibraryW(L"mscoree.dll");
    if (!hMscoree)
    {
        printf("[-] LoadLibraryW(mscoree.dll) failed: %lx\n", GetLastError());
        hResult = HRESULT_FROM_WIN32(GetLastError());
        goto _END_OF_FUNC;
    }

    pCLRCreateInstance = (pfnCLRCreateInstance)GetProcAddress(hMscoree, "CLRCreateInstance");
    if (!pCLRCreateInstance)
    {
        printf("[-] GetProcAddress(CLRCreateInstance) failed\n");
        hResult = E_NOTIMPL;
        goto _END_OF_FUNC;
    }

    if ((hResult = pCLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, reinterpret_cast<PVOID*>(&pMetaHost))))
    {
        printf("[-] CLRCreateInstance failed: %lx\n", hResult);
        goto _END_OF_FUNC;
    }

    if ((hResult = pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, reinterpret_cast<PVOID*>(&pRuntimeInfo))))
    {
        printf("[-] IMetaHost->GetRuntime failed: %lx\n", hResult);
        goto _END_OF_FUNC;
    }

    if ((hResult = pRuntimeInfo->IsLoadable(&bIsLoadable)) || !bIsLoadable)
    {
        printf("[-] IRuntimeInfo->IsLoadable failed: %lx (IsLoadable: %s)\n", hResult, bIsLoadable ? "true" : "false");
        goto _END_OF_FUNC;
    }

    if ((hResult = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, reinterpret_cast<PVOID*>(&pRuntimeHost))))
    {
        printf("[-] IRuntimeInfo->GetInterface failed: %lx\n", hResult);
        goto _END_OF_FUNC;
    }

    if ((hResult = pRuntimeHost->Start()))
    {
        printf("[-] IRuntimeHost->Start failed: %lx\n", hResult);
        goto _END_OF_FUNC;
    }

    if ((hResult = pRuntimeHost->CreateDomain(pwszAppDomain, nullptr, &pAppDomainThunk)))
    {
        printf("[-] IRuntimeHost->CreateDomain failed: %lx\n", hResult);
        goto _END_OF_FUNC;
    }

    if ((hResult = pAppDomainThunk->QueryInterface(IID_PPV_ARGS(&pAppDomain))))
    {
        printf("[-] IAppDomainThunk->QueryInterface failed: %lx\n", hResult);
        goto _END_OF_FUNC;
    }

    SafeArrayBound = { cbAssembly, 0 };
    pSafeAssembly  = SafeArrayCreate(VT_UI1, 1, &SafeArrayBound);
    memcpy(pSafeAssembly->pvData, pbAssembly, cbAssembly);

    if ((hResult = pAppDomain->Load_3(pSafeAssembly, &pAssembly)))
    {
        printf("[-] AppDomain->Load_3 failed: %lx\n", hResult);
        goto _END_OF_FUNC;
    }

    if ((hResult = pAssembly->get_EntryPoint(&pMethodInfo)))
    {
        printf("[-] Assembly->get_EntryPoint failed: %lx\n", hResult);
        goto _END_OF_FUNC;
    }

    if ((hResult = pMethodInfo->GetParameters(&pSafeExpected)))
    {
        printf("[-] MethodInfo->GetParameters failed: %lx\n", hResult);
        goto _END_OF_FUNC;
    }

    // Build argument SAFEARRAY if the entry point declares parameters
    if (pSafeExpected && pSafeExpected->cDims && pSafeExpected->rgsabound[0].cElements)
    {
        pSafeArguments = SafeArrayCreateVector(VT_VARIANT, 0, 1);

        varArgv.parray = SafeArrayCreateVector(VT_BSTR, 0, nArgc);
        varArgv.vt     = (VT_ARRAY | VT_BSTR);

        for (iIndex = 0; iIndex < (LONG)nArgc; iIndex++)
            SafeArrayPutElement(varArgv.parray, &iIndex, SysAllocString(ppwszArgv[iIndex]));

        iIndex = 0;
        SafeArrayPutElement(pSafeArguments, &iIndex, &varArgv);
        SafeArrayDestroy(varArgv.parray);
    }

    {
        VARIANT vtEmpty = {};
        if ((hResult = pMethodInfo->Invoke_3(vtEmpty, pSafeArguments, nullptr)))
        {
            printf("[-] MethodInfo->Invoke_3 failed: %lx\n", hResult);
            goto _END_OF_FUNC;
        }
    }

_END_OF_FUNC:
    if (pSafeAssembly)   { SafeArrayDestroy(pSafeAssembly);   pSafeAssembly  = NULL; }
    if (pSafeExpected)   { SafeArrayDestroy(pSafeExpected);   pSafeExpected  = NULL; }
    if (pSafeArguments)  { SafeArrayDestroy(pSafeArguments);  pSafeArguments = NULL; }
    if (pMethodInfo)     { pMethodInfo->Release();     pMethodInfo    = NULL; }
    if (pAssembly)       { pAssembly->Release();       pAssembly      = NULL; }
    if (pAppDomain)      { pAppDomain->Release();      pAppDomain     = NULL; }
    if (pAppDomainThunk) { pAppDomainThunk->Release(); pAppDomainThunk = NULL; }
    if (pRuntimeHost)    { pRuntimeHost->Release();    pRuntimeHost   = NULL; }
    if (pRuntimeInfo)    { pRuntimeInfo->Release();    pRuntimeInfo   = NULL; }
    if (pMetaHost)       { pMetaHost->Release();       pMetaHost      = NULL; }
    if (hMscoree)        { FreeLibrary(hMscoree);      hMscoree       = NULL; }

    return hResult;
}
