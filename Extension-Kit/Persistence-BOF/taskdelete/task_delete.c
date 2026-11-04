/*
 * task_delete.c — delete a persisted scheduled task by name (COM ITaskService,
 * in-process, no schtasks.exe child).
 *
 * args: str taskName (optional leading '\\' folder path supported)
 */
#define CINTERFACE 1
#define COBJMACROS 1
#include <windows.h>
#include <taskschd.h>
#include "beacon.h"

DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantClear(VARIANTARG*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantInit(VARIANTARG*);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, const char*, int, wchar_t*, int);
DECLSPEC_IMPORT int __cdecl MSVCRTsprintf(char*, const char*, ...);

static const GUID kTaskCls  = { 0x0f87369f, 0xa4e5, 0x4cfc, { 0xbd,0x3e, 0x73,0xe6, 0x15,0x45, 0x72,0xdd } };
static const GUID kTaskIidS = { 0x2faba4c7, 0x4da9, 0x4013, { 0x96,0x97, 0x20,0xcc, 0x3f,0xd4, 0x0f,0x85 } };
static const GUID kTaskIidF = { 0x8cfac062, 0xa080, 0x4c15, { 0x9a,0x88, 0xaa,0x7c, 0x2a,0xf8, 0x0d,0xfc } };

void go(char* args, int alen)
{
    datap p;
    BeaconDataParse(&p, args, alen);
    char* nameA = BeaconDataExtract(&p, NULL);
    if (!nameA || !*nameA) {
        BeaconPrintf(CALLBACK_ERROR, "usage: task-delete <taskName>\n");
        return;
    }

    char pathA[160];
    if (nameA[0] == '\\') {
        MSVCRTsprintf(pathA, "%s", nameA);
    } else {
        MSVCRTsprintf(pathA, "\\%s", nameA);
    }

    wchar_t nameW[160];
    if (!KERNEL32$MultiByteToWideChar(CP_UTF8, 0, pathA, -1, nameW, 160)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] wide conversion failed\n");
        return;
    }

    HRESULT hr;
    ITaskService* svc = NULL;
    ITaskFolder*  folder = NULL;

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeEx hr=0x%08lx\n", (unsigned long)hr);
        return;
    }
    hr = OLE32$CoCreateInstance(&kTaskCls, NULL, CLSCTX_INPROC_SERVER, &kTaskIidS, (void**)&svc);
    if (FAILED(hr) || !svc) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoCreateInstance(TaskScheduler) hr=0x%08lx\n", (unsigned long)hr);
        goto out;
    }
    {
        VARIANT vEmpty;
        VariantInit(&vEmpty);
        hr = ITaskService_Connect(svc, vEmpty, vEmpty, vEmpty, vEmpty);
        VariantClear(&vEmpty);
    }
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ITaskService::Connect hr=0x%08lx\n", (unsigned long)hr);
        goto out;
    }

    hr = ITaskService_GetFolder(svc, L"\\", &folder);
    if (FAILED(hr) || !folder) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetFolder('\\') hr=0x%08lx\n", (unsigned long)hr);
        goto out;
    }

    {
        BSTR bName = OLEAUT32$SysAllocString(nameW);
        hr = ITaskFolder_DeleteTask(folder, bName, 0);
        OLEAUT32$SysFreeString(bName);
    }

    if (SUCCEEDED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] task deleted: %s\n", nameA);
    } else if (hr == 0x80070002) {
        BeaconPrintf(CALLBACK_OUTPUT, "[i] task absent: %s\n", nameA);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] DeleteTask(%s) hr=0x%08lx\n", nameA, (unsigned long)hr);
    }

out:
    if (folder) folder->lpVtbl->Release(folder);
    if (svc)    svc->lpVtbl->Release(svc);
    OLE32$CoUninitialize();
}