/*
 * persist_inventory.c — read-only sweep of the persistence locations the kit
 * itself uses (and the ones an IR sweep looks for). No writes, no child processes.
 *
 * Sections:
 *   1. Run / RunOnce values (HKCU, HKLM, HKLM W6432)
 *   2. Startup folder LNKs (user + all-users)
 *   3. WMI subscriptions — __EventFilter / __CommandLineEventConsumer /
 *      __ActiveScriptEventConsumer / __FilterToConsumerBinding (root\subscription)
 *   4. Scheduled tasks — %SystemRoot%\System32\Tasks tree (shallow, command pulled
 *      from the task XML)
 *   5. Services with non-windows image paths (OpenSCManager enum + QueryServiceConfig)
 *   6. IFEO — Image File Execution Options with a Debugger value or GlobalFlag set
 *   7. Winlogon Shell / Userinit overrides
 *
 * args: none (optional int capsTasks / capsSvc defaults 40)
 *
 * Everything is enum/read; the only "loud" part is the WMI COM connection
 * (WMI-Activity 5857-5861) — inherent to reading subscriptions via COM.
 */
#define CINTERFACE 1
#define COBJMACROS 1
#include <windows.h>
#include <objbase.h>
#include <wbemcli.h>
#include <string.h>
#include <stdio.h>
#include "beacon.h"

/* -------- imports -------- */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, void*, DWORD);
DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantClear(VARIANTARG*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantInit(VARIANTARG*);

DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegOpenKeyExA(HKEY, const char*, DWORD, REGSAM, HKEY*);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegEnumValueA(HKEY, DWORD, char*, DWORD*, LPDWORD, LPDWORD, BYTE*, DWORD*);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegEnumKeyExA(HKEY, DWORD, char*, DWORD*, LPDWORD, char*, DWORD*, FILETIME*);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegQueryValueExA(HKEY, const char*, LPDWORD, LPDWORD, BYTE*, LPDWORD);

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$FindFirstFileA(const char*, WIN32_FIND_DATAA*);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindNextFileA(HANDLE, WIN32_FIND_DATAA*);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileA(const char*, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile(HANDLE, void*, DWORD, LPDWORD, void*);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetEnvironmentVariableA(const char*, char*, DWORD);

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(const char*, const char*, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE, const char*, DWORD);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$EnumServicesStatusA(SC_HANDLE, DWORD, DWORD, LPENUM_SERVICE_STATUSA, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$QueryServiceConfigA(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);

DECLSPEC_IMPORT int  __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int  __cdecl MSVCRT$_snprintf(char*, size_t, const char*, ...);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT char*  __cdecl MSVCRT$strstr(const char*, const char*);

static const GUID kLocCls  = { 0x4590f811, 0x1d3a, 0x11d0, { 0x89,0x1f, 0x00,0xaa, 0x00,0x4b, 0x2e,0x24 } };
static const GUID kLocIid  = { 0xdc12a687, 0x737f, 0x11cf, { 0x88,0x4d, 0x00,0xaa, 0x00,0x4b, 0x2e,0x24 } };
static const GUID kSvcIid  = { 0xb81142ae, 0x5da6, 0x11d2, { 0xbb,0xd0, 0x00,0x10, 0x4b,0xcc, 0x4b,0x4c } };

/* -------- helpers -------- */

static void PrintStr(const char* s)
{
    BeaconOutput(CALLBACK_OUTPUT, s, (int)strlen(s));
}

static BOOL EnvPathA(char* var, char* out, DWORD cap)
{
    DWORD n = KERNEL32$GetEnvironmentVariableA(var, out, cap);
    if (n == 0 || n >= cap) return FALSE;
    return TRUE;
}

/* -------- section 1: Run keys -------- */

static void SweepRunKey(HKEY root, const char* label, const char* sub)
{
    HKEY h;
    if (ADVAPI32$RegOpenKeyExA(root, sub, 0, KEY_READ, &h) != ERROR_SUCCESS) {
        char buf[128];
        MSVCRT$sprintf(buf, "[run] %s\\%s : (absent)\n", label, sub);
        PrintStr(buf);
        return;
    }
    char buf[520];
    MSVCRT$sprintf(buf, "[run] %s\\%s\n", label, sub);
    PrintStr(buf);
    DWORD i = 0;
    for (;;) {
        DWORD nameLen = 100, type = 0, dataLen = 400;
        char name[100], data[400];
        st:
        LSTATUS stq = ADVAPI32$RegEnumValueA(h, i, name, &nameLen, NULL, &type, (BYTE*)data, &dataLen);
        if (stq != ERROR_SUCCESS) break;
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            data[dataLen >= sizeof(data) ? sizeof(data) - 1 : dataLen] = '\0';
            MSVCRT$sprintf(buf, "    %s = %s\n", name, data);
            PrintStr(buf);
        }
        i++;
        if (i > 32) break;
    }
    ADVAPI32$RegCloseKey(h);
}

/* -------- section 3: WMI subscriptions -------- */

static void SweepWmiClass(IWbemServices* svc, const wchar_t* cls, const wchar_t* prop1, const wchar_t* prop2)
{
    IEnumWbemClassObject* penum = NULL;
    IWbemClassObject*     obj   = NULL;
    VARIANT v;
    VariantInit(&v);
    ULONG  got = 0;
    char   buf[512];
    wchar_t wql[] = L"WQL";

    HRESULT hr = IWbemServices_ExecQuery(svc, wql, (wchar_t*)cls, 0, NULL, &penum);
    if (FAILED(hr) || !penum) {
        MSVCRT$sprintf(buf, "[wmi] %ls : enum failed 0x%08lx\n", cls, (unsigned long)hr);
        PrintStr(buf);
        return;
    }

    int shown = 0;
    while (penum->lpVtbl->Next(penum, 5000, 1, &obj, &got) == WBEM_S_FALSE || got == 1) {
        if (!obj) break;
        VariantClear(&v);
        char p1[160] = "", p2[300] = "";
        int j;
        if (SUCCEEDED(IWbemClassObject_Get(obj, prop1, 0, &v, NULL, NULL)) && v.vt == VT_BSTR) {
            for (j = 0; (size_t)j < MSVCRT$wcslen(v.bstrVal) && j < (int)sizeof(p1) - 1; j++)
                p1[j] = (char)v.bstrVal[j];
            p1[j] = 0;
        }
        VariantClear(&v);
        if (SUCCEEDED(IWbemClassObject_Get(obj, prop2, 0, &v, NULL, NULL)) && v.vt == VT_BSTR) {
            for (j = 0; (size_t)j < MSVCRT$wcslen(v.bstrVal) && j < (int)sizeof(p2) - 1; j++)
                p2[j] = (v.bstrVal[j] >= 32 && v.bstrVal[j] < 127) ? (char)v.bstrVal[j] : '.';
            p2[j] = 0;
        }
        VariantClear(&v);
        MSVCRT$sprintf(buf, "[wmi] %ls: %s\n       %s\n", cls, p1, p2);
        PrintStr(buf);
        obj->lpVtbl->Release(obj);
        obj = NULL;
        shown++;
        if (shown > 24) break;
    }
    if (penum) penum->lpVtbl->Release(penum);
    if (shown == 0) {
        MSVCRT$sprintf(buf, "[wmi] %ls : (none)\n", cls);
        PrintStr(buf);
    }
}

/* -------- section 4: task tree -------- */

static void SweepTasks(int cap)
{
    char tasksPath[MAX_PATH];
    char rootA[MAX_PATH];
    DWORD sl = KERNEL32$GetEnvironmentVariableA("SystemRoot", rootA, MAX_PATH);
    if (!sl) { MSVCRT$sprintf(rootA, "C:\\Windows"); }
    MSVCRT$sprintf(tasksPath, "%s\\System32\\Tasks", rootA);

    WIN32_FIND_DATAA fd;
    HANDLE hf = KERNEL32$FindFirstFileA(tasksPath, &fd);
    if (hf == INVALID_HANDLE_VALUE) {
        PrintStr("[tasks] tree not readable\n");
        return;
    }
    int shown = 0;
    char buf[600], full[MAX_PATH + 1], subPath[MAX_PATH + 1];
    MSVCRT$sprintf(subPath, "%s\\*", tasksPath);
    KERNEL32$FindClose(hf);
    hf = KERNEL32$FindFirstFileA(subPath, &fd);
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (fd.cFileName[0] == '.') continue;
            char dir[MAX_PATH + 1];
            MSVCRT$sprintf(dir, "%s\\%s", tasksPath, fd.cFileName);
            char inside[MAX_PATH + 4];
            MSVCRT$sprintf(inside, "%s\\*", dir);
            WIN32_FIND_DATAA inner;
            HANDLE hi = KERNEL32$FindFirstFileA(inside, &inner);
            if (hi == INVALID_HANDLE_VALUE) continue;
            do {
                if (inner.cFileName[0] == '.') continue;
                MSVCRT$sprintf(full, "%s\\%s", dir, inner.cFileName);
                HANDLE fh = KERNEL32$CreateFileA(full, GENERIC_READ, FILE_SHARE_READ, NULL, 3, 0x80, NULL);
                if (fh == INVALID_HANDLE_VALUE) continue;
                char xml[1024];
                DWORD rd = 0;
                if (KERNEL32$ReadFile(fh, xml, sizeof(xml) - 1, &rd, NULL) && rd > 100) {
                    xml[rd] = '\0';
                    xml[sizeof(xml) - 1] = '\0';
                    char* cmd = MSVCRT$strstr(xml, "<Command>");
                    char cmdBuf[300] = "(?)";
                    if (cmd) {
                        cmd += 9;
                        int k = 0;
                        while (cmd[k] && cmd[k] != '<' && k < 280) { cmdBuf[k] = cmd[k]; k++; }
                        cmdBuf[k] = 0;
                    }
                    MSVCRT$sprintf(buf, "[tasks] task=%s\\%s\n       cmd=%s\n", fd.cFileName, inner.cFileName, cmdBuf);
                    PrintStr(buf);
                    if (++shown >= (cap > 0 ? cap : 40)) break;
                }
                KERNEL32$CloseHandle(fh);
            } while (KERNEL32$FindNextFileA(hi, &inner));
            KERNEL32$FindClose(hi);
        } else {
            MSVCRT$sprintf(full, "%s\\%s", tasksPath, fd.cFileName);
            HANDLE fh = KERNEL32$CreateFileA(full, GENERIC_READ, FILE_SHARE_READ, NULL, 3, 0x80, NULL);
            if (fh == INVALID_HANDLE_VALUE) continue;
            char xml[1024];
            DWORD rd = 0;
            if (KERNEL32$ReadFile(fh, xml, sizeof(xml) - 1, &rd, NULL) && rd > 100) {
                xml[rd] = '\0'; xml[sizeof(xml) - 1] = '\0';
                char* cmd = MSVCRT$strstr(xml, "<Command>");
                char cmdBuf[300] = "(?)";
                if (cmd) {
                    cmd += 9;
                    int k = 0;
                    while (cmd[k] && cmd[k] != '<' && k < 280) { cmdBuf[k] = cmd[k]; k++; }
                    cmdBuf[k] = 0;
                }
                MSVCRT$sprintf(buf, "[tasks] task=%s\n       cmd=%s\n", fd.cFileName, cmdBuf);
                PrintStr(buf);
                if (++shown >= (cap > 0 ? cap : 40)) break;
            }
            KERNEL32$CloseHandle(fh);
        }
        if (shown >= (cap > 0 ? cap : 40)) break;
    } while (KERNEL32$FindNextFileA(hf, &fd));
    KERNEL32$FindClose(hf);
    if (shown == 0) {
        MSVCRT$sprintf(buf, "[tasks] (no task XML readable)\n");
        PrintStr(buf);
    }
}

/* -------- section 5: services -------- */

static void SweepServices(int cap)
{
    SC_HANDLE sc = ADVAPI32$OpenSCManagerA(NULL, NULL, 0x0005); /* SC_MANAGER_ENUMERATE_SERVICE */
    if (!sc) {
        PrintStr("[svc] SCM open failed\n");
        return;
    }
    static BYTE svcBuf[48 * 1024];
    DWORD need = 0, count = 0, resume = 0;
    if (!ADVAPI32$EnumServicesStatusA(sc, SERVICE_WIN32, SERVICE_STATE_ALL,
                                      (LPENUM_SERVICE_STATUSA)svcBuf, sizeof(svcBuf),
                                      &need, &count, &resume)) {
        ADVAPI32$CloseServiceHandle(sc);
        PrintStr("[svc] enum failed\n");
        return;
    }
    LPENUM_SERVICE_STATUSA list = (LPENUM_SERVICE_STATUSA)svcBuf;
    int flag = 0, shown = 0;
    char buf[600];
    for (DWORD i = 0; i < count; i++) {
        SC_HANDLE h = ADVAPI32$OpenServiceA(sc, list[i].lpServiceName, 0x2); /* SERVICE_QUERY_CONFIG */
        if (!h) continue;
        static BYTE cfgBuf[4096];
        DWORD cfgNeed = 0;
        LPQUERY_SERVICE_CONFIGA cfg = (LPQUERY_SERVICE_CONFIGA)cfgBuf;
        if (ADVAPI32$QueryServiceConfigA(h, cfg, sizeof(cfgBuf), &cfgNeed)) {
            const char* bin = cfg->lpBinaryPathName;
            if (bin || *bin) {
                /* lowercase copy for a single case-insensitive check */
                char lower[512];
                int k;
                for (k = 0; bin[k] && k < 500; k++)
                    lower[k] = (bin[k] >= 'A' && bin[k] <= 'Z') ? bin[k] + 32 : bin[k];
                lower[k] = 0;
                /* flag binaries outside the windows dir (covers non-drive,
                 * UNC, %TEMP% and program-data paths — the IR-relevant set) */
                if (!strstr(lower, "c:\\windows")) {
                    MSVCRT$sprintf(buf, "[svc] %s -> %s\n", list[i].lpServiceName, bin);
                    PrintStr(buf);
                    flag++;
                }
            }
        }
        ADVAPI32$CloseServiceHandle(h);
        if (++shown >= (cap > 0 ? cap : 200)) break;
    }
    ADVAPI32$CloseServiceHandle(sc);
    MSVCRT$sprintf(buf, "[svc] scanned=%d non-system flagged=%d\n", shown, flag);
    PrintStr(buf);
}

/* -------- section 6: IFEO -------- */

static void SweepIfeo(void)
{
    char ifeoPath[] = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    HKEY hIfeo;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, ifeoPath, 0, KEY_READ, &hIfeo) != ERROR_SUCCESS) {
        PrintStr("[ifeo] key not readable\n");
        return;
    }
    char buf[520];
    char name[MAX_PATH + 1];
    DWORD i = 0, flg = 0;
    for (;;) {
        DWORD nameLen = sizeof(name);
        LSTATUS s = ADVAPI32$RegEnumKeyExA(hIfeo, i++, name, &nameLen, NULL, NULL, NULL, NULL);
        if (s != ERROR_SUCCESS) break;
        HKEY hk;
        if (ADVAPI32$RegOpenKeyExA(hIfeo, name, 0, KEY_QUERY_VALUE, &hk) == ERROR_SUCCESS) {
            DWORD type = 0, need = 320;
            BYTE  data[320];
            const char* keys[] = { "Debugger", "GlobalFlag" };
            for (int k = 0; k < 2; k++) {
                LSTATUS q = ADVAPI32$RegQueryValueExA(hk, keys[k], NULL, &type, data, &need);
                if (q == ERROR_SUCCESS && need > 0 && (k == 1 || need > 1)) {
                    data[need >= sizeof(data) ? sizeof(data)-1 : need] = '\0';
                    if (type == REG_SZ && ((char*)data)[0] != '\0') {
                        MSVCRT$sprintf(buf, "[ifeo] %s : %s = %s\n", name, keys[k], (char*)data);
                        PrintStr(buf);
                        flg++;
                    }
                }
                need = 320;
            }
            ADVAPI32$RegCloseKey(hk);
        }
        if (i > 400) break;
    }
    ADVAPI32$RegCloseKey(hIfeo);
    MSVCRT$sprintf(buf, "[ifeo] entries with Debugger=%d\n", flg);
    PrintStr(buf);
}

/* -------- section 7: winlogon -------- */

static void SweepWinlogon(void)
{
    char path[] = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    HKEY h;
    if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &h) != ERROR_SUCCESS) return;
    DWORD type = 0, need = 300;
    char data[300];
    const char* vals[] = { "Shell", "Userinit" };
    for (int k = 0; k < 2; k++) {
        LSTATUS q = ADVAPI32$RegQueryValueExA(h, vals[k], NULL, &type, (BYTE*)data, &need);
        if (q == ERROR_SUCCESS && type == REG_SZ) {
            data[need >= sizeof(data) ? sizeof(data) - 1 : need] = '\0';
            char buf[376];
            MSVCRT$sprintf(buf, "[winlogon] %s = %s\n", vals[k], data);
            PrintStr(buf);
        }
        need = 300;
    }
    ADVAPI32$RegCloseKey(h);
}

/* -------- section 2: startup folders -------- */

static void SweepStartup(const char* envVar, const char* fallbackTail, const char* label)
{
    char base[MAX_PATH];
    if (!KERNEL32$GetEnvironmentVariableA(envVar, base, MAX_PATH)) {
        MSVCRT$sprintf(base, "C:\\ProgramData");
    }
    char pattern[MAX_PATH + 64];
    MSVCRT$sprintf(pattern, "%s\\%s", base, "*");
    char subStart[MAX_PATH + 64];
    MSVCRT$sprintf(subStart, "%s\\%s", base, fallbackTail);
    MSVCRT$sprintf(pattern, "%s\\*", subStart);

    char buf[600];
    MSVCRT$sprintf(buf, "[startup] %s (%s)\n", label, subStart);
    PrintStr(buf);
    WIN32_FIND_DATAA fd;
    HANDLE hf = KERNEL32$FindFirstFileA(pattern, &fd);
    if (hf == INVALID_HANDLE_VALUE) {
        MSVCRT$sprintf(buf, "    (absent)\n");
        PrintStr(buf);
        return;
    }
    int shown = 0;
    do {
        if (fd.cFileName[0] == '.') continue;
        MSVCRT$sprintf(buf, "    %s\n", fd.cFileName);
        PrintStr(buf);
        if (++shown > 24) break;
    } while (KERNEL32$FindNextFileA(hf, &fd));
    KERNEL32$FindClose(hf);
    if (!shown) {
        MSVCRT$sprintf(buf, "    (empty)\n");
        PrintStr(buf);
    }
}

/* -------- go -------- */

void go(char* args, int alen)
{
    datap p;
    BeaconDataParse(&p, args, alen);
    int cap = BeaconDataInt(&p);

    PrintStr("=== persist_inventory ===\n");

    /* 1. run keys */
    SweepRunKey(HKEY_CURRENT_USER, "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    SweepRunKey(HKEY_CURRENT_USER, "HKCU", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    SweepRunKey(HKEY_LOCAL_MACHINE, "HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    SweepRunKey(HKEY_LOCAL_MACHINE, "HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    SweepRunKey(HKEY_LOCAL_MACHINE, "HKLM-W6432", "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run");

    /* 2. startup folders */
    SweepStartup("APPDATA", "Microsoft\\Windows\\Start Menu\\Programs\\Startup", "user");
    SweepStartup("ProgramData", "Microsoft\\Windows\\Start Menu\\Programs\\StartUp", "all-users");

    /* 3. WMI subscriptions */
    {
        HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) {
            IWbemLocator*  pLoc = NULL;
            IWbemServices* pSvc = NULL;
            if (SUCCEEDED(OLE32$CoCreateInstance(&kLocCls, NULL, CLSCTX_INPROC_SERVER, &kLocIid, (void**)&pLoc)) && pLoc) {
                if (SUCCEEDED(IWbemLocator_ConnectServer(pLoc, L"ROOT\\subscription", NULL, NULL, NULL, 0, NULL, NULL, &pSvc)) && pSvc) {
                    OLE32$CoSetProxyBlanket((IUnknown*)pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                                            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
                    wchar_t f[] = L"__EventFilter";
                    wchar_t c[] = L"__CommandLineEventConsumer";
                    wchar_t s[] = L"__ActiveScriptEventConsumer";
                    wchar_t b[] = L"__FilterToConsumerBinding";
                    SweepWmiClass(pSvc, f, L"Name", L"Query");
                    SweepWmiClass(pSvc, c, L"Name", L"CommandLineTemplate");
                    SweepWmiClass(pSvc, s, L"Name", L"ScriptText");
                    SweepWmiClass(pSvc, b, L"Filter", L"Consumer");
                    pSvc->lpVtbl->Release(pSvc);
                } else {
                    PrintStr("[wmi] (subscription ns not readable)\n");
                }
                pLoc->lpVtbl->Release(pLoc);
            }
            OLE32$CoUninitialize();
        }
    }

    /* 4. tasks */
    SweepTasks(cap);

    /* 5. services */
    SweepServices(cap);

    /* 6. IFEO */
    SweepIfeo();

    /* 7. winlogon */
    SweepWinlogon();

    PrintStr("=== persist_inventory done ===\n");
}