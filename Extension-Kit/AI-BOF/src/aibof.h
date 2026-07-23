/*
 * aibof.h — shared helpers for OSAI AI-BOF suite.
 * Grounded in ai-300.pdf / OSAI-AI300-STUDY-GUIDE.md.
 * Conventions: include bofdefs.h (all MODULE$func decls + intAlloc/intFree),
 *              call MODULE$func directly, Beacon* for I/O, narrow strings.
 */
#ifndef AIBOF_H
#define AIBOF_H

#include "beacon.h"
#include "bofdefs.h"

/* gcc emits a call to ___chkstk_ms for functions with >4KB of stack locals.
 * The AdaptixC2 loader does NOT resolve it (not __imp_, not in the Beacon
 * switch), so we provide the standard community no-op stub — the beacon runs
 * in the host's thread with a pre-committed 1MB stack, so probing is unneeded.
 * Must be non-static: the compiler's backend references the bare name. */
#ifdef BOF
void ___chkstk_ms(void) {}
void __chkstk_ms(void) {}
#endif

/* ---------- self-contained libc replacements ----------
 * The AdaptixC2 BOF loader (coffer_windows.go resolveExternalAddress) only
 * resolves __imp_-prefixed symbols: MODULE$func (LoadLibrary/GetProcAddress)
 * and the hardcoded Beacon-prefixed / Ax-prefixed switch.  Bare libc intrinsics
 * (strlen, strcmp, memcpy, ...) and htons/htonl (compile to __imp_htons /
 * __imp_htonl, no $, not in switch)
 * hit "Unknown symbol" -> address 0 -> crash.  So every libc op we need is
 * implemented here as a pure pointer loop with NO external dependency.  Keep
 * these names free of the bare-libc tokens so they never collide with grep. */
static int xlen(const char* s) { int n = 0; if (s) while (s[n]) n++; return n; }
static int xcmp(const char* a, const char* b) {
  if (!a) a = ""; if (!b) b = "";
  while (*a && *a == *b) { a++; b++; }
  return (unsigned char)*a - (unsigned char)*b;
}
static int xstricmp(const char* a, const char* b) {
  if (!a) a = ""; if (!b) b = "";
  while (*a) {
    char x = *a, y = *b;
    if (x >= 'A' && x <= 'Z') x += 32;
    if (y >= 'A' && y <= 'Z') y += 32;
    if (x != y) return (unsigned char)x - (unsigned char)y;
    a++; b++;
  }
  return -(unsigned char)*b;
}
static int xmemcmp(const void* a, const void* b, int n) {
  const unsigned char* x = (const unsigned char*)a;
  const unsigned char* y = (const unsigned char*)b;
  for (int i = 0; i < n; i++) if (x[i] != y[i]) return (int)x[i] - (int)y[i];
  return 0;
}
static void xmemcpy(void* d, const void* s, int n) {
  unsigned char* dd = (unsigned char*)d;
  const unsigned char* ss = (const unsigned char*)s;
  for (int i = 0; i < n; i++) dd[i] = ss[i];
}
static void xmemset(void* d, int v, int n) {
  unsigned char* dd = (unsigned char*)d;
  for (int i = 0; i < n; i++) dd[i] = (unsigned char)v;
}
static void xstrcpy(char* d, const char* s) { if (!s) { d[0] = 0; return; } int i = 0; while ((d[i] = s[i])) i++; }
static char* xstrstr(const char* h, const char* n) {
  if (!h || !n) return NULL;
  int nl = xlen(n); if (nl == 0) return (char*)h;
  for (; *h; h++) {
    if (*h == *n && xmemcmp(h, n, nl) == 0) return (char*)h;
  }
  return NULL;
}
static int xstrncmp(const char* a, const char* b, int n) {
  for (int i = 0; i < n; i++) {
    unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
    if (x != y || x == 0) return (int)x - (int)y;
  }
  return 0;
}
/* byte-swap helpers replacing winsock htons/htonl (which import unresolved) */
static unsigned short bs16(unsigned short v) {
  return (unsigned short)(((v & 0xff) << 8) | ((v >> 8) & 0xff));
}
static unsigned int bs32(unsigned int v) {
  return ((v & 0xff) << 24) | (((v >> 8) & 0xff) << 16) |
         (((v >> 16) & 0xff) << 8) | ((v >> 24) & 0xff);
}

/* ---------- pattern tables (course-grounded) ---------- */

/* High-entropy / secret substrings (M3.2.1, M7.2.1, M9.1.1, M11.4) */
static const char* AIBOF_SECRETS[] = {
  "sk-", "AKIA", "ASIA", "glpat-", "xoxb-", "xoxp-", "ghp_", "gho_",
  "github_pat_", "ntk_prod_", "eyJ", "-----BEGIN OPENSSH",
  "-----BEGIN RSA", "-----BEGIN EC", "-----BEGIN PRIVATE KEY",
  "password=", "pwd=", "Password\"", "postgres://", "redis://",
  "mongodb+srv://", "mongodb://", "Authorization: Bearer",
  "SLACK_BOT_TOKEN", "slack_bot_token", "API_KEY", "api_key",
  "SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "SAGEMAKER_ENDPOINT",
  "BACKEND_ROLE_ARN", "DYNAMODB_TABLE", "Megacorp_", NULL
};

/* AI-specific content signatures (M2.3 headers, M2.4 configs, M4.7 directives,
 * M5 RAG, M7 MCP, M8 supply chain) */
static const char* AIBOF_AI_SIGS[] = {
  "X-AI-Backend", "X-RAG-Provider", "rag_enabled", "mcp_enabled",
  "embedding", "vector_score", "bm25_score", "chunk_id",
  "mcpServers", "tool", "weights_only", "__reduce__", "torch.load",
  "xp_cmdshell", "[INTERNAL PROCESSING DIRECTIVE]", "safetensors",
  "tokenizer", "vocab", "all-MiniLM", "Modelfile", "agent.log",
  "ingest_ok", "lm_response", "read_file", "connection string",
  "system prompt", "safety.yaml", "rag.yaml", NULL
};

/* AI artifact filename substrings (M2.4, M7.1.1, M8, M11.5) */
static const char* AIBOF_AI_NAMES[] = {
  "rag.yaml", "system.txt", "safety.yaml", "models.yaml",
  "requirements.txt", ".env", "config.yaml", "Modelfile",
  "vocab.json", "tokenizer.json", "agent.log", "openapi.json",
  "agent.json", "train.jsonl", "server.py", "kubeconfig",
  ".well-known", NULL
};

/* ---------- helpers ---------- */

/* naive substring search with first/last-char fast path (SauronEye style) */
static int buf_contains(const char* buf, int len, const char* pat) {
  if (!buf || !pat) return 0;
  int plen = (int)xlen(pat);
  if (plen == 0 || len < plen) return 0;
  unsigned char first = (unsigned char)pat[0];
  int maxp = len - plen;
  for (int i = 0; i <= maxp; i++) {
    if ((unsigned char)buf[i] != first) continue;
    if (plen > 1 && (unsigned char)buf[i + plen - 1] != (unsigned char)pat[plen - 1]) continue;
    int j = 1;
    for (; j < plen - 1; j++)
      if ((unsigned char)buf[i + j] != (unsigned char)pat[j]) break;
    if (j == plen - 1) return 1;
  }
  return 0;
}

/* case-insensitive variant for filenames */
static int buf_contains_ci(const char* buf, int len, const char* pat) {
  if (!buf || !pat) return 0;
  int plen = (int)xlen(pat);
  if (plen == 0 || len < plen) return 0;
  int maxp = len - plen;
  for (int i = 0; i <= maxp; i++) {
    int j = 0;
    for (; j < plen; j++) {
      char a = buf[i + j], b = pat[j];
      if (a >= 'A' && a <= 'Z') a += 32;
      if (b >= 'A' && b <= 'Z') b += 32;
      if (a != b) break;
    }
    if (j == plen) return 1;
  }
  return 0;
}

/* read up to maxbytes of a file into a heap buffer; caller frees with intFree.
 * returns 1 on success, 0 on failure. */
static int read_file(const char* path, unsigned char** out, DWORD* outlen, DWORD maxbytes) {
  *out = NULL; *outlen = 0;
  HANDLE h = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return 0;
  LARGE_INTEGER sz; sz.QuadPart = 0;
  KERNEL32$GetFileSizeEx(h, &sz);
  DWORD want = (sz.QuadPart > (LONGLONG)maxbytes) ? maxbytes : (DWORD)sz.QuadPart;
  if (want == 0) { KERNEL32$CloseHandle(h); return 0; }
  unsigned char* buf = (unsigned char*)intAlloc(want + 1);
  if (!buf) { KERNEL32$CloseHandle(h); return 0; }
  DWORD got = 0;
  if (!KERNEL32$ReadFile(h, buf, want, &got, NULL) || got == 0) {
    intFree(buf); KERNEL32$CloseHandle(h); return 0;
  }
  buf[got] = 0;
  KERNEL32$CloseHandle(h);
  *out = buf; *outlen = got;
  return 1;
}

/* wide -> narrow into caller-provided buffer (length-preserved, '?' on bad char) */
static void w2a(const wchar_t* w, char* a, int max) {
  int i = 0;
  for (; w && w[i] && i < max - 1; i++) {
    wchar_t c = w[i];
    a[i] = (c < 128) ? (char)c : '?';
  }
  a[i] = 0;
}

/* CRC32 (table-less, reflected) — non-cryptographic fingerprint for manifests */
static unsigned int crc32(const unsigned char* d, int n) {
  unsigned int c = 0xFFFFFFFF;
  for (int i = 0; i < n; i++) {
    c ^= d[i];
    for (int k = 0; k < 8; k++)
      c = (c >> 1) ^ (0xEDB88320u & (-(int)(c & 1)));
  }
  return ~c;
}

/* base64 decode into out (caller-allocated); returns decoded len or 0 */
static int b64decode(const char* in, int inlen, unsigned char* out, int outmax) {
  static const int8_t dv[256] = {
    ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,['I']=8,['J']=9,
    ['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,['T']=19,
    ['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,
    ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,['i']=34,['j']=35,
    ['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,
    ['u']=46,['v']=47,['w']=48,['x']=49,['y']=50,['z']=51,
    ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,
    ['+']=62,['/']=63
  };
  int v = 0, bits = 0, o = 0;
  for (int i = 0; i < inlen; i++) {
    unsigned char c = (unsigned char)in[i];
    if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
    int8_t d = dv[c];
    if (d < 0) continue;
    v = (v << 6) | d; bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= outmax) return 0;
      out[o++] = (unsigned char)((v >> bits) & 0xFF);
    }
  }
  return o;
}

/* parse "a.b.c.d" -> host-order DWORD (0 on error) */
static unsigned int parse_ipv4(const char* s) {
  unsigned int v[4] = {0,0,0,0}; int p = 0, n = 0, any = 0;
  for (int i = 0; ; i++) {
    char ch = s[i];
    if (ch >= '0' && ch <= '9') { n = n * 10 + (ch - '0'); if (n > 255) return 0; any = 1; }
    else {
      if (!any) return 0;
      if (p >= 4) return 0;
      v[p++] = (unsigned int)n; n = 0; any = 0;
      if (ch == 0) break;
      if (ch != '.') return 0;
    }
  }
  if (p != 4) return 0;
  return (v[0]<<24)|(v[1]<<16)|(v[2]<<8)|v[3];
}

#endif /* AIBOF_H */