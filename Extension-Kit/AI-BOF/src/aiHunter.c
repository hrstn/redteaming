/*
 * aiHunter.c — recursive AI-artifact + content-signature hunter (OSAI T1).
 * Course: M2.4 repo mining, M7.1.1 .continue/config.yaml + git MCP,
 *         M8 model artifacts, M11.5 agent.log/KB.  ATLAS recon; OWASP LLM02/07.
 * Replaces `find / -name ... -exec grep` / `findstr /S` — zero child processes.
 *
 * args (ax.bof_pack): str root, int maxDepth(0=unlimited)
 */
#include "aibof.h"

#define READWIN 16384

static int ext_hit(const char* n) {
  if (xstrstr(n, ".pt") || xstrstr(n, ".pkl") ||
      xstrstr(n, ".safetensors") || xstrstr(n, ".gguf") ||
      xstrstr(n, ".onnx") || xstrstr(n, ".bin") ||
      xstrstr(n, ".env") || xstrstr(n, ".json") ||
      xstrstr(n, ".yaml") || xstrstr(n, ".yml") ||
      xstrstr(n, ".log") || xstrstr(n, ".txt") ||
      xstrstr(n, ".jsonl") || xstrstr(n, ".py"))
    return 1;
  return 0;
}

static int name_hit(const char* n) {
  for (int i = 0; AIBOF_AI_NAMES[i]; i++)
    if (buf_contains_ci(n, (int)xlen(n), AIBOF_AI_NAMES[i])) return 1;
  return ext_hit(n);
}

static void scan(const char* path, int depth, int maxd) {
  char pat[520];
  int n = (int)xlen(path);
  if (n > 500) return;
  xmemcpy(pat, path, n); xmemcpy(pat + n, "\\*", 3);
  WIN32_FIND_DATAA fd;
  HANDLE h = KERNEL32$FindFirstFileA(pat, &fd);
  if (h == INVALID_HANDLE_VALUE) return;
  do {
    if (!xcmp(fd.cFileName, ".") || !xcmp(fd.cFileName, "..")) continue;
    char full[1024];
    int pn = (int)xlen(path), fn = (int)xlen(fd.cFileName);
    if (pn + fn + 2 > 1023) continue;
    xmemcpy(full, path, pn); full[pn] = '\\'; xmemcpy(full + pn + 1, fd.cFileName, fn + 1);

    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      /* skip reparse points / system volume noise */
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
      if (maxd == 0 || depth < maxd) scan(full, depth + 1, maxd);
    } else {
      int nh = name_hit(fd.cFileName);
      const char* hit = NULL;
      if (nh || 1) {
        unsigned char* buf = NULL; DWORD got = 0;
        if (read_file(full, &buf, &got, READWIN) && got > 0) {
          for (int i = 0; AIBOF_AI_SIGS[i]; i++)
            if (buf_contains((char*)buf, got, AIBOF_AI_SIGS[i])) { hit = AIBOF_AI_SIGS[i]; break; }
          if (!hit)
            for (int i = 0; AIBOF_SECRETS[i]; i++)
              if (buf_contains((char*)buf, got, AIBOF_SECRETS[i])) { hit = AIBOF_SECRETS[i]; break; }
        }
        if (buf) intFree(buf);
      }
      if (nh || hit)
        BeaconPrintf(CALLBACK_OUTPUT, "%s | name=%d sig=%s\n", full, nh, hit ? hit : "-");
    }
  } while (KERNEL32$FindNextFileA(h, &fd));
  KERNEL32$FindClose(h);
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* root = BeaconDataExtract(&p, NULL);
  int maxd = BeaconDataInt(&p);
  if (!root || !*root) {
    BeaconPrintf(CALLBACK_ERROR, "usage: aiHunter <root> <maxDepth 0=unlimited>\n");
    return;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[*] aiHunter root=%s maxd=%d\n", root, maxd);
  scan(root, 0, maxd);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] aiHunter done\n");
}