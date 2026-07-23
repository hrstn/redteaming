/*
 * shareWalk.c — SMB KB-share enumerator + writable-dir probe (OSAI T2).
 * Course: M11.5 \\FILESERVER01\Knowledgebase, rag_kb READ+WRITE, agent.log,
 *         documents/, 60s heartbeat.  ATLAS AML.T0051.001 (prep), AML.T0020.
 * Replaces `net use` + `dir /S` + `netexec --shares` — zero child processes.
 *
 * args: str host, str share(empty=list only), str user, str pass, int maxDepth
 */
#include "aibof.h"
#include <winnetwk.h>
#include <lm.h>

static void enum_shares(const wchar_t* server) {
  SHARE_INFO_1* buf = NULL;
  DWORD entries = 0, total = 0, resume = 0;
  NET_API_STATUS st = NETAPI32$NetShareEnum((LPWSTR)server, 1, (LPBYTE*)&buf,
                                            MAX_PREFERRED_LENGTH, &entries, &total, &resume);
  if (st != ERROR_SUCCESS) { BeaconPrintf(CALLBACK_ERROR, "NetShareEnum %lu\n", st); return; }
  BeaconPrintf(CALLBACK_OUTPUT, "[shares] %lu\n", entries);
  for (DWORD i = 0; i < entries; i++) {
    char nm[256], rm[256];
    w2a(buf[i].shi1_netname, nm, sizeof nm);
    w2a(buf[i].shi1_remark ? buf[i].shi1_remark : L"", rm, sizeof rm);
    BeaconPrintf(CALLBACK_OUTPUT, "  %s  type=0x%x  %s\n", nm, buf[i].shi1_type, rm);
  }
  NETAPI32$NetApiBufferFree(buf);
}

static int writable(const char* dir) {
  char p[1024];
  int n = (int)xlen(dir); if (n > 1000) return 0;
  xmemcpy(p, dir, n); xmemcpy(p + n, "\\.__wp", 7);
  HANDLE h = KERNEL32$CreateFileA(p, GENERIC_WRITE, 0, NULL,
                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return 0;
  KERNEL32$CloseHandle(h);
  KERNEL32$DeleteFileA(p);
  return 1;
}

static void walk(const char* unc, int depth, int maxd) {
  char pat[1100]; int n = (int)xlen(unc); if (n > 1080) return;
  xmemcpy(pat, unc, n); xmemcpy(pat + n, "\\*", 3);
  WIN32_FIND_DATAA fd;
  HANDLE h = KERNEL32$FindFirstFileA(pat, &fd);
  if (h == INVALID_HANDLE_VALUE) return;
  do {
    if (!xcmp(fd.cFileName, ".") || !xcmp(fd.cFileName, "..")) continue;
    char full[1200]; int pn = (int)xlen(unc), fn = (int)xlen(fd.cFileName);
    if (pn + fn + 2 > 1199) continue;
    xmemcpy(full, unc, pn); full[pn] = '\\'; xmemcpy(full + pn + 1, fd.cFileName, fn + 1);
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      int w = writable(full);
      BeaconPrintf(CALLBACK_OUTPUT, "[D%s] %s\n", w ? "W" : " ", full);
      if (maxd == 0 || depth < maxd) walk(full, depth + 1, maxd);
    } else {
      /* flag course-relevant files: agent.log, README, docs */
      int interesting = buf_contains_ci(fd.cFileName, (int)xlen(fd.cFileName), "agent.log") ||
                        buf_contains_ci(fd.cFileName, (int)xlen(fd.cFileName), "readme") ||
                        buf_contains_ci(fd.cFileName, (int)xlen(fd.cFileName), ".txt") ||
                        buf_contains_ci(fd.cFileName, (int)xlen(fd.cFileName), ".pdf") ||
                        buf_contains_ci(fd.cFileName, (int)xlen(fd.cFileName), ".doc");
      BeaconPrintf(CALLBACK_OUTPUT, "[F%s] %s (%lu bytes)\n",
                   interesting ? "!" : " ", full, fd.nFileSizeLow);
    }
  } while (KERNEL32$FindNextFileA(h, &fd));
  KERNEL32$FindClose(h);
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* host = BeaconDataExtract(&p, NULL);
  char* share = BeaconDataExtract(&p, NULL);
  char* user = BeaconDataExtract(&p, NULL);
  char* pass = BeaconDataExtract(&p, NULL);
  int maxd = BeaconDataInt(&p);
  if (!host || !*host) { BeaconPrintf(CALLBACK_ERROR, "usage: shareWalk <host> [share user pass maxd]\n"); return; }

  /* build UNC server wide: \\host */
  wchar_t wserver[300]; int hn = (int)xlen(host);
  wserver[0] = L'\\'; wserver[1] = L'\\';
  for (int i = 0; i < hn && i < 290; i++) wserver[2 + i] = (wchar_t)host[i];
  wserver[2 + hn] = 0;

  /* connect IPC$ with creds if supplied */
  if (user && *user) {
    wchar_t wunc[320]; int i=0;
    wunc[0]=L'\\'; wunc[1]=L'\\';
    for (; host[i] && i<200; i++) wunc[2+i]=(wchar_t)host[i];
    wunc[2+i]=0; xmemcpy(wunc+2+i, L"\\IPC$", 12);
    wchar_t wuser[150], wpass[150];
    for (i=0; user[i] && i<140; i++) wuser[i]=(wchar_t)user[i]; wuser[i]=0;
    for (i=0; pass && pass[i] && i<140; i++) wpass[i]=(wchar_t)pass[i]; wpass[i]=0;
    NETRESOURCEW nr; xmemset(&nr, 0, sizeof nr); nr.dwType = RESOURCETYPE_DISK; nr.lpRemoteName = wunc;
    DWORD r = MPR$WNetAddConnection2W(&nr, wpass, wuser, 0);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] shareWalk WNet ipc rc=%lu\n", r);
  }

  enum_shares(wserver);

  if (share && *share) {
    char unc[1100];
    int hn = (int)xlen(host), sn = (int)xlen(share);
    if (hn + sn + 4 < 1099) {
      unc[0]='\\'; unc[1]='\\'; xmemcpy(unc+2, host, hn); unc[2+hn]='\\';
      xmemcpy(unc+3+hn, share, sn+1);
      BeaconPrintf(CALLBACK_OUTPUT, "[*] walking %s maxd=%d\n", unc, maxd);
      walk(unc, 0, maxd);
    }
    if (user && *user) {
      wchar_t wunc[320]; int i=0; wunc[0]=L'\\'; wunc[1]=L'\\';
      for (; host[i] && i<200; i++) wunc[2+i]=(wchar_t)host[i];
      wunc[2+i]=0; xmemcpy(wunc+2+i, L"\\IPC$", 12);
      MPR$WNetCancelConnection2W(wunc, 0, TRUE);
    }
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[*] shareWalk done\n");
}