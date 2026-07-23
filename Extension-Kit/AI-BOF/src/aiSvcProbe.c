/*
 * aiSvcProbe.c — localhost AI-service port sweep (OSAI T1).
 * Course: M5 Weaviate :8080, M6 Phoenix/Ollama :11434, M2.3 /api/health,
 *         M4.2 :8000-8003 + /.well-known/agent.json, M7 MCP SSE.  ATLAS AML.T0040.
 * Raw-socket connect() + 1-line HTTP GET; prints port/open/first bytes.
 * No curl/netstat/Test-NetConnection child.
 *
 * args: str ip(default 127.0.0.1), int doHttp(0/1)
 */
#include "aibof.h"
#include <winsock2.h>
#include <ws2tcpip.h>

typedef struct { int port; const char* path; const char* svc; } probe_t;
static const probe_t PROBES[] = {
  {8080,  "GET /v1/schema HTTP/1.0\r\nHost: x\r\n\r\n",        "weaviate"},
  {11434, "GET /api/health HTTP/1.0\r\nHost: x\r\n\r\n",       "ollama/phoenix"},
  {6333,  "GET /collections HTTP/1.0\r\nHost: x\r\n\r\n",      "qdrant"},
  {16333, "GET /collections HTTP/1.0\r\nHost: x\r\n\r\n",      "qdrant-staging"},
  {8000,  "GET /.well-known/agent.json HTTP/1.0\r\nHost: x\r\n\r\n", "a2a-orch"},
  {8001,  "GET /.well-known/agent.json HTTP/1.0\r\nHost: x\r\n\r\n", "a2a-agent"},
  {8002,  "GET /openapi.json HTTP/1.0\r\nHost: x\r\n\r\n",     "fastapi"},
  {8003,  "GET /openapi.json HTTP/1.0\r\nHost: x\r\n\r\n",     "fastapi"},
  {9000,  "GET / HTTP/1.0\r\nHost: x\r\n\r\n",                 "minio/milvus"},
  {3000,  "GET / HTTP/1.0\r\nHost: x\r\n\r\n",                 "open-webui"},
  {80,    "GET /api/health HTTP/1.0\r\nHost: x\r\n\r\n",       "http-rag"},
  {443,   "GET /api/health HTTP/1.0\r\nHost: x\r\n\r\n",       "https-rag"},
  {5432,  "", "postgres"}, {1433, "", "mssql"}, {0, NULL, NULL}
};

static int probe_one(unsigned int hip, const probe_t* pr, int doHttp) {
  SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == INVALID_SOCKET) return 0;
  /* short timeout via non-blocking + select-less: just connect, default */
  struct sockaddr_in sa; xmemset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_addr.S_un.S_addr = bs32(hip);
  sa.sin_port = bs16((u_short)pr->port);
  int open = 0;
  if (WS2_32$connect(s, (struct sockaddr*)&sa, sizeof(sa)) == 0) open = 1;
  if (open && doHttp && pr->path && *pr->path) {
    int pl = (int)xlen(pr->path);
    WS2_32$send(s, pr->path, pl, 0);
    char buf[300]; int r = WS2_32$recv(s, buf, sizeof(buf) - 1, 0);
    if (r > 0) { buf[r < 299 ? r : 299] = 0; BeaconPrintf(CALLBACK_OUTPUT, "%d/%s OPEN :: %s\n", pr->port, pr->svc, buf); }
    else BeaconPrintf(CALLBACK_OUTPUT, "%d/%s OPEN (no-read)\n", pr->port, pr->svc);
  } else if (open) {
    BeaconPrintf(CALLBACK_OUTPUT, "%d/%s OPEN\n", pr->port, pr->svc);
  }
  WS2_32$closesocket(s);
  return open;
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* ips = BeaconDataExtract(&p, NULL);
  int doHttp = BeaconDataInt(&p);
  if (!ips || !*ips) ips = "127.0.0.1";
  unsigned int hip = parse_ipv4(ips);
  if (hip == 0) { BeaconPrintf(CALLBACK_ERROR, "bad ip %s\n", ips); return; }
  BeaconPrintf(CALLBACK_OUTPUT, "[*] aiSvcProbe ip=%s http=%d\n", ips, doHttp);
  WSADATA wsa;
  if (WS2_32$WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
    BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed\n"); return;
  }
  int hits = 0;
  for (int i = 0; PROBES[i].port; i++) hits += probe_one(hip, &PROBES[i], doHttp);
  WS2_32$WSACleanup();
  BeaconPrintf(CALLBACK_OUTPUT, "[*] aiSvcProbe done, %d open\n", hits);
}