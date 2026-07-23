/*
 * Icacls.c — quick DACL / rights enumeration for a file or directory.
 * A compact in-process icacls: resolves the owner + every DACL ACE on a path,
 * translates each ACE's access mask to icacls-style rights letters (F/M/RX/R/W
 * composites, else bit decomposition), shows inheritance flags (OI/CI/IO/NP/ID)
 * and marks DENY ACEs.  Optional recursive descent into subdirectories.
 *
 * OPSEC: pure in-process (no `icacls.exe` / `cmd` child).  Uses
 * GetNamedSecurityInfoW + LookupAccountSidW only — no CreateProcess telemetry.
 *
 * args (bof_pack "wstr,int"):  <path>  <depth>   (depth 0 = this path only)
 */
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include "beacon.h"
#include "Icacls.h"

#define MAX_DEPTH    8
#define MAX_ENTRIES  2000          /* safety cap so a huge tree can't flood */
#define PATH_W       520           /* wchars per path buffer (under 4KB stack) */

static int g_entries = 0;

/* ---- tiny wide helpers (no bare libc; the loader won't resolve it) ---- */
static int wseq(const wchar_t* a, const wchar_t* b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}

/* ---- access-mask -> icacls letters ---- */
static const struct { DWORD bit; const char* s; } BITS[] = {
    { 0x00000001, "RD"  }, { 0x00000002, "WD"  }, { 0x00000004, "AD"  },
    { 0x00000008, "REA" }, { 0x00000010, "WEA" }, { 0x00000020, "X"   },
    { 0x00000040, "DC"  }, { 0x00000080, "RA"  }, { 0x00000100, "WA"  },
    { 0x00010000, "D"   }, { 0x00020000, "RC"  }, { 0x00040000, "WDAC"},
    { 0x00080000, "WO"  }, { 0x00100000, "S"   }, { 0x01000000, "AS"  },
};
#define NBITS (sizeof(BITS)/sizeof(BITS[0]))

static void rights_str(DWORD mask, char* out, int outsz) {
    /* exact composites first (icacls prints the largest match) */
    if ((mask & GENERIC_ALL) || mask == 0x001F01FF) { /* Full */
        /* append "F" */
        out[0]='F'; out[1]=0; return;
    }
    if (mask == 0x001301BF) { out[0]='M'; out[1]=0; return; }   /* Modify   */
    if (mask == 0x001200A9) { out[0]='R'; out[1]='X'; out[2]=0; return; } /* R&X */
    if (mask == 0x00120089) { out[0]='R'; out[1]=0; return; }   /* Read     */
    if (mask == 0x00120116) { out[0]='W'; out[1]=0; return; }   /* Write    */
    int o = 0;
    if (mask & GENERIC_READ)    { if(o<outsz-3){out[o++]='G';out[o++]='R';} mask &= ~GENERIC_READ; }
    if (mask & GENERIC_WRITE)   { if(o<outsz-3){out[o++]='G';out[o++]='W';} mask &= ~GENERIC_WRITE; }
    if (mask & GENERIC_EXECUTE) { if(o<outsz-3){out[o++]='G';out[o++]='X';} mask &= ~GENERIC_EXECUTE; }
    for (int i = 0; i < (int)NBITS && o < outsz - 6; i++) {
        if (mask & BITS[i].bit) {
            const char* p = BITS[i].s; while (*p && o < outsz - 2) out[o++] = *p++;
            out[o++] = ',';
        }
    }
    if (o && out[o-1] == ',') o--;
    if (o == 0) { out[0]='n'; out[1]='o'; out[2]='n'; out[3]='e'; out[4]=0; return; }
    out[o] = 0;
}

/* ---- ACE inheritance flags -> "(OI)(CI)..." ---- */
static void flags_str(BYTE f, char* out, int outsz) {
    int o = 0;
    #define AP(s) do { const char* _p=s; while(*_p && o<outsz-2) out[o++]=*_p++; } while(0)
    if (f & OBJECT_INHERIT_ACE)         AP("(OI)");
    if (f & CONTAINER_INHERIT_ACE)      AP("(CI)");
    if (f & NO_PROPAGATE_INHERIT_ACE)   AP("(NP)");
    if (f & INHERIT_ONLY_ACE)           AP("(IO)");
    if (f & INHERITED_ACE)              AP("(ID)");
    #undef AP
    out[o] = 0;
}

/* resolve a SID to "DOMAIN\name" (or "S-1-..." fallback) into buf (wchars) */
static void sid_to_name(PSID sid, wchar_t* buf, int bufsz) {
    wchar_t name[256], dom[256]; DWORD cn = 256, cd = 256; SID_NAME_USE euse;
    MSVCRT$memset(name, 0, sizeof name); MSVCRT$memset(dom, 0, sizeof dom);
    if (ADVAPI32$IsValidSid(sid) && ADVAPI32$LookupAccountSidW(NULL, sid, name, &cn, dom, &cd, &euse)) {
        if (cd > 0 && dom[0]) {
            /* buf = dom + "\\" + name */
            MSVCRT$wcscpy_s(buf, bufsz, dom);
            MSVCRT$wcscat_s(buf, bufsz, L"\\");
            MSVCRT$wcscat_s(buf, bufsz, name);
        } else {
            MSVCRT$wcscpy_s(buf, bufsz, name);
        }
        return;
    }
    LPWSTR sstr = NULL;
    if (ADVAPI32$ConvertSidToStringSidW(sid, &sstr) && sstr) {
        MSVCRT$wcscpy_s(buf, bufsz, sstr);
        KERNEL32$LocalFree(sstr);
    } else {
        MSVCRT$wcscpy_s(buf, bufsz, L"?");
    }
}

/* print the owner + DACL of one path */
static void print_dacl(const wchar_t* path) {
    PSID owner = NULL; PACL dacl = NULL; PSECURITY_DESCRIPTOR sd = NULL;
    DWORD rc = ADVAPI32$GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &owner, NULL, &dacl, NULL, &sd);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "%ls  (GetNamedSecurityInfoW err %lu)\n", path, rc);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "%ls\n", path);

    if (owner) {
        wchar_t who[256];
        MSVCRT$memset(who, 0, sizeof who);
        sid_to_name(owner, who, 256);
        BeaconPrintf(CALLBACK_OUTPUT, "  owner: %ls\n", who);
    }

    if (dacl == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "  No DACL (NULL DACL = everyone full access)\n");
        KERNEL32$LocalFree(sd);
        return;
    }
    if (!ADVAPI32$IsValidAcl(dacl)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  Invalid ACL\n");
        KERNEL32$LocalFree(sd);
        return;
    }

    ACL_SIZE_INFORMATION ai; MSVCRT$memset(&ai, 0, sizeof ai);
    if (!ADVAPI32$GetAclInformation(dacl, &ai, sizeof ai, AclSizeInformation)) {
        BeaconPrintf(CALLBACK_OUTPUT, "  (GetAclInformation err)\n");
        KERNEL32$LocalFree(sd);
        return;
    }

    for (DWORD i = 0; i < ai.AceCount; i++) {
        LPVOID pace = NULL;
        if (!ADVAPI32$GetAce(dacl, i, &pace) || !pace) continue;
        PACE_HEADER ah = (PACE_HEADER)pace;
        ACCESS_MASK mask; PSID sid;
        if (ah->AceType == ACCESS_ALLOWED_OBJECT_ACE_TYPE ||
            ah->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE) {
            PACCESS_ALLOWED_OBJECT_ACE oa = (PACCESS_ALLOWED_OBJECT_ACE)pace;
            mask = oa->Mask;
            DWORD off = sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + sizeof(DWORD);
            if (oa->Flags & ACE_OBJECT_TYPE_PRESENT)         off += 16;
            if (oa->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) off += 16;
            sid = (PSID)((LPBYTE)pace + off);
        } else {
            PACCESS_ALLOWED_ACE a = (PACCESS_ALLOWED_ACE)pace;
            mask = a->Mask;
            sid = (PSID)&a->SidStart;
        }
        char rights[80];  rights_str(mask, rights, sizeof rights);
        char fl[32];      flags_str(ah->AceFlags, fl, sizeof fl);
        wchar_t who[256]; MSVCRT$memset(who, 0, sizeof who);
        sid_to_name(sid, who, 256);
        const char* deny = (ah->AceType == ACCESS_DENIED_ACE_TYPE ||
                            ah->AceType == ACCESS_DENIED_OBJECT_ACE_TYPE) ? "DENY " : "";
        BeaconPrintf(CALLBACK_OUTPUT, "  %s%ls:(%s)(%s) [0x%08lx]\n",
                     deny, who, fl, rights, (unsigned long)mask);
    }
    KERNEL32$LocalFree(sd);
}

/* recursive walk */
static void walk(const wchar_t* path, int depth) {
    if (g_entries >= MAX_ENTRIES) return;
    g_entries++;
    print_dacl(path);

    if (depth <= 0) return;
    DWORD attr = KERNEL32$GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) return;

    wchar_t spec[PATH_W];
    MSVCRT$wcscpy_s(spec, PATH_W, path);
    MSVCRT$wcscat_s(spec, PATH_W, L"\\*");

    WIN32_FIND_DATAW fd; MSVCRT$memset(&fd, 0, sizeof fd);
    HANDLE h = KERNEL32$FindFirstFileW(spec, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (g_entries >= MAX_ENTRIES) {
            BeaconPrintf(CALLBACK_OUTPUT, "  (... %d-entry cap reached, stopping)\n", MAX_ENTRIES);
            break;
        }
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wseq(fd.cFileName, L".") || wseq(fd.cFileName, L"..")) continue;
            wchar_t child[PATH_W];
            MSVCRT$wcscpy_s(child, PATH_W, path);
            MSVCRT$wcscat_s(child, PATH_W, L"\\");
            MSVCRT$wcscat_s(child, PATH_W, fd.cFileName);
            walk(child, depth - 1);
        } else {
            wchar_t child[PATH_W];
            MSVCRT$wcscpy_s(child, PATH_W, path);
            MSVCRT$wcscat_s(child, PATH_W, L"\\");
            MSVCRT$wcscat_s(child, PATH_W, fd.cFileName);
            print_dacl(child);
            g_entries++;
        }
    } while (KERNEL32$FindNextFileW(h, &fd));
    KERNEL32$FindClose(h);
}

VOID go(IN PCHAR Args, IN ULONG Length) {
    datap parser; BeaconDataParse(&parser, Args, Length);
    wchar_t* path = (wchar_t*)BeaconDataExtract(&parser, NULL);
    int depth = BeaconDataInt(&parser);
    if (!path || !*path) {
        BeaconPrintf(CALLBACK_ERROR, "usage: icacls <path> [depth 0..%d]  (depth 0 = this path only)\n", MAX_DEPTH);
        return;
    }
    if (depth < 0) depth = 0;
    if (depth > MAX_DEPTH) depth = MAX_DEPTH;
    g_entries = 0;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] icacls %ls depth=%d\n", path, depth);
    walk(path, depth);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] icacls done: %d entries\n", g_entries);
}