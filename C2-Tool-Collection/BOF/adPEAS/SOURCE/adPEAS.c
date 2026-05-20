/*
 * adPEAS BOF - Active Directory Enumeration
 *
 * Performs automated AD security enumeration covering:
 *   - Domain Controllers and domain metadata
 *   - krbtgt account password age
 *   - Default password policy
 *   - Fine-Grained Password Policies (FGPP/PSO)
 *   - Domain trusts
 *   - AS-REP Roastable accounts (DONT_REQ_PREAUTH)
 *   - Kerberoastable accounts (SPN on user, enabled)
 *   - Unconstrained delegation (non-DC)
 *   - Constrained delegation (msDS-AllowedToDelegateTo)
 *   - Resource-Based Constrained Delegation (RBCD)
 *   - Privileged group members (DA, EA, SA, Admins, Operators)
 *   - Accounts with possible password in description
 *   - ADCS Enrollment Services (Certificate Authorities)
 *
 * Usage: adpeas [-s <dc>]
 *
 * Ported from adPEAS PowerShell by Alexander Sturz (@_61106960_)
 * BOF by Outflank / adapted for adPEAS enumeration
 */

#include <windows.h>
#include <activeds.h>

#include "adPEAS.h"
#include "beacon.h"

#define PRINT_BUF_SIZE (8192 * 2)
#define PATH_BUF       1024
#define DN_BUF         512

static INT iGarbage = 1;
static LPSTREAM g_lpStream = (LPSTREAM)1;
static LPWSTR   g_lpwPrintBuffer = (LPWSTR)1;

// ============================================================
// Streaming output helpers
// ============================================================

static HRESULT BeaconPrintToStreamW(_In_z_ LPCWSTR lpwFormat, ...) {
    HRESULT hr = S_FALSE;
    va_list argList;
    DWORD dwWritten = 0;

    if (g_lpStream <= (LPSTREAM)1) {
        hr = OLE32$CreateStreamOnHGlobal(NULL, TRUE, &g_lpStream);
        if (FAILED(hr)) return hr;
    }

    if (g_lpwPrintBuffer <= (LPWSTR)1) {
        g_lpwPrintBuffer = (LPWSTR)MSVCRT$calloc(PRINT_BUF_SIZE, sizeof(WCHAR));
        if (g_lpwPrintBuffer == NULL) return E_OUTOFMEMORY;
    }

    va_start(argList, lpwFormat);
    MSVCRT$_vsnwprintf_s(g_lpwPrintBuffer, PRINT_BUF_SIZE, PRINT_BUF_SIZE - 1, lpwFormat, argList);
    va_end(argList);

    if (g_lpStream != NULL) {
        hr = g_lpStream->lpVtbl->Write(g_lpStream, g_lpwPrintBuffer,
            (ULONG)MSVCRT$wcslen(g_lpwPrintBuffer) * sizeof(WCHAR), &dwWritten);
    }

    if (g_lpwPrintBuffer != NULL) {
        MSVCRT$memset(g_lpwPrintBuffer, 0, PRINT_BUF_SIZE * sizeof(WCHAR));
    }

    return SUCCEEDED(hr) ? S_OK : hr;
}

static VOID BeaconOutputStreamW(void) {
    STATSTG ssStreamData = { 0 };
    SIZE_T cbSize = 0;
    ULONG cbRead = 0;
    LARGE_INTEGER pos;
    LPWSTR lpwOutput = NULL;

    if (g_lpStream <= (LPSTREAM)1) return;

    if (FAILED(g_lpStream->lpVtbl->Stat(g_lpStream, &ssStreamData, STATFLAG_NONAME))) goto CleanUp;

    cbSize = ssStreamData.cbSize.LowPart;
    if (cbSize == 0) goto CleanUp;

    lpwOutput = (LPWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize + 2);
    if (lpwOutput == NULL) goto CleanUp;

    pos.QuadPart = 0;
    if (FAILED(g_lpStream->lpVtbl->Seek(g_lpStream, pos, STREAM_SEEK_SET, NULL))) goto CleanUp;
    if (FAILED(g_lpStream->lpVtbl->Read(g_lpStream, lpwOutput, (ULONG)cbSize, &cbRead))) goto CleanUp;

    BeaconPrintf(CALLBACK_OUTPUT, "%ls", lpwOutput);

CleanUp:
    if (g_lpStream != NULL) {
        g_lpStream->lpVtbl->Release(g_lpStream);
        g_lpStream = NULL;
    }
    if (g_lpwPrintBuffer != NULL) {
        MSVCRT$free(g_lpwPrintBuffer);
        g_lpwPrintBuffer = NULL;
    }
    if (lpwOutput != NULL) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpwOutput);
    }
}

// ============================================================
// Print one ADSI column value with human-readable notes
// ============================================================

static VOID PrintColumnValue(_In_ ADS_SEARCH_COLUMN *pCol) {
    PSID pSID;
    LPWSTR szSID = NULL;
    FILETIME ft;
    SYSTEMTIME st;
    DATE d;
    VARIANT v;
    LARGE_INTEGER li;
    PSECURITY_DESCRIPTOR pSD;
    LPWSTR lpwSD = NULL;
    DWORD iFlags;
    int iDir, iTT, iUAC;
    LONGLONG ticks, days, mins;

    for (DWORD x = 0; x < pCol->dwNumValues; x++) {

        if (pCol->dwADsType == ADSTYPE_DN_STRING) {
            BeaconPrintToStreamW(L"    %ls\n", pCol->pADsValues[x].DNString);
        }

        else if (pCol->dwADsType == ADSTYPE_CASE_EXACT_STRING   ||
                 pCol->dwADsType == ADSTYPE_CASE_IGNORE_STRING  ||
                 pCol->dwADsType == ADSTYPE_PRINTABLE_STRING     ||
                 pCol->dwADsType == ADSTYPE_NUMERIC_STRING       ||
                 pCol->dwADsType == ADSTYPE_OBJECT_CLASS) {
            BeaconPrintToStreamW(L"    %ls\n", pCol->pADsValues[x].CaseIgnoreString);
        }

        else if (pCol->dwADsType == ADSTYPE_BOOLEAN) {
            BeaconPrintToStreamW(L"    %ls\n", pCol->pADsValues[x].Boolean ? L"TRUE" : L"FALSE");
        }

        else if (pCol->dwADsType == ADSTYPE_INTEGER) {
            // Special-case certain attributes for readability
            if (MSVCRT$_wcsicmp(pCol->pszAttrName, L"pwdProperties") == 0) {
                iFlags = (DWORD)pCol->pADsValues[x].Integer;
                BeaconPrintToStreamW(L"    %d (flags)\n", iFlags);
                if (iFlags & 0x01) BeaconPrintToStreamW(L"      -> PASSWORD_COMPLEXITY: Enabled\n");
                else               BeaconPrintToStreamW(L"      -> PASSWORD_COMPLEXITY: Disabled [!]\n");
                if (iFlags & 0x10) BeaconPrintToStreamW(L"      -> STORE_CLEARTEXT: Enabled [!] reversible encryption\n");
                if (iFlags & 0x02) BeaconPrintToStreamW(L"      -> NO_ANON_CHANGE\n");
                if (iFlags & 0x08) BeaconPrintToStreamW(L"      -> LOCKOUT_ADMINS\n");
            }
            else if (MSVCRT$_wcsicmp(pCol->pszAttrName, L"trustDirection") == 0) {
                iDir = pCol->pADsValues[x].Integer;
                LPCWSTR dirStr = (iDir == 0) ? L"Disabled" :
                                 (iDir == 1) ? L"Inbound (remote -> us)" :
                                 (iDir == 2) ? L"Outbound (us -> remote)" :
                                 (iDir == 3) ? L"Bidirectional" : L"Unknown";
                BeaconPrintToStreamW(L"    %d (%ls)\n", iDir, dirStr);
            }
            else if (MSVCRT$_wcsicmp(pCol->pszAttrName, L"trustType") == 0) {
                iTT = pCol->pADsValues[x].Integer;
                LPCWSTR ttStr = (iTT == 1) ? L"Downlevel (NT4)" :
                                (iTT == 2) ? L"Uplevel (AD)" :
                                (iTT == 3) ? L"MIT Kerberos" :
                                (iTT == 4) ? L"DCE" : L"Unknown";
                BeaconPrintToStreamW(L"    %d (%ls)\n", iTT, ttStr);
            }
            else if (MSVCRT$_wcsicmp(pCol->pszAttrName, L"trustAttributes") == 0) {
                iFlags = (DWORD)pCol->pADsValues[x].Integer;
                BeaconPrintToStreamW(L"    0x%08X\n", iFlags);
                if (iFlags & 0x01) BeaconPrintToStreamW(L"      -> NON_TRANSITIVE\n");
                if (iFlags & 0x02) BeaconPrintToStreamW(L"      -> UPLEVEL_ONLY\n");
                if (iFlags & 0x04) BeaconPrintToStreamW(L"      -> QUARANTINED_DOMAIN (SID Filtering)\n");
                if (iFlags & 0x08) BeaconPrintToStreamW(L"      -> FOREST_TRANSITIVE [forest trust]\n");
                if (iFlags & 0x10) BeaconPrintToStreamW(L"      -> CROSS_ORGANIZATION\n");
                if (iFlags & 0x20) BeaconPrintToStreamW(L"      -> WITHIN_FOREST\n");
                if (iFlags & 0x40) BeaconPrintToStreamW(L"      -> TREAT_AS_EXTERNAL\n");
                if (iFlags & 0x400) BeaconPrintToStreamW(L"      -> PIM_TRUST\n");
            }
            else if (MSVCRT$_wcsicmp(pCol->pszAttrName, L"userAccountControl") == 0) {
                iUAC = pCol->pADsValues[x].Integer;
                BeaconPrintToStreamW(L"    %d (0x%08X)\n", iUAC, (DWORD)iUAC);
                if (iUAC & 0x1000000) BeaconPrintToStreamW(L"      -> TRUSTED_TO_AUTH_FOR_DELEGATION [protocol transition!]\n");
                if (iUAC & 0x080000)  BeaconPrintToStreamW(L"      -> TRUSTED_FOR_DELEGATION [unconstrained]\n");
                if (iUAC & 0x400000)  BeaconPrintToStreamW(L"      -> DONT_REQ_PREAUTH\n");
            }
            else if (MSVCRT$_wcsicmp(pCol->pszAttrName, L"lockoutThreshold") == 0) {
                int thr = pCol->pADsValues[x].Integer;
                if (thr == 0) BeaconPrintToStreamW(L"    0 (disabled - no lockout!) [!]\n");
                else          BeaconPrintToStreamW(L"    %d attempts\n", thr);
            }
            else if (MSVCRT$_wcsicmp(pCol->pszAttrName, L"minPwdLength") == 0) {
                int minLen = pCol->pADsValues[x].Integer;
                BeaconPrintToStreamW(L"    %d characters%ls\n", minLen,
                    minLen < 8  ? L" [!] weak" :
                    minLen < 14 ? L" [~] moderate" : L" [+] ok");
            }
            else {
                BeaconPrintToStreamW(L"    %d\n", pCol->pADsValues[x].Integer);
            }
        }

        else if (pCol->dwADsType == ADSTYPE_OCTET_STRING) {
            if (MSVCRT$_wcsicmp(pCol->pszAttrName, L"objectSID")        == 0 ||
                MSVCRT$_wcsicmp(pCol->pszAttrName, L"securityIdentifier") == 0) {
                pSID = (PSID)(pCol->pADsValues[x].OctetString.lpValue);
                if (ADVAPI32$ConvertSidToStringSidW(pSID, &szSID)) {
                    BeaconPrintToStreamW(L"    %ls\n", szSID);
                    KERNEL32$LocalFree(szSID);
                }
            } else {
                BeaconPrintToStreamW(L"    <binary, %lu bytes>\n", pCol->pADsValues[x].OctetString.dwLength);
            }
        }

        else if (pCol->dwADsType == ADSTYPE_LARGE_INTEGER) {
            li = pCol->pADsValues[x].LargeInteger;
            ft.dwLowDateTime  = li.LowPart;
            ft.dwHighDateTime = li.HighPart;

            if (ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0) {
                BeaconPrintToStreamW(L"    0 (not set / disabled)\n");
            }
            else if ((DWORD)li.LowPart == 0xFFFFFFFF && li.HighPart == (LONG)0x7FFFFFFF) {
                BeaconPrintToStreamW(L"    (never)\n");
            }
            // Time-stamp attributes: convert to local date/time
            else if (MSVCRT$_wcsicmp(pCol->pszAttrName, L"pwdLastSet")           == 0 ||
                     MSVCRT$_wcsicmp(pCol->pszAttrName, L"lastLogon")             == 0 ||
                     MSVCRT$_wcsicmp(pCol->pszAttrName, L"lastLogonTimestamp")    == 0 ||
                     MSVCRT$_wcsicmp(pCol->pszAttrName, L"accountExpires")        == 0 ||
                     MSVCRT$_wcsicmp(pCol->pszAttrName, L"badPasswordTime")       == 0 ||
                     MSVCRT$_wcsicmp(pCol->pszAttrName, L"whenCreated")           == 0) {
                if (KERNEL32$FileTimeToLocalFileTime(&ft, &ft) &&
                    KERNEL32$FileTimeToSystemTime(&ft, &st)    &&
                    OLEAUT32$SystemTimeToVariantTime(&st, &d)) {
                    v.vt = VT_DATE;
                    v.date = d;
                    OLEAUT32$VariantChangeType(&v, &v, VARIANT_NOVALUEPROP, VT_BSTR);
                    BeaconPrintToStreamW(L"    %ls\n", v.bstrVal);
                    OLEAUT32$VariantClear(&v);
                }
            }
            // Duration/interval attributes: convert from negative 100-ns to days or minutes
            else if (MSVCRT$_wcsicmp(pCol->pszAttrName, L"maxPwdAge")               == 0 ||
                     MSVCRT$_wcsicmp(pCol->pszAttrName, L"minPwdAge")               == 0 ||
                     MSVCRT$_wcsicmp(pCol->pszAttrName, L"lockoutDuration")         == 0 ||
                     MSVCRT$_wcsicmp(pCol->pszAttrName, L"lockOutObservationWindow") == 0) {
                ticks = li.QuadPart;
                if (ticks < 0) ticks = -ticks;
                days = ticks / 864000000000LL;
                mins = ticks / 600000000LL;
                if (days > 0) {
                    BeaconPrintToStreamW(L"    %lld days\n", days);
                } else if (mins > 0) {
                    BeaconPrintToStreamW(L"    %lld minutes\n", mins);
                } else {
                    BeaconPrintToStreamW(L"    %lld (100-ns ticks)\n", li.QuadPart);
                }
            }
            else {
                BeaconPrintToStreamW(L"    %lld\n", li.QuadPart);
            }
        }

        else if (pCol->dwADsType == ADSTYPE_UTC_TIME) {
            st = pCol->pADsValues[x].UTCTime;
            if (OLEAUT32$SystemTimeToVariantTime(&st, &d)) {
                v.vt = VT_DATE;
                v.date = d;
                OLEAUT32$VariantChangeType(&v, &v, VARIANT_NOVALUEPROP, VT_BSTR);
                BeaconPrintToStreamW(L"    %ls\n", v.bstrVal);
                OLEAUT32$VariantClear(&v);
            }
        }

        else if (pCol->dwADsType == ADSTYPE_NT_SECURITY_DESCRIPTOR) {
            pSD = (PSECURITY_DESCRIPTOR)(pCol->pADsValues[x].SecurityDescriptor.lpValue);
            if (ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    pSD, SDDL_REVISION_1,
                    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    &lpwSD, NULL)) {
                // Truncate very long SDDL strings for readability
                if (MSVCRT$wcslen(lpwSD) > 250) lpwSD[250] = 0;
                BeaconPrintToStreamW(L"    %ls\n", lpwSD);
                KERNEL32$LocalFree(lpwSD);
            } else {
                BeaconPrintToStreamW(L"    <security descriptor>\n");
            }
        }

        else {
            BeaconPrintToStreamW(L"    <ADSI type %d>\n", pCol->dwADsType);
        }
    }
}

// ============================================================
// Run LDAP query against an already-opened IDirectorySearch.
// Prints results and returns the count of objects found.
// ============================================================

static INT RunQuery(
    _In_ IDirectorySearch *pSearch,
    _In_ LPWSTR            lpwFilter,
    _In_ LPWSTR           *lpwAttrs,
    _In_ DWORD             dwAttrCount,
    _In_ INT               iMaxResults,
    _In_ _FreeADsMem       FreeADsMem
) {
    ADS_SEARCHPREF_INFO prefs[2];
    ADS_SEARCH_HANDLE   hSearch = NULL;
    HRESULT             hr;
    INT                 iCount = 0;

    prefs[0].dwSearchPref       = ADS_SEARCHPREF_PAGESIZE;
    prefs[0].vValue.dwType      = ADSTYPE_INTEGER;
    prefs[0].vValue.Integer     = 200;
    prefs[1].dwSearchPref       = ADS_SEARCHPREF_SEARCH_SCOPE;
    prefs[1].vValue.dwType      = ADSTYPE_INTEGER;
    prefs[1].vValue.Integer     = ADS_SCOPE_SUBTREE;
    pSearch->lpVtbl->SetSearchPreference(pSearch, prefs, 2);

    if (dwAttrCount > 0) {
        hr = pSearch->lpVtbl->ExecuteSearch(pSearch, lpwFilter, lpwAttrs, dwAttrCount, &hSearch);
    } else {
        hr = pSearch->lpVtbl->ExecuteSearch(pSearch, lpwFilter, NULL, (DWORD)-1L, &hSearch);
    }

    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[adPEAS] ExecuteSearch failed (filter: %ls): 0x%08lx\n", lpwFilter, hr);
        return 0;
    }

    hr = pSearch->lpVtbl->GetFirstRow(pSearch, hSearch);
    while (hr != S_ADS_NOMORE_ROWS && SUCCEEDED(hr)) {
        ADS_SEARCH_COLUMN col;
        LPWSTR pszColumn = NULL;

        iCount++;
        BeaconPrintToStreamW(L"  ---\n");

        while (pSearch->lpVtbl->GetNextColumnName(pSearch, hSearch, &pszColumn) != S_ADS_NOMORE_COLUMNS) {
            hr = pSearch->lpVtbl->GetColumn(pSearch, hSearch, pszColumn, &col);
            if (SUCCEEDED(hr)) {
                BeaconPrintToStreamW(L"  [%ls]\n", col.pszAttrName);
                PrintColumnValue(&col);
                pSearch->lpVtbl->FreeColumn(pSearch, &col);
            }
            if (pszColumn != NULL) {
                FreeADsMem(pszColumn);
                pszColumn = NULL;
            }
        }

        if (iMaxResults > 0 && iCount >= iMaxResults) break;

        // Flush to avoid unbounded buffer growth on large result sets
        if (iCount > 0 && iCount % 40 == 0) BeaconOutputStreamW();

        hr = pSearch->lpVtbl->GetNextRow(pSearch, hSearch);
    }

    pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    return iCount;
}

// ============================================================
// Open an IDirectorySearch on the given LDAP path
// ============================================================

static HRESULT OpenSearch(
    _In_  LPWSTR            lpwPath,
    _Out_ IDirectorySearch **ppSearch,
    _In_  _ADsOpenObject    ADsOpenObject
) {
    IID iid;
    LPCOLESTR pIID = L"{109BA8EC-92F0-11D0-A790-00C04FD8D5A8}";
    OLE32$IIDFromString(pIID, &iid);
    return ADsOpenObject(lpwPath, NULL, NULL,
        ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION,
        &iid, (void **)ppSearch);
}

// ============================================================
// BOF entry point
// ============================================================

VOID go(IN PCHAR Args, IN ULONG Length) {
    HRESULT           hr;
    HMODULE           hActiveds      = NULL;
    IADs             *pRootDSE       = NULL;
    IDirectorySearch *pDomainSearch  = NULL;
    IDirectorySearch *pTempSearch    = NULL;
    IID               IADsIID;
    VARIANT           varDomainDN, varConfigDN, varDnsHost, varDomainFunc;
    WCHAR             wcPath[PATH_BUF]     = { 0 };
    WCHAR             wcDomainDN[DN_BUF]   = { 0 };
    WCHAR             wcConfigDN[DN_BUF]   = { 0 };
    LPWSTR            lpwAttrs[16]         = { 0 };
    INT               iFound               = 0;

    // --- Parse optional server argument ---
    datap parser;
    BeaconDataParse(&parser, Args, Length);
    LPWSTR lpwServer = (LPWSTR)BeaconDataExtract(&parser, NULL);
    BOOL   bHasServer = (lpwServer != NULL && lpwServer[0] != L'\0');

    // --- Load Activeds.dll and resolve function pointers ---
    hActiveds = LoadLibraryA("Activeds.dll");
    if (!hActiveds) {
        BeaconPrintf(CALLBACK_ERROR, "[adPEAS] Failed to load Activeds.dll\n");
        return;
    }

    _ADsOpenObject ADsOpenObject = (_ADsOpenObject)GetProcAddress(hActiveds, "ADsOpenObject");
    _FreeADsMem    FreeADsMem    = (_FreeADsMem)   GetProcAddress(hActiveds, "FreeADsMem");
    if (!ADsOpenObject || !FreeADsMem) {
        BeaconPrintf(CALLBACK_ERROR, "[adPEAS] Failed to resolve Activeds functions\n");
        return;
    }

    // --- Initialize COM ---
    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[adPEAS] CoInitializeEx failed: 0x%08lx\n", hr);
        return;
    }

    // --- Connect to rootDSE ---
    LPCOLESTR pIADsIID = L"{FD8256D0-FD15-11CE-ABC4-02608C9E7553}";
    OLE32$IIDFromString(pIADsIID, &IADsIID);

    if (bHasServer) {
        MSVCRT$swprintf_s(wcPath, PATH_BUF, L"LDAP://%ls/rootDSE", lpwServer);
    } else {
        MSVCRT$wcscpy_s(wcPath, PATH_BUF, L"LDAP://rootDSE");
    }

    hr = ADsOpenObject(wcPath, NULL, NULL,
        ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION,
        &IADsIID, (void **)&pRootDSE);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[adPEAS] Cannot connect to rootDSE (0x%08lx). Check domain membership / network.\n", hr);
        goto Cleanup;
    }

    OLEAUT32$VariantInit(&varDomainDN);
    OLEAUT32$VariantInit(&varConfigDN);
    OLEAUT32$VariantInit(&varDnsHost);
    OLEAUT32$VariantInit(&varDomainFunc);

    hr = pRootDSE->lpVtbl->Get(pRootDSE, (BSTR)L"defaultNamingContext", &varDomainDN);
    if (FAILED(hr) || varDomainDN.bstrVal == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[adPEAS] Failed to get defaultNamingContext\n");
        goto Cleanup;
    }
    pRootDSE->lpVtbl->Get(pRootDSE, (BSTR)L"configurationNamingContext", &varConfigDN);
    pRootDSE->lpVtbl->Get(pRootDSE, (BSTR)L"dnsHostName",                &varDnsHost);
    pRootDSE->lpVtbl->Get(pRootDSE, (BSTR)L"domainFunctionality",         &varDomainFunc);
    pRootDSE->lpVtbl->Release(pRootDSE);
    pRootDSE = NULL;

    MSVCRT$wcscpy_s(wcDomainDN, DN_BUF, varDomainDN.bstrVal);
    if (varConfigDN.bstrVal)
        MSVCRT$wcscpy_s(wcConfigDN, DN_BUF, varConfigDN.bstrVal);

    // Build main domain LDAP path
    if (bHasServer) {
        MSVCRT$swprintf_s(wcPath, PATH_BUF, L"LDAP://%ls/%ls", lpwServer, wcDomainDN);
    } else {
        MSVCRT$swprintf_s(wcPath, PATH_BUF, L"LDAP://%ls", wcDomainDN);
    }

    // ====================================================
    // BANNER
    // ====================================================
    BeaconPrintToStreamW(L"================================================================================\n");
    BeaconPrintToStreamW(L"  adPEAS BOF - Active Directory Enumeration\n");
    BeaconPrintToStreamW(L"================================================================================\n");
    BeaconPrintToStreamW(L"  Domain DN   : %ls\n", wcDomainDN);
    if (varDnsHost.bstrVal)
        BeaconPrintToStreamW(L"  DC (rootDSE): %ls\n", varDnsHost.bstrVal);
    if (varDomainFunc.bstrVal) {
        int dfl = MSVCRT$_wtoi(varDomainFunc.bstrVal);
        LPCWSTR dflStr =
            dfl == 0 ? L"2000" :
            dfl == 1 ? L"2003" :
            dfl == 2 ? L"2003 Interim" :
            dfl == 3 ? L"2008" :
            dfl == 4 ? L"2008 R2" :
            dfl == 5 ? L"2012" :
            dfl == 6 ? L"2012 R2" :
            dfl == 7 ? L"2016+" : L"Unknown";
        BeaconPrintToStreamW(L"  Domain FL   : Windows Server %ls (level %d)\n", dflStr, dfl);
    }
    BeaconPrintToStreamW(L"\n");

    OLEAUT32$VariantClear(&varDomainDN);
    OLEAUT32$VariantClear(&varConfigDN);
    OLEAUT32$VariantClear(&varDnsHost);
    OLEAUT32$VariantClear(&varDomainFunc);

    // --- Open primary domain search context ---
    hr = OpenSearch(wcPath, &pDomainSearch, ADsOpenObject);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[adPEAS] Cannot open domain LDAP context: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // ====================================================
    // [1] Domain Controllers
    // ====================================================
    BeaconPrintToStreamW(L"[1] Domain Controllers\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    lpwAttrs[0] = L"cn";
    lpwAttrs[1] = L"dNSHostName";
    lpwAttrs[2] = L"operatingSystem";
    lpwAttrs[3] = L"operatingSystemVersion";
    lpwAttrs[4] = L"whenCreated";
    iFound = RunQuery(pDomainSearch,
        L"(primaryGroupID=516)",
        lpwAttrs, 5, 0, FreeADsMem);
    if (iFound == 0) BeaconPrintToStreamW(L"  None found.\n");
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [2] krbtgt Account (password age indicator)
    // ====================================================
    BeaconPrintToStreamW(L"[2] krbtgt Account\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    BeaconPrintToStreamW(L"  Note: Old pwdLastSet may indicate no recent domain security events.\n");
    lpwAttrs[0] = L"sAMAccountName";
    lpwAttrs[1] = L"pwdLastSet";
    lpwAttrs[2] = L"description";
    lpwAttrs[3] = L"userAccountControl";
    iFound = RunQuery(pDomainSearch,
        L"(samAccountName=krbtgt)",
        lpwAttrs, 4, 1, FreeADsMem);
    if (iFound == 0) BeaconPrintToStreamW(L"  Not found (unexpected).\n");
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [3] Default Password Policy
    // ====================================================
    BeaconPrintToStreamW(L"[3] Default Password Policy\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    lpwAttrs[0] = L"minPwdLength";
    lpwAttrs[1] = L"pwdHistoryLength";
    lpwAttrs[2] = L"maxPwdAge";
    lpwAttrs[3] = L"minPwdAge";
    lpwAttrs[4] = L"pwdProperties";
    lpwAttrs[5] = L"lockoutThreshold";
    lpwAttrs[6] = L"lockoutDuration";
    lpwAttrs[7] = L"lockOutObservationWindow";
    iFound = RunQuery(pDomainSearch,
        L"(objectClass=domain)",
        lpwAttrs, 8, 1, FreeADsMem);
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [4] Fine-Grained Password Policies (FGPP/PSO)
    // ====================================================
    BeaconPrintToStreamW(L"[4] Fine-Grained Password Policies (FGPP)\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    {
        WCHAR wcFGPPPath[PATH_BUF] = { 0 };
        if (bHasServer) {
            MSVCRT$swprintf_s(wcFGPPPath, PATH_BUF,
                L"LDAP://%ls/CN=Password Settings Container,CN=System,%ls",
                lpwServer, wcDomainDN);
        } else {
            MSVCRT$swprintf_s(wcFGPPPath, PATH_BUF,
                L"LDAP://CN=Password Settings Container,CN=System,%ls", wcDomainDN);
        }

        hr = OpenSearch(wcFGPPPath, &pTempSearch, ADsOpenObject);
        if (SUCCEEDED(hr) && pTempSearch != NULL) {
            lpwAttrs[0] = L"name";
            lpwAttrs[1] = L"msDS-PasswordSettingsPrecedence";
            lpwAttrs[2] = L"msDS-MinimumPasswordLength";
            lpwAttrs[3] = L"msDS-PasswordComplexityEnabled";
            lpwAttrs[4] = L"msDS-PasswordReversibleEncryptionEnabled";
            lpwAttrs[5] = L"msDS-LockoutThreshold";
            lpwAttrs[6] = L"msDS-PSOAppliesTo";
            iFound = RunQuery(pTempSearch,
                L"(objectClass=msDS-PasswordSettings)",
                lpwAttrs, 7, 0, FreeADsMem);
            if (iFound == 0) BeaconPrintToStreamW(L"  No Fine-Grained Password Policies configured.\n");
            else             BeaconPrintToStreamW(L"  [!] %d FGPP polic%ls found.\n", iFound, iFound == 1 ? L"y" : L"ies");
            pTempSearch->lpVtbl->Release(pTempSearch);
            pTempSearch = NULL;
        } else {
            BeaconPrintToStreamW(L"  No Fine-Grained Password Policies (container not found or DFL < 2008).\n");
        }
    }
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [5] Domain Trusts
    // ====================================================
    BeaconPrintToStreamW(L"[5] Domain Trusts\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    lpwAttrs[0] = L"name";
    lpwAttrs[1] = L"flatName";
    lpwAttrs[2] = L"trustDirection";
    lpwAttrs[3] = L"trustType";
    lpwAttrs[4] = L"trustAttributes";
    lpwAttrs[5] = L"securityIdentifier";
    iFound = RunQuery(pDomainSearch,
        L"(objectClass=trustedDomain)",
        lpwAttrs, 6, 0, FreeADsMem);
    if (iFound == 0) BeaconPrintToStreamW(L"  No domain trusts found.\n");
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [6] AS-REP Roastable Accounts
    // ====================================================
    BeaconPrintToStreamW(L"[6] AS-REP Roastable Accounts (DONT_REQ_PREAUTH, enabled)\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    lpwAttrs[0] = L"sAMAccountName";
    lpwAttrs[1] = L"description";
    lpwAttrs[2] = L"pwdLastSet";
    lpwAttrs[3] = L"memberOf";
    iFound = RunQuery(pDomainSearch,
        L"(&(objectCategory=person)(objectClass=user)"
        L"(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
        L"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        lpwAttrs, 4, 0, FreeADsMem);
    if (iFound == 0) BeaconPrintToStreamW(L"  None found. [+]\n");
    else             BeaconPrintToStreamW(L"  [!] %d account(s) - AS-REP hashes can be captured without credentials!\n", iFound);
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [7] Kerberoastable Accounts
    // ====================================================
    BeaconPrintToStreamW(L"[7] Kerberoastable Accounts (SPN set, enabled, not krbtgt)\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    lpwAttrs[0] = L"sAMAccountName";
    lpwAttrs[1] = L"servicePrincipalName";
    lpwAttrs[2] = L"pwdLastSet";
    lpwAttrs[3] = L"description";
    iFound = RunQuery(pDomainSearch,
        L"(&(objectCategory=person)(objectClass=user)"
        L"(servicePrincipalName=*)"
        L"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        L"(!(samAccountName=krbtgt)))",
        lpwAttrs, 4, 0, FreeADsMem);
    if (iFound == 0) BeaconPrintToStreamW(L"  None found. [+]\n");
    else             BeaconPrintToStreamW(L"  [!] %d account(s) - Request TGS tickets and crack offline!\n", iFound);
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [8] Unconstrained Delegation (excluding DCs)
    // ====================================================
    BeaconPrintToStreamW(L"[8] Unconstrained Delegation (non-DC accounts)\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    lpwAttrs[0] = L"sAMAccountName";
    lpwAttrs[1] = L"cn";
    lpwAttrs[2] = L"objectClass";
    lpwAttrs[3] = L"operatingSystem";
    lpwAttrs[4] = L"description";
    iFound = RunQuery(pDomainSearch,
        L"(&"
        L"(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        L"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        L"(!(primaryGroupID=516)))",
        lpwAttrs, 5, 0, FreeADsMem);
    if (iFound == 0) BeaconPrintToStreamW(L"  None found. [+]\n");
    else             BeaconPrintToStreamW(L"  [!] %d account(s) - Printer bug / coerce to capture TGTs!\n", iFound);
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [9] Constrained Delegation
    // ====================================================
    BeaconPrintToStreamW(L"[9] Constrained Delegation (msDS-AllowedToDelegateTo)\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    lpwAttrs[0] = L"sAMAccountName";
    lpwAttrs[1] = L"cn";
    lpwAttrs[2] = L"msDS-AllowedToDelegateTo";
    lpwAttrs[3] = L"userAccountControl";
    iFound = RunQuery(pDomainSearch,
        L"(&"
        L"(msDS-AllowedToDelegateTo=*)"
        L"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        lpwAttrs, 4, 0, FreeADsMem);
    if (iFound == 0) BeaconPrintToStreamW(L"  None found.\n");
    else             BeaconPrintToStreamW(L"  [!] %d account(s) - Check for TRUSTED_TO_AUTH_FOR_DELEGATION (S4U abuse)!\n", iFound);
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [10] Resource-Based Constrained Delegation (RBCD)
    // ====================================================
    BeaconPrintToStreamW(L"[10] Resource-Based Constrained Delegation (RBCD)\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    lpwAttrs[0] = L"sAMAccountName";
    lpwAttrs[1] = L"cn";
    lpwAttrs[2] = L"msDS-AllowedToActOnBehalfOfOtherIdentity";
    iFound = RunQuery(pDomainSearch,
        L"(&"
        L"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
        L"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        lpwAttrs, 3, 0, FreeADsMem);
    if (iFound == 0) BeaconPrintToStreamW(L"  None found.\n");
    else             BeaconPrintToStreamW(L"  [!] %d account(s) with RBCD configured!\n", iFound);
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [11] Privileged Group Members
    // ====================================================
    BeaconPrintToStreamW(L"[11] Privileged Group Members\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    lpwAttrs[0] = L"sAMAccountName";
    lpwAttrs[1] = L"member";
    lpwAttrs[2] = L"description";
    iFound = RunQuery(pDomainSearch,
        L"(&(objectClass=group)"
        L"(|(sAMAccountName=Domain Admins)"
        L"  (sAMAccountName=Enterprise Admins)"
        L"  (sAMAccountName=Schema Admins)"
        L"  (sAMAccountName=Administrators)"
        L"  (sAMAccountName=Account Operators)"
        L"  (sAMAccountName=Backup Operators)"
        L"  (sAMAccountName=Server Operators)"
        L"  (sAMAccountName=Print Operators)"
        L"  (sAMAccountName=Group Policy Creator Owners)"
        L"  (sAMAccountName=DnsAdmins)))",
        lpwAttrs, 3, 0, FreeADsMem);
    if (iFound == 0) BeaconPrintToStreamW(L"  No privileged groups found (unexpected).\n");
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [12] Accounts with Possible Password in Description
    // ====================================================
    BeaconPrintToStreamW(L"[12] Accounts with Possible Password in Description\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    lpwAttrs[0] = L"sAMAccountName";
    lpwAttrs[1] = L"description";
    iFound = RunQuery(pDomainSearch,
        L"(&(objectCategory=person)(objectClass=user)"
        L"(description=*)"
        L"(|(description=*pass*)(description=*pwd*)(description=*cred*)(description=*secret*))"
        L"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        lpwAttrs, 2, 0, FreeADsMem);
    if (iFound == 0) BeaconPrintToStreamW(L"  None found. [+]\n");
    else             BeaconPrintToStreamW(L"  [!] %d account(s) - Review descriptions for cleartext credentials!\n", iFound);
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // [13] ADCS Enrollment Services (Certificate Authorities)
    // ====================================================
    BeaconPrintToStreamW(L"[13] ADCS Enrollment Services\n");
    BeaconPrintToStreamW(L"------------------------------------------------------------\n");
    if (wcConfigDN[0]) {
        WCHAR wcAdcsPath[PATH_BUF] = { 0 };
        if (bHasServer) {
            MSVCRT$swprintf_s(wcAdcsPath, PATH_BUF,
                L"LDAP://%ls/CN=Enrollment Services,CN=Public Key Services,CN=Services,%ls",
                lpwServer, wcConfigDN);
        } else {
            MSVCRT$swprintf_s(wcAdcsPath, PATH_BUF,
                L"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,%ls",
                wcConfigDN);
        }

        hr = OpenSearch(wcAdcsPath, &pTempSearch, ADsOpenObject);
        if (SUCCEEDED(hr) && pTempSearch != NULL) {
            lpwAttrs[0] = L"cn";
            lpwAttrs[1] = L"dNSHostName";
            lpwAttrs[2] = L"certificateTemplates";
            lpwAttrs[3] = L"whenCreated";
            iFound = RunQuery(pTempSearch,
                L"(objectClass=pKIEnrollmentService)",
                lpwAttrs, 4, 0, FreeADsMem);
            if (iFound == 0) BeaconPrintToStreamW(L"  No Certificate Authorities found (ADCS not installed).\n");
            else             BeaconPrintToStreamW(L"  [!] %d CA(s) found - enumerate templates for ESC vulnerabilities!\n", iFound);
            pTempSearch->lpVtbl->Release(pTempSearch);
            pTempSearch = NULL;
        } else {
            BeaconPrintToStreamW(L"  ADCS container not accessible (ADCS likely not installed).\n");
        }
    } else {
        BeaconPrintToStreamW(L"  Configuration naming context unavailable.\n");
    }
    BeaconPrintToStreamW(L"\n");

    // ====================================================
    // FOOTER
    // ====================================================
    BeaconPrintToStreamW(L"================================================================================\n");
    BeaconPrintToStreamW(L"  adPEAS BOF - Enumeration Complete\n");
    BeaconPrintToStreamW(L"================================================================================\n");

Cleanup:
    if (pRootDSE)      { pRootDSE->lpVtbl->Release(pRootDSE);           pRootDSE = NULL;      }
    if (pDomainSearch) { pDomainSearch->lpVtbl->Release(pDomainSearch);  pDomainSearch = NULL; }
    if (pTempSearch)   { pTempSearch->lpVtbl->Release(pTempSearch);      pTempSearch = NULL;   }
    OLE32$CoUninitialize();
    BeaconOutputStreamW();
}
