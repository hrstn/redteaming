# Capture-BOF — in-process input capture

Clipboard watch + keystroke capture from inside the beacon process. No global
hooks (`SetWindowsHookEx` is never called), no cross-process access, no file
drops — one worker thread in the beacon process, output returned in the task
result.

## Commands

| Command | What | Notes |
|---|---|---|
| `clipmon -secs 60` / `clipmon -secs 0` | poll OpenClipboard/`CF_TEXT` every 500 ms, dedupe by content signature | `0` stops a running window and flushes |
| `keylog -secs 60` / `keylog -secs 0` | poll `GetAsyncKeyState` over the VK range, decode via `ToUnicode` against the current layout | `0` stops + flushes; idle gaps get a `[tick]` marker |

Both default to a 60-second window. State (buffers, stop flags) lives in the
resident BOF section — the sync-slot module-stomped pool keeps statics across
calls, so stop-by-`0` works within the same beacon (a *reloaded* slot reports
"no active capture" — expected).

## OPSEC notes

- **No hooks**: no `WH_KEYBOARD`, no `SetClipboardViewer`, no
  `AddClipboardFormatListener`, no window chain — polling only.
- **Own process only**: `CreateThread` in the beacon process; nothing remote.
- Behavioural note: long-running `GetAsyncKeyState` loop is itself a known
  keylogger pattern some detections watch — keep `keylog` windows short and
  prefer `clipmon` when clipboard content answers the question.
- No telemetry events beyond the beacon's own thread creation (Sysmon 8 does
  not apply — the thread is local; Sysmon 1 never fires — no child processes).
- Output arrives at the operator via the normal BOF result channel; nothing is
  written to target disk. Thread-side `BeaconOutput` is lock-safe on the NaX
  beacon (`src/Bof/Api.c` — output routes under lock for async BOFs); on other
  kit beacons it uses the standard post-ex path — verify in the lab before
  long-running captures there.

## Pairing with persistence

`clipmon`/`keylog` are session-local. A `wmi-sub`/`task-create` entry that runs
them needs a beacon to reach the output — they only make sense paired with an
interactive session, not unattended persistence. The Persistence-BOF README's
"pair install with clear" rule applies doubly here: don't leave a task entry
that spawns a capture with no operator to receive it.

## Build

```bash
cd Extension-Kit/Capture-BOF && make   # -> _bin/*.x64.o + *.x86.o (stripped)
```

Requires `x86_64-w64-mingw32-gcc` / `i686-w64-mingw32-gcc`. Load via
`Extension-Kit/extension-kit.axs` (registers `clipmon` and `keylog`).