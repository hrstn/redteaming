# ThreadlessInject BOF

Hooks a function in a remote process so an EXISTING thread executes the
payload on its next call. No thread creation - no
`PsSetCreateThreadNotifyRoutine` events, no ETW `ThreadStart` telemetry, no
`CreateRemoteThread`. (Based on CCob's ThreadlessInject; see
NaX/wiki/SelfTaught-Course-Gap-Analysis.md.)

## Build

```bash
cd SOURCE && make
```

Output: `threadlessinject.x64.o`

## Usage

Agent console (NaX beacon BOF command), CS inline-execute format:

    threadlessinject <pid> <target_dll> <target_function> [payload bin]

- payload = x64 shellcode; must be one-shot: spawn worker threads and return
  fast (a blocking payload permanently hijacks the triggering thread).
- System-DLL targets (ntdll/kernel32/kernelbase/user32) resolve locally
  (shared per-boot ASLR == remote base). Cleanup: write the printed 14 saved
  prologue bytes back onto the export.

## OPSEC notes

- Remote allocation is RW -> written -> RX (never RWX at rest).
- The hook install is a transient RWX on 14 bytes of the export page,
  restored immediately (the unavoidable window; seconds, not minutes).
- pe-sieve/HookShark-style inline-hook scans see the 14-byte drift on the
  DLL page - this is the technique's known surface (detect after the fact);
  self-restore of the export kills the artifact after execution.
