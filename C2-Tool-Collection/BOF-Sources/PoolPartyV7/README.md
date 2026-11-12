# PoolParty V7 BOF (TP_DIRECT)

Threadless injection via the target's threadpool IOCP fast path: a
completion packet whose key is a remote `TP_DIRECT{Callback = shellcode}`
is posted with `NtSetIoCompletionEx`. The next pool dispatch runs
`TppDirectpExecuteCallback` -> shellcode, on a thread that already existed
(zero thread-creation telemetry, fully legitimate call stack). Variant 7 is
the structurally simplest of the PoolParty set: no TP_POOL/queue LIST_ENTRY
surgery, no build-offset assumptions.

## Build

```bash
cd SOURCE && make
```

Output: `poolpartyv7.x64.o`

## Usage

    poolpartyv7 <pid> [payload bin]

- payload = x64 shellcode.
- Works only where the target process owns a default threadpool IOCP
  (svchost instances, most services, GUI processes with threadpool work).
- Type-index discovery is hangless (SystemHandleInformation vs
  SystemHandleExtendedInformation count-diff; the differing types are
  IoCompletion + TpWorkerFactory). The pool IOCP is disambiguated by
  scanning each TpWorkerFactory's basic information for the IOCP kernel
  object pointer; falls back to the first IoCompletion handle.
- Cross-check on your target build first (sandbox) - variant validated by
  the SafeBreach 2023 research (100% EDR bypass at the time), re-verify
  against current sensors.

## OPSEC notes

- Shellcode region RW -> RX; TP_DIRECT stays RW (never executed).
- Cross-process `NtSetIoCompletion(Ex)` posting is the technique's
  detection vector (rare legitimately); kernel ETW-TI can correlate it
  with the preceding alloc/write.
