# NoNameAx (NaX) 

THIS IS PORT OF [https://github.com/MaorSabag/NaX/](https://github.com/MaorSabag/NaX) full credits to MaorSabag

## Evasion (P1–P11)

Layered in-memory evasion hardening on top of the base beacon, validated against
Win11 26200 + Cloud Defender (latest). Each layer is independent and degrades
gracefully (falls back to the non-evasive path on any resolution/runtime failure,
never crashes the beacon). See `wiki/SelfTaught-Course-Gap-Analysis.md` for the
full review that drove P5–P11.

- **P1 — Indirect syscalls** ✅ *live-validated 2026-07-24.* HellsGate/HalosGate SSN
  extraction + a Tartarus in-ntdll `syscall;ret` gadget; the 12 direct `Nt*` calls
  execute `syscall` inside ntdll. `src_beacon/asm/Syscall.x64.asm` (raw-byte stubs),
  `src_beacon/include/Syscall.h`, `src_beacon/src/Core/Syscall.c`. Default follows
  the selected build lane (`NAX_LANE`): elastic = direct ntdll stubs
  (`NAX_INDIRECT_SYSCALLS=0`), defender = indirect stubs (`NAX_INDIRECT_SYSCALLS=1`).
  *P8 addition:* secondary SSN validation (`stub[6]==0 && stub[7]==0`) — defeats
  partially-clobbered SSN reads (e.g. `E9` displacement collisions); boot-time
  hooked-stub tally in the debug log (operator intel: which SSNs an EDR hooked).
- **P2 — Encrypted sleepmask** ✅ *live-validated 2026-07-24.* XOR-encrypts the
  beacon `.text` across each sleep with an XOR key held on the sleepmask BOF's
  stack, decrypts on wake; `ActiveJobCount`/`SleepObf` guarded.
  `src_sleepmask/src/main.c`.
  *P6 addition:* the per-sleep key is obfuscated on the stack across the wait with
  a wait-recomputable seed (`BeaconBase ^ SpoofCount`) — a stack dump alone can no
  longer decrypt the masked spans offline.
- **P3 — AMSI/ETW patch** ✅ `src_beacon/src/Core/Patch.c`. Lane-gated
  (`NAX_LANE=defender` → on; `elastic` → off, override with `NAX_ETW_PATCH=1`):
  `ntdll!EtwEventWrite` + `NtTraceEvent` → `33 C0 C3`, `amsi.dll!AmsiScanBuffer`
  → `31 C0 C3` (only when amsi is already loaded — never self-LoadLibrary'd).
  Protects via the stub-routed `NtProtectVirtualMemory`; every step fails soft.
  Kernel ETW-TI remains out of scope for userland patches (see wiki note).
- **P4 — Stack / return-address spoofing** ✅ *shipped, on by default.* Spoofs
  the sleepmask's on-stack return address with an image-backed ntdll address for
  the duration of each sleep-cycle `VirtualProtect` syscall (the
  `SpoofedVirtualProtect` trampoline in `src_sleepmask/src/main.c`), so
  thread-call-stack heuristics (`call_stack_contains_unbacked`) and
  return-address provenance checks see only legitimate frames. Default-on
  (`NAX_SPOOF_STACK ?= 1`); wired in `src_beacon/src/Commands/Sleepmask.c` and
  `src_beacon/include/Gate.h`.
- **P5 — Full-wait stack spoof** ✅ `SpoofWait` trampoline (`src_sleepmask`):
  the same RBP-chain rewrite applied across the WHOLE `NtWaitForSingleObject`
  window, not only the VP syscalls — periodic stack sweeps of the sleeping thread
  see only image-backed ntdll frames for the full dwell window. Saved real return
  addresses are stored XOR'd with the ntdll base (no beacon addresses at rest on
  the thread stack while sleeping). Gated by `NAX_SM_WAIT_SPOOF` (default on;
  no effect when SpoofReady==0, i.e. the defender lane) + `SpoofCount` diagnostic.
- **P6 — Private-heap masking** ✅ sleepmask masks all busy blocks of the
  beacon-owned private heap (`RtlLockHeap` + `RtlWalkHeap`; the lock is held
  across the wait for a deterministic wake unmask) with the same per-sleep key.
  Task buffers, results, tunnel state and strings no longer sit plaintext
  during dwell. Heap masking runs after the code-span mask and unmasking runs
  last on wake (threads blocked on the heap lock resume only into fully
  restored memory).
- **P10 — Load-time call-stack hygiene** ✅ `NaxTpLoadLibraryW`
  (`src_beacon/src/Core/Bootstrap.c`): winhttp loads via a TpWork callback that
  JMPs to a `call r10; ret` call-gadget in dsdmo.dll (LibTPLoadLib pattern) —
  defeats BOTH the "network module from unbacked memory" and the "library loaded
  via a callback function" call-stack rule signatures. Falls back to plain
  LoadLibraryW on any miss (gadget absent, TP APIs unresolved). The callback is
  CFG-whitelisted in its enclosing module via NtQueryVirtualMemory.
- **P11 — Encrypt-sleep threshold** ✅ `NAX_SM_MIN_SLEEP_MS` (default 1000,
  the FOLIAGE >=1s gate): sleeps below the threshold skip the P2 mask/protect
  cycle — short jitter sleeps stop burning VirtualProtect churn that correlates
  with beaconing without buying scanner evasion. Operator-tunable at build and
  at runtime via `sleepobf-config {sleep_obf} [min_ms]` (older agents ignore
  the extra argument).

> Note on Cloud Defender: Defender uses kernel ETW-TI + AMSI, not userland ntdll
> prologue hooks, so HellsGate reads every SSN directly
> (HalosGate is robustness for EDRs that *do* hook). Indirect syscalls alone do
> not defeat kernel ETW-TI — that is the P3 concern (userland half only).

## Post-ex injections (BOFs)

New BOF tools under `C2-Tool-Collection/BOF-Sources/` (run via the beacon's BOF
command or any COFF loader):

- `ThreadlessInject/` — hook a target function in a remote process so an
  existing thread executes the payload: zero thread-creation telemetry
  (`PsSetCreateThreadNotifyRoutine` + ETW ThreadStart silent).
- `PoolPartyV7/` — TP_DIRECT injection via `NtSetIoCompletionEx`: threadless,
  no queue surgery, legitimate call stack (TppDirectpExecuteCallback frame).
