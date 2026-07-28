# NoNameAx (NaX) 

THIS IS PORT OF [https://github.com/MaorSabag/NaX/](https://github.com/MaorSabag/NaX) full credits to MaorSabag

## Evasion (P1–P4)

adding; 
Layered in-memory evasion hardening on top of the base beacon, validated against
Win11 26200 + Cloud Defender (latest). Each layer is independent and degrades
gracefully (falls back to the non-evasive path on any resolution/runtime failure,
never crashes the beacon).

- **P1 — Indirect syscalls** ✅ *live-validated 2026-07-24.* HellsGate/HalosGate SSN
  extraction + a Tartarus in-ntdll `syscall;ret` gadget; the 12 direct `Nt*` calls
  execute `syscall` inside ntdll. `src_beacon/asm/Syscall.x64.asm` (raw-byte stubs),
  `src_beacon/include/Syscall.h`, `src_beacon/src/Core/Syscall.c`. On by default
  (`NAX_INDIRECT_SYSCALLS=1`).
- **P2 — Encrypted sleepmask** ✅ *live-validated 2026-07-24.* XOR-encrypts the
  beacon `.text` across each sleep with a per-sleep BCrypt key, decrypts on wake;
  `ActiveJobCount`/`SleepObf` guarded. `src_sleepmask/src/main.c`.
- **P3 — AMSI/ETW patch** ⏳ *next.* Patches `amsi.dll!AmsiScanBuffer` and the
  ETW/ETW-TI write path to return-clean stubs at boot, closing the kernel-ETW-TI
  visibility of P2's `RX↔RW` page-flips and P1's stub-span `VirtualProtect`.
- **P4 — Stack / return-address spoofing** ⏳ *planned.* Spoofed call stacks and
  return addresses during sleep and syscalls so thread-call-stack heuristics and
  return-address provenance checks see only legitimate frames.

> Note on Cloud Defender: Defender uses kernel ETW-TI + AMSI, not userland ntdll
> prologue hooks, so HellsGate reads every SSN directly
> (HalosGate is robustness for EDRs that *do* hook). Indirect syscalls alone do
> not defeat kernel ETW-TI — that is the P3 concern.
