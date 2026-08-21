# Cenotaph — EDR-fit disk host for the NaX beacon

> **Full reference:** [`docs/Cenotaph.md`](docs/Cenotaph.md) — architecture,
> threat model, module reference, audit, live-test plan, troubleshooting.
> This README is the quickstart.

Cenotaph is a small (~4 KB) native x64 Windows PE that launches the NaX fork's
packed beacon (`nax.x64.bin`) from disk in a way that survives an **Elastic
Defend**-graded environment. It is a stealthy drop-in replacement for NaX's
dev `stomper.exe` / `loader.c`, which allocates RWX and `CreateThread`s at a
private start address — the one unstealthy thing the dev launcher does.

Cenotaph does **no** module-stomping and **no** beacon work itself. It:

1. PEB-walks every functional API via compile-time FNV1a hashes (zero API-name
   strings in the binary).
2. Runs a silent anti-sandbox check (`NtQuerySystemInformation` CPU count +
   `GetTickCount` uptime).
3. Reads the packed blob from a sibling `<exe-stem>.dat` file with mundane
   `CreateFileW`/`ReadFile`.
4. Allocates the buffer **RW** via `NtAllocateVirtualMemory`, reads into it,
   then flips it **RX** (`NtProtectVirtualMemory`) — never RWX.
5. Hands execution to the **Stardust loader's `Start`** (offset 0 of
   `nax.x64.bin`) via the thread pool (`TpAllocWork`/`TpPostWork`/
   `TpReleaseWork`), so the worker thread's start address is
   `ntdll!TppWorkerThread`, not a private allocation.
6. `Sleep(INFINITE)`s on the main thread while the beacon runs on the pool.

Stardust then module-stomps the beacon into `chakra.dll` (image-backed `.text`)
and runs it on its own pool thread — the production NaX path, unchanged.

---

## Why this design (and not the original proposal)

Cenotaph was specified in a design doc that proposed, for an **Elastic** target:
raw/direct `syscall` instructions, an `ntfs.sys` IRP walk, NTFS alternate-data-
stream reads, `NtCreateSection` chunked allocation, a PE-header `ImageBase` jump
trick, a custom RWX `.bss` via yasm, and UPX packing. **Every one of those is
wrong for Elastic.** This section records why, so the choices are auditable.

Elastic Defend (the CRTL/OSAI lane EDR) is **not** a userland-`ntdll`-hook EDR.
It feeds on **kernel ETW-Threat-Intelligence** plus image/behavior analytics.
That inverts the usual evasion playbook:

| Proposed technique | Verdict vs Elastic | Why |
|---|---|---|
| Direct / raw `syscall` insn | **Rejected** | Elastic keys on the `syscall` RIP being outside `ntdll` → `image_indirect_call` fires rule `e7d63d66` (kill process). Indirect syscalls only bypass *userland* hooks, which Elastic doesn't use. Pure downside. Use ntdll's **own wrappers** (PEB-walked `Nt*` stubs). |
| AMSI / ETW patch in-process | **Rejected** | Patches trip rule `3046168a`, and patching userland `EtwEventWrite` does **not** blind kernel ETW-TI. No benefit, active cost. |
| `ntfs.sys` IRP walk / `NtCreateSection` / ADS reads | **Rejected** | Noisy kernel-surface primitives with zero payoff over a mundane userland file read. `CreateFileW`+`ReadFile` (PEB-walked) is invisible. |
| PE-header `ImageBase` jump trick | **Rejected** | Gimmick with no Elastic-relevant signal; adds fragility. |
| Custom RWX `.bss` via yasm | **Rejected** | Violates RW→RX memory discipline. RWX page transitions are themselves a signal. |
| UPX packing | **Rejected** | High-entropy section + known unpacker stub = a signature/entropy beacon, and it breaks the mundane-IAT story. |

**Net:** Cenotaph is smaller, simpler, and more Elastic-fit than the proposal —
because most of the proposal was actively harmful against this EDR. The only
"evasion" Cenotaph needs is the architectural evasion NaX already provides
(module-stomping into image memory, `TppWorkerThread` start address, FNV1a PEB
walk) plus a boring IAT. Source of truth for these verdicts: the fork's
`stealthy-agentbuilder` LESSONS.md, "CRTL lane — Elastic Security fitness audit."

---

## Repository layout

```
Cenotaph/
├── include/
│   ├── Cenotaph.h      types, hash constants, full x64 PEB/LDR structs, INSTANCE
│   └── Constexpr.h     compile-time FNV1a (HASH_STR -> immediate, no name strings)
├── src/
│   ├── Ldr.c           PEB walk + export-table resolution (adapted from NaX)
│   ├── Utils.c         FNV1a-32 HashString (verbatim NaX logic — load-bearing)
│   └── Host.c          entry: resolve → sandbox → read → RW→RX → thread-pool hand-off
├── tools/
│   └── hash.py         FNV1a verifier (reproduces every constant Cenotaph uses)
└── Makefile            mingw cross-build + `make audit`
```

---

## Build

Cross-compiled on Linux with mingw-w64 (`x86_64-w64-mingw32-g++`).

```
make            # cenotaph.exe       (release, windows subsystem, stripped, ~4 KB)
make debug      # cenotaph-debug.exe (console subsystem, sandbox check disabled)
make audit      # strings + IAT + undefined-symbol + entry-point checks
make clean
```

No CRT is linked (`-nostdlib`, explicit entry `CenotaphEntry`). The only linked
import lib is **kernel32**, for two/three mundane IAT imports (`GetTickCount`,
`Sleep`, `CloseHandle`). Every functional API is resolved at runtime via the PEB
walk — there are no API-name strings in the binary.

### Audit gates (`make audit`)

1. **API-name string scan** — `strings | grep -iE 'NtAllocate|NtProtect|…'` must
   be **empty** (all APIs are FNV1a hashes).
2. **IAT** — only `{ CloseHandle, GetTickCount, Sleep }`.
3. **Undefined symbols** — `nm -u` empty (no CRT, no bare libc).
4. **Entry-point disasm** — FNV1a hashes appear as **immediates**
   (`0x318a7963` ntdll, `0x04a1a06a` kernel32, `0xd58d5a18`
   `NtAllocateVirtualMemory`, `0x626981af` `TpAllocWork`, …); `gs:0x60` PEB read
   in `LdrModulePeb`; `TpAllocWork`/`TpPostWork`/`TpReleaseWork` + `Sleep(INFINITE)`
   tail. `tools/hash.py` reproduces every constant.

---

## Deploy / use

1. Build `cenotaph.exe` and produce `nax.x64.bin` from the NaX fork
   (`$NAX` build → `pack_nax.py`).
2. On target, rename the pair to a bland combination, e.g.
   `MicrosoftEdgeUpdate.exe` + `MicrosoftEdgeUpdate.dat`. Place
   `nax.x64.bin` as the `.dat` (Cenotaph derives the path from its own module
   filename: `<exe-dir>\<exe-stem>.dat`).
3. Run the exe. Sandbox check → read blob → RX → thread-pool hand-off → Stardust
   stomps the beacon into `chakra.dll` → beacon heartbeats from image-backed
   memory.

The beacon's AES key / URL / profile are baked into `nax.x64.bin` by the NaX
build; Cenotaph only launches it. Generate the beacon payload from the current
Adaptix listener so the baked key matches the listener's `encrypt_key`.

---

## Notes & limits

- **Live run under Elastic Defend is pending.** The build is audit-clean and
  disasm-verified, not yet executed on the OSAI/CRTL Win11 box. TODO: confirm
  no `e7d63d66` / `3046168a` and that the beacon heartbeats with a
  `TppWorkerThread` worker start address.
- Cenotaph is a normal PE (not PIC shellcode), so it keeps a file-scope
  `CEN_INSTANCE g_Inst` in `.bss` — no TLS egghunter, no PIC constraints. The
  beacon itself stays PIC; only the host is a normal PE.
- The `___chkstk_ms` no-op stub is a safety net for `CenotaphEntry`'s ~4.3 KB
  stack frame (`WCHAR path[1100]`); safe on a 1 MB stack. Can be retired by
  shrinking the path buffer below one page.
- FNV1a `HashString` in `Utils.c` is copied **byte-for-byte** from NaX. The
  `if(!*Ptr) ++Ptr;` (no `continue`) + `U_PTR(U_PTR(Ptr)-U_PTR(String))` tail is
  load-bearing — a "cleaner" rewrite produces wrong hashes. Do not tidy it.