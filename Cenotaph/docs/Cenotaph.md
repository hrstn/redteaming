# Cenotaph — Tool Documentation

> EDR-fit disk host / launcher for the NaX fork's packed beacon (`nax.x64.bin`).
> Built for **Elastic Defend** (kernel ETW-TI feed).
>
> **Status:** BUILD-GREEN, audit-clean, disasm-verified. Live validation under
> Elastic Defend: pending (see §10).

---

## 1. Overview

Cenotaph is a small (~4 KB) native x64 Windows PE that launches the NaX fork's
packed beacon from disk. It is a stealthy launcher: it performs no
module-stomping and no beacon work itself. It reads the packed blob from a
sibling file, maps it RX, and hands execution to the **Stardust loader's
`Start`** (offset 0 of `nax.x64.bin`) on a thread-pool worker. Stardust then
module-stomps the beacon into `chakra.dll` (image-backed `.text`) and runs it
on its own pool thread — the production NaX path.

```
Cenotaph.exe
  │  1. PEB-walk every functional API via compile-time FNV1a hashes (no name strings)
  │  2. Silent anti-sandbox check (NtQuerySystemInformation CPU + GetTickCount uptime)
  │  3. Read packed blob from sibling <exe-stem>.dat  (CreateFileW / ReadFile, PEB-walked)
  │  4. NtAllocateVirtualMemory RW  →  read  →  NtProtectVirtualMemory RX   (never RWX)
  │  5. TpAllocWork(blob=Start)/TpPostWork/TpReleaseWork   (worker start = ntdll!TppWorkerThread)
  │  6. Sleep(INFINITE) on the main thread
  ▼
Stardust loader  (offset 0 of nax.x64.bin)
  │  module-stomps beacon into chakra.dll (image-backed .text)
  ▼
NaX beacon  heartbeats from image-backed memory, on a pool worker thread
```

The beacon's AES key / URL / profile are baked into `nax.x64.bin` by the NaX
build. Cenotaph only launches it.

---

## 2. Design posture

Cenotaph is built for **Elastic Defend**, which feeds on **kernel ETW-
Threat-Intelligence** (ETW-TI) plus image/behavior analytics rather than
userland `ntdll` hooks. Its posture follows from that:

- **APIs resolved by FNV1a PEB walk.** Every functional API is located by
  walking `InLoadOrderModuleList` and matching a compile-time FNV1a-32 hash of
  the export name. The binary carries **no API-name strings**.
- **ntdll syscalls via their own wrappers.** `Nt*` routines are called through
  the PEB-resolved function pointers inside `ntdll` itself, so the `syscall`
  instruction's RIP stays within `ntdll`'s `.text`. No private `syscall`
  instruction and no indirect-syscall gadget are present.
- **No RWX.** The payload buffer is allocated `PAGE_READWRITE`, read into, then
  flipped `PAGE_EXECUTE_READ`. No page is ever writable and executable at once.
- **No AMSI / ETW patching.**
- **In-process execution, thread-pool hand-off.** The beacon runs in-process on
  a pool worker whose start address is `ntdll!TppWorkerThread`, not the private
  RX buffer. No child process is spawned.
- **Mundane IAT.** The only linked import lib is `kernel32`, for three ordinary
  imports (`CloseHandle`, `GetTickCount`, `Sleep`). The import table reads as a
  small utility, and nothing functional appears in it.
- **Image-backed beacon.** Cenotaph does not stomp the beacon itself; Stardust
  does, into `chakra.dll`, so the beacon executes from a loaded image's `.text`.

---

## 3. Repository layout

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
├── docs/
│   └── Cenotaph.md      this file
├── Makefile            mingw cross-build + `make audit`
├── .gitignore
└── README.md           quickstart
```

---

## 4. Build

Cross-compiled on Linux with mingw-w64 (`x86_64-w64-mingw32-g++`).

```
make            # cenotaph.exe        (release, windows subsystem, stripped, ~4 KB)
make debug      # cenotaph-debug.exe  (console subsystem, sandbox check disabled)
make audit      # strings + IAT + undefined-symbol + entry-point checks
make clean
```

No CRT is linked (`-nostdlib`, explicit entry `CenotaphEntry`). The only linked
import lib is **kernel32**, for the mundane IAT imports. Every functional API
is resolved at runtime via the PEB walk.

### 4.1 Prerequisites
- `x86_64-w64-mingw32-g++` (mingw-w64)
- `x86_64-w64-mingw32-strip`, `-objcopy`, `-nm`, `-readelf` (ships with mingw-w64)
- host `binutils` for `strings`

### 4.2 Key flags
| Flag | Purpose |
|---|---|
| `-Os` | small binary |
| `-nostdlib` | no CRT — bare native PE |
| `-lkernel32` | only linked import lib (mundane IAT) |
| `-Wl,-e,CenotaphEntry` | explicit entry (no CRT main) |
| `-fno-exceptions -fno-rtti -fno-ident` | strip C++ runtime baggage / identity |
| `-fno-asynchronous-unwind-tables` | no `.pdata`/`.xdata` bloat in the host |
| `-Wl,-subsystem,windows` (release) | no console window |
| `-Wl,-subsystem,console` (debug) | stdout visible for testing |
| `-fpermissive` | void*↔typed* casts in `Ldr.c` |

C++ (not C) is used so `HASH_STR` evaluates FNV1a at **compile time** via
`constexpr` — the hashes become immediates in the disasm, never strings.

---

## 5. Module reference

### 5.1 `include/Constexpr.h` — compile-time FNV1a
- `HASH_STR("NtAllocateVirtualMemory")` → a `constexpr ULONG` immediate.
- FNV1a-32, case-insensitive (uppercased before hashing), seed `0x811c9dc5`,
  prime `0x01000193` — byte-identical to NaX.

### 5.2 `include/Cenotaph.h` — types & INSTANCE
- `CEN_PEB` / `CEN_PEB_LDR_DATA` / `CEN_LDR_DATA_TABLE_ENTRY` — **full** x64
  layouts (mingw `<winternl.h>` ships only partial structs; `InLoadOrderModuleList`
  / `BaseDllName` are missing). `DllBase` @ +0x30, `BaseDllName` @ +0x58.
- `CenPeb()` via `__readgsqword(0x60)` — no API call to get the PEB.
- `CEN_INSTANCE g_Inst` (`.bss`) — every PEB-walked API pointer + the two module
  bases. Cenotaph is a normal PE, so a file-scope INSTANCE is fine (no TLS
  egghunter, no PIC constraint).
- `PFN_*` typedefs for all resolved APIs. The `Nt*` stubs are documented as
  called through their own ntdll wrappers.
- `CEN_SYS_BASIC` for `NtQuerySystemInformation(SystemBasicInformation)`.

### 5.3 `src/Utils.c` — `HashString` (FNV1a-32)
Byte-for-byte from NaX. The `if(!*Ptr) ++Ptr;` (no `continue`) +
`U_PTR(U_PTR(Ptr)-U_PTR(String))` tail is load-bearing — a "cleaner" rewrite
produces wrong hashes. See §11 / `docs/development.md` before editing this
function.

### 5.4 `src/Ldr.c` — PEB walk + export resolution
- `LdrModulePeb(Hash)` — walk `InLoadOrderModuleList` by FNV1a of
  `BaseDllName.Buffer`/`Length`; return `DllBase`.
- `LdrFunction(Library, Function)` — parse the export directory, match by hash,
  resolve forwarded exports recursively (`LdrpFwdResolve`).
- Adapted from NaX `src_loader/src/Ldr.c` with explicit typed casts.

### 5.5 `src/Host.c` — entry point `CenotaphEntry`
1. `(void) GetTickCount();` — touch the mundane IAT import once (normalizing).
2. `CenResolve()` — PEB-walk all 10 APIs into `g_Inst`; fail-closed if any missing.
3. `CenSandboxOk()` — `NtQuerySystemInformation` (`NumberOfProcessors < 2` → bail)
   + `GetTickCount() < 600000` (boot < 10 min → bail). Fail-closed, silent.
4. `CenBuildPayloadPath()` — `GetModuleFileNameW` → derive `<exe-dir>\<exe-stem>.dat`.
5. `CenReadPayload()` — `CreateFileW`+`GetFileSize`+`NtAllocateVirtualMemory`
   (RW, page-aligned)+`ReadFile`; 8 MB cap; fail-closed.
6. `NtProtectVirtualMemory` → **RX** (whole page-aligned span).
7. `TpAllocWork(callback=blob)` + `TpPostWork` + `TpReleaseWork` → hand off to
   Stardust `Start` (offset 0) on a pool worker (start address `TppWorkerThread`).
   Fallback: direct call on this thread if the pool alloc fails.
8. `Sleep(INFINITE)` — keep the process alive while the beacon runs on the pool.

`___chkstk_ms` is a no-op stub: `CenotaphEntry`'s `WCHAR path[1100]` makes a
~4.3 KB stack frame that trips gcc's stack-probe call; with `-nostdlib` there is
no CRT to provide it. A no-op probe is safe on a 1 MB stack.

---

## 6. Deploy / use

1. **Build Cenotaph:** `make` → `cenotaph.exe`.
2. **Build the beacon:** in the NaX fork (`$NAX`), build → `pack_nax.py` →
   `nax.x64.bin`. Generate the beacon payload **from the current Adaptix
   listener** so the baked AES key matches the listener's `encrypt_key` (§11).
3. **Stage on target:** rename the pair to a bland combination, e.g.
   `MicrosoftEdgeUpdate.exe` + `MicrosoftEdgeUpdate.dat`. Place `nax.x64.bin` as
   the `.dat` (Cenotaph derives the path from its own module filename:
   `<exe-dir>\<exe-stem>.dat`).
4. **Run** the exe. Sandbox check → read blob → RX → thread-pool hand-off →
   Stardust stomps the beacon into `chakra.dll` → beacon heartbeats from
   image-backed memory.

The `.dat` is **never committed** (`.gitignore`); it is staged on the target.

---

## 7. Audit (`make audit`)

Four gates; all must pass before any live run.

1. **API-name string scan — must be EMPTY.**
   `strings -a cenotaph.exe | grep -iE 'NtAllocate|NtProtect|NtQuerySystem|TpAllocWork|TpPostWork|TpReleaseWork|VirtualAlloc|VirtualProtect|LoadLibrary|GetProcAddress|CreateFile|ReadFile|GetModuleFileName|GetFileSize|AmsiScan|EtwEvent'`
   All APIs are FNV1a hashes; a leaked name string is an OPSEC failure.
2. **IAT — only mundane kernel32.** Expected: `{ CloseHandle, GetTickCount, Sleep }`.
3. **Undefined symbols — empty.** `nm -u` must show nothing (no CRT, no bare libc).
4. **Entry-point disasm.** FNV1a hashes appear as **immediates**:
   - `0x318a7963` = ntdll, `0x04a1a06a` = kernel32
   - `0xd58d5a18` `NtAllocateVirtualMemory`, `0x069ff566` `NtProtectVirtualMemory`,
     `0x37072d8a` `NtQuerySystemInformation`, `0x626981af` `TpAllocWork`,
     `0x77d8b8e6` `TpPostWork`, `0x18b7bcaf` `TpReleaseWork`,
     `0x34f76bdb` `GetModuleFileNameW`, …
   - `gs:0x60` PEB read in `LdrModulePeb`; `TpAllocWork`/`TpPostWork`/`TpReleaseWork`
     + `Sleep(INFINITE)` tail.
   - `tools/hash.py` reproduces every constant.

### 7.1 Disassembling the entry point
```
x86_64-w64-mingw32-objdump -d --no-show-raw-insn cenotaph.exe | \
  sed -n '/<CenotaphEntry>:/,/^$/p'
x86_64-w64-mingw32-objdump -d --no-show-raw-insn --start-address=0x140001000 \
  --stop-address=0x140001049 cenotaph.exe   # LdrModulePeb: gs:0x60
```
(Adjust addresses to your build's actual RVAs — read them from `readelf -h` /
`objdump -t`.)

---

## 8. Anti-sandbox

`CenSandboxOk()` (in `src/Host.c`, gated by `CENOTAPH_SANDBOX_CHECK`):
- `NtQuerySystemInformation(SystemBasicInformation)` → `NumberOfProcessors < 2`
  ⇒ bail (likely a single-vCPU sandbox).
- `GetTickCount() < 600000` ⇒ boot was < 10 minutes ago ⇒ bail.
- **Fail-closed and silent**: on any failure (including a bad
  `NtQuerySystemInformation`) the process returns from entry and exits — no
  beacon thread is spawned, no error output.
- `make debug` defines `CENOTAPH_SANDBOX_CHECK=0` to exercise the full path on a
  freshly-booted test VM.

Tunable constants: `CEN_MIN_CPUS` (2), `CEN_MIN_UPTIME_MS` (600000),
`CEN_MAX_PAYLOAD` (8 MB) — at the top of `src/Host.c`.

---

## 9. Security & OPSEC

- **No API name strings** in the binary (audit gate 1).
- **No RWX** — payload is RW then RX.
- **No private `syscall`, no indirect-syscall gadget** — ntdll's own wrappers.
- **No AMSI/ETW patching.**
- **No child process** — beacon runs in-process on a pool worker.
- **Worker start address = `ntdll!TppWorkerThread`**, not a private allocation.
- **Mundane IAT** — three kernel32 imports.
- **Image-backed beacon** — module-stomped into `chakra.dll` by Stardust.
- The `.dat` payload is **not committed** (`.gitignore`).

---

## 10. Live validation under Elastic Defend — test plan (PENDING)

The build is audit-clean and disasm-verified. Before claiming Elastic-fit, run
this on the OSAI/CRTL Win11 box with Elastic Defend enrolled:

1. **Build & audit** on Linux: `make && make audit` (all four gates green).
2. **Stage** `MicrosoftEdgeUpdate.exe` + `MicrosoftEdgeUpdate.dat` (a freshly
   generated `nax.x64.bin` from the current listener).
3. **Run** and observe:
   - No `e7d63d66` alert (image_indirect_call / syscall-outside-ntdll).
   - No `3046168a` alert (AMSI/ETW patch).
   - Beacon heartbeats to the listener (advances past REGISTER into HEARTBEAT — §11).
   - Worker start address of the beacon thread = `ntdll!TppWorkerThread`
     (Process Hacker / `!uniqstack`-style walk), not the private RX buffer.
   - Beacon `.text` is image-backed (stomped into `chakra.dll`), not a private RX
     allocation.
4. **If a detection fires**, capture the rule ID + the behaviour it named and
   append a dated entry to `stealthy-agentbuilder/LESSONS.md` (the skill's
   mandatory self-improvement step).

Pass criteria: no `e7d63d66`/`3046168a`, beacon heartbeats, worker start address
is `TppWorkerThread`.

---

## 11. Troubleshooting

### 11.1 "agent appeared in Adaptix UI but `decrypt failed` / loops on REGISTER"
Server-side key mismatch, not a Cenotaph regression. The beacon's baked AES key
(from the NaX build) must equal the listener's current `encrypt_key`. Recreate
the listener, or regenerate the beacon payload from the current listener, then
rebuild `nax.x64.bin`. Confirm: beacon boot log `aes_key:` == listener
`encrypt_key`, and no `CreateAgent: decrypt FAILED` on the Adaptix server
console. ("callback appeared" alone is not live-validation success.)

### 11.2 Process exits immediately on target
- Sandbox check tripped: `NumberOfProcessors < 2` or uptime < 10 min. Use
  `make debug` (`CENOTAPH_SANDBOX_CHECK=0`) to confirm the full path works, then
  revisit the thresholds in `src/Host.c`. Do not disable the check for
  production; lower `CEN_MIN_CPUS` only if the lab genuinely runs on 1 vCPU.
- Payload path wrong: Cenotaph looks for `<exe-stem>.dat` **next to the exe**.
  Confirm the `.dat` exists, is named exactly `<exe-stem>.dat`, and is readable.
- Payload too large: `> 8 MB` (`CEN_MAX_PAYLOAD`) → rejected. Raise the cap only
  if you packed something other than the beacon.

### 11.3 Link error: `cannot find entry symbol CenotaphEntry`
Entry must be `extern "C"` — C++ mangles it otherwise. Already handled in
`Host.c`; keep `extern "C"` on any new entry.

### 11.4 Link error: `undefined reference to ___chkstk_ms`
A function's frame crossed a page boundary and gcc emitted a stack-probe call.
Keep the `___chkstk_ms` no-op stub (safe for small frames on a 1 MB stack), or
shrink the offending local buffer below one page (e.g. `WCHAR path[1100]` →
`[600]`) so the probe call disappears.

### 11.5 FNV1a hashes don't match after editing `Utils.c`
`HashString` was altered. Revert to the NaX-verbatim version — the
`if(!*Ptr) ++Ptr;` (no `continue`) + `U_PTR(U_PTR(Ptr)-U_PTR(String))` tail is
load-bearing. Verify with `tools/hash.py` (must reproduce `0x318a7963` for
ntdll, `0x04a1a06a` for kernel32). Full background in `docs/development.md`.

### 11.6 `make audit` finds an API-name string
A call was added with a literal name instead of `HASH_STR("…")`. All functional
APIs must be PEB-walked via compile-time hashes. See §12.

---

## 12. Adding a new resolved API

1. Add the `PFN_*` typedef to `include/Cenotaph.h`.
2. Add the pointer field to `CEN_INSTANCE.Api` (+ module to `Mod` if new).
3. In `CenResolve()` (`src/Host.c`): resolve via
   `LdrFunction(g_Inst.Mod.<module>, HASH_STR("<ApiName>"))` and store in `g_Inst`.
4. Add it to the fail-closed null-check at the end of `CenResolve()`.
5. Call it through `g_Inst.Api.<Name>(...)`, never a literal.
6. Add the name to the `make audit` grep list (`Makefile`) as a tripwire.
7. `make && make audit` — name-string scan must stay empty; `tools/hash.py`
   must reproduce the new hash.

---

## 13. Glossary

- **NaX fork** — hardened AdaptixC2 PIC beacon (module-stomping, thread-pool
  exec, FNV1a PEB walk). `$NAX` = its working copy.
- **Stardust loader** — the PIC loader prepended to the beacon; `nax.x64.bin` =
  `[Stardust Start][NaxHeader v2 160B][beacon][.pdata][.xdata]`; offset 0 = `Start`.
- **Module stomping** — writing the beacon over a legit loaded DLL's `.text`
  (here `chakra.dll`) so it executes from image-backed memory.
- **ETW-TI** — kernel ETW Threat Intelligence; Elastic's primary feed.
- **FNV1a-32** — the hash used for API/module resolution; case-insensitive.
- **`TppWorkerThread`** — `ntdll`'s thread-pool worker entry; using it as the
  beacon thread's start address hides the private allocation.

---

## 14. Pointers

- NaX fork wiki: `$NAX/wiki/Stardust-Loader-Guide.md`, `BeaconGate-Sleepmask.md`.
- Hash verifier: `tools/hash.py`.
- Quickstart: `README.md`.
- Design history & rejected alternatives: `docs/development.md` (local only).