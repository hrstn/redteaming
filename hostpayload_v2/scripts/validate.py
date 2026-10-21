#!/usr/bin/env python3
"""
Static validation for build outputs (canonical, absorbed the
remote_bof_loader/scripts/validate.py checks).

Two modes:

1. Artifact scan (default):   validate.py <file.c|.exe|.bin>
     - signatured AMSI/ETW/PowerShell bypass strings
     - plaintext HTTP staging strings
     - RWX (PAGE_EXECUTE_READWRITE) constant or byte patterns
     - toy-cipher mentions
     - dead family wire tokens (NoNameAx/0.1, X-NaX-Public) that must never
       reappear in any built artifact (W1.1/W1.1b regression markers)
     - .exe: empty import table check (objdump)

2. Memory-snapshot scan (W1.4 harness, runs against a procdump/full-dump of
   the beacon process):    validate.py --snapshot dump.bin --marker <s> ...
     - scans for identity material (C2 URL, UA, custom header names) in
       ASCII and UTF-16LE, plus raw AES key bytes, at sleep boundaries the
       sleepmask should have masked. Clean = exit 0, any hit = exit 1.
     - always-on family markers: NoNameAx, X-NaX-Public, nax.x64
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


SIGNATURES = {
    # dead family wire tokens - build outputs must never carry these again
    "NoNameAx/0.1": "pre-W1.1 static UA",
    "X-NaX-Public": "pre-W1.1 family wire header",
    # AMSI / Script-block logging
    "amsiInitFailed": "AMSI reflection bypass",
    "AmsiUtils": "AMSI type reference",
    "AmsiScanBuffer": "AMSI scan API",
    "AmsiScanString": "AMSI scan API",
    "amsi.dll": "AMSI DLL name",
    # ETW
    "EtwEventWrite": "ETW write API",
    "EtwEventWriteTransfer": "ETW write API",
    "EventWrite": "ETW write API",
    "ntdll!Etw": "ETW ntdll reference",
    # PowerShell / .NET
    "System.Management.Automation": "PowerShell automation namespace",
    "Add-Type": "PowerShell compiled type injection",
    "GetDelegateForFunctionPointer": "PowerShell shellcode execution API",
    "Marshal.Copy": "PowerShell memory copy API",
    "System.Net.WebClient": "PowerShell download client",
    "IEX ": "PowerShell invoke-expression",
    "Invoke-Expression": "PowerShell invoke-expression",
    "PowerShell": "PowerShell mention",
    # Staging / OPSEC
    "github.com": "GitHub API / raw URL reference",
    # RWX / dangerous allocation strings
    "PAGE_EXECUTE_READWRITE": "RWX protection string",
    "0x3000, 0x40": "RWX allocation constant pair",
    "0x40 )": "RWX PAGE_EXECUTE_READWRITE constant",
}

# Regex-based signatures (word boundaries / lookaheads avoid the ROTL32/ROTR32
# bit-rotation helper FPs and allow https:// over http://).
REGEX_SIGNATURES = {
    r"\bROT\b": "Caesar / toy cipher mention",
    r"(?<![sS])http://": "Plaintext HTTP URL",
}

# Byte patterns that commonly represent RWX allocation constants.
RWX_BYTE_PATTERNS = [
    b"\x00\x30\x00\x00\x40\x00\x00\x00",  # 0x3000 0x40 little-endian
    b"\x00\x00\x30\x00\x00\x00\x40\x00",
]


def run_text_scan(text: str) -> list[tuple[str, str]]:
    hits = []
    for pattern, description in SIGNATURES.items():
        if re.search(re.escape(pattern), text, re.IGNORECASE):
            hits.append((pattern, description))
    for pattern, description in REGEX_SIGNATURES.items():
        if re.search(pattern, text, re.IGNORECASE):
            hits.append((pattern, description))
    return hits


def run_binary_scan(path: Path) -> list[tuple[str, str]]:
    data = path.read_bytes()
    text = data.decode("utf-8", errors="ignore")

    hits = run_text_scan(text)

    for pat in RWX_BYTE_PATTERNS:
        if pat in data:
            hits.append((pat.hex(), "RWX allocation byte pattern"))
            break

    return hits


def check_imports_empty(path: Path) -> tuple[bool, str]:
    """Use objdump -p and look for non-empty import table entries."""
    objdump = shutil.which("objdump") or shutil.which("x86_64-w64-mingw32-objdump")
    if not objdump:
        return (True, "objdump not found on PATH - import check skipped")

    try:
        result = subprocess.run(
            [objdump, "-p", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as e:
        return (False, f"objdump failed: {e}")

    in_imports = False
    for line in result.stdout.splitlines():
        if "The Import Tables" in line:
            in_imports = True
            continue
        if in_imports:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("vma:") or re.match(r"^[0-9a-fA-F\s]+$", stripped):
                continue
            if any(c.isalpha() for c in stripped):
                return (False, f"imported symbol/DLL detected: {stripped}")

    return (True, "import table is empty")


# ===== snapshot scan (W1.4) =====

# Family markers that should never be resident in any beacon process.
SNAPSHOT_DEFAULT_MARKERS = ["NoNameAx", "X-NaX-Public", "nax.x64"]


def utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


def scan_snapshot(path: Path, markers: list[str], aeskey_hex: str | None,
                  check_rwx_page: bool) -> list[tuple[str, str, int]]:
    data = path.read_bytes()
    hits = []

    for marker in markers:
        for label, needle in (
            (f"{marker!r} ascii", marker.encode("utf-8")),
            (f"{marker!r} utf16", utf16(marker)),
        ):
            off = data.find(needle)
            if off != -1:
                hits.append(("identity", label, off))

    if aeskey_hex:
        needle = bytes.fromhex(aeskey_hex.replace(" ", ""))
        off = data.find(needle)
        if off != -1:
            hits.append(("aeskey", "AES key raw bytes", off))

    if check_rwx_page:
        for pat in RWX_BYTE_PATTERNS:
            off = data.find(pat)
            if off != -1:
                hits.append(("rwx", f"RWX byte pattern {pat.hex()}", off))
                break

    return hits


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate artifacts / memory snapshots for EDR-visible signatures"
    )
    parser.add_argument("path", nargs="?", type=Path,
                        help="artifact to scan (source .c or built .exe/.bin)")
    parser.add_argument("--snapshot", metavar="DUMP", type=Path,
                        help="scan a process memory dump instead")
    parser.add_argument("--marker", action="append", default=[],
                        help="identity marker to look for in the dump (repeatable)")
    parser.add_argument("--aeskey", metavar="HEX",
                        help="16-byte AES key as hex - scan for its raw bytes")
    parser.add_argument("--rwx", action="store_true",
                        help="also flag RWX byte patterns in the snapshot")
    args = parser.parse_args()

    if args.snapshot:
        path = args.snapshot
        if not path.exists():
            print(f"[!] dump not found: {path}", file=sys.stderr)
            return 1
        markers = SNAPSHOT_DEFAULT_MARKERS + [m for m in args.marker if m]
        hits = scan_snapshot(path, markers, args.aeskey, args.rwx)
        if hits:
            print(f"[-] {path}: {len(hits)} identity-material hit(s)")
            for kind, label, off in hits:
                print(f"    [{kind}] {label:<44} @ 0x{off:x}")
            return 1
        print(f"[+] {path}: clean ({len(markers)} markers"
              f"{', aeskey' if args.aeskey else ''}{', rwx' if args.rwx else ''})")
        return 0

    path = args.path
    if not path:
        parser.print_usage()
        return 1
    if not path.exists():
        print(f"[!] file not found: {path}", file=sys.stderr)
        return 1

    if path.suffix.lower() == ".exe":
        ok_imports, import_msg = check_imports_empty(path)
        print(f"[{'-' if not ok_imports else '+'}] imports: {import_msg}")
        if not ok_imports:
            return 1

    if path.suffix.lower() == ".c":
        hits = run_text_scan(path.read_text(errors="ignore"))
    else:
        hits = run_binary_scan(path)

    if hits:
        print(f"[-] {path}: {len(hits)} signature hit(s)")
        for pattern, desc in hits:
            print(f"    {pattern:<40} -> {desc}")
        return 1

    print(f"[+] {path}: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())