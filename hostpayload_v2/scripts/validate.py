#!/usr/bin/env python3
"""
Static validation for generated hostpayload_v2 output.

Scans a generated source/EXE for patterns that modern EDR/AMSI commonly flag:
  - RWX memory allocation strings / constants (0x40 after 0x3000)
  - signatured AMSI bypass strings (amsiInitFailed, AmsiUtils, etc.)
  - signatured PowerShell APIs (Add-Type, GetDelegateForFunctionPointer, etc.)
  - plaintext HTTP URLs on port 80
  - toy-cipher mentions (XOR, RC4, ROT)
  - VirtualAlloc direct calls in source
"""

import argparse
import re
import sys
from pathlib import Path


SIGNATURES = {
    "amsiInitFailed": "AMSI reflection bypass",
    "AmsiUtils": "AMSI type reference",
    "System.Management.Automation": "PowerShell automation namespace",
    "Add-Type": "PowerShell compiled type injection",
    "GetDelegateForFunctionPointer": "PowerShell shellcode execution API",
    "Marshal.Copy": "PowerShell memory copy API",
    "System.Net.WebClient": "PowerShell download client",
    "IEX ": "PowerShell invoke-expression",
    "Invoke-Expression": "PowerShell invoke-expression",
    "VirtualAlloc": "Direct VirtualAlloc reference",
    "0x3000, 0x40": "RWX allocation constant pair",
    "0x40 )": "RWX PAGE_EXECUTE_READWRITE",
    "0x1000 + 0x2000, 0x20 + 0x20": "PowerShell RWX pattern",
    "http://": "Plaintext HTTP URL",
    "RC4": "Weak stream cipher",
    "XOR encryption": "Toy cipher mention",
}

# Regex-based signatures (use word boundaries / negative lookaheads to avoid
# false positives, e.g. ROTL32 / ROTR32 are bit-rotation helpers, not Caesar).
REGEX_SIGNATURES = {
    r"\bROT\b": "Caesar cipher mention",
}


def scan_text(text: str) -> list[tuple[str, str]]:
    hits = []
    for pattern, description in SIGNATURES.items():
        if re.search(re.escape(pattern), text, re.IGNORECASE):
            hits.append((pattern, description))
    for pattern, description in REGEX_SIGNATURES.items():
        if re.search(pattern, text, re.IGNORECASE):
            hits.append((pattern, description))
    return hits


def scan_binary(path: Path) -> list[tuple[str, str]]:
    data = path.read_bytes()
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    # Also scan for byte signatures in binary
    hits = scan_text(text)
    # RWX constant pair in binary: 0x3000 0x40 may appear as little-endian bytes
    if b"\x00\x30\x00\x00\x40\x00\x00\x00" in data or b"\x00\x00\x30\x00\x00\x00\x40\x00" in data:
        hits.append(("RWX byte pattern", "PAGE_EXECUTE_READWRITE constant pair in binary"))
    return hits


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="file to scan (source .c or compiled .exe)")
    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"[!] file not found: {path}", file=sys.stderr)
        return 1

    if path.suffix.lower() == ".c":
        hits = scan_text(path.read_text(errors="ignore"))
    else:
        hits = scan_binary(path)

    if hits:
        print(f"[-] {path}: {len(hits)} signature hit(s)")
        for pattern, desc in hits:
            print(f"    {pattern:<30} -> {desc}")
        return 1
    print(f"[+] {path}: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
