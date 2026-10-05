#!/usr/bin/env python3
"""
Static validation for remote_bof_loader output.

Checks the compiled bofloader.exe for:
  - zero imported DLLs / functions
  - no signatured AMSI/ETW bypass strings
  - no plaintext HTTP staging strings
  - no RWX (PAGE_EXECUTE_READWRITE) constant or string patterns
  - no obvious hard-coded payload URLs or .NET / PowerShell artifacts
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


TEXT_SIGNATURES = {
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
    "etw": "ETW reference (case-insensitive)",
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
    "api.github.com": "GitHub API endpoint",
    # RWX / dangerous allocation strings
    "PAGE_EXECUTE_READWRITE": "RWX protection string",
    "0x3000, 0x40": "RWX allocation constant pair",
    "0x40 )": "RWX PAGE_EXECUTE_READWRITE constant",
}

REGEX_SIGNATURES = {
    # Standalone ROT cipher mention (not bit-rotation helpers)
    r"\bROT\b": "Caesar / toy cipher mention",
    # Plaintext HTTP URL, but allow https://
    r"(?<![sS])http://": "Plaintext HTTP URL",
}

# Byte patterns that commonly represent RWX allocation constants.
RWX_BYTE_PATTERNS = [
    b"\x00\x30\x00\x00\x40\x00\x00\x00",  # 0x3000 0x40 little-endian
    b"\x00\x00\x30\x00\x00\x00\x40\x00",
]


def find_tool(name: str) -> str | None:
    path = shutil.which(name)
    if path:
        return path
    # Try common prefixed names on PATH even if which returns None
    for prefix in ("x86_64-w64-mingw32-", "x86_64-w64-mingw32-"):
        p = shutil.which(prefix + name)
        if p:
            return p
    return None


def run_text_scan(text: str) -> list[tuple[str, str]]:
    hits = []
    for pattern, description in TEXT_SIGNATURES.items():
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
    objdump = find_tool("objdump")
    if not objdump:
        return (False, "x86_64-w64-mingw32-objdump not found on PATH")

    try:
        result = subprocess.run(
            [objdump, "-p", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as e:
        return (False, f"objdump failed: {e}")

    out = result.stdout
    # If any DLL name line appears after "The Import Tables", imports exist.
    in_imports = False
    for line in out.splitlines():
        if "The Import Tables" in line:
            in_imports = True
            continue
        if in_imports:
            # objdump prints empty rows of zeros for no imports.
            # A real import line contains a DLL name, not just hex fields.
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("vma:") or re.match(r"^[0-9a-fA-F\s]+$", stripped):
                continue
            # Looks like a textual DLL/function name line.
            if any(c.isalpha() for c in stripped):
                return (False, f"imported symbol/DLL detected: {stripped}")

    return (True, "import table is empty")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate remote_bof_loader binary for AMSI/ETW/RWX/import signatures"
    )
    parser.add_argument("path", type=Path, help="compiled .exe to scan")
    args = parser.parse_args()

    path = args.path
    if not path.exists():
        print(f"[!] file not found: {path}", file=sys.stderr)
        return 1

    ok_imports, import_msg = check_imports_empty(path)
    if not ok_imports:
        print(f"[-] {path}: {import_msg}")
        return 1
    print(f"[+] imports: {import_msg}")

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
