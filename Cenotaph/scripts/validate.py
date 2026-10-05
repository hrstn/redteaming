#!/usr/bin/env python3
"""
Static validation for Cenotaph output.

Checks the compiled cenotaph.exe for:
  - zero imported DLLs / functions
  - no functional API name strings (all APIs resolved via FNV1a PEB walk)
  - no RWX (PAGE_EXECUTE_READWRITE) references
  - no AMSI/ETW bypass strings
  - no undefined CRT/libc symbols
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


TEXT_SIGNATURES = {
    "NtAllocateVirtualMemory": "API name string",
    "NtProtectVirtualMemory": "API name string",
    "NtQuerySystemInformation": "API name string",
    "NtClose": "API name string",
    "NtDelayExecution": "API name string",
    "NtCreateFile": "API name string",
    "NtReadFile": "API name string",
    "TpAllocWork": "API name string",
    "TpPostWork": "API name string",
    "TpReleaseWork": "API name string",
    "GetModuleFileNameW": "API name string",
    "CreateFileW": "API name string",
    "ReadFile": "API name string",
    "GetFileSize": "API name string",
    "GetTickCount": "API name string",
    "Sleep": "API name string",
    "CloseHandle": "API name string",
    "VirtualAlloc": "API name string",
    "VirtualProtect": "API name string",
    "LoadLibrary": "API name string",
    "GetProcAddress": "API name string",
    "amsiInitFailed": "AMSI reflection bypass",
    "AmsiUtils": "AMSI type reference",
    "AmsiScan": "AMSI API",
    "EtwEventWrite": "ETW API",
    "etw": "ETW reference",
    "PAGE_EXECUTE_READWRITE": "RWX protection string",
    "github.com": "GitHub URL reference",
    "api.github.com": "GitHub API endpoint",
}

REGEX_SIGNATURES = {
    r"(?<![sS])http://": "Plaintext HTTP URL",
    r"\bROT\b": "Caesar / toy cipher mention",
}


def find_tool(name: str) -> str | None:
    for prefix in ("x86_64-w64-mingw32-", ""):
        p = shutil.which(prefix + name)
        if p:
            return p
    return None


def check_imports_empty(path: Path) -> tuple[bool, str]:
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
    in_imports = False
    for line in out.splitlines():
        if "The Import Tables" in line:
            in_imports = True
            continue
        if in_imports:
            stripped = line.strip()
            if not stripped:
                continue
            # Skip the column header line and pure-hex rows.
            if stripped.startswith("vma:"):
                continue
            if "Table" in stripped and "Stamp" in stripped and "Chain" in stripped:
                continue
            if re.match(r"^[0-9a-fA-F\s]+$", stripped):
                continue
            if any(c.isalpha() for c in stripped):
                return (False, f"imported symbol/DLL detected: {stripped}")

    return (True, "import table is empty")


def check_undefined_empty(path: Path) -> tuple[bool, str]:
    nm = find_tool("nm")
    if not nm:
        return (True, "nm not found, skipping undefined-symbol check")

    try:
        result = subprocess.run(
            [nm, "-u", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as e:
        return (False, f"nm failed: {e}")

    lines = [l for l in result.stdout.splitlines() if l.strip()]
    if lines:
        return (False, f"undefined symbols: {', '.join(lines[:5])}")
    return (True, "no undefined symbols")


def run_text_scan(text: str) -> list[tuple[str, str]]:
    hits = []
    for pattern, description in TEXT_SIGNATURES.items():
        if re.search(re.escape(pattern), text, re.IGNORECASE):
            hits.append((pattern, description))
    for pattern, description in REGEX_SIGNATURES.items():
        if re.search(pattern, text, re.IGNORECASE):
            hits.append((pattern, description))
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Cenotaph binary for imports/API/RWX/AMSI signatures"
    )
    parser.add_argument("path", type=Path, help="compiled .exe to scan")
    args = parser.parse_args()

    path = args.path
    if not path.exists():
        print(f"[!] file not found: {path}", file=sys.stderr)
        return 1

    ok_imports, import_msg = check_imports_empty(path)
    print(f"[{'+' if ok_imports else '-'}] imports: {import_msg}")
    if not ok_imports:
        return 1

    ok_undef, undef_msg = check_undefined_empty(path)
    print(f"[{'+' if ok_undef else '-'}] undefineds: {undef_msg}")
    if not ok_undef:
        return 1

    text = path.read_bytes().decode("utf-8", errors="ignore")
    hits = run_text_scan(text)
    if hits:
        print(f"[-] {path}: {len(hits)} signature hit(s)")
        for pattern, desc in hits:
            print(f"    {pattern:<40} -> {desc}")
        return 1

    print(f"[+] {path}: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
