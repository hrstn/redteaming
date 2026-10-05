#!/usr/bin/env python3
"""
hostpayload_v2 MinGW cross-compile helper.

Compiles a generated dropper.c with the same flags used by pack.py.
Useful when you want to edit the source by hand or compile a source-only
artifact produced with `pack.py --format c`.
"""

import argparse
import subprocess
import sys
from pathlib import Path


CC = "x86_64-w64-mingw32-gcc"
CFLAGS = [
    "-Os",
    "-nostdlib",
    "-fno-asynchronous-unwind-tables",
    "-fno-ident",
    "-fvisibility=hidden",
    "-ffunction-sections",
    "-fno-builtin",
    "-fno-stack-check",
    "-m64",
]
LDFLAGS = [
    "-Wl,--strip-all",
    "-Wl,--entry,DropperEntry",
    "-Wl,--subsystem,windows",
]


def compile_dropper(c_path: Path, exe_path: Path) -> None:
    args = [CC, *CFLAGS, *LDFLAGS, str(c_path), "-o", str(exe_path)]
    print(f"[+] compiling: {' '.join(args)}")
    subprocess.run(args, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile a hostpayload_v2 dropper.c")
    parser.add_argument("source", type=Path, help="path to dropper.c")
    parser.add_argument("-o", "--output", type=Path, required=True, help="output EXE path")
    args = parser.parse_args()

    if not args.source.exists():
        print(f"[!] source not found: {args.source}", file=sys.stderr)
        return 1

    compile_dropper(args.source, args.output)
    print(f"[+] wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
