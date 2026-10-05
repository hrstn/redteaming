#!/usr/bin/env python3
"""
remote_bof_loader MinGW cross-compile helper.

Compiles the standalone native BOF loader from src/*.c into bin/bofloader.exe.
No standard library, no imports, console subsystem.
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
    "-Wall",
    "-Wextra",
    "-Wno-unused-parameter",
    "-Wno-unused-variable",
]
LDFLAGS = [
    "-Wl,--strip-all",
    "-Wl,--entry,BofLoaderEntry",
    "-Wl,--subsystem,console",
]


def compile_loader(src_dir: Path, out: Path) -> None:
    srcs = sorted(src_dir.glob("*.c"))
    if not srcs:
        print("[!] no .c files found in src/", file=sys.stderr)
        sys.exit(1)
    args = [CC, *CFLAGS, *LDFLAGS] + [str(s) for s in srcs] + ["-o", str(out)]
    print(f"[+] compiling: {' '.join(args)}")
    subprocess.run(args, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the remote_bof_loader native binary")
    parser.add_argument("-o", "--output", type=Path, default=Path("bin/bofloader.exe"), help="output EXE path")
    args = parser.parse_args()

    root = Path(__file__).parent.parent
    src_dir = root / "src"
    out = args.output
    out.parent.mkdir(parents=True, exist_ok=True)

    compile_loader(src_dir, out)
    print(f"[+] wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
