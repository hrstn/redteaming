#!/usr/bin/env python3
"""
End-to-end regression test for remote_bof_loader.

Compiles a tiny test BOF, builds the loader, validates the resulting binary,
and — if a Windows x86_64 runtime is available (wine or qemu-x86_64) — runs
the loader against the test BOF and checks for expected output.
"""

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parent.parent
SRC = ROOT / "src"
BIN = ROOT / "bin"
TESTS = ROOT / "tests"


def run(cmd: list[str | Path], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    print(f"[+] {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)


def find_cc() -> str:
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if not cc:
        raise RuntimeError("x86_64-w64-mingw32-gcc not found on PATH")
    return cc


def find_runtime() -> tuple[str | None, str | None]:
    """Return (runtime_command, runtime_name) or (None, None)."""
    if shutil.which("wine"):
        return ("wine", "wine")
    if shutil.which("qemu-x86_64"):
        return ("qemu-x86_64", "qemu-x86_64")
    return (None, None)


def main() -> int:
    cc = find_cc()
    runtime, runtime_name = find_runtime()

    # Build loader
    print("== Building loader ==")
    run([sys.executable, ROOT / "scripts" / "build.py"])
    loader = BIN / "bofloader.exe"
    if not loader.exists():
        print(f"[-] loader not produced: {loader}", file=sys.stderr)
        return 1

    # Compile test BOF
    print("== Compiling test BOF ==")
    bof_o = TESTS / "test_bof.o"
    run([cc, "-c", "-o", bof_o, TESTS / "test_bof.c"])
    if not bof_o.exists():
        print(f"[-] failed to compile {bof_o}", file=sys.stderr)
        return 1

    # Validate loader binary (canonical validator lives in hostpayload_v2)
    print("== Validating loader binary ==")
    run([sys.executable, ROOT.parent / "hostpayload_v2" / "scripts" / "validate.py", loader])

    # Verify zero imports with objdump
    print("== Verifying zero imports ==")
    objdump = shutil.which("x86_64-w64-mingw32-objdump")
    if objdump:
        result = run([objdump, "-p", loader], check=False)
        if "DLL Name" in result.stdout:
            print("[-] loader has unexpected import DLLs", file=sys.stderr)
            return 1
        print("[+] import table appears empty")
    else:
        print("[!] x86_64-w64-mingw32-objdump not found; skipping import check")

    # Run the loader if a runtime is available
    if runtime:
        print(f"== Running loader under {runtime_name} ==")
        cmd = [runtime, str(loader), "--file", str(bof_o), "--entry", "go"]
        result = run(cmd, cwd=ROOT, check=False)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        if result.returncode != 0:
            print(f"[-] loader returned {result.returncode}", file=sys.stderr)
            return 1
        if "test_bof: go() executed" not in result.stdout:
            print("[-] expected output not captured", file=sys.stderr)
            return 1
        print("[+] runtime test passed")
    else:
        print("[!] no Windows x86_64 runtime found (wine/qemu-x86_64); skipping runtime test")

    print("== All static tests passed ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
