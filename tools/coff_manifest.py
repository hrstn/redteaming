#!/usr/bin/env python3
"""
integrity manifest — sha256 for every built COFF under *_bin/*.

Two uses:
  1. `python3 tools/coff_manifest.py`            -> prints the current manifest
  2. `python3 tools/coff_manifest.py --check`    -> verifies `tools/coff_manifest.json`
     matches the tree (regen: --check --write)

Guards the supply chain: a COFF that does not match a manifest row was either
rebuilt from different tooling or tampered with — resolve before shipping.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = Path(__file__).parent / "coff_manifest.json"


def repo_coffs():
    out = []
    for bin_dir in sorted(REPO.rglob("_bin")):
        rel = bin_dir.relative_to(REPO)
        for o in sorted(bin_dir.glob("*.o")):
            out.append((str(rel / o.name), o))
    return out


def blob_entry(path: str, pth: Path) -> dict:
    data = pth.read_bytes()
    return {
        "path": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    entries = [blob_entry(rel, p) for rel, p in repo_coffs()]

    if not entries:
        print("[i] no COFFs on disk (build a suite first: make kit)")
        return 0

    if args.write:
        MANIFEST.write_text(json.dumps({
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "coffs": entries,
        }, indent=1) + "\n")
        print(f"[+] manifest written: {MANIFEST.relative_to(REPO)} ({len(entries)} coffs)")
        return 0

    if args.check:
        if not MANIFEST.exists():
            print("[-] no manifest to check against (write one: --check --write)")
            return 1
        try:
            stored = json.loads(MANIFEST.read_text())["coffs"]
        except Exception as e:
            print(f"[-] manifest unreadable: {e}")
            return 1
        stored_map = {e["path"]: e for e in stored}
        now_map = {e["path"]: e for e in entries}
        diffs = []
        for path, e in now_map.items():
            s = stored_map.get(path)
            if not s:
                diffs.append(f"new:     {path}")
            elif s["sha256"] != e["sha256"]:
                diffs.append(f"drift:   {path} (stored {s['sha256'][:16]}…, now {e['sha256'][:16]}…)")
        for path in stored_map:
            if path not in now_map:
                diffs.append(f"gone:    {path}")
        if diffs:
            for d in diffs:
                print(f"[-] {d}")
            return 1
        print(f"[+] manifest check: {len(entries)} coffs match")
        return 0

    for e in entries:
        print(f"{e['sha256']}  {e['size']:>9}  {e['path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())