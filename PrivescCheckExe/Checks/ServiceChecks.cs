using System.Runtime.InteropServices;
using PrivescCheckExe.Core;

namespace PrivescCheckExe.Checks;

/// <summary>
/// Service-based privesc: unquoted service paths, writable service binaries,
/// and services the current user can reconfigure (CHANGE_CONFIG / start as own process).
/// </summary>
public static class ServiceChecks
{
    public static void Run(List<Finding> findings)
    {
        var services = NativeServices.EnumerateWin32Services();
        if (services.Count == 0)
        {
            Report.WriteLine("    SCM enumeration unavailable - skipping service checks.", ConsoleColor.DarkYellow);
            return;
        }

        foreach (var svc in services)
        {
            if (string.IsNullOrWhiteSpace(svc.Name)) continue;
            CheckUnquotedPath(findings, svc.Name, svc.BinaryPath, svc.State);
            CheckWritableBinary(findings, svc.Name, svc.BinaryPath);
            CheckServicePermissions(findings, svc.Name, svc.State);
        }
    }

    /// <summary>Detect unquoted service paths containing spaces, with writable parent dirs.</summary>
    private static void CheckUnquotedPath(List<Finding> findings, string name, string path, string state)
    {
        var raw = path.Trim();
        if (string.IsNullOrWhiteSpace(raw)) return;
        if (raw.StartsWith("\"")) return;          // quoted - safe
        if (!raw.Contains(" ")) return;            // no spaces - safe

        // Walk up directories looking for a writable parent that would win path resolution.
        // The vulnerable pattern: C:\Program Files\My Service\svc.exe with C:\Program Files\My writable.
        var firstSpace = raw.IndexOf(' ');
        string cursor = raw;
        var sb = new System.Text.StringBuilder();
        while (true)
        {
            int sp = cursor.IndexOf(' ');
            if (sp < 0) break;
            var candidate = cursor[..sp];
            // strip trailing args - take the part that looks like a path
            candidate = candidate.Trim('"');
            if (!candidate.Contains(':'))
            {
                cursor = cursor[(sp + 1)..];
                continue;
            }
            // candidate is the path up to first space; the "phantom" exe is candidate.exe
            var phantomExe = candidate + ".exe";
            var dir = Path.GetDirectoryName(candidate);
            if (!string.IsNullOrWhiteSpace(dir) && Utils.IsWritable(dir))
            {
                sb.AppendLine($"  Service      : {name} ({state})");
                sb.AppendLine($"  BinPath      : {path}");
                sb.AppendLine($"  Writable dir : {dir}");
                sb.AppendLine($"  Phantom exe  : {phantomExe}");
                findings.Add(new Finding
                {
                    Id = "SVC-001",
                    Category = "Services",
                    Title = "Unquoted service path with writable parent directory",
                    Severity = Severity.High,
                    Description = "Place an executable matching the truncated path name to intercept service start.",
                    Evidence = sb.ToString(),
                    Remediation = $"Place {phantomExe} in {dir}, then start the service (if permitted) for elevated execution."
                });
                break;
            }
            cursor = cursor[(sp + 1)..];
        }
    }

    private static void CheckWritableBinary(List<Finding> findings, string name, string path)
    {
        var bin = ExtractServiceBinary(path);
        if (string.IsNullOrWhiteSpace(bin)) return;
        if (Utils.IsWritable(bin))
        {
            findings.Add(new Finding
            {
                Id = "SVC-002",
                Category = "Services",
                Title = "Service binary is writable by current user",
                Severity = Severity.Critical,
                Description = $"Service '{name}' runs a binary you can overwrite.",
                Evidence = $"  BinPath : {path}\n  Binary  : {bin}",
                Remediation = "Back up then replace the binary with an alternate; (re)start the service for elevated execution."
            });
        }
    }

    /// <summary>Test whether the current user can reconfigure or start each service via native SCM.</summary>
    private static void CheckServicePermissions(List<Finding> findings, string name, string state)
    {
        const uint SERVICE_CHANGE_CONFIG = 0x0002;
        const uint SERVICE_START = 0x0010;
        const uint SC_MANAGER_CONNECT = 0x0001;

        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) return;
        try
        {
            IntPtr h = OpenService(scm, name, SERVICE_CHANGE_CONFIG);
            if (h != IntPtr.Zero)
            {
                CloseServiceHandle(h);
                findings.Add(new Finding
                {
                    Id = "SVC-003",
                    Category = "Services",
                    Title = $"Service '{name}' can be reconfigured (CHANGE_CONFIG)",
                    Severity = Severity.High,
                    Description = "You can repoint the service's ImagePath to an alternate binary via ChangeServiceConfig.",
                    Evidence = $"  Service: {name}  State: {state}",
                    Remediation = "Use sc.exe config <name> binPath= <alternate> then start the service."
                });
            }

            IntPtr hs = OpenService(scm, name, SERVICE_START);
            if (hs != IntPtr.Zero)
            {
                CloseServiceHandle(hs);
                // Only interesting if it's not already running.
                if (!state.Equals("Running", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new Finding
                    {
                        Id = "SVC-004",
                        Category = "Services",
                        Title = $"Service '{name}' can be started (SERVICE_START)",
                        Severity = Severity.Medium,
                        Description = "Combined with a reconfigurable or replaceable binary, you can trigger execution.",
                        Evidence = $"  Service: {name}  State: {state}",
                        Remediation = "Start the service (sc start) after planting your payload."
                    });
                }
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }

    internal static string ExtractServiceBinary(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";
        var s = path.Trim();
        // strip leading quotes
        if (s.StartsWith("\""))
        {
            var end = s.IndexOf('"', 1);
            if (end > 0) return s[1..end];
        }
        // System32\svchost ... -> not directly exploitable, but capture first .exe-ish token
        var match = System.Text.RegularExpressions.Regex.Match(s, @"[A-Za-z]:\\[^\s""]+\.(?:exe|dll|bat|cmd|ps1|scr)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return match.Success ? match.Value : "";
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);
}