using System.Diagnostics;
using System.Management;
using Microsoft.Win32;
using PrivescCheckExe.Core;

namespace PrivescCheckExe.Core;

public static class Utils
{
    public static bool IsAdmin()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var p = new System.Security.Principal.WindowsPrincipal(id);
            return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    public static bool IsHighIntegrity() => IsAdmin();

    /// <summary>Query WMI and return list of property dictionaries.</summary>
    public static List<Dictionary<string, object?>> QueryWmi(string wql, string scope = null!)
    {
        var rows = new List<Dictionary<string, object?>>();
        try
        {
            using var searcher = scope == null
                ? new ManagementObjectSearcher(wql)
                : new ManagementObjectSearcher(scope, wql);
            foreach (ManagementObject mo in searcher.Get())
            {
                var row = new Dictionary<string, object?>();
                foreach (PropertyData p in mo.Properties)
                    row[p.Name] = p.Value;
                rows.Add(row);
            }
        }
        catch { /* WMI may be unavailable; swallow */ }
        return rows;
    }

    public static string? GetReg(RegistryHive hive, string path, string value) => GetRegHive(hive, path, value);

    public static string? GetRegHive(RegistryHive hive, string path, string value)
    {
        try
        {
            using var key = (hive switch
            {
                RegistryHive.ClassesRoot => Registry.ClassesRoot,
                RegistryHive.CurrentUser => Registry.CurrentUser,
                RegistryHive.Users => Registry.Users,
                RegistryHive.CurrentConfig => Registry.CurrentConfig,
                _ => Registry.LocalMachine
            }).OpenSubKey(path);
            return key?.GetValue(value)?.ToString();
        }
        catch { return null; }
    }

    public static string[]? GetRegSubKeys(RegistryHive hive, string path)
    {
        try
        {
            using var key = (hive switch
            {
                RegistryHive.ClassesRoot => Registry.ClassesRoot,
                RegistryHive.CurrentUser => Registry.CurrentUser,
                RegistryHive.Users => Registry.Users,
                RegistryHive.CurrentConfig => Registry.CurrentConfig,
                _ => Registry.LocalMachine
            }).OpenSubKey(path);
            return key?.GetSubKeyNames();
        }
        catch { return null; }
    }

    /// <summary>Run an external command and capture combined stdout (best-effort, quiet).</summary>
    public static string Run(string exe, string args, int timeoutMs = 8000)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8
            };
            using var p = Process.Start(psi);
            if (p == null) return "";
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(); } catch { }
                return "";
            }
            return p.StandardOutput.ReadToEnd();
        }
        catch { return ""; }
    }

    /// <summary>Check whether a file/dir is writable by current user/token.</summary>
    public static bool IsWritable(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            if (Directory.Exists(path))
            {
                var probe = Path.Combine(path, ".pcw_probe_" + Guid.NewGuid().ToString("N"));
                File.WriteAllText(probe, "x");
                File.Delete(probe);
                return true;
            }
            if (File.Exists(path))
            {
                try { using var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.None); return true; }
                catch { return false; }
            }
        }
        catch { }
        return false;
    }

    public static bool ExistsOnPath(string exe)
    {
        try { return File.Exists(exe) || !string.IsNullOrWhiteSpace(GetFullPath(exe)); }
        catch { return false; }
    }

    private static string? GetFullPath(string exe)
    {
        var values = Environment.GetEnvironmentVariable("PATH")?.Split(';') ?? Array.Empty<string>();
        foreach (var dir in values)
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            try
            {
                var full = Path.Combine(dir.Trim('"'), exe);
                if (File.Exists(full)) return full;
            }
            catch { }
        }
        return null;
    }

    public static IEnumerable<string> SafeSplitPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) yield break;
        foreach (var part in path.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var p = part.Trim().Trim('"');
            if (!string.IsNullOrWhiteSpace(p)) yield return p;
        }
    }
}