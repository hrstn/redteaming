using Microsoft.Win32;
using PrivescCheckExe.Core;

namespace PrivescCheckExe.Checks;

/// <summary>
/// Registry-based privesc vectors: AlwaysInstallElevated, AutoLogon credentials,
/// and AutoRun entries (Run keys, Winlogon, Startup folders) - checks if any are writable.
/// </summary>
public static class RegistryChecks
{
    public static void Run(List<Finding> findings)
    {
        AlwaysInstallElevated(findings);
        AutoLogon(findings);
        AutoRuns(findings);
    }

    private static void AlwaysInstallElevated(List<Finding> findings)
    {
        // HKLM and HKCU must both be 1 for MSI to run elevated with SYSTEM.
        var hklm = Utils.GetRegHive(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated");
        var hkcu = Utils.GetRegHive(RegistryHive.CurrentUser,  @"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated");
        if (hklm == "1" && hkcu == "1")
        {
            findings.Add(new Finding
            {
                Id = "REG-001",
                Category = "Registry",
                Title = "AlwaysInstallElevated is enabled (HKLM+HKCU=1)",
                Severity = Severity.Critical,
                Description = "MSI packages run with elevated/SYSTEM privileges regardless of invoking user.",
                Remediation = "Craft a malicious MSI (msfvenom payload/windows/x64/custom/...) and run: msiexec /quiet /i payload.msi"
            });
        }
    }

    private static void AutoLogon(List<Finding> findings)
    {
        var key = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        var username = Utils.GetRegHive(RegistryHive.LocalMachine, key, "DefaultUserName");
        if (string.IsNullOrWhiteSpace(username)) return;
        var password = Utils.GetRegHive(RegistryHive.LocalMachine, key, "DefaultPassword");
        var domain   = Utils.GetRegHive(RegistryHive.LocalMachine, key, "DefaultDomainName");
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"  DefaultDomainName : {domain}");
        sb.AppendLine($"  DefaultUserName   : {username}");
        sb.AppendLine($"  DefaultPassword   : {(string.IsNullOrWhiteSpace(password) ? "(empty/LSA-encrypted)" : password)}");
        findings.Add(new Finding
        {
            Id = "REG-002",
            Category = "Registry",
            Title = "AutoLogon credentials are stored in the registry",
            Severity = string.IsNullOrWhiteSpace(password) ? Severity.Medium : Severity.High,
            Description = "If AutoLogon is configured, credentials live in Winlogon (plaintext or LSA-encrypted).",
            Evidence = sb.ToString(),
            Remediation = "If DefaultPassword is present in plaintext it is immediately usable. Otherwise decrypt via LSA secrets (e.g. lsadump)."
        });
    }

    private static void AutoRuns(List<Finding> findings)
    {
        // Common autorun locations -> list entries, flag those pointing at writable binaries.
        var runLocations = new (RegistryHive Hive, string Path, string Label)[]
        {
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",                 "HKLM Run"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",             "HKLM RunOnce"),
            (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",                "HKCU Run"),
            (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",            "HKCU RunOnce"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",          "HKLM RunOnceEx"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",     "HKLM Run (32-bit)"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",        "Winlogon (Shell/Userinit)"),
            (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",     "Explorer RunMRU"),
        };

        foreach (var (hive, path, label) in runLocations)
        {
            try
            {
                using var k = (hive switch
                {
                    RegistryHive.CurrentUser => Registry.CurrentUser,
                    _ => Registry.LocalMachine
                }).OpenSubKey(path);
                if (k == null) continue;
                var names = k.GetValueNames();
                if (names.Length == 0) continue;

                var sb = new System.Text.StringBuilder();
                bool writableFound = false;
                foreach (var n in names)
                {
                    var v = k.GetValue(n)?.ToString() ?? "";
                    sb.AppendLine($"  [{label}] {n} = {v}");
                    // For Winlogon only flag Shell/Userinit
                    if (label.StartsWith("Winlogon", StringComparison.OrdinalIgnoreCase)
                        && n is not ("Shell" or "Userinit")) continue;
                    var bin = ExtractFirstPath(v);
                    if (!string.IsNullOrWhiteSpace(bin) && Utils.IsWritable(bin))
                    {
                        writableFound = true;
                        sb.AppendLine($"    !! WRITABLE: {bin}");
                    }
                }
                if (sb.Length > 0)
                {
                    findings.Add(new Finding
                    {
                        Id = "REG-003",
                        Category = "Registry",
                        Title = $"Autorun entries in {label}",
                        Severity = writableFound ? Severity.High : Severity.Medium,
                        Description = writableFound
                            ? "At least one autorun binary is writable by the current user -> hijack on next boot/login."
                            : "Autorun entries reviewed for hijack-able targets.",
                        Evidence = sb.ToString(),
                        Remediation = writableFound ? "Replace the writable binary with a payload that spawns a high-integrity shell." : ""
                    });
                }
            }
            catch { }
        }

        // Startup folder
        CheckStartupFolder(findings, Environment.GetFolderPath(Environment.SpecialFolder.Startup), "User Startup");
        CheckStartupFolder(findings, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "All Users Startup");
    }

    private static void CheckStartupFolder(List<Finding> findings, string folder, string label)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) return;
        var entries = Directory.GetFiles(folder).Concat(Directory.GetDirectories(folder)).ToArray();
        if (entries.Length == 0) return;
        bool writableFound = entries.Any(e => Utils.IsWritable(e));
        findings.Add(new Finding
        {
            Id = "REG-004",
            Category = "Registry",
            Title = $"Startup folder contains entries ({label})",
            Severity = writableFound ? Severity.High : Severity.Medium,
            Evidence = string.Join('\n', entries),
            Remediation = writableFound ? "Drop / overwrite a payload in this startup folder." : ""
        });
    }

    /// <summary>Grab the first plausible .exe/.bat/.ps1/.cmd path from a command line value.</summary>
    internal static string ExtractFirstPath(string v)
    {
        if (string.IsNullOrWhiteSpace(v)) return "";
        var s = v.Trim('"');
        // try "C:\path\to\exe.exe"
        var match = System.Text.RegularExpressions.Regex.Match(s, @"[A-Za-z]:\\[^\s""]+\.(?:exe|bat|cmd|ps1|vbs|js|scr|com|dll)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return match.Success ? match.Value : "";
    }
}