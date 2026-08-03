using Microsoft.Win32;
using PrivescCheckExe.Core;

namespace PrivescCheckExe.Checks;

/// <summary>Installed software inventory + missing patches + WSUS configuration.</summary>
public static class SoftwareChecks
{
    public static void Run(List<Finding> findings)
    {
        InstalledSoftware(findings);
        MissingPatches(findings);
    }

    public static void RunWsus(List<Finding> findings)
    {
        Wsus(findings);
    }

    private static void InstalledSoftware(List<Finding> findings)
    {
        var paths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };
        var sb = new System.Text.StringBuilder();
        int count = 0;
        foreach (var root in paths)
        {
            using var key = Registry.LocalMachine.OpenSubKey(root);
            if (key == null) continue;
            foreach (var sub in key.GetSubKeyNames())
            {
                try
                {
                    using var sk = key.OpenSubKey(sub);
                    var name = sk?.GetValue("DisplayName")?.ToString();
                    var ver  = sk?.GetValue("DisplayVersion")?.ToString();
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    sb.AppendLine($"  {name}  {ver}");
                    count++;
                }
                catch { }
            }
        }
        if (count > 0)
        {
            findings.Add(new Finding
            {
                Id = "SW-001",
                Category = "Software",
                Title = $"{count} installed application(s) enumerated",
                Severity = Severity.Info,
                Description = "Review for EOL/known-vulnerable apps (browser, Java, Adobe, dev tooling) that may expose local privilege escalation via services.",
                Evidence = sb.ToString()
            });
        }
    }

    private static void MissingPatches(List<Finding> findings)
    {
        // No WMI (AOT-friendly). Read legacy HotFix key + CBS RollupFix packages.
        var sb = new System.Text.StringBuilder();
        var ids = new System.Collections.Generic.HashSet<string>();

        // Legacy: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix\<KBxxxxxx>
        var legacySubs = Utils.GetRegSubKeys(RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix");
        if (legacySubs != null)
        {
            foreach (var sub in legacySubs)
            {
                if (ids.Add(sub))
                    sb.AppendLine($"  {sub}");
            }
        }

        // Modern: CBS packages whose name contains "RollupFix" (cumulative updates).
        // Revision number encodes the build the CU corresponds to.
        string? newest = null;
        var cbsSubs = Utils.GetRegSubKeys(RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages");
        if (cbsSubs != null)
        {
            foreach (var sub in cbsSubs)
            {
                if (!sub.Contains("RollupFix", StringComparison.OrdinalIgnoreCase)) continue;
                // package name tail like ...~amd64~~10.0.19045.5000
                var parts = sub.Split('~');
                if (parts.Length > 0)
                {
                    var ver = parts[^1];
                    if (!string.IsNullOrWhiteSpace(ver)) newest = ver;
                }
            }
            if (newest != null)
                sb.AppendLine($"  Latest RollupFix build: {newest}");
        }

        if (sb.Length == 0)
        {
            findings.Add(new Finding
            {
                Id = "SW-003",
                Category = "Software",
                Title = "Could not enumerate installed updates from registry",
                Severity = Severity.Info,
                Description = "CBS/HotFix keys not readable. Verify patching state via 'dism /online /get-packages' or wmic qfe."
            });
            return;
        }

        findings.Add(new Finding
        {
            Id = "SW-003",
            Category = "Software",
            Title = $"{ids.Count} KB(s) + cumulative update info enumerated",
            Severity = Severity.Medium,
            Description = "Compare the latest RollupFix build against a current baseline to identify missing security updates. Outdated hosts are candidates for known public exploits.",
            Evidence = sb.ToString(),
            Remediation = "Cross-reference the RollupFix build/KBs against Microsoft's patch catalog; identify missing security rollups."
        });
    }

    private static void Wsus(List<Finding> findings)
    {
        var key = @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
        var useWu = Utils.GetRegHive(RegistryHive.LocalMachine, key, "UseWUServer");
        var wuServer = Utils.GetRegHive(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", "WUServer");
        var au = Utils.GetRegHive(RegistryHive.LocalMachine, key, "AUOptions");
        if (useWu == "1" && !string.IsNullOrWhiteSpace(wuServer))
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"  WUServer    : {wuServer}");
            sb.AppendLine($"  AUOptions   : {au}");
            findings.Add(new Finding
            {
                Id = "SW-004",
                Category = "Software",
                Title = "WSUS is configured - verify it serves over HTTP",
                Severity = Severity.High,
                Description = "If WUServer uses http:// (not https://) and the host is attacker-reachable, updates can be spoofed (Wsuxploit/UsoPrivesc) to deliver a fake update that runs as SYSTEM.",
                Evidence = sb.ToString(),
                Remediation = "Confirm WUServer uses HTTPS or that the URL is not attacker-controlled. If HTTP and MITM-able, fake-update privesc is viable."
            });
        }
    }
}