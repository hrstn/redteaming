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
        var hotfixes = Utils.QueryWmi("SELECT HotFixID,InstalledOn FROM Win32_QuickFixEngineering");
        if (hotfixes.Count == 0)
        {
            findings.Add(new Finding
            {
                Id = "SW-002",
                Category = "Software",
                Title = "Could not enumerate installed hotfixes (WMI failure)",
                Severity = Severity.Info,
                Description = "Verify patching state via wmic qfe or Get-HotFix."
            });
            return;
        }
        var sb = new System.Text.StringBuilder();
        foreach (var h in hotfixes)
            sb.AppendLine($"  {h["HotFixID"]?.ToString(),-12}  installed {h["InstalledOn"]}");
        findings.Add(new Finding
        {
            Id = "SW-003",
            Category = "Software",
            Title = $"{hotfixes.Count} hotfix(es) installed",
            Severity = Severity.Medium,
            Description = "Compare against a recent build to identify missing security updates. Outdated hosts are candidates for known public exploits.",
            Evidence = sb.ToString(),
            Remediation = "Cross-reference HotFix IDs against Microsoft's patch catalog; identify the newest missing security rollup."
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