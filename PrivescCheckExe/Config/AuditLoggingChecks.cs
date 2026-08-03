using Microsoft.Win32;
using PrivescCheckExe.Core;

namespace PrivescCheckExe.Config;

/// <summary>Audit & logging posture: advanced audit policy, PowerShell logging, Event Log config, Sysmon.</summary>
public static class AuditLoggingChecks
{
    public static void Run(List<Finding> findings)
    {
        AdvancedAudit(findings);
        PowerShellLogging(findings);
        EventLogConfig(findings);
        Sysmon(findings);
    }

    private static void AdvancedAudit(List<Finding> findings)
    {
        var outp = Utils.Run("auditpol.exe", "/get /category:*", 12000);
        if (string.IsNullOrWhiteSpace(outp))
        {
            findings.Add(new Finding { Id = "CFG-AUD-001", Category = "Audit & Logging", Title = "auditpol unavailable", Severity = Severity.Info });
            return;
        }
        var sb = new System.Text.StringBuilder();
        int enabled = 0, total = 0;
        foreach (var line in outp.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!line.Contains("  Success and Failure", StringComparison.OrdinalIgnoreCase)
             && !line.Contains("  Success", StringComparison.OrdinalIgnoreCase)
             && !line.Contains("  Failure", StringComparison.OrdinalIgnoreCase)) continue;
            total++;
            if (line.Contains("Success", StringComparison.OrdinalIgnoreCase) || line.Contains("Failure", StringComparison.OrdinalIgnoreCase))
            {
                // crude detection: any non "No Auditing"
                if (!line.Contains("No Auditing", StringComparison.OrdinalIgnoreCase)) { enabled++; sb.AppendLine("  " + line.Trim()); }
            }
        }
        findings.Add(new Finding
        {
            Id = "CFG-AUD-001",
            Category = "Audit & Logging",
            Title = $"Advanced audit policy: ~{enabled}/{total} subcategories audited",
            Severity = enabled == 0 ? Severity.High : (enabled < total / 2 ? Severity.Medium : Severity.Low),
            Description = enabled == 0
                ? "No advanced auditing configured - attacker actions leave minimal traces."
                : "Review which subcategories are audited; privilege-use and logon auditing matter most for privesc detection.",
            Evidence = sb.ToString(),
            Remediation = "Enable at least Audit Logon, Audit Privilege Use, Audit Process Creation via GPO: Computer Config > Windows Settings > Advanced Audit Policy."
        });
    }

    private static void PowerShellLogging(List<Finding> findings)
    {
        var key = @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
        var en = Utils.GetRegHive(RegistryHive.LocalMachine, key, "EnableScriptBlockLogging");
        var key2 = @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging";
        var modEn = Utils.GetRegHive(RegistryHive.LocalMachine, key2, "EnableModuleLogging");
        var key3 = @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription";
        var transEn = Utils.GetRegHive(RegistryHive.LocalMachine, key3, "EnableTranscripting");
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"  EnableScriptBlockLogging : {en ?? "(not set)"}");
        sb.AppendLine($"  EnableModuleLogging       : {modEn ?? "(not set)"}");
        sb.AppendLine($"  EnableTranscripting       : {transEn ?? "(not set)"}");
        var sbOff = en != "1" && modEn != "1" && transEn != "1";
        findings.Add(new Finding
        {
            Id = "CFG-AUD-002",
            Category = "Audit & Logging",
            Title = sbOff ? "PowerShell logging not enabled via policy" : "PowerShell logging partially/fully enabled",
            Severity = sbOff ? Severity.High : Severity.Info,
            Description = sbOff
                ? "Without ScriptBlock/Module logging, malicious PowerShell is largely invisible to SOC. (Note: this is also good news for offensive use.)"
                : "ScriptBlock logging will record de-obfuscated payloads - obfuscation won't hide intent.",
            Evidence = sb.ToString(),
            Remediation = sbOff ? "Set EnableScriptBlockLogging=1 at minimum." : ""
        });
    }

    private static void EventLogConfig(List<Finding> findings)
    {
        var key = @"SYSTEM\CurrentControlSet\Services\Eventlog\Security";
        var retention = Utils.GetRegHive(RegistryHive.LocalMachine, key, "Retention");
        var maxSize = Utils.GetRegHive(RegistryHive.LocalMachine, key, "MaxSize");
        findings.Add(new Finding
        {
            Id = "CFG-AUD-003",
            Category = "Audit & Logging",
            Title = "Security Event Log configuration",
            Severity = Severity.Info,
            Evidence = $"  Security MaxSize  : {(string.IsNullOrEmpty(maxSize) ? "default" : maxSize + " KB")}\n  Security Retention : {(string.IsNullOrEmpty(retention) ? "default" : retention)}",
            Description = "Small logs overwrite quickly; investigate retention vs. operational needs."
        });
    }

    private static void Sysmon(List<Finding> findings)
    {
        var found = false;
        try
        {
            using var sc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Sysmon");
            if (sc != null)
            {
                found = true;
                var img = sc.GetValue("ImagePath")?.ToString();
                var cfg = Utils.GetRegHive(RegistryHive.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Services\Sysmon\Parameters", "Config");
                findings.Add(new Finding
                {
                    Id = "CFG-AUD-004",
                    Category = "Audit & Logging",
                    Title = "Sysmon is installed",
                    Severity = Severity.Info,
                    Evidence = $"  ImagePath      : {img}\n  Config version : {cfg ?? "(n/a)"}",
                    Description = "Sysmon is running - process/network/image-load telemetry is captured. Adjust tradecraft accordingly."
                });
            }
        }
        catch { }
        if (!found)
        {
            findings.Add(new Finding
            {
                Id = "CFG-AUD-004",
                Category = "Audit & Logging",
                Title = "Sysmon is not installed",
                Severity = Severity.Medium,
                Description = "No Sysmon service present - no high-fidelity process-tree telemetry. Recommend deploying for detection coverage (also flagged to client)."
            });
        }
    }
}