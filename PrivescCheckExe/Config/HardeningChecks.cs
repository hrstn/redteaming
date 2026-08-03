using Microsoft.Win32;
using PrivescCheckExe.Core;

namespace PrivescCheckExe.Config;

/// <summary>Hardening baseline audit: LAPS, BitLocker, Defender/real-time, ASR, Exploit Protection, Firewall.</summary>
public static class HardeningChecks
{
    public static void Run(List<Finding> findings)
    {
        Laps(findings);
        BitLocker(findings);
        Defender(findings);
        AsrRules(findings);
        ExploitProtection(findings);
        Firewall(findings);
    }

    private static void Laps(List<Finding> findings)
    {
        // LAPS v1 (legacy): registry indicates policy presence; managed status best inferred from
        // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS (built-in LAPS on modern Windows)
        // and the legacy AdmPwd path.
        var builtin = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS", "BackupDirectory");
        var legacy = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SOFTWARE\Policies\Microsoft Services\AdmPwd", "AdmPwdEnabled");
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"  Built-in LAPS BackupDirectory : {builtin ?? "(not set)"}");
        sb.AppendLine($"  Legacy LAPS AdmPwdEnabled      : {legacy ?? "(not set)"}");

        if (string.IsNullOrEmpty(builtin) && legacy != "1")
        {
            findings.Add(new Finding
            {
                Id = "CFG-HARD-001",
                Category = "Hardening",
                Title = "No LAPS policy detected",
                Severity = Severity.High,
                Description = "Without LAPS, local Administrator passwords are identical/stale across machines - one compromise cascades laterally.",
                Evidence = sb.ToString(),
                Remediation = "Deploy Windows LAPS (built-in) or legacy Microsoft LAPS via GPO/Intune to randomize & back up the local admin password."
            });
        }
        else
        {
            findings.Add(new Finding
            {
                Id = "CFG-HARD-001",
                Category = "Hardening",
                Title = "LAPS appears configured",
                Severity = Severity.Info,
                Evidence = sb.ToString()
            });
        }
    }

    private static void BitLocker(List<Finding> findings)
    {
        var outp = Utils.Run("manage-bde.exe", "-status", 10000);
        if (string.IsNullOrWhiteSpace(outp))
        {
            findings.Add(new Finding { Id = "CFG-HARD-002", Category = "Hardening", Title = "manage-bde unavailable", Severity = Severity.Info });
            return;
        }
        bool isProtected = outp.Contains("Protection Status:    On", StringComparison.OrdinalIgnoreCase)
                      || outp.Contains("Protection Status:On", StringComparison.OrdinalIgnoreCase);
        var lines = outp.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => l.Length > 0).Take(12);
        findings.Add(new Finding
        {
            Id = "CFG-HARD-002",
            Category = "Hardening",
            Title = isProtected ? "BitLocker protection ON" : "BitLocker protection OFF (or not on system drive)",
            Severity = isProtected ? Severity.Info : Severity.High,
            Description = isProtected ? "" : "Drives without BitLocker expose plaintext data and offline-modification risk on physical access/loss.",
            Evidence = string.Join('\n', lines),
            Remediation = isProtected ? "" : "Enable BitLocker with TPM+PIN; back up recovery keys to AD/Entra."
        });
    }

    private static void Defender(List<Finding> findings)
    {
        // Real-time / anti-spyware state via registry (no WMI -> AOT-friendly).
        var disableRt = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring");
        var disableRtDword = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring");
        var disableAntiSpy = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows Defender", "DisableAntiSpyware");
        var disableAntiSpyPol = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware");

        bool rtOff = disableRt == "1" || disableRtDword == "1";
        bool spyOff = disableAntiSpy == "1" || disableAntiSpyPol == "1";

        findings.Add(new Finding
        {
            Id = "CFG-HARD-003",
            Category = "Hardening",
            Title = rtOff ? "Defender real-time protection is disabled" : "Defender real-time protection is ON",
            Severity = rtOff ? Severity.Medium : Severity.Info,
            Description = rtOff ? "On-access scanning is off - files execute without immediate scanning." : "",
            Evidence = $"  DisableRealtimeMonitoring (reg)  : {disableRt ?? "(unset)"}\n  DisableRealtimeMonitoring (policy): {disableRtDword ?? "(unset)"}",
            Remediation = rtOff ? "Re-enable real-time monitoring unless intentionally disabled for sanctioned testing." : ""
        });

        if (spyOff)
        {
            findings.Add(new Finding
            {
                Id = "CFG-HARD-004",
                Category = "Hardening",
                Title = "Defender / anti-spyware engine appears disabled",
                Severity = Severity.Medium,
                Evidence = $"  DisableAntiSpyware (reg)   : {disableAntiSpy ?? "(unset)"}\n  DisableAntiSpyware (policy): {disableAntiSpyPol ?? "(unset)"}"
            });
        }
    }

    private static void AsrRules(List<Finding> findings)
    {
        var key = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
        var subkeys = Utils.GetRegSubKeys(RegistryHive.LocalMachine, key);
        if (subkeys == null || subkeys.Length == 0)
        {
            findings.Add(new Finding
            {
                Id = "CFG-HARD-005",
                Category = "Hardening",
                Title = "No Attack Surface Reduction (ASR) rules configured",
                Severity = Severity.Medium,
                Description = "ASR blocks common lolbins/Office macro execution paths. Absence raises phishing/macro-driven escalation risk."
            });
            return;
        }
        var sb = new System.Text.StringBuilder();
        foreach (var rule in subkeys)
        {
            using var rk = Registry.LocalMachine.OpenSubKey(key + "\\" + rule);
            var action = rk?.GetValue("Action")?.ToString();
            sb.AppendLine($"  {rule}  Action={action}");
        }
        findings.Add(new Finding
        {
            Id = "CFG-HARD-005",
            Category = "Hardening",
            Title = $"{subkeys.Length} ASR rule(s) configured",
            Severity = Severity.Info,
            Evidence = sb.ToString()
        });
    }

    private static void ExploitProtection(List<Finding> findings)
    {
        // System-wide Exploit Protection: registry SystemMitigation settings.
        var key = @"SYSTEM\CurrentControlSet\Control\Session Manager\kernel\ExploitProtection\ExploitProtectionFlags";
        var flags = Utils.GetRegHive(RegistryHive.LocalMachine, key, "");
        // The richer config is XML; report presence only.
        var setkey = @"SYSTEM\CurrentControlSet\Control\Session Manager\ExploitProtection";
        var sb = new System.Text.StringBuilder();
        using (var k = Registry.LocalMachine.OpenSubKey(setkey))
        {
            if (k != null)
                foreach (var v in k.GetValueNames())
                    sb.AppendLine($"  {v} = {k.GetValue(v)}");
        }
        if (sb.Length == 0)
        {
            findings.Add(new Finding
            {
                Id = "CFG-HARD-006",
                Category = "Hardening",
                Title = "System-wide Exploit Protection not configured",
                Severity = Severity.Low,
                Description = "No custom system Exploit Protection mitigations applied (CFG, DEP, ASLR, etc.)."
            });
        }
        else
        {
            findings.Add(new Finding { Id = "CFG-HARD-006", Category = "Hardening", Title = "System-wide Exploit Protection configured", Severity = Severity.Info, Evidence = sb.ToString() });
        }
    }

    private static void Firewall(List<Finding> findings)
    {
        var outp = Utils.Run("netsh.exe", "advfirewall show allprofiles state", 10000);
        if (string.IsNullOrWhiteSpace(outp)) return;
        var lines = outp.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Trim()).ToArray();
        var sb = new System.Text.StringBuilder();
        bool anyOff = false;
        for (int i = 0; i < lines.Length; i++)
        {
            if (lines[i].Contains("Profile", StringComparison.OrdinalIgnoreCase))
            {
                var prof = lines[i];
                var status = (i + 1 < lines.Length && lines[i + 1].StartsWith("State", StringComparison.OrdinalIgnoreCase)) ? lines[i + 1] : "";
                sb.AppendLine($"  {prof}");
                sb.AppendLine($"    {status}");
                if (status.Contains("OFF", StringComparison.OrdinalIgnoreCase)) anyOff = true;
            }
        }
        findings.Add(new Finding
        {
            Id = "CFG-HARD-007",
            Category = "Hardening",
            Title = anyOff ? "One or more firewall profiles are disabled" : "All firewall profiles enabled",
            Severity = anyOff ? Severity.High : Severity.Info,
            Description = anyOff ? "A disabled profile increases exposed attack surface on that network class." : "",
            Evidence = sb.ToString(),
            Remediation = anyOff ? "Re-enable the disabled profile(s): netsh advfirewall set <profile> state on" : ""
        });
    }
}