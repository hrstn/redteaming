using System.Diagnostics;
using System.Runtime.InteropServices;
using PrivescCheckExe.Core;

namespace PrivescCheckExe.Checks;

/// <summary>Current user identity, integrity, group memberships and token privileges (whoami /priv /groups equivalent).</summary>
public static class TokenChecks
{
    public static void Run(List<Finding> findings)
    {
        // Identity & integrity
        bool admin = Utils.IsAdmin();
        findings.Add(new Finding
        {
            Id = "TOKEN-001",
            Category = "User & Token",
            Title = admin ? "Running with HIGH integrity (Administrator)" : "Running with MEDIUM integrity (non-admin)",
            Severity = admin ? Severity.High : Severity.Info,
            Description = $"Current user: {Environment.UserDomainName}\\{Environment.UserName}",
            Evidence = admin ? "Token is elevated. Local privilege escalation may be unnecessary." : "If a finding grants a privilege, consider exploiting it before further checks."
        });

        // Group memberships via whoami
        var groups = Utils.Run("whoami.exe", "/groups /fo csv /nh");
        if (!string.IsNullOrWhiteSpace(groups))
        {
            var interesting = groups
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Where(l => l.Contains("Administrators", StringComparison.OrdinalIgnoreCase)
                         || l.Contains("Backup Operators", StringComparison.OrdinalIgnoreCase)
                         || l.Contains("Server Operators", StringComparison.OrdinalIgnoreCase)
                         || l.Contains("Hyper-V Administrators", StringComparison.OrdinalIgnoreCase)
                         || l.Contains("Print Operators", StringComparison.OrdinalIgnoreCase)
                         || l.Contains("Event Log Readers", StringComparison.OrdinalIgnoreCase))
                .Select(l => l.Trim())
                .ToArray();
            if (interesting.Length > 0)
            {
                findings.Add(new Finding
                {
                    Id = "TOKEN-002",
                    Category = "User & Token",
                    Title = "Current user is a member of a privileged group",
                    Severity = Severity.High,
                    Description = "Privileged group membership can be leveraged for local privesc.",
                    Evidence = string.Join('\n', interesting)
                });
            }
        }

        // Privileges via whoami /priv
        var privs = Utils.Run("whoami.exe", "/priv");
        if (!string.IsNullOrWhiteSpace(privs))
        {
            var dangerPrivs = new[]
            {
                "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeDebugPrivilege",
                "SeTcbPrivilege", "SeCreateTokenPrivilege", "SeLoadDriverPrivilege",
                "SeRestorePrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege",
                "SeManageVolumePrivilege", "SeSecurityPrivilege", "SeRelabelPrivilege",
                "SeTrustedCredManAccessPrivilege"
            };
            var lines = privs.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            var sb = new System.Text.StringBuilder();
            foreach (var priv in dangerPrivs)
            {
                var hit = Array.Find(lines, l => l.Contains(priv, StringComparison.OrdinalIgnoreCase));
                if (hit != null)
                {
                    var enabled = hit.Contains("Enabled", StringComparison.OrdinalIgnoreCase);
                    sb.AppendLine($"{hit.Trim()}{(enabled ? "  [ENABLED]" : "  [disabled]")}");
                }
            }
            if (sb.Length > 0)
            {
                findings.Add(new Finding
                {
                    Id = "TOKEN-003",
                    Category = "User & Token",
                    Title = "Dangerous privileges present on current token",
                    Severity = Severity.Critical,
                    Description = "These privileges are directly exploitable for local privilege escalation.",
                    Evidence = sb.ToString(),
                    Remediation = "SeImpersonate -> Potato family. SeDebug -> inject into SYSTEM process. SeLoadDriver -> load a signed vulnerable driver. SeTakeOwnership -> own a SYSTEM binary then replace it."
                });
            }
        }
    }
}