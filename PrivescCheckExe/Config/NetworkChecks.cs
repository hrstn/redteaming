using Microsoft.Win32;
using PrivescCheckExe.Core;

namespace PrivescCheckExe.Config;

/// <summary>Network & service exposure: listening ports, service binary paths, SMB, RDP, WinRM, shares.</summary>
public static class NetworkChecks
{
    public static void Run(List<Finding> findings)
    {
        ListeningPorts(findings);
        ServiceBinaries(findings);
        Smb(findings);
        Rdp(findings);
        Winrm(findings);
        Shares(findings);
    }

    private static void ListeningPorts(List<Finding> findings)
    {
        var outp = Utils.Run("netstat.exe", "-ano -p tcp", 10000);
        if (string.IsNullOrWhiteSpace(outp)) return;
        var sb = new System.Text.StringBuilder();
        foreach (var line in outp.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var t = line.Trim();
            if (!t.StartsWith("TCP", StringComparison.OrdinalIgnoreCase)) continue;
            if (!t.Contains("LISTENING", StringComparison.OrdinalIgnoreCase)) continue;
            sb.AppendLine("  " + t);
        }
        if (sb.Length > 0)
        {
            findings.Add(new Finding
            {
                Id = "CFG-NET-001",
                Category = "Network",
                Title = "Listening TCP ports",
                Severity = Severity.Medium,
                Description = "Map PIDs to services (next check). Local services with bindings to 0.0.0.0 may be reachable across the network for remote exploitation.",
                Evidence = sb.ToString()
            });
        }
    }

    private static void ServiceBinaries(List<Finding> findings)
    {
        var services = NativeServices.EnumerateWin32Services();
        var sb = new System.Text.StringBuilder();
        int count = 0;
        foreach (var svc in services)
        {
            if (string.IsNullOrWhiteSpace(svc.BinaryPath)) continue;
            sb.AppendLine($"  {svc.Name,-28} {svc.State,-10} {svc.BinaryPath}");
            count++;
        }
        if (count > 0)
        {
            findings.Add(new Finding
            {
                Id = "CFG-NET-002",
                Category = "Network",
                Title = $"{count} running/installed service(s) with binary paths",
                Severity = Severity.Info,
                Description = "Review binaries for unsigned/old/custom services. Combined with the Services checks above, look for replaceable paths.",
                Evidence = sb.ToString()
            });
        }
    }

    private static void Smb(List<Finding> findings)
    {
        var sb = new System.Text.StringBuilder();
        var smb1 = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
        var enableSmb2 = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableSMB2");
        sb.AppendLine($"  SMB1         : {(string.IsNullOrEmpty(smb1) ? "default(0)" : smb1)}");
        sb.AppendLine($"  EnableSMB2   : {(string.IsNullOrEmpty(enableSmb2) ? "default(1)" : enableSmb2)}");

        var requireSign = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature");
        sb.AppendLine($"  Server signing required : {requireSign ?? "(default 0)"}");

        if (smb1 == "1")
        {
            findings.Add(new Finding
            {
                Id = "CFG-NET-003",
                Category = "Network",
                Title = "SMB1 protocol enabled",
                Severity = Severity.High,
                Description = "SMB1 is legacy, vulnerable to EternalBlue-class exploits and supports weak signing.",
                Evidence = sb.ToString(),
                Remediation = "Set SMB1=0; modern Windows uses SMB2/3 with mandatory signing."
            });
        }
        else
        {
            findings.Add(new Finding { Id = "CFG-NET-003", Category = "Network", Title = "SMB configuration", Severity = Severity.Info, Evidence = sb.ToString() });
        }
    }

    private static void Rdp(List<Finding> findings)
    {
        var enabled = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
        var nla = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
        var secLayer = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "SecurityLayer");
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"  fDenyTSConnections : {enabled ?? "(0 = RDP on)"}");
        sb.AppendLine($"  SecurityLayer      : {secLayer ?? "(default)"}");
        sb.AppendLine($"  UserAuthentication (NLA): {nla ?? "(default)"}");
        findings.Add(new Finding
        {
            Id = "CFG-NET-004",
            Category = "Network",
            Title = enabled == "0" ? "RDP is enabled" : "RDP is disabled",
            Severity = enabled == "0" ? Severity.Medium : Severity.Info,
            Description = enabled == "0" ? "RDP enabled - check NLA/SecurityLayer (0=legacy RDP, 1=negotiate, 2=TLS). Weak configs enable BlueKeep/MITM." : "",
            Evidence = sb.ToString(),
            Remediation = enabled == "0" ? "Ensure NLA required and SecurityLayer=2 (TLS)." : ""
        });
    }

    private static void Winrm(List<Finding> findings)
    {
        var enabled = Utils.GetRegHive(RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service", "config\\Automatic");
        var outp = Utils.Run("winrm.exe", "get winrm/config/service", 6000);
        var allowUnencrypted = outp.Contains("AllowUnencrypted = true", StringComparison.OrdinalIgnoreCase);
        var sb = new System.Text.StringBuilder();
        if (!string.IsNullOrWhiteSpace(outp))
            foreach (var line in outp.Split('\n', StringSplitOptions.RemoveEmptyEntries).Take(10))
                sb.AppendLine("  " + line.Trim());
        findings.Add(new Finding
        {
            Id = "CFG-NET-005",
            Category = "Network",
            Title = allowUnencrypted ? "WinRM allows unencrypted traffic" : "WinRM service configuration",
            Severity = allowUnencrypted ? Severity.High : Severity.Info,
            Description = allowUnencrypted ? "AllowUnencrypted=true exposes credentials to network sniffing." : "",
            Evidence = sb.ToString(),
            Remediation = allowUnencrypted ? "Set AllowUnencrypted=false; require encryption." : ""
        });
    }

    private static void Shares(List<Finding> findings)
    {
        var outp = Utils.Run("net.exe", "share", 6000);
        if (string.IsNullOrWhiteSpace(outp)) return;
        var sb = new System.Text.StringBuilder();
        foreach (var line in outp.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.Trim()))
            sb.AppendLine("  " + line);
        findings.Add(new Finding
        {
            Id = "CFG-NET-006",
            Category = "Network",
            Title = "Configured shares",
            Severity = Severity.Low,
            Description = "Review non-default shares and their ACLs; writable shares are lateral-movement + drop points.",
            Evidence = sb.ToString()
        });
    }
}