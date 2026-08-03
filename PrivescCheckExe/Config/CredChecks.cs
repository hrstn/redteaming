using Microsoft.Win32;
using PrivescCheckExe.Core;

namespace PrivescCheckExe.Config;

/// <summary>Credentials & tokens: Credential Manager, saved RDP files, browser-stored creds, autologon, recent commands.</summary>
public static class CredChecks
{
    public static void Run(List<Finding> findings)
    {
        CredentialManager(findings);
        SavedRdp(findings);
        BrowserCreds(findings);
        AutoLogon(findings);
        RecentCommands(findings);
    }

    private static void CredentialManager(List<Finding> findings)
    {
        // cmdkey /list enumerates stored credentials (Generic + Domain + Windows).
        var outp = Utils.Run("cmdkey.exe", "/list", 8000);
        if (string.IsNullOrWhiteSpace(outp)) return;
        var entries = outp.Split(new[] { "Target:", "\r\n\r\n" }, StringSplitOptions.None);
        int count = outp.Split("Target:", StringSplitOptions.RemoveEmptyEntries).Length - 1;
        if (count <= 0 && !outp.Contains("Credential", StringComparison.OrdinalIgnoreCase)) return;

        findings.Add(new Finding
        {
            Id = "CFG-CRED-001",
            Category = "Creds & Tokens",
            Title = "Stored credentials in Credential Manager",
            Severity = Severity.High,
            Description = "Saved credentials can be abused by an attacker (e.g. via runas /savecred or local secret extraction).",
            Evidence = outp,
            Remediation = "Review whether saved creds are necessary; they can be retrieved via the CredEnumerate API under the user context."
        });
    }

    private static void SavedRdp(List<Finding> findings)
    {
        var sb = new System.Text.StringBuilder();
        int count = 0;
        foreach (var baseDir in new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Terminal Server Client", "Default"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Terminal Server Client", "Servers")
        })
        {
            if (!Directory.Exists(baseDir)) continue;
            foreach (var f in Directory.GetFiles(baseDir, "*.*", SearchOption.AllDirectories))
            {
                sb.AppendLine($"  {f}");
                count++;
                // .rdp files may contain password hash
                if (f.EndsWith(".rdp", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var c = File.ReadAllText(f);
                        if (c.Contains("password 51:b:", StringComparison.OrdinalIgnoreCase) || c.Contains("password", StringComparison.OrdinalIgnoreCase))
                            sb.AppendLine("    -> contains a saved password (hashed) field");
                    }
                    catch { }
                }
            }
        }
        if (count > 0)
        {
            findings.Add(new Finding
            {
                Id = "CFG-CRED-002",
                Category = "Creds & Tokens",
                Title = "Saved RDP connection files found",
                Severity = Severity.Medium,
                Description = "Saved RDP files reveal target hosts and may include an encrypted password hash (password 51:b:).",
                Evidence = sb.ToString(),
                Remediation = "Parse the password hash and crack via tools that support RDP saved-cred format."
            });
        }
    }

    private static void BrowserCreds(List<Finding> findings)
    {
        var sb = new System.Text.StringBuilder();
        // Chrome / Edge login-data paths (user-key encrypted but worth noting).
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var candidates = new[]
        {
            Path.Combine(localApp, "Google", "Chrome", "User Data", "Default", "Login Data"),
            Path.Combine(localApp, "Microsoft", "Edge", "User Data", "Default", "Login Data"),
            Path.Combine(localApp, "Google", "Chrome", "User Data", "Default", "Cookies"),
            Path.Combine(localApp, "Microsoft", "Edge", "User Data", "Default", "Cookies")
        };
        bool found = false;
        foreach (var c in candidates)
        {
            if (File.Exists(c))
            {
                sb.AppendLine($"  {c}");
                found = true;
            }
        }
        if (found)
        {
            findings.Add(new Finding
            {
                Id = "CFG-CRED-003",
                Category = "Creds & Tokens",
                Title = "Chromium-based browser credential/cookie stores present",
                Severity = Severity.Medium,
                Description = "Login Data (encrypted under the user key) holds saved passwords; Cookies hold session tokens. Decrypted using the user's local key material.",
                Evidence = sb.ToString(),
                Remediation = "Use appropriate credential-access tooling under the user context to decrypt the stores."
            });
        }
    }

    private static void AutoLogon(List<Finding> findings)
    {
        var key = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        var username = Utils.GetRegHive(RegistryHive.LocalMachine, key, "DefaultUserName");
        var password = Utils.GetRegHive(RegistryHive.LocalMachine, key, "DefaultPassword");
        if (string.IsNullOrWhiteSpace(username)) return;
        findings.Add(new Finding
        {
            Id = "CFG-CRED-004",
            Category = "Creds & Tokens",
            Title = "AutoLogon configured (credentials in registry)",
            Severity = string.IsNullOrWhiteSpace(password) ? Severity.Medium : Severity.Critical,
            Description = "DefaultUserName/DefaultPassword in Winlogon are plaintext credentials usable for lateral movement.",
            Evidence = $"  DefaultUserName : {username}\n  DefaultPassword : {(string.IsNullOrWhiteSpace(password) ? "(empty / LSA-encrypted)" : password)}",
            Remediation = "Disable AutoLogon or at minimum remove the plaintext DefaultPassword value."
        });
    }

    private static void RecentCommands(List<Finding> findings)
    {
        // PSReadLine history - may contain secrets typed interactively.
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var history = Path.Combine(appdata, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
        if (File.Exists(history))
        {
            try
            {
                var lines = File.ReadAllLines(history);
                var sb = new System.Text.StringBuilder();
                foreach (var l in lines.Take(40))
                    sb.AppendLine("  " + l);
                findings.Add(new Finding
                {
                    Id = "CFG-CRED-005",
                    Category = "Creds & Tokens",
                    Title = "PowerShell command history present",
                    Severity = Severity.Medium,
                    Description = "PSReadLine history may contain secrets, tokens, or passwords typed at the console. (First 40 lines shown.)",
                    Evidence = sb.ToString(),
                    Remediation = "Grep history for password/token patterns; useful for credential discovery."
                });
            }
            catch { }
        }
    }
}