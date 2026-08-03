using PrivescCheckExe.Core;
using PrivescCheckExe.Checks;
using PrivescCheckExe.Config;

namespace PrivescCheckExe;

internal static class Program
{
    private static int Main(string[] args)
    {
        // Honor --silent (report file only) and --console-only if passed.
        var silent = Array.Exists(args, a => a.Equals("--silent", StringComparison.OrdinalIgnoreCase));
        var consoleOnly = Array.Exists(args, a => a.Equals("--console-only", StringComparison.OrdinalIgnoreCase));
        if (silent)
        {
            Console.SetOut(TextWriter.Null);
            Console.SetError(TextWriter.Null);
        }

        Report.InitPaths();
        if (!silent) Report.Banner();

        var findings = new List<Finding>();

        // Groups of checks. Each runs independently.
        var groups = new (string Title, Action<List<Finding>> Run)[]
        {
            ("User & Token",                 TokenChecks.Run),
            ("UAC & Misc Registry",           RegistryChecks.Run),
            ("Services",                      ServiceChecks.Run),
            ("DLL Hijacking / PATH",          DllHijackChecks.Run),
            ("Scheduled Tasks",               ScheduledTaskChecks.Run),
            ("Installed Software & Patches",  SoftwareChecks.Run),
            ("WSUS / Updates",                 SoftwareChecks.RunWsus),
            // Configuration issues (beyond PrivescCheck)
            ("Config: Hardening Baselines",   HardeningChecks.Run),
            ("Config: Audit & Logging",       AuditLoggingChecks.Run),
            ("Config: Network & Services",    NetworkChecks.Run),
            ("Config: Creds & Tokens",        CredChecks.Run),
        };

        foreach (var (title, run) in groups)
        {
            if (!silent) Report.Section(title);
            int before = findings.Count;
            try { run(findings); }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Id = "RUNNER-ERR",
                    Category = title,
                    Title = $"Check group '{title}' threw an exception",
                    Severity = Severity.Info,
                    Description = ex.Message
                });
            }
            if (!silent && findings.Count == before)
                Report.WriteLine("    (no findings)");
        }

        // Sort by severity (critical first), then category.
        findings = findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Category)
            .ToList();

        if (!silent) Report.Section("Findings Summary");
        if (!silent)
        {
            foreach (var f in findings) Report.Print(f);
            Report.Summary(findings);
        }

        if (!consoleOnly)
            Report.WriteFiles(findings);
        else if (!silent)
            Report.WriteLine("[i] --console-only: skipping report files.", ConsoleColor.DarkGray);

        return 0;
    }
}