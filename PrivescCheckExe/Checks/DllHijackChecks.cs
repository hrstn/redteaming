using PrivescCheckExe.Core;

namespace PrivescCheckExe.Checks;

/// <summary>
/// DLL hijacking opportunities: writable directories on PATH (and System32 adjacent),
/// plus writable directories containing known auto-elevated binaries.
/// </summary>
public static class DllHijackChecks
{
    public static void Run(List<Finding> findings)
    {
        WritablePathDirs(findings);
        SystemPathWritable(findings);
    }

    /// <summary>Any writable directory on the PATH can be used to shadow a planted DLL.</summary>
    private static void WritablePathDirs(List<Finding> findings)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        var sb = new System.Text.StringBuilder();
        bool found = false;
        foreach (var dir in Utils.SafeSplitPath(path))
        {
            if (!Directory.Exists(dir)) continue;
            if (Utils.IsWritable(dir))
            {
                found = true;
                sb.AppendLine($"  {dir}");
            }
        }
        if (found)
        {
            findings.Add(new Finding
            {
                Id = "DLL-001",
                Category = "DLL Hijacking",
                Title = "Writable directories present on PATH",
                Severity = Severity.Medium,
                Description = "A PATH entry writable by the current user enables DLL planting / executable shadowing for any process that resolves from PATH.",
                Evidence = sb.ToString(),
                Remediation = "Place a replacement library (or shadowing executable) named to match a target process's search order."
            });
        }
    }

    /// <summary>Is %SystemRoot%\\System32 itself (or a sibling) writable? Rare but critical.</summary>
    private static void SystemPathWritable(List<Finding> findings)
    {
        var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);   // System32
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);  // Windows
        foreach (var d in new[] { sys, win })
        {
            if (!string.IsNullOrWhiteSpace(d) && Utils.IsWritable(d))
            {
                findings.Add(new Finding
                {
                    Id = "DLL-002",
                    Category = "DLL Hijacking",
                    Title = $"Critical Windows directory is writable: {d}",
                    Severity = Severity.Critical,
                    Description = "The current user can write into a core Windows directory.",
                    Remediation = "Replace any auto-elevated/SYSTEM binary or drop a DLL in this folder."
                });
            }
        }
    }
}