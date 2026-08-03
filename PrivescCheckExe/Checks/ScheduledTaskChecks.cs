using PrivescCheckExe.Core;

namespace PrivescCheckExe.Checks;

/// <summary>Scheduled tasks whose action executable or working dir is writable by current user.</summary>
public static class ScheduledTaskChecks
{
    public static void Run(List<Finding> findings)
    {
        var xml = Utils.Run("schtasks.exe", "/query /fo csv /nh /v", 12000);
        if (string.IsNullOrWhiteSpace(xml)) return;

        // CSV columns include: TaskName, NextRun, LastRun, LastResult, Creator, Schedule, Task To Run, Run As User
        var lines = xml.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var cols = CsvSplit(line);
            if (cols.Length < 15) continue;
            var taskToRun = cols.Length > 7 ? cols[7]?.Trim().Trim('"') : "";
            var taskName  = cols[0]?.Trim().Trim('"');
            var runAs     = cols.Length > 14 ? cols[14]?.Trim().Trim('"') : "";
            if (string.IsNullOrWhiteSpace(taskToRun)) continue;
            // skip built-in powershell/cmd wrappers pointing only at system32
            if (taskToRun.Contains("\\System32\\", StringComparison.OrdinalIgnoreCase)
                && !taskToRun.Contains(" ", StringComparison.Ordinal)) continue;

            var bin = RegistryChecks.ExtractFirstPath(taskToRun) ?? ServiceChecks.ExtractServiceBinary(taskToRun);
            if (string.IsNullOrWhiteSpace(bin)) continue;
            if (Utils.IsWritable(bin))
            {
                findings.Add(new Finding
                {
                    Id = "TASK-001",
                    Category = "Scheduled Tasks",
                    Title = "Scheduled task action binary is writable",
                    Severity = Severity.High,
                    Description = $"Task '{taskName}' runs '{bin}' which you can overwrite.",
                    Evidence = $"  Task     : {taskName}\n  Action   : {taskToRun}\n  Run As   : {runAs}",
                    Remediation = "Replace the binary; the task will run your alternate with the task's account context (often elevated)."
                });
            }
        }
    }

    private static string[] CsvSplit(string line)
    {
        var result = new System.Collections.Generic.List<string>();
        var cur = new System.Text.StringBuilder();
        bool inQuotes = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { cur.Append('"'); i++; }
                    else inQuotes = false;
                }
                else cur.Append(c);
            }
            else
            {
                if (c == '"') inQuotes = true;
                else if (c == ',') { result.Add(cur.ToString()); cur.Clear(); }
                else cur.Append(c);
            }
        }
        result.Add(cur.ToString());
        return result.ToArray();
    }
}