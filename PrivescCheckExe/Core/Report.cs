using System.Text;

namespace PrivescCheckExe.Core;

/// <summary>
/// Colored console output + TXT and CSV report files written next to the exe.
/// </summary>
public static class Report
{
    public static string TxtPath { get; private set; } = "";
    public static string CsvPath { get; private set; } = "";
    public static string Host { get; private set; } = "";
    public static string User { get; private set; } = "";

    public static void InitPaths()
    {
        Host = Environment.MachineName;
        User = $"{Environment.UserDomainName}\\{Environment.UserName}";
        var dir = AppContext.BaseDirectory;
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        TxtPath = Path.Combine(dir, $"HostAudit_{Host}_{stamp}.txt");
        CsvPath = Path.Combine(dir, $"HostAudit_{Host}_{stamp}.csv");
    }

    public static void Banner()
    {
        Console.WriteLine();
        WriteLine("HostAudit  -  host security & configuration audit", ConsoleColor.White);
        WriteLine($"Host: {Host}    User: {User}    Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}", ConsoleColor.DarkGray);
        WriteLine("For authorized pentest use only.", ConsoleColor.DarkGray);
        Console.WriteLine();
    }

    public static void Section(string title)
    {
        Console.WriteLine();
        WriteLine($"[*] {title}", ConsoleColor.Green);
        WriteLine(new string('-', 78), ConsoleColor.DarkGreen);
    }

    public static void Print(Finding f)
    {
        var sev = $"[{f.Severity.ToString().ToUpper()}]";
        WriteLine($"{sev} {f.Title}", f.Color);
        if (!string.IsNullOrWhiteSpace(f.Description))
            WriteLine($"    {f.Description}", ConsoleColor.DarkGray);
        if (!string.IsNullOrWhiteSpace(f.Evidence))
        {
            foreach (var line in f.Evidence.Replace("\r", "").Split('\n'))
                WriteLine($"      {line}", ConsoleColor.Gray);
        }
        if (!string.IsNullOrWhiteSpace(f.Remediation))
            WriteLine($"    -> Remediation: {f.Remediation}", ConsoleColor.DarkCyan);
        Console.WriteLine();
    }

    public static void Summary(List<Finding> findings)
    {
        Console.WriteLine();
        WriteLine($"[=] Done. {findings.Count} finding(s).", ConsoleColor.White);
        var bySev = findings.GroupBy(f => f.Severity)
            .OrderBy(g => g.Key);
        foreach (var g in bySev)
            WriteLine($"    {g.Key}: {g.Count()}", ConsoleColor.Gray);
        WriteLine($"[+] TXT report : {TxtPath}", ConsoleColor.Green);
        WriteLine($"[+] CSV report : {CsvPath}", ConsoleColor.Green);
    }

    public static void WriteFiles(List<Finding> findings)
    {
        var sb = new StringBuilder();
        sb.AppendLine("HostAudit - host security & configuration audit");
        sb.AppendLine($"Host: {Host}  User: {User}  Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();
        foreach (var f in findings)
        {
            sb.AppendLine($"[{f.Severity.ToString().ToUpper()}] {f.Id} - {f.Title}");
            sb.AppendLine($"  Category  : {f.Category}");
            if (!string.IsNullOrWhiteSpace(f.Description)) sb.AppendLine($"  Detail    : {f.Description}");
            if (!string.IsNullOrWhiteSpace(f.Evidence))    sb.AppendLine($"  Evidence  :\n{Indent(f.Evidence)}");
            if (!string.IsNullOrWhiteSpace(f.Remediation)) sb.AppendLine($"  Remediate : {f.Remediation}");
            sb.AppendLine();
        }
        File.WriteAllText(TxtPath, sb.ToString(), Encoding.UTF8);

        var csv = new StringBuilder();
        csv.AppendLine("Id,Category,Title,Severity,Description,Evidence,Remediation");
        foreach (var f in findings)
            csv.AppendLine(string.Join(',',
                Esc(f.Id), Esc(f.Category), Esc(f.Title), f.Severity,
                Esc(f.Description), Esc(f.Evidence), Esc(f.Remediation)));
        File.WriteAllText(CsvPath, csv.ToString(), Encoding.UTF8);
    }

    private static string Indent(string s)
    {
        var lines = s.Replace("\r", "").Split('\n');
        return string.Join('\n', lines.Select(l => "    " + l));
    }

    private static string Esc(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) < 0) return s;
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    public static void WriteLine(string s, ConsoleColor c)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = c;
        Console.WriteLine(s);
        Console.ForegroundColor = prev;
    }

    public static void WriteLine(string s)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine(s);
        Console.ForegroundColor = prev;
    }
}