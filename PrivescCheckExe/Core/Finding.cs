namespace PrivescCheckExe.Core;

public enum Severity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public class Finding
{
    public string Id { get; set; } = "";
    public string Category { get; set; } = "";
    public string Title { get; set; } = "";
    public Severity Severity { get; set; } = Severity.Info;
    public string Description { get; set; } = "";
    public string Evidence { get; set; } = "";
    public string Remediation { get; set; } = "";

    public ConsoleColor Color => Severity switch
    {
        Severity.Critical => ConsoleColor.Red,
        Severity.High => ConsoleColor.Magenta,
        Severity.Medium => ConsoleColor.Yellow,
        Severity.Low => ConsoleColor.Cyan,
        _ => ConsoleColor.Gray
    };
}