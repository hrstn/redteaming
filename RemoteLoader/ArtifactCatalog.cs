// ArtifactCatalog.cs -- discovery/normalization/resolution for the interactive
// RemoteLoader artifact browser. Pure data + logic, no I/O. The REPL
// (ArtifactCli.cs) drives this; RemoteLoader.cs feeds it the raw GitHub
// listing and an executor callback.
//
// Responsibilities (kept separate on purpose):
//   * NormalizeArtifactCommandName   -- filename -> clean command alias
//   * ParseArchitecture               -- filename -> arch label (best effort)
//   * ArtifactCatalog.Build           -- raw listing -> catalog w/ aliases
//   * ArtifactCatalog.Resolve         -- alias/substring -> entry (or ambiguous)
//
// Resolution rules keep built-in REPL commands (help/list/exit/...) reserved:
// an artifact that normalizes to a reserved word is only reachable via the
// explicit `run <alias>` / `use <alias>` path, never via a bare alias.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace RemoteLoader
{
    public enum ArtifactKind { Exe, Dll, Bof }

    public sealed class ArtifactEntry
    {
        // Stable 1-based number shown in `list` (matches the legacy menu).
        public int Index { get; internal set; }

        public string OriginalName { get; } = "";
        public string DownloadUrl { get; } = "";
        public string Branch { get; } = "";
        public ArtifactKind Kind { get; }
        public string KindLabel { get; }   // "exe" / "dll" / "o"
        public string? Arch { get; }       // x64/x86/amd64/arm64/... or null
        public long Size { get; }

        // The normalized short command name, e.g. "bofkatz".
        public string CommandName { get; }

        // Specific disambiguator alias assigned only when the short name
        // collides, e.g. "tool-x64". null when the short name is unambiguous.
        public string? SpecificAlias { get; internal set; }

        // Convenience: what to show in the `list` alias column.
        public string PrimaryAlias =>
            string.IsNullOrEmpty(SpecificAlias) ? CommandName : SpecificAlias!;

        // Every alias string that resolves back to this entry (short name +
        // specific alias). The short name is always present so an ambiguous
        // `tool` typed by the user surfaces as "ambiguous" rather than silently
        // resolving to one of the variants.
        public List<string> Aliases { get; } = new();

        public string DisplayArch => string.IsNullOrEmpty(Arch) ? KindLabel : Arch!;

        public ArtifactEntry(string originalName, string downloadUrl, string branch,
            ArtifactKind kind, string kindLabel, string? arch, long size)
        {
            OriginalName = originalName;
            DownloadUrl   = downloadUrl;
            Branch        = branch;
            Kind          = kind;
            KindLabel     = kindLabel;
            Arch          = arch;
            Size          = size;
            CommandName   = ArtifactCatalog.NormalizeArtifactCommandName(originalName);
        }
    }

    public enum ResolveResultKind { None, Single, Ambiguous }

    public readonly struct ResolveResult
    {
        public ResolveResultKind Kind { get; init; }
        public ArtifactEntry?    Entry { get; init; }
        public IReadOnlyList<ArtifactEntry> Candidates { get; init; }

        public static readonly ResolveResult None = new() { Kind = ResolveResultKind.None };
        public static ResolveResult Single(ArtifactEntry e) => new() { Kind = ResolveResultKind.Single, Entry = e, Candidates = new[] { e } };
        public static ResolveResult Ambiguous(IReadOnlyList<ArtifactEntry> c) => new() { Kind = ResolveResultKind.Ambiguous, Candidates = c };

        public bool IsSingle  => Kind == ResolveResultKind.Single;
        public bool IsAmbiguous => Kind == ResolveResultKind.Ambiguous;
        public bool IsNone    => Kind == ResolveResultKind.None;
    }

    public static class ArtifactCatalog
    {
        // Built-in REPL verbs. A bare alias matching one of these is always
        // treated as a command, never an artifact. To reach an artifact whose
        // normalized name collides with one of these, use `run <alias>` /
        // `use <alias>`.
        private static readonly HashSet<string> ReservedCommands = new(StringComparer.OrdinalIgnoreCase)
        {
            "help", "list", "exit", "quit", "search", "run", "use", "info", "refresh", "back"
        };

        public static bool IsReservedCommand(string token) =>
            !string.IsNullOrEmpty(token) && ReservedCommands.Contains(token);

        // -- Architecture markers ------------------------------------------
        // Known architecture segments that appear before the `.o` suffix on
        // BOF object files. Best-effort: BofRunner only executes AMD64, but the
        // catalog lists every supported extension so the operator can see and
        // disambiguate them.
        private static readonly HashSet<string> ArchMarkers = new(StringComparer.OrdinalIgnoreCase)
        {
            "x64","x86","amd64","arm64","aarch64","arm","i386","i486","i586","i686"
        };

        private static readonly Regex ArchObjSuffix =
            new(@"\.(x64|x86|amd64|arm64|aarch64|arm|i386|i486|i586|i686)\.o$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        // -- public, unit-testable normalizer ------------------------------
        // Produces a clean, lowercase command alias from a filename. Strips
        // known executable/object suffixes and architecture markers, keeps
        // meaningful dots/dashes/underscores inside the base name, and never
        // returns an empty string.
        public static string NormalizeArtifactCommandName(string filename)
        {
            if (string.IsNullOrEmpty(filename))
                return "artifact";

            string name = filename;
            // Strip any directory component defensively (GitHub API names have
            // none, but a hand-supplied path should still normalise).
            int slash = name.LastIndexOfAny(new[] { '/', '\\' });
            if (slash >= 0 && slash < name.Length - 1) name = name[(slash + 1)..];

            string base_;
            // 1) architecture-qualified object file: foo.x64.o -> foo
            var m = ArchObjSuffix.Match(name);
            if (m.Success)
            {
                base_ = name[..m.Index];
            }
            else
            {
                // 2) plain known suffixes: .exe / .dll / .o (single trailing ext)
                int dot = name.LastIndexOf('.');
                if (dot > 0) base_ = name[..dot];
                else         base_ = name;
            }

            // 3) sanitize: keep [A-Za-z0-9._-]; collapse everything else (incl.
            //    whitespace and shell metacharacters) to a single dash.
            var sb = new StringBuilder(base_.Length);
            bool justDash = false;
            foreach (char c in base_)
            {
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')
                {
                    sb.Append(char.ToLowerInvariant(c));
                    justDash = false;
                }
                else
                {
                    if (!justDash) { sb.Append('-'); justDash = true; }
                }
            }
            string clean = sb.ToString().Trim('-', '.');

            // 4) never empty: fall back to an alnum-only slug of the whole name,
            //    then to a fixed placeholder.
            if (string.IsNullOrEmpty(clean))
            {
                string fallback = SanitizeAlphaNumeric(name);
                clean = string.IsNullOrEmpty(fallback) ? "artifact" : fallback;
            }
            return clean;
        }

        private static string SanitizeAlphaNumeric(string s)
        {
            var sb = new StringBuilder();
            foreach (char c in s)
                if (char.IsLetterOrDigit(c)) sb.Append(char.ToLowerInvariant(c));
            return sb.ToString();
        }

        // -- architecture parsing (unit-testable) ---------------------------
        public static string? ParseArchitecture(string filename)
        {
            if (string.IsNullOrEmpty(filename)) return null;
            var m = ArchObjSuffix.Match(filename);
            return m.Success ? m.Groups[1].Value.ToLowerInvariant() : null;
        }

        // -- kind / label helpers ------------------------------------------
        internal static (ArtifactKind kind, string label) Classify(string name)
        {
            if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return (ArtifactKind.Exe, "exe");
            if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return (ArtifactKind.Dll, "dll");
            return (ArtifactKind.Bof, "o");
        }

        // -- catalog construction -----------------------------------------
        // rawBinaries: the (Name, DownloadUrl, Size) tuples returned by the
        // existing ListBinaries() enumerator. We do NOT re-fetch here; the
        // refresh path calls back into RemoteLoader which re-lists and feeds
        // us fresh tuples.
        public static ArtifactCatalogInstance Build(
            string branch,
            IEnumerable<(string Name, string DownloadUrl, long Size)> rawBinaries)
        {
            var entries = new List<ArtifactEntry>();
            foreach (var b in rawBinaries)
            {
                var (kind, label) = Classify(b.Name);
                string? arch = ParseArchitecture(b.Name);
                var e = new ArtifactEntry(b.Name, b.DownloadUrl, branch, kind, label, arch, b.Size);
                entries.Add(e);
            }
            return Build(branch, entries);
        }

        // Second stage, testable directly from a pre-built entry list.
        public static ArtifactCatalogInstance Build(string branch, IReadOnlyList<ArtifactEntry> entries)
        {
            var cat = new ArtifactCatalogInstance(branch, entries);

            // Assign stable 1-based indices.
            for (int i = 0; i < entries.Count; i++)
                entries[i].Index = i + 1;

            // Group by short command name.
            var groups = entries.GroupBy(e => e.CommandName)
                                .ToDictionary(g => g.Key, g => g.ToList());

            var aliasMap = new Dictionary<string, List<ArtifactEntry>>(StringComparer.OrdinalIgnoreCase);
            void Register(string alias, ArtifactEntry e)
            {
                if (!aliasMap.TryGetValue(alias, out var list)) { list = new(); aliasMap[alias] = list; }
                if (!list.Contains(e)) list.Add(e);
            }

            foreach (var (shortName, group) in groups)
            {
                if (group.Count == 1)
                {
                    var e = group[0];
                    e.SpecificAlias = null;
                    e.Aliases.Clear();
                    e.Aliases.Add(shortName);
                    Register(shortName, e);
                }
                else
                {
                    // Collisions: assign a specific alias per entry (arch
                    // preferred, else kind label), then keep the short name as
                    // an ambiguous pointer into every variant so the user is
                    // prompted, never silently resolved.
                    var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var e in group)
                    {
                        string suffix = !string.IsNullOrEmpty(e.Arch) ? e.Arch! : e.KindLabel;
                        string specific = $"{shortName}-{suffix}";
                        int n = 2;
                        while (used.Contains(specific))
                        {
                            specific = $"{shortName}-{suffix}{n}";
                            n++;
                        }
                        used.Add(specific);
                        e.SpecificAlias = specific;
                        e.Aliases.Clear();
                        e.Aliases.Add(shortName);       // ambiguous pointer
                        e.Aliases.Add(specific);
                        Register(shortName, e);          // ambiguous -> all
                        Register(specific, e);           // unique -> one
                    }
                }
            }

            cat.SetAliasMap(aliasMap);
            return cat;
        }
    }

    // Mutable-enough container holding the built catalog + lookup map. Kept
    // separate from the static ArtifactCatalog so a REPL can hold a snapshot
    // and rebuild it on `refresh`.
    public sealed class ArtifactCatalogInstance
    {
        public string Branch { get; }
        public IReadOnlyList<ArtifactEntry> Entries { get; }
        private Dictionary<string, List<ArtifactEntry>>? _aliases;

        internal ArtifactCatalogInstance(string branch, IReadOnlyList<ArtifactEntry> entries)
        {
            Branch = branch;
            Entries = entries;
        }

        internal void SetAliasMap(Dictionary<string, List<ArtifactEntry>> map) => _aliases = map;

        public int Count => Entries.Count;

        // Resolve a 1-based number (as displayed in `list`).
        public ResolveResult ResolveNumber(int n)
        {
            if (n < 1 || n > Entries.Count) return ResolveResult.None;
            return ResolveResult.Single(Entries[n - 1]);
        }

        // Resolve a name token. `allowReserved`: when false (direct alias /
        // plain-number context) tokens equal to a built-in command never
        // resolve to an artifact; when true (`run`/`use` context) we look the
        // artifact up regardless so reserved-named artifacts are reachable.
        public ResolveResult Resolve(string token, bool allowReserved = false)
        {
            if (string.IsNullOrWhiteSpace(token)) return ResolveResult.None;
            if (!allowReserved && ArtifactCatalog.IsReservedCommand(token))
                return ResolveResult.None;

            string key = token.Trim();
            // exact alias match first
            if (_aliases!.TryGetValue(key, out var exact) && exact.Count > 0)
            {
                if (exact.Count == 1) return ResolveResult.Single(exact[0]);
                return ResolveResult.Ambiguous(exact);
            }

            // substring fallback across aliases + original filename + arch
            var hits = new List<ArtifactEntry>();
            foreach (var e in Entries)
            {
                bool match = e.OriginalName.IndexOf(key, StringComparison.OrdinalIgnoreCase) >= 0
                          || (e.Arch != null && e.Arch.IndexOf(key, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!match)
                {
                    foreach (var a in e.Aliases)
                        if (a.IndexOf(key, StringComparison.OrdinalIgnoreCase) >= 0) { match = true; break; }
                }
                if (match && !hits.Contains(e)) hits.Add(e);
            }
            if (hits.Count == 0) return ResolveResult.None;
            if (hits.Count == 1) return ResolveResult.Single(hits[0]);
            return ResolveResult.Ambiguous(hits);
        }

        // Exact-alias-only resolution: returns Single/Ambiguous only when `token`
        // is an exact (case-insensitive) alias key in the map. No substring
        // fallback. The REPL uses this for direct execution so a *partial* like
        // "bof" (which substring-matches "bofkatz") is NOT auto-executed --
        // partials are routed to the suggestion engine instead.
        public ResolveResult ResolveExact(string token, bool allowReserved = false)
        {
            if (string.IsNullOrWhiteSpace(token)) return ResolveResult.None;
            if (!allowReserved && ArtifactCatalog.IsReservedCommand(token))
                return ResolveResult.None;

            string key = token.Trim();
            if (_aliases != null && _aliases.TryGetValue(key, out var exact) && exact.Count > 0)
            {
                if (exact.Count == 1) return ResolveResult.Single(exact[0]);
                return ResolveResult.Ambiguous(exact);
            }
            return ResolveResult.None;
        }
        public IEnumerable<ArtifactEntry> Search(string term)
        {
            if (string.IsNullOrWhiteSpace(term)) return Entries;
            term = term.Trim();
            return Entries.Where(e =>
                e.OriginalName.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0 ||
                e.CommandName.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0 ||
                (e.Arch != null && e.Arch.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0) ||
                e.Aliases.Any(a => a.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0));
        }
    }
}
