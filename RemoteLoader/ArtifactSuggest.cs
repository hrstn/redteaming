// ArtifactSuggest.cs -- the terminal-independent command/alias suggestion
// engine for the `artifacts>` REPL. Pure logic, no I/O and no GitHub calls:
// it reads only the in-memory catalog. ArtifactCli calls SuggestCommands to
// decide what to show after the user submits a partial/unknown line.
//
// Design goals (from the spec):
//   * context-aware: bare input -> commands + aliases (top) / commands only
//     (active); after run/use/info -> aliases + numeric IDs; after search ->
//     nothing.
//   * matching priority: exact < prefix < substring < fuzzy(subsequence);
//     fuzzy only when there are no prefix matches.
//   * ordering: exact, then prefix, then substring, then fuzzy; within a tier
//     shorter-then-alphabetical.
//   * reserved command words stay reserved even if an artifact normalises to
//     one -- a reserved alias is never offered as a *bare* artifact suggestion
//     (it is reachable via `run <alias>`, hence included after run/use/info).
//   * capped result set with a "Showing N of M" hint.
//
// This engine is intentionally separate from the terminal so it stays unit
// testable. Real-time tab completion is not wired here; the REPL is built on
// TextReader.ReadLine() (so it is redirectable/injectable), so suggestions are
// surfaced after the user submits an incomplete line -- the fallback the spec
// permits when live tab completion is impractical.

using System;
using System.Collections.Generic;
using System.Linq;

namespace RemoteLoader
{
    public readonly struct SuggestionResult
    {
        public IReadOnlyList<string> Items { get; init; }
        public int TotalMatches { get; init; }
        public int Limit { get; init; }

        public bool HasMore => TotalMatches > Items.Count;

        public static readonly SuggestionResult Empty =
            new() { Items = Array.Empty<string>(), TotalMatches = 0, Limit = 0 };
    }

    public static class ArtifactSuggest
    {
        // Built-in REPL verbs, in their canonical (lowercase) form.
        public static readonly string[] BuiltInCommands =
        {
            "list", "help", "search", "info", "run", "use", "back", "refresh", "exit", "quit"
        };

        // Commands that take an artifact name/number as their first argument;
        // after these we suggest artifact aliases (+ numeric IDs).
        private static readonly HashSet<string> ArgCommands =
            new(StringComparer.OrdinalIgnoreCase) { "run", "use", "info" };

        private const int DefaultLimit = 10;

        // The testable suggestion function.
        //   input          : the full current line (no trailing newline)
        //   catalog        : the in-memory artifact catalog (may be null)
        //   activeArtifact : the active artifact, or null at the top prompt
        //   limit          : max items to return (default 10)
        public static SuggestionResult SuggestCommands(
            string input, ArtifactCatalogInstance? catalog, ArtifactEntry? active,
            int limit = DefaultLimit)
        {
            if (string.IsNullOrWhiteSpace(input) || catalog == null)
                return SuggestionResult.Empty;

            string line = input.Trim();
            if (line.Length == 0) return SuggestionResult.Empty;

            int sp = line.IndexOf(' ');
            if (sp < 0)
            {
                // Single token: commands (+ aliases at top level).
                IEnumerable<string> pool = active != null
                    ? BuiltInCommands
                    : BuiltInCommands
                        .Concat(ArtifactAliasCandidates(catalog, excludeReserved: true));
                return Rank(pool, line, limit);
            }

            // Has a space: context-sensitive argument suggestions.
            string cmd = line.Substring(0, sp);
            string rest = line.Substring(sp + 1).TrimStart();

            if (ArgCommands.Contains(cmd))
            {
                // After run/use/info: aliases (reserved-named included: reachable
                // via run/use) + numeric IDs when rest is a digit prefix.
                var pool = ArtifactAliasCandidates(catalog, excludeReserved: false)
                           .Concat(NumericCandidates(catalog, rest));
                return Rank(pool, rest, limit);
            }

            // After search (and any non-argument command) we offer nothing:
            // `search` keeps its own free-form behaviour, and we never want to
            // suggest artifacts for e.g. "list foo".
            return SuggestionResult.Empty;
        }

        // Distinct artifact alias strings. When excludeReserved is true, aliases
        // that collide with a reserved command word are dropped (they are only
        // reachable via explicit `run`/`use`).
        private static IEnumerable<string> ArtifactAliasCandidates(
            ArtifactCatalogInstance catalog, bool excludeReserved)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in catalog.Entries)
                foreach (var a in e.Aliases)
                    if (!excludeReserved || !ArtifactCatalog.IsReservedCommand(a))
                        set.Add(a);
            return set;
        }

        // Numeric IDs as "#<index> <alias>" for entries whose index starts with
        // `rest`. Only meaningful when rest is empty or all digits.
        private static IEnumerable<string> NumericCandidates(
            ArtifactCatalogInstance catalog, string rest)
        {
            bool allDigits = rest.Length > 0;
            if (rest.Length > 0)
            {
                foreach (char c in rest)
                    if (c < '0' || c > '9') { allDigits = false; break; }
            }
            // rest.Length == 0 -> suggest every index (after "run " etc.).
            if (rest.Length > 0 && !allDigits) return Enumerable.Empty<string>();

            var list = new List<string>();
            foreach (var e in catalog.Entries)
                if (rest.Length == 0 ||
                    e.Index.ToString().StartsWith(rest, StringComparison.Ordinal))
                    list.Add($"#{e.Index} {e.PrimaryAlias}");
            return list;
        }

        // Rank candidates against `target`: exact(0) < prefix(1) < substring(2)
        // < fuzzy(3). Fuzzy is only retained when there are no exact/prefix
        // matches. Within a tier: shorter first, then ordinal. Dedupe
        // (case-insensitive). Apply limit last.
        private static SuggestionResult Rank(IEnumerable<string> candidates, string target, int limit)
        {
            if (limit <= 0) limit = DefaultLimit;

            var scored = new List<(string Item, int Tier, int Len)>();
            foreach (var c in candidates)
            {
                int tier = MatchTier(c, target);
                if (tier < 0) continue;
                scored.Add((c, tier, c.Length));
            }

            bool havePrefix = scored.Any(s => s.Tier == 0 || s.Tier == 1);
            // drop fuzzy when a prefix (or exact) match exists
            var kept = havePrefix ? scored.Where(s => s.Tier != 3).ToList() : scored;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ordered = kept
                .OrderBy(s => s.Tier)
                .ThenBy(s => s.Len)
                .ThenBy(s => s.Item, StringComparer.Ordinal)
                .Where(s => seen.Add(s.Item))
                .Select(s => s.Item)
                .ToList();

            int total = ordered.Count;
            var page = ordered.Take(limit).ToList();
            return new SuggestionResult
            {
                Items = page,
                TotalMatches = total,
                Limit = limit
            };
        }

        // 0 exact, 1 prefix, 2 substring, 3 fuzzy(subsequence), -1 none.
        // An empty target matches everything as a prefix (used after "run ").
        private static int MatchTier(string candidate, string target)
        {
            if (candidate.Length == 0) return -1;
            if (target.Length == 0) return 1;
            if (candidate.Equals(target, StringComparison.OrdinalIgnoreCase)) return 0;
            if (candidate.StartsWith(target, StringComparison.OrdinalIgnoreCase)) return 1;
            if (candidate.IndexOf(target, StringComparison.OrdinalIgnoreCase) >= 0) return 2;
            if (IsSubsequence(target, candidate)) return 3;
            return -1;
        }

        // Case-insensitive subsequence: every char of `needle` appears in
        // `hay` in order (gaps allowed). Used only as a last-resort fuzzy tier.
        private static bool IsSubsequence(string needle, string hay)
        {
            int j = 0;
            for (int i = 0; i < hay.Length && j < needle.Length; i++)
                if (char.ToLowerInvariant(hay[i]) == char.ToLowerInvariant(needle[j])) j++;
            return j == needle.Length;
        }
    }
}