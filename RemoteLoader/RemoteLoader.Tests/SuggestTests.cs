// SuggestTests.cs -- the terminal-independent ArtifactSuggest.SuggestCommands
// engine: prefix/case-insensitive/builtin/argument-context/collision/reserved/
// limit+ordering/fuzzy tests. No I/O, no network.

using System;
using System.Linq;
using Xunit;

namespace RemoteLoader.Tests
{
    public class SuggestTests
    {
        // params shim (ArtifactCatalog.Build takes an IEnumerable, not params).
        private static ArtifactCatalogInstance BuildCat(
            string branch, params (string Name, string DownloadUrl, long Size)[] raw) =>
            ArtifactCatalog.Build(branch, raw);

        // A representative catalog: unambiguous aliases + a `tool` collision.
        private static ArtifactCatalogInstance MakeCatalog() =>
            BuildCat("main",
                ("whoami.x64.o",   "u1", 6 * 1024),
                ("arp.x64.o",      "u2", 4 * 1024),
                ("BOFKatz.x64.o",  "u3", 1451 * 1024),
                ("Seatbelt.exe",   "u4", 820 * 1024),
                ("tool.x64.o",     "u5", 1),
                ("tool.x86.o",     "u6", 2),
                ("tool.exe",       "u7", 3));

        private static SuggestionResult Sugg(string input, ArtifactEntry? active = null,
            ArtifactCatalogInstance? cat = null, int limit = 10) =>
            ArtifactSuggest.SuggestCommands(input, cat ?? MakeCatalog(), active, limit);

        // ---- prefix suggestion -------------------------------------------
        [Fact]
        public void Prefix_Bof_SuggestsBofkatz()
        {
            var r = Sugg("bof");
            Assert.Single(r.Items);
            Assert.Equal("bofkatz", r.Items[0]);
        }

        [Fact]
        public void Substring_Kat_SuggestsBofkatz()
        {
            // "kat" is a substring (not prefix) of "bofkatz"
            var r = Sugg("kat");
            Assert.Contains("bofkatz", r.Items);
        }

        [Fact]
        public void Prefix_Who_SuggestsWhoami()
        {
            var r = Sugg("who");
            Assert.Single(r.Items);
            Assert.Equal("whoami", r.Items[0]);
        }

        // ---- case-insensitive -------------------------------------------
        [Fact]
        public void Matching_IsCaseInsensitive()
        {
            Assert.Equal("bofkatz", Sugg("BOF").Items[0]);
            Assert.Equal("bofkatz", Sugg("BoF").Items[0]);
            Assert.Equal("whoami",  Sugg("WHO").Items[0]);
        }

        // ---- built-in commands from partial input ------------------------
        [Fact]
        public void BuiltInCommand_Partial_Run_SuggestsRun()
        {
            var r = Sugg("ru");
            Assert.Contains("run", r.Items);
            // "refresh" is not a prefix/substring/subsequence of "ru" (it has
            // no 'u'); it IS suggestable from its real prefix "re".
            Assert.DoesNotContain("refresh", r.Items);
        }

        [Fact]
        public void BuiltInCommand_Partial_Re_SuggestsRefresh()
        {
            var r = Sugg("re");
            Assert.Contains("refresh", r.Items);
        }

        [Fact]
        public void BuiltInCommand_Partial_He_SuggestsHelp()
        {
            var r = Sugg("he");
            Assert.Contains("help", r.Items);
        }

        [Fact]
        public void BuiltInCommand_ListedAmongAliases()
        {
            // single-char prefix that hits a command only
            var r = Sugg("s");
            Assert.Contains("search", r.Items);
        }

        // ---- argument-context suggestions --------------------------------
        [Fact]
        public void AfterRun_SuggestsArtifactAliases()
        {
            var r = Sugg("run bof");
            Assert.Contains("bofkatz", r.Items);
        }

        [Fact]
        public void AfterUse_SuggestsArtifactAliases()
        {
            var r = Sugg("use bo");
            Assert.Contains("bofkatz", r.Items);
        }

        [Fact]
        public void AfterInfo_SuggestsArtifactAliases()
        {
            var r = Sugg("info wh");
            Assert.Single(r.Items);
            Assert.Equal("whoami", r.Items[0]);
        }

        [Fact]
        public void AfterRun_Numeric_SuggestsIndexId()
        {
            // "run 1" -> the engine surfaces a "#1 <alias>" numeric id
            var r = Sugg("run 1");
            Assert.Contains(r.Items, s => s.StartsWith("#1 "));
        }


        [Fact]
        public void AfterSearch_SuggestsNothing()
        {
            // search keeps free-form behaviour; no artifact auto-suggestions
            var r = Sugg("search any");
            Assert.Empty(r.Items);
        }

        [Fact]
        public void UnknownCommand_WithArgs_SuggestsNothing()
        {
            // "list foo" -- list takes no artifact argument
            Assert.Empty(Sugg("list foo").Items);
        }

        // ---- collision aliases ------------------------------------------
        [Fact]
        public void Collision_SuggestsShortAndSpecificAliases()
        {
            var r = Sugg("tool");
            // exact short alias ranks first
            Assert.Equal("tool", r.Items[0]);
            Assert.Contains("tool-x64", r.Items);
            Assert.Contains("tool-x86", r.Items);
            Assert.Contains("tool-exe", r.Items);
        }

        [Fact]
        public void Collision_SpecificAliasPrefix_SuggestsOnlyThatBranch()
        {
            var r = Sugg("tool-x");
            Assert.Contains("tool-x64", r.Items);
            Assert.Contains("tool-x86", r.Items);
            // the unrelated tool-exe does not share the "tool-x" prefix
            Assert.DoesNotContain("tool-exe", r.Items);
        }

        // ---- reserved-command conflict behavior -------------------------
        [Fact]
        public void Reserved_NamedArtifact_NotSuggestedAsBareAlias()
        {
            // help.x64.o normalises to "help", a reserved word. At the top-level
            // prompt the bare alias is suppressed (it would shadow the command);
            // only the built-in "help" command is offered.
            var cat = BuildCat("main", ("help.x64.o", "u1", 1));
            var r = Sugg("help", cat: cat);
            Assert.Single(r.Items);
            Assert.Equal("help", r.Items[0]); // the command, not the artifact
        }

        [Fact]
        public void Reserved_NamedArtifact_ReachableAfterRun()
        {
            // After `run` the reserved-named artifact alias is reachable, so it
            // is suggested there.
            var cat = BuildCat("main", ("help.x64.o", "u1", 1));
            var r = Sugg("run help", cat: cat);
            Assert.Contains("help", r.Items);
        }

        // ---- maximum-results limit + deterministic ordering -------------
        [Fact]
        public void Limit_CapsResults_AndReportsTotal()
        {
            // 12 distinct aliases a01..a12, all share the prefix "a"
            var raw = Enumerable.Range(1, 12)
                .Select(i => ($"a{i:D2}.x64.o", $"u{i}", 1L))
                .ToArray();
            (string, string, long)[] typed = raw.Select(t => (t.Item1, t.Item2, t.Item3)).ToArray();
            var cat = BuildCat("main", typed);
            var r = Sugg("run a", cat: cat, limit: 10);
            Assert.Equal(10, r.Items.Count);
            Assert.Equal(12, r.TotalMatches);
            Assert.True(r.HasMore);
            // deterministic: shorter-then-alpha within the prefix tier
            Assert.Equal("a01", r.Items[0]);
            Assert.Equal("a10", r.Items[9]);
        }

        [Fact]
        public void Ordering_ExactFirst_ThenShorter_ThenAlpha()
        {
            // "a" exact, "aa"/"ab" prefix -- exact first, then by length/alpha
            var cat = BuildCat("main",
                ("a.x64.o",  "u1", 1),
                ("ab.x64.o", "u2", 1),
                ("aa.x64.o", "u3", 1));
            var r = Sugg("run a", cat: cat);
            Assert.Equal(new[] { "a", "aa", "ab" }, r.Items);
        }

        // ---- fuzzy (last resort) ----------------------------------------
        [Fact]
        public void Fuzzy_UsedWhenNoPrefixMatch()
        {
            // "bfk" is a subsequence (not prefix/substring) of "bofkatz"
            var r = Sugg("bfk");
            Assert.Contains("bofkatz", r.Items);
        }

        [Fact]
        public void Fuzzy_SuppressedWhenPrefixMatchExists()
        {
            // "bof": bofkatz is a prefix match; baxofuz only matches as a fuzzy
            // subsequence. With a prefix match present, fuzzy is suppressed.
            var cat = BuildCat("main",
                ("BOFKatz.x64.o", "u1", 1),
                ("baxofuz.x64.o", "u2", 1));
            var r = Sugg("bof", cat: cat);
            Assert.Contains("bofkatz", r.Items);
            Assert.DoesNotContain("baxofuz", r.Items);
        }

        // ---- active-artifact context ------------------------------------
        [Fact]
        public void ActiveContext_SuggestsControlCommandsOnly()
        {
            // When an artifact is active, a single token suggests control
            // commands only -- never artifact aliases (which would clash with
            // bare argument entry).
            var active = MakeCatalog().Entries[0];
            var r = Sugg("ba", active: active);
            Assert.Contains("back", r.Items);
            Assert.DoesNotContain("bofkatz", r.Items);
        }

        [Fact]
        public void ActiveContext_BareArgLikeToken_SuggestsNothing()
        {
            // a token that looks like an argument (no command prefix) yields no
            // suggestion, so argument entry is not interfered with
            var active = MakeCatalog().Entries[0];
            Assert.Empty(Sugg("/all", active: active).Items);
        }

        // ---- empty / null guards ----------------------------------------
        [Fact]
        public void EmptyInput_SuggestsNothing() => Assert.Empty(Sugg("").Items);

        [Fact]
        public void NullCatalog_SuggestsNothing() =>
            Assert.Empty(ArtifactSuggest.SuggestCommands("bof", null, null).Items);
    }
}