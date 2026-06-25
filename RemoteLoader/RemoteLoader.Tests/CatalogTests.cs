// CatalogTests.cs -- Build/resolve/collision/reserved-conflict behaviour.

using System;
using System.Linq;
using Xunit;

namespace RemoteLoader.Tests
{
    public class CatalogTests
    {
        // helper: build a catalog from raw (Name,Url,Size) tuples on a branch.
        private static ArtifactCatalogInstance Build(string branch,
            params (string Name, string Url, long Size)[] raw) =>
            ArtifactCatalog.Build(branch, raw);

        // ---- resolving a number ------------------------------------------

        [Fact]
        public void ResolveNumber_ReturnsCorrectEntry()
        {
            var cat = Build("main",
                ("whoami.x64.o", "u1", 6 * 1024),
                ("arp.x64.o",    "u2", 4 * 1024));
            var r = cat.ResolveNumber(2);
            Assert.True(r.IsSingle);
            Assert.Equal("arp.x64.o", r.Entry!.OriginalName);
            Assert.Equal(2, r.Entry.Index);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(99)]
        public void ResolveNumber_OutOfRange_IsNone(int n)
        {
            var cat = Build("main", ("whoami.x64.o", "u1", 6));
            Assert.True(cat.ResolveNumber(n).IsNone);
        }

        // ---- unambiguous alias -------------------------------------------

        [Fact]
        public void Resolve_UnambiguousAlias_IsSingle()
        {
            var cat = Build("main",
                ("whoami.x64.o", "u1", 6),
                ("arp.x64.o",    "u2", 4));
            var r = cat.Resolve("whoami");
            Assert.True(r.IsSingle);
            Assert.Equal("whoami.x64.o", r.Entry!.OriginalName);
        }

        [Fact]
        public void Resolve_IsCaseInsensitive()
        {
            var cat = Build("main", ("Seatbelt.exe", "u1", 820 * 1024));
            Assert.True(cat.Resolve("SEATBELT").IsSingle);
            Assert.True(cat.Resolve("Seatbelt").IsSingle);
        }

        // ---- ambiguous aliases are rejected (not silently resolved) ------

        [Fact]
        public void Resolve_AmbiguousShortAlias_IsAmbiguous()
        {
            var cat = Build("main",
                ("tool.x64.o", "u1", 1),
                ("tool.x86.o", "u2", 2),
                ("tool.exe",   "u3", 3));
            var r = cat.Resolve("tool");
            Assert.True(r.IsAmbiguous);
            Assert.Equal(3, r.Candidates.Count);
        }

        [Fact]
        public void Collision_AssignsSpecificAliases()
        {
            var cat = Build("main",
                ("tool.x64.o", "u1", 1),
                ("tool.x86.o", "u2", 2),
                ("tool.exe",   "u3", 3));

            // arch-specific aliases resolve uniquely
            Assert.True(cat.Resolve("tool-x64").IsSingle);
            Assert.True(cat.Resolve("tool-x86").IsSingle);
            // no arch -> falls back to the kind label "exe"
            var exe = cat.Resolve("tool-exe");
            Assert.True(exe.IsSingle);
            Assert.Equal("tool.exe", exe.Entry!.OriginalName);
        }

        [Fact]
        public void Collision_SpecificAliasesPointAtDistinctEntries()
        {
            var cat = Build("main",
                ("tool.x64.o", "u1", 1),
                ("tool.x86.o", "u2", 2));
            Assert.Equal("tool.x64.o", cat.Resolve("tool-x64").Entry!.OriginalName);
            Assert.Equal("tool.x86.o", cat.Resolve("tool-x86").Entry!.OriginalName);
        }

        [Fact]
        public void Collision_AllAliasesListedContainShortName()
        {
            var cat = Build("main",
                ("tool.x64.o", "u1", 1),
                ("tool.x86.o", "u2", 2));
            // the short alias is still present on every entry so an ambiguous
            // `tool` surfaces the variants rather than silently resolving.
            foreach (var e in cat.Entries)
                Assert.Contains("tool", e.Aliases);
        }

        [Fact]
        public void NoCollision_KeepsShortAliasOnly()
        {
            var cat = Build("main", ("tool.x64.o", "u1", 1));
            var e = cat.Entries[0];
            Assert.Null(e.SpecificAlias);
            Assert.Single(e.Aliases);
            Assert.Equal("tool", e.Aliases[0]);
        }

        // ---- reserved command conflicts ----------------------------------

        [Theory]
        [InlineData("help")]
        [InlineData("list")]
        [InlineData("exit")]
        [InlineData("quit")]
        [InlineData("search")]
        [InlineData("run")]
        [InlineData("use")]
        [InlineData("info")]
        [InlineData("refresh")]
        [InlineData("back")]
        public void ReservedCommands_AreReserved(string word) =>
            Assert.True(ArtifactCatalog.IsReservedCommand(word));

        [Theory]
        [InlineData("HELP")]
        [InlineData("List")]
        [InlineData("Exit")]
        public void ReservedCommands_CaseInsensitive(string word) =>
            Assert.True(ArtifactCatalog.IsReservedCommand(word));

        [Fact]
        public void NonReservedWord_IsNotReserved() =>
            Assert.False(ArtifactCatalog.IsReservedCommand("whoami"));

        [Fact]
        public void ArtifactNamedLikeReservedWord_NotReachableByBareAlias()
        {
            // help.x64.o normalises to "help", a reserved command.
            var cat = Build("main", ("help.x64.o", "u1", 1));
            // bare alias path (allowReserved=false) -> not resolved as artifact
            Assert.True(cat.Resolve("help", allowReserved: false).IsNone);
        }

        [Fact]
        public void ArtifactNamedLikeReservedWord_ReachableViaExplicitRun()
        {
            var cat = Build("main", ("help.x64.o", "u1", 1));
            // explicit run/use path (allowReserved=true) -> resolves
            var r = cat.Resolve("help", allowReserved: true);
            Assert.True(r.IsSingle);
            Assert.Equal("help.x64.o", r.Entry!.OriginalName);
        }

        // ---- substring fallback ------------------------------------------

        [Fact]
        public void Resolve_SubstringFallback_UniqueMatch()
        {
            var cat = Build("main",
                ("whoami.x64.o", "u1", 6),
                ("arp.x64.o",    "u2", 4));
            // "who" matches only whoami -> single
            Assert.True(cat.Resolve("who").IsSingle);
        }

        [Fact]
        public void Resolve_SubstringFallback_Ambiguous()
        {
            var cat = Build("main",
                ("whoami.x64.o", "u1", 6),
                ("whoami.x86.o", "u2", 4));
            // "who" matches both -> ambiguous
            Assert.True(cat.Resolve("who").IsAmbiguous);
        }

        [Fact]
        public void Resolve_UnknownAlias_IsNone()
        {
            var cat = Build("main", ("whoami.x64.o", "u1", 6));
            Assert.True(cat.Resolve("does-not-exist").IsNone);
        }

        // ---- search -------------------------------------------------------

        [Fact]
        public void Search_FiltersByArch()
        {
            var cat = Build("main",
                ("whoami.x64.o", "u1", 6),
                ("whoami.x86.o", "u2", 4));
            Assert.Single(cat.Search("x64"));
            Assert.Equal(2, cat.Search("whoami").Count());
        }

        // ---- metadata retention ------------------------------------------

        [Fact]
        public void Entry_RetainsRequiredMetadata()
        {
            var cat = Build("dev",
                ("BOFKatz.x64.o", "https://dl/BOFKatz.x64.o", 1451 * 1024));
            var e = cat.Entries[0];
            Assert.Equal("BOFKatz.x64.o", e.OriginalName);
            Assert.Equal("bofkatz", e.CommandName);
            Assert.Equal("https://dl/BOFKatz.x64.o", e.DownloadUrl);
            Assert.Equal("dev", e.Branch);
            Assert.Equal(ArtifactKind.Bof, e.Kind);
            Assert.Equal("x64", e.Arch);
            Assert.Equal(1451 * 1024, e.Size);
        }
    }
}
