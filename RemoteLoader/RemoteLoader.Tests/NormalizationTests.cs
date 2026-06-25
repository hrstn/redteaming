// NormalizationTests.cs -- NormalizeArtifactCommandName + ParseArchitecture.
// Pure functions, no I/O.

using System;
using Xunit;

namespace RemoteLoader.Tests
{
    public class NormalizationTests
    {
        // The canonical examples from the spec.
        [Theory]
        [InlineData("BOFKatz.x64.o",   "bofkatz")]
        [InlineData("whoami.x64.o",    "whoami")]
        [InlineData("arp.x64.o",       "arp")]
        [InlineData("Tool.exe",        "tool")]
        [InlineData("Seatbelt.exe",    "seatbelt")]
        [InlineData("Example.amd64.o", "example")]
        [InlineData("Example.arm64.o", "example")]
        [InlineData("something.dll",   "something")]
        public void SpecExamples(string file, string expected) =>
            Assert.Equal(expected, ArtifactCatalog.NormalizeArtifactCommandName(file));

        [Theory]
        [InlineData("net.exe", "net")]
        [InlineData("a.b.c.dll", "a.b.c")]          // internal dots preserved
        [InlineData("my-tool.exe", "my-tool")]       // dash preserved
        [InlineData("my_tool.x64.o", "my_tool")]     // underscore preserved
        [InlineData("net.4.8.dll", "net.4.8")]
        public void PreservesMeaningfulSeparators(string file, string expected) =>
            Assert.Equal(expected, ArtifactCatalog.NormalizeArtifactCommandName(file));

        [Fact]
        public void IsAlwaysLowercase() =>
            Assert.Equal("seatbelt", ArtifactCatalog.NormalizeArtifactCommandName("SeatBelt.Exe"));

        [Theory]
        [InlineData("tool.x64.o",   "tool")]        // arch marker stripped
        [InlineData("tool.x86.o",   "tool")]
        [InlineData("tool.amd64.o", "tool")]
        [InlineData("tool.arm64.o", "tool")]
        [InlineData("tool.aarch64.o", "tool")]
        public void StripsArchitectureMarkers(string file, string expected) =>
            Assert.Equal(expected, ArtifactCatalog.NormalizeArtifactCommandName(file));

        [Fact]
        public void NeverReturnsEmpty_ForBlank() =>
            Assert.False(string.IsNullOrEmpty(ArtifactCatalog.NormalizeArtifactCommandName("")));

        [Fact]
        public void NeverReturnsEmpty_ForWhitespaceAndSymbols()
        {
            string r = ArtifactCatalog.NormalizeArtifactCommandName("   @#$%   ");
            Assert.False(string.IsNullOrEmpty(r));
            // shell metacharacters become dashes / are sanitized, never raw
            Assert.DoesNotContain("@", r);
            Assert.DoesNotContain("#", r);
        }

        [Fact]
        public void SanitizesShellMetacharacters()
        {
            // something that would be dangerous in a shell becomes a dash slug
            string r = ArtifactCatalog.NormalizeArtifactCommandName("foo;bar.exe");
            Assert.Equal("foo-bar", r);
        }

        [Fact]
        public void CollapsesWhitespaceToDash()
        {
            string r = ArtifactCatalog.NormalizeArtifactCommandName("foo bar.exe");
            Assert.Equal("foo-bar", r);
        }

        [Fact]
        public void StripsDirectoryComponent()
        {
            // a hand-supplied path still normalises to the bare file base
            Assert.Equal("whoami", ArtifactCatalog.NormalizeArtifactCommandName("payloads/whoami.x64.o"));
            Assert.Equal("whoami", ArtifactCatalog.NormalizeArtifactCommandName(@"C:\dir\whoami.x64.o"));
        }

        [Fact]
        public void FallbackPlaceholderForAllSymbolFilename()
        {
            // entire name is non-alphanumeric after suffix strip -> non-empty fallback
            string r = ArtifactCatalog.NormalizeArtifactCommandName("!!!.exe");
            Assert.False(string.IsNullOrEmpty(r));
        }

        // ---- Architecture parsing ----------------------------------------

        [Theory]
        [InlineData("whoami.x64.o",    "x64")]
        [InlineData("Example.amd64.o", "amd64")]
        [InlineData("Example.arm64.o", "arm64")]
        [InlineData("foo.aarch64.o",   "aarch64")]
        [InlineData("foo.i386.o",      "i386")]
        public void ParsesArchitecture(string file, string expected) =>
            Assert.Equal(expected, ArtifactCatalog.ParseArchitecture(file));

        [Theory]
        [InlineData("Tool.exe")]
        [InlineData("something.dll")]
        [InlineData("plain.o")]            // .o without an arch marker
        [InlineData("")]
        public void ReturnsNullWhenNoArchMarker(string file) =>
            Assert.Null(ArtifactCatalog.ParseArchitecture(file));
    }
}
