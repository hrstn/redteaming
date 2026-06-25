// ReplTests.cs -- ArtifactCli REPL behaviour: persistent prompt, use/back
// state transitions, direct aliases, run, numeric selection, exit, and
// graceful handling of ambiguous / unknown input. Driven entirely through
// in-memory TextReader/TextWriter + fake callbacks (no network, no loading).

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace RemoteLoader.Tests
{
    public class ReplTests
    {
        // Records every execution handed off by the REPL.
        private sealed class Recorder
        {
            public List<(string Name, string Args)> Executions { get; } = new();
            public int ExitResult { get; set; } = 0;
            public Task<int> Execute(ArtifactEntry e, string args)
            {
                Executions.Add((e.OriginalName, args));
                return Task.FromResult(ExitResult);
            }
        }

        // params shim: ArtifactCatalog.Build takes an IEnumerable, not params.
        private static ArtifactCatalogInstance BuildCat(
            string branch, params (string Name, string DownloadUrl, long Size)[] raw) =>
            ArtifactCatalog.Build(branch, raw);

        // Build a catalog the REPL can browse. `tool` is deliberately colliding
        // so ambiguous-alias tests work; `whoami`/`arp`/`bofkatz` are unambiguous.
        private static ArtifactCatalogInstance MakeCatalog() =>
            BuildCat("main",
                ("whoami.x64.o",  "u1", 6 * 1024),
                ("arp.x64.o",     "u2", 4 * 1024),
                ("BOFKatz.x64.o", "u3", 1451 * 1024),
                ("tool.x64.o",    "u4", 1),
                ("tool.x86.o",    "u5", 2));

        // Run a sequence of input lines; discard stdout (for tests that only
        // care about the execution recorder / exit code).
        private static async Task<(int Rc, Recorder Rec)> Run(params string[] lines)
        {
            var rec = new Recorder();
            var catalog = MakeCatalog();
            var cli = new ArtifactCli(
                input:  new StringReader(string.Join("\n", lines)),
                output: new StringWriter(),
                refresh: () => Task.FromResult<ArtifactCatalogInstance?>(catalog),
                execute: (e, a) => rec.Execute(e, a));
            int rc = await cli.RunLoop();
            return (rc, rec);
        }

        // Run a sequence of input lines and keep stdout for assertions.
        private static async Task<(int Rc, string Out, Recorder Rec)> RunWithOutput(
            params string[] lines)
        {
            var rec = new Recorder();
            var catalog = MakeCatalog();
            var sw = new StringWriter();
            var cli = new ArtifactCli(
                new StringReader(string.Join("\n", lines)),
                sw,
                () => Task.FromResult<ArtifactCatalogInstance?>(catalog),
                (e, a) => rec.Execute(e, a));
            int rc = await cli.RunLoop();
            return (rc, sw.ToString(), rec);
        }

        // ---- persistent prompt: still active after a completed action ----
        [Fact]
        public async Task PromptRemains_AfterCompletedAction()
        {
            var (rc, rec) = await Run("whoami", "list", "exit");
            Assert.Equal(0, rc);
            Assert.Single(rec.Executions);
            Assert.Equal("whoami.x64.o", rec.Executions[0].Name);
        }

        // ---- direct alias invocation uses the existing action path --------
        [Fact]
        public async Task DirectAlias_InvokesExecutor()
        {
            var (rc, rec) = await Run("whoami", "exit");
            Assert.Equal(0, rc);
            Assert.Single(rec.Executions);
            Assert.Equal("whoami.x64.o", rec.Executions[0].Name);
            Assert.Equal("", rec.Executions[0].Args);
        }

        [Fact]
        public async Task DirectAlias_PassesArgumentsThrough()
        {
            var (rc, rec) = await Run("whoami /all", "exit");
            Assert.Equal(0, rc);
            Assert.Single(rec.Executions);
            Assert.Equal("/all", rec.Executions[0].Args);
        }

        // ---- run <alias> [args] ------------------------------------------
        [Fact]
        public async Task RunCommand_InvokesExecutorWithArgs()
        {
            var (rc, rec) = await Run("run arp -a", "exit");
            Assert.Equal(0, rc);
            Assert.Single(rec.Executions);
            Assert.Equal("arp.x64.o", rec.Executions[0].Name);
            Assert.Equal("-a", rec.Executions[0].Args);
        }

        // ---- numeric selection preserves legacy behaviour ----------------
        [Fact]
        public async Task NumericSelection_RunsThatArtifact()
        {
            var (rc, rec) = await Run("2", "exit");
            Assert.Equal(0, rc);
            Assert.Single(rec.Executions);
            Assert.Equal("arp.x64.o", rec.Executions[0].Name);
        }

        // ---- use / back state transitions --------------------------------
        [Fact]
        public async Task Use_ActivatesArtifact_Back_ReturnsToCatalog()
        {
            var (rc, out_, rec) = await RunWithOutput("use whoami", "back", "exit");
            Assert.Equal(0, rc);
            Assert.Contains("Active artifact: whoami", out_);
            Assert.Contains("Returned to catalog.", out_);
            Assert.Empty(rec.Executions);
        }

        [Fact]
        public async Task Use_ThenBareArgs_RunsActiveArtifact()
        {
            var (rc, rec) = await Run("use whoami", "/all", "back", "exit");
            Assert.Equal(0, rc);
            Assert.Single(rec.Executions);
            Assert.Equal("whoami.x64.o", rec.Executions[0].Name);
            Assert.Equal("/all", rec.Executions[0].Args);
        }

        [Fact]
        public async Task ActivePrompt_Run_NoArgs_RunsActiveWithEmptyArgs()
        {
            var (rc, rec) = await Run("use whoami", "run", "back", "exit");
            Assert.Equal(0, rc);
            Assert.Single(rec.Executions);
            Assert.Equal("", rec.Executions[0].Args);
        }

        [Fact]
        public async Task Zero_InActive_ReturnsToCatalog()
        {
            var (rc, out_, rec) = await RunWithOutput("use whoami", "0", "exit");
            Assert.Equal(0, rc);
            Assert.Contains("Returned to catalog.", out_);
            Assert.Empty(rec.Executions);
        }

        [Fact]
        public async Task Zero_AtTop_Exits()
        {
            var (rc, rec) = await Run("0");
            Assert.Equal(0, rc);
            Assert.Empty(rec.Executions);
        }

        // ---- ambiguous alias: surface variants, stay at prompt -----------
        [Fact]
        public async Task AmbiguousAlias_ShowsVariantsAndStaysAtPrompt()
        {
            var (rc, out_, rec) = await RunWithOutput("tool", "exit");
            Assert.Equal(0, rc);
            // spec disambiguation format (no silent resolution, no execution)
            Assert.Contains("\"tool\" matches multiple artifacts", out_);
            Assert.Contains("tool-x64", out_);
            Assert.Contains("tool-x86", out_);
            Assert.Contains("Use one of the specific aliases", out_);
            Assert.Empty(rec.Executions);
        }

        [Fact]
        public async Task AmbiguousAlias_SpecificAlias_Executes()
        {
            var (rc, rec) = await Run("tool-x64", "exit");
            Assert.Equal(0, rc);
            Assert.Single(rec.Executions);
            Assert.Equal("tool.x64.o", rec.Executions[0].Name);
        }

        // ---- unknown / empty input: stay at prompt, no exit ---------------
        [Fact]
        public async Task UnknownAlias_ReportsAndStaysAtPrompt()
        {
            // "nope" is a partial/unknown -> suggestions (not execution), then
            // the REPL stays at the prompt and reaches the final "exit".
            var (rc, out_, rec) = await RunWithOutput("nope", "exit");
            Assert.Equal(0, rc);
            Assert.Contains("No suggestions for 'nope'", out_);
            Assert.Empty(rec.Executions);
        }

        [Fact]
        public async Task EmptyInput_IsIgnoredAndPromptContinues()
        {
            var (rc, rec) = await Run("", "  ", "whoami", "exit");
            Assert.Equal(0, rc);
            Assert.Single(rec.Executions);
        }

        // ---- refresh ------------------------------------------------------
        [Fact]
        public async Task Refresh_RebuildsCatalogAndStaysAtPrompt()
        {
            var (rc, out_, rec) = await RunWithOutput("refresh", "exit");
            Assert.Equal(0, rc);
            Assert.Contains("Catalog refreshed.", out_);
            Assert.Empty(rec.Executions);
        }

        // ---- help ---------------------------------------------------------
        [Fact]
        public async Task Help_ListsCommands()
        {
            var (rc, out_, _) = await RunWithOutput("help", "exit");
            Assert.Equal(0, rc);
            Assert.Contains("Commands:", out_);
            Assert.Contains("run", out_);
            Assert.Contains("use", out_);
            Assert.Contains("back", out_);
        }

        // ---- exit codes propagate ----------------------------------------
        [Fact]
        public async Task NonZeroExitResult_PropagatesAsOverallReturnCode()
        {
            var rec = new Recorder { ExitResult = 42 };
            var catalog = MakeCatalog();
            var cli = new ArtifactCli(
                new StringReader("whoami\nexit\n"),
                new StringWriter(),
                () => Task.FromResult<ArtifactCatalogInstance?>(catalog),
                (e, a) => rec.Execute(e, a));
            int rc = await cli.RunLoop();
            Assert.Equal(42, rc);
        }

        // ---- EOF exits cleanly -------------------------------------------
        [Fact]
        public async Task Eof_ExitsCleanly()
        {
            var (rc, rec) = await Run("whoami");
            Assert.Equal(0, rc);
            Assert.Single(rec.Executions);
        }
        // ---- suggestions: never auto-execute on a partial ----------------
        [Fact]
        public async Task SuggestionNotAutoExecuted()
        {
            // "bof" is a partial of "bofkatz" -> show suggestions, do NOT execute.
            var (rc, out_, rec) = await RunWithOutput("bof", "exit");
            Assert.Equal(0, rc);
            Assert.Contains("Suggestions:", out_);
            Assert.Contains("bofkatz", out_);
            Assert.Empty(rec.Executions);
        }

        [Fact]
        public async Task SuggestionThenExactAlias_Executes()
        {
            // first "bof" only suggests; the following exact "bofkatz" runs.
            var (rc, rec) = await Run("bof", "bofkatz", "exit");
            Assert.Equal(0, rc);
            Assert.Single(rec.Executions);
            Assert.Equal("BOFKatz.x64.o", rec.Executions[0].Name);
        }

        [Fact]
        public async Task RunPartial_ShowsSuggestions_NoExecution()
        {
            var (rc, out_, rec) = await RunWithOutput("run bof", "exit");
            Assert.Equal(0, rc);
            Assert.Contains("Suggestions:", out_);
            Assert.Contains("bofkatz", out_);
            Assert.Empty(rec.Executions);
        }

        // ---- suggestion index refresh after a GitHub refresh -----------
        // The engine reads the live catalog, so after `refresh` rebuilds it,
        // suggestions reflect the new content. Stateful refresh: first call
        // returns a catalog WITHOUT bofkatz, the second (refresh) WITH it.
        [Fact]
        public async Task Refresh_UpdatesSuggestionIndex()
        {
            int calls = 0;
            var catA = BuildCat("main", ("arp.x64.o", "u1", 4 * 1024));
            var catB = BuildCat("main",
                ("arp.x64.o",    "u1", 4 * 1024),
                ("BOFKatz.x64.o","u2", 1451 * 1024));

            var rec = new Recorder();
            var sw = new StringWriter();
            var cli = new ArtifactCli(
                new StringReader("refresh\nbof\nexit\n"),
                sw,
                refresh: () => { calls++; return Task.FromResult<ArtifactCatalogInstance?>(calls == 1 ? catA : catB); },
                execute: (e, a) => rec.Execute(e, a));
            int rc = await cli.RunLoop();

            Assert.Equal(0, rc);
            string output = sw.ToString();
            Assert.Contains("Catalog refreshed.", output);
            Assert.Contains("Suggestions:", output);
            Assert.Contains("bofkatz", output);
            Assert.Empty(rec.Executions);
        }
    }
}