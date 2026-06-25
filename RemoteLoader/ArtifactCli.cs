// ArtifactCli.cs -- the persistent `artifacts>` REPL layered over the existing
// GitHub fetch / download / validation / execution path. No network or
// loading logic lives here: it asks the catalog to resolve, then hands an
// ArtifactEntry + raw args back to RemoteLoader via injected callbacks.
//
// All user input flows through CmdTokenizer (quote-aware). Argument strings
// are passed unchanged to the executor; nothing is eval'd, shell-joined, or
// interpolated into a command line.
//
// State rule (robustness): only a *real* execution updates the tracked last
// exit code. Ordinary input errors (ambiguous alias, no match, bad number,
// partial input) print a message or suggestions and return to the prompt
// without mutating state, so a typo can never masquerade as the tool's final
// exit code.
//
// Suggestions: a submitted line that is a *partial* (no exact alias match)
// never auto-executes -- it is routed to the testable ArtifactSuggest engine
// which surfaces matching commands/aliases. Live tab completion is not wired:
// the REPL reads via TextReader.ReadLine() (redirectable/injectable), so we
// use the spec's post-submit suggestion fallback. The engine itself is
// terminal-independent and unit-tested separately.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace RemoteLoader
{
    internal sealed class ArtifactCli
    {
        private readonly TextReader _in;
        private readonly TextWriter _out;
        // Rebuilds the catalog (re-query GitHub). Returns null on failure.
        private readonly Func<Task<ArtifactCatalogInstance?>> _refresh;
        // Executes one artifact with a raw argument string (BOF packer / .NET
        // ParseArgs handle it downstream). Returns the tool exit code.
        private readonly Func<ArtifactEntry, string, Task<int>> _execute;

        private ArtifactCatalogInstance? _catalog;
        private ArtifactEntry? _active;

        // Tracked exit code from the most recent *execution*. Input errors
        // (ambiguous/none/partial/usage) deliberately do not touch this.
        private int _lastRc = 0;
        // Sentinel: exit was requested from the active-artifact prompt.
        private bool _exitRequested;

        public ArtifactCli(TextReader input, TextWriter output,
            Func<Task<ArtifactCatalogInstance?>> refresh,
            Func<ArtifactEntry, string, Task<int>> execute)
        {
            _in = input; _out = output; _refresh = refresh; _execute = execute;
        }

        // Run until the user exits (exit/quit/0 at top level) or EOF.
        public async Task<int> RunLoop()
        {
            _catalog = await _refresh();
            if (_catalog == null || _catalog.Count == 0)
            {
                _out.WriteLine("No artifacts available.");
                return 1;
            }
            PrintList();

            while (true)
            {
                string prompt = _active == null ? "artifacts> " : $"{_active.PrimaryAlias}> ";
                _out.Write(prompt);
                string? line = _in.ReadLine();
                if (line == null) { _out.WriteLine(); return _lastRc; } // EOF
                line = line.Trim();
                if (line.Length == 0) continue;

                var tokens = CmdTokenizer.Split(line);
                string first = tokens[0];
                bool isTop = _active == null;

                // `0` is the legacy exit/back shortcut.
                if (first == "0")
                {
                    if (!isTop) { _active = null; _out.WriteLine("Returned to catalog."); continue; }
                    return _lastRc;
                }

                if (!isTop)
                {
                    await HandleActive(line, tokens, first);
                    if (_exitRequested) return _lastRc;
                    continue;
                }

                // top-level
                // plain number -> run that artifact (preserves legacy behaviour)
                if (int.TryParse(first, out int n) && tokens.Count == 1 && n >= 1)
                {
                    var r = _catalog!.ResolveNumber(n);
                    if (r.IsNone)        { _out.WriteLine($"No artifact #{n}."); continue; }
                    if (r.IsAmbiguous)   { PrintAmbiguous(first, r.Candidates); continue; }
                    await Execute(r.Entry!, "");
                    continue;
                }

                // reserved command words always win
                if (ArtifactCatalog.IsReservedCommand(first))
                {
                    switch (first)
                    {
                        case "help":    PrintHelp(); continue;
                        case "list":    PrintList(); continue;
                        case "search":
                            if (tokens.Count < 2) { _out.WriteLine("usage: search <term>"); continue; }
                            PrintSearch(string.Join(" ", tokens.Skip(1)));
                            continue;
                        case "info":
                            if (tokens.Count < 2) { _out.WriteLine("usage: info <name-or-number>"); continue; }
                            PrintInfo(tokens[1], line, allowReserved: false);
                            continue;
                        case "run":
                            if (tokens.Count < 2) { _out.WriteLine("usage: run <name-or-number> [args...]"); continue; }
                            await HandleRun(line, tokens, fromIndex: 2, name: tokens[1], allowReserved: true, activate: false);
                            continue;
                        case "use":
                            if (tokens.Count < 2) { _out.WriteLine("usage: use <name-or-number>"); continue; }
                            HandleUse(line, tokens[1], allowReserved: true);
                            continue;
                        case "back": _out.WriteLine("Nothing to go back to (top of catalog)."); continue;
                        case "refresh":
                            {
                                var fresh = await _refresh();
                                if (fresh == null || fresh.Count == 0) { _out.WriteLine("Refresh failed: no artifacts."); return 1; }
                                _catalog = fresh;
                                _out.WriteLine("Catalog refreshed.");
                                PrintList();
                                continue;
                            }
                        case "exit": case "quit": return _lastRc;
                    }
                }

                // direct alias invocation: first token is an artifact alias,
                // remaining tokens are its arguments. Use EXACT alias match so a
                // partial (e.g. "bof") is not auto-executed; partials -> suggestions.
                {
                    var r = _catalog!.ResolveExact(first, allowReserved: false);
                    if (r.IsNone)       { ShowSuggestions(line); continue; }
                    if (r.IsAmbiguous)  { PrintAmbiguous(first, r.Candidates); continue; }
                    string rawArgs = CmdTokenizer.JoinArgs(tokens, 1);
                    await Execute(r.Entry!, rawArgs);
                }
            }
        }

        // ---- active-artifact prompt --------------------------------------
        private async Task HandleActive(string line, IReadOnlyList<string> tokens, string first)
        {
            switch (first)
            {
                case "back":
                    _active = null;
                    _out.WriteLine("Returned to catalog.");
                    return;
                case "help":
                    PrintHelp(active: true);
                    return;
                case "list":
                    PrintList();
                    return;
                case "info":
                    PrintInfo(_active!);
                    return;
                case "search":
                    if (tokens.Count < 2) { _out.WriteLine("usage: search <term>"); return; }
                    PrintSearch(string.Join(" ", tokens.Skip(1)));
                    return;
                case "refresh":
                    {
                        var fresh = await _refresh();
                        if (fresh == null || fresh.Count == 0) { _out.WriteLine("Refresh failed: no artifacts."); _active = null; return; }
                        _catalog = fresh;
                        _out.WriteLine("Catalog refreshed.");
                        // re-resolve the active artifact's primary alias, if it survived
                        var res = _catalog.ResolveExact(_active!.PrimaryAlias, allowReserved: true);
                        if (res.IsSingle) _active = res.Entry!;
                        else { _active = null; _out.WriteLine("Active artifact no longer present; returned to catalog."); }
                        PrintList();
                        return;
                    }
                case "run":
                    // `run` with no extra args runs the active artifact with no args.
                    await Execute(_active!, tokens.Count < 2 ? "" : CmdTokenizer.JoinArgs(tokens, 1));
                    return;
                case "use":
                    if (tokens.Count < 2) { _out.WriteLine("usage: use <name-or-number>"); return; }
                    HandleUse(line, tokens[1], allowReserved: true);
                    return;
                case "exit": case "quit":
                    _exitRequested = true;
                    return;
            }

            // anything else: treat the whole line as arguments to the active
            // artifact (preserving the existing action path). Bare arguments are
            // never suggested against artifact aliases here, so argument entry is
            // not interfered with.
            await Execute(_active!, line);
        }

        // ---- helpers ------------------------------------------------------
        private async Task Execute(ArtifactEntry e, string rawArgs)
        {
            _out.WriteLine($"[*] Running {e.OriginalName} ...");
            int rc;
            try { rc = await _execute(e, rawArgs); }
            catch (Exception ex) { _out.WriteLine($"[-] Execution error: {ex.Message}"); _lastRc = 1; return; }
            _out.WriteLine($"[+] Done (exit={rc}).");
            _lastRc = rc;
        }

        // Resolve a name for run/use. Numeric -> ResolveNumber; otherwise exact
        // alias match only, so a partial name -> suggestions (never auto-exec).
        private async Task HandleRun(string line, IReadOnlyList<string> tokens, int fromIndex, string name, bool allowReserved, bool activate)
        {
            if (int.TryParse(name, out int n))
            {
                var r = _catalog!.ResolveNumber(n);
                if (r.IsNone)       { _out.WriteLine($"No artifact #{n}."); return; }
                if (r.IsAmbiguous)  { PrintAmbiguous(name, r.Candidates); return; }
                if (activate) { Activate(r.Entry!); return; }
                await Execute(r.Entry!, CmdTokenizer.JoinArgs(tokens, fromIndex));
                return;
            }
            var res = _catalog!.ResolveExact(name, allowReserved: allowReserved);
            if (res.IsNone)       { ShowSuggestions(line); return; }
            if (res.IsAmbiguous)  { PrintAmbiguous(name, res.Candidates); return; }
            if (activate) { Activate(res.Entry!); return; }
            await Execute(res.Entry!, CmdTokenizer.JoinArgs(tokens, fromIndex));
        }

        private void HandleUse(string line, string name, bool allowReserved)
        {
            if (int.TryParse(name, out int n))
            {
                var r = _catalog!.ResolveNumber(n);
                if (r.IsNone)       { _out.WriteLine($"No artifact #{n}."); return; }
                if (r.IsAmbiguous)  { PrintAmbiguous(name, r.Candidates); return; }
                Activate(r.Entry!); return;
            }
            var res = _catalog!.ResolveExact(name, allowReserved: allowReserved);
            if (res.IsNone)       { ShowSuggestions(line); return; }
            if (res.IsAmbiguous)  { PrintAmbiguous(name, res.Candidates); return; }
            Activate(res.Entry!);
        }

        private void Activate(ArtifactEntry e)
        {
            _active = e;
            _out.WriteLine($"Active artifact: {e.PrimaryAlias} ({e.OriginalName}, {e.DisplayArch})");
            _out.WriteLine("Enter arguments, use \"back\" to return to the catalog, or \"help\" for commands.");
        }

        // ---- suggestions --------------------------------------------------
        // Surface matching commands/artifacts for a partial/unknown line. Never
        // executes or selects anything -- the user must retype and confirm.
        private void ShowSuggestions(string input)
        {
            var res = ArtifactSuggest.SuggestCommands(input, _catalog, _active);
            if (res.Items.Count == 0)
            {
                _out.WriteLine($"No suggestions for '{input.Trim()}'. Type 'list' or 'help'.");
                return;
            }
            _out.WriteLine("Suggestions:");
            foreach (var s in res.Items)
                _out.WriteLine($"  {s}");
            if (res.HasMore)
                _out.WriteLine($"Showing {res.Items.Count} of {res.TotalMatches} matches. Use \"search <term>\" for the full result.");
        }

        // ---- rendering ----------------------------------------------------
        private static string HumanSize(long bytes)
        {
            if (bytes >= 1024L * 1024L) return $"{bytes / (1024L * 1024L)} MB";
            if (bytes >= 1024L)         return $"{bytes / 1024L} KB";
            return $"{bytes} B";
        }

        public void PrintList()
        {
            var cat = _catalog!;
            _out.WriteLine();
            _out.WriteLine("Available artifacts:");
            _out.WriteLine();
            int idxW = Math.Max(2, cat.Count.ToString().Length);
            foreach (var e in cat.Entries)
                _out.WriteLine($" [{e.Index.ToString().PadLeft(idxW)}] {e.PrimaryAlias.PadRight(14)} {e.OriginalName.PadRight(22)} {e.DisplayArch.PadRight(8)} {HumanSize(e.Size),8}");
            _out.WriteLine();
            _out.WriteLine("Type an alias directly, use \"run <alias>\", or type \"help\".");
        }

        private void PrintSearch(string term)
        {
            var hits = _catalog!.Search(term).ToList();
            if (hits.Count == 0) { _out.WriteLine($"No artifacts match '{term}'."); return; }
            _out.WriteLine($"Matches for '{term}':");
            foreach (var e in hits)
                _out.WriteLine($" [{e.Index.ToString().PadLeft(2)}] {e.PrimaryAlias,-14} {e.OriginalName,-22} {e.DisplayArch,-8} {HumanSize(e.Size),8}");
        }

        // `info <name-or-number>`: exact alias match only; partials -> suggestions.
        private void PrintInfo(string nameOrNumber, string line, bool allowReserved)
        {
            ArtifactEntry? e = null;
            if (int.TryParse(nameOrNumber, out int n))
            {
                var r = _catalog!.ResolveNumber(n);
                if (r.IsSingle) e = r.Entry;
                else if (r.IsAmbiguous) { PrintAmbiguous(nameOrNumber, r.Candidates); return; }
            }
            else
            {
                var r = _catalog!.ResolveExact(nameOrNumber, allowReserved: allowReserved);
                if (r.IsSingle)        e = r.Entry;
                else if (r.IsAmbiguous) { PrintAmbiguous(nameOrNumber, r.Candidates); return; }
            }
            if (e == null) { ShowSuggestions(line); return; }
            PrintInfo(e);
        }

        private void PrintInfo(ArtifactEntry e)
        {
            _out.WriteLine($"Index      : {e.Index}");
            _out.WriteLine($"Alias      : {e.PrimaryAlias}");
            _out.WriteLine($"Aliases    : {string.Join(", ", e.Aliases)}");
            _out.WriteLine($"Original   : {e.OriginalName}");
            _out.WriteLine($"Kind       : {e.KindLabel}");
            _out.WriteLine($"Arch       : {e.DisplayArch}");
            _out.WriteLine($"Size       : {HumanSize(e.Size)}");
            _out.WriteLine($"Branch     : {e.Branch}");
            _out.WriteLine($"DownloadUrl: {e.DownloadUrl}");
        }

        private void PrintAmbiguous(string token, IReadOnlyList<ArtifactEntry> cands)
        {
            _out.WriteLine($"\"{token}\" matches multiple artifacts:");
            foreach (var e in cands)
                _out.WriteLine($"  {e.PrimaryAlias,-14} {e.OriginalName}");
            _out.WriteLine();
            _out.WriteLine($"Use one of the specific aliases, or run \"info {cands[0].PrimaryAlias}\".");
        }

        private void PrintHelp(bool active = false)
        {
            _out.WriteLine("Commands:");
            _out.WriteLine("  list                      show all artifacts");
            _out.WriteLine("  search <term>             filter by alias/name/arch");
            _out.WriteLine("  info <name-or-number>     detailed metadata");
            _out.WriteLine("  run <name-or-number> [args]   execute an artifact");
            _out.WriteLine("  use <name-or-number>      set the active artifact");
            _out.WriteLine("  <alias> [args]            run an unambiguous alias directly");
            _out.WriteLine("  refresh                   re-query GitHub and rebuild catalog");
            if (active)
            {
                _out.WriteLine("  <args...>                 run the active artifact with these args");
                _out.WriteLine("  back                       clear active artifact, return to catalog");
            }
            _out.WriteLine("  0                         exit (top) / back (active)");
            _out.WriteLine("  exit | quit                leave the tool");
            _out.WriteLine("  (partial input prints suggestions; it never auto-runs)");
        }
    }
}