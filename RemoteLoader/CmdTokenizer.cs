// CmdTokenizer.cs -- a tiny, quote-aware token splitter shared by the
// interactive REPL. Same semantics as RemoteLoader.ParseArgs (honours double
// quotes) but factored out so ArtifactCli has no dependency on the I/O code.

using System.Collections.Generic;
using System.Text;

namespace RemoteLoader
{
    internal static class CmdTokenizer
    {
        // Split a command line into tokens, honouring double-quoted segments.
        // Quotes are removed; spaces inside quotes are preserved.
        public static List<string> Split(string input)
        {
            var tokens = new List<string>();
            if (string.IsNullOrEmpty(input)) return tokens;
            var cur = new StringBuilder();
            bool inQ = false;
            foreach (char c in input)
            {
                if (c == '"') { inQ = !inQ; continue; }
                if (c == ' ' && !inQ)
                {
                    if (cur.Length > 0) { tokens.Add(cur.ToString()); cur.Clear(); }
                    continue;
                }
                cur.Append(c);
            }
            if (cur.Length > 0) tokens.Add(cur.ToString());
            return tokens;
        }

        // Rejoin the argument tokens (everything after the command/alias) into
        // a single raw string. BOF args are packed from the raw string, .NET
        // args are parsed back from it via ParseArgs -- so joining here is just
        // a stable transport, not a shell command.
        public static string JoinArgs(IReadOnlyList<string> tokens, int fromIndex)
        {
            if (tokens == null || fromIndex >= tokens.Count) return "";
            var sb = new StringBuilder();
            for (int i = fromIndex; i < tokens.Count; i++)
            {
                if (i > fromIndex) sb.Append(' ');
                // Re-quote if the token contains a space so a round-trip
                // through ParseArgs reconstructs the same value.
                if (tokens[i].Contains(' ')) sb.Append('"').Append(tokens[i]).Append('"');
                else                          sb.Append(tokens[i]);
            }
            return sb.ToString();
        }
    }
}
