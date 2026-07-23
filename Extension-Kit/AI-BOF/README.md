# AI-BOF — OSAI AdaptixC2 Beacon Object Files

Beacon Object Files that help AdaptixC2 beacons **find AI content and solve the
lab tasks** in the OffSec OSAI (AI-300) course/exam. Every BOF runs **in-process**
inside the beacon thread — zero child processes — which is the OPSEC point for the
SIEM-monitored labs: `FindFirstFile` / `ReadProcessMemory` / raw-socket / `WNet`
sweeps produce **no `CreateProcess` / `net use` / `curl` telemetry**.

Grounded in `~/osai/ai-300.pdf` and `OSAI-AI300-STUDY-GUIDE.md`. Design catalog:
`~/osai/OSAI-BOF-IDEAS.md`.

## Build

```bash
cd /home/hstn/c2tool/Extension-Kit/AI-BOF
make            # -> _bin/*.x64.o + *.x86.o  (15 BOFs x 2 arches = 30 COFFs)
make x64        # 64-bit only
make clean
```

Requires `x86_64-w64-mingw32-gcc` / `i686-w64-mingw32-gcc` (mingw-w64).

## Load in AdaptixC2

The loader `extension-kit.axs` already pulls in `AI-BOF/aibof.axs`. After
rebuilding, re-import the extension kit in the client; the 15 commands below
register for `beacon`, `gopher`, `kharon` on `windows`.

## Commands (course module → BOF → ATLAS)

| Command | Course | What it does | ATLAS |
|---|---|---|---|
| `aiHunter` | M2.4 | Recursive name+content hunt for AI artifacts & secrets on disk | T0040/T0051 |
| `credsMem` | M11.4 | `OpenProcess`+`VirtualQueryEx`+`ReadProcessMemory` secret sweep | T0024/T0025 |
| `credsLaunch` | M11.4 | Launch a short-lived binary & harvest its memory (suspend-only or run+poll) | T0024/T0025 |
| `envScraper` | M9.1.1 | Own env vars + registry secret locations (SSRF/env creds) | T0024 |
| `aiSvcProbe` | M5/M6 | Raw-socket probe of localhost AI service ports (Weaviate/Ollama/Phoenix) | T0040 |
| `shareWalk` | M11.5 | SMB KB-share enum + writable-dir probe (`\\FILESERVER01\Knowledgebase`) | T0051.001 |
| `poisonStage` | M5/M4.7 | Plant RAG/retrieval poison docs (pwdreset/collision/retrhijack/directive/memarticle) | T0020/T0051.001 |
| `configDump` | M7 | Dump semicolon-separated config files (`.env`/`config.yaml`/`rag.yaml`) | T0024 |
| `logTail` | M5 | Tail/grep `ingest_ok`/`lm_response`/`heartbeat`/`read_file` log lines | T0040 |
| `kubeHunter` | M9.2.2 | Find kubeconfig, b64-decode client-cert, scan DER for `system:masters` | T0018 |
| `tokenizerSwap` | M8 | Swap MAL↔FUN token ids in **both** `vocab.json` AND `tokenizer.json` | T0010.003 |
| `picklePlant` | M8 | Write a prebuilt pickle/.pt `__reduce__` RCE checkpoint (blob via `-file`) | T0010.005 |
| `gitMine` | M2.4 | Inflate+grep `.git/objects/` loose objects for secrets/AI content | T0024 |
| `vectorExport` | M5 | Dump Weaviate `/v1/schema` + `/v1/objects?class=DocChunk` | T0024 |
| `sessionBrute` | M3.4.2 | Brute predictable `MC-YYYYMMDD-NNNN` session ids over `/chat` | T0024 |

Run `help <command>` in the client for per-command usage. Examples:

```
aiHunter C:\Users -d 6
credsMem 0 -c 80
shareWalk FILESERVER01 Knowledgebase user pass -d 4
poisonStage 1 \\fileserver\kb\password_reset.txt -b 500
tokenizerSwap C:\app\vocab.json C:\app\tokenizer.json -dry
gitMine C:\app -g sk-
sessionBrute 10.10.10.10 8009 20260301 14 20
```

## Source layout

```
src/aibof.h          shared helpers + pattern tables (AIBOF_SECRETS/AI_SIGS/AI_NAMES)
src/<name>.c         one BOF per file, exports go(args, alen)
src/mininflate.c     RFC1951 DEFLATE inflater (included by gitMine.c, not built alone)
_bin/*.x64.o,.x86.o  compiled COFFs (stripped)
aibof.axs            AdaptixC2 command wrappers (bof_pack / execute_alias / arch)
Makefile
```

## Loader-compatibility notes (read before editing)

The AdaptixC2 BOF symbol resolver (`AdaptixServer/extenders/gopher_agent/
src_gopher/bof/coffer/coffer_windows.go`, `resolveExternalAddress`) **only
resolves `__imp_`-prefixed symbols**: `MODULE$func` via `LoadLibrary`/
`GetProcAddress`, plus the hardcoded `Beacon*`/`Ax*` switch. Anything else hits
`default: Unknown symbol -> 0`. Consequences enforced in `aibof.h`:

- **No bare libc.** `strlen`/`strcmp`/`memcmp`/`memcpy`/`strcpy`/`_stricmp` are
  reimplemented as `xlen`/`xcmp`/`xmemcmp`/`xmemcpy`/`xstrcpy`/`xstricmp`
  (pure pointer loops). Do not call bare libc anywhere.
- **No `htonl`/`htons`.** They import as `__imp_htons`/`__imp_htonl` (no `$`,
  not in the switch). Use `bs16()`/`bs32()`.
- **No compiler-emitted `memset`/`memcpy`.** Avoid partial `= {0}` aggregate
  inits (gcc lowers them to a `memset` libcall); zero with `xmemset`. The
  Makefile passes `-fno-tree-loop-distribute-patterns` so manual zero/copy
  loops are not converted back into `memset`/`memcpy` calls.
- **`___chkstk_ms` stub.** gcc emits a `___chkstk_ms` call for functions with
  >4 KB of stack locals; the loader does not resolve it, so `aibof.h` ships the
  standard community no-op stub (beacon thread stack is pre-committed).

After any source edit, rebuild and audit:

```bash
make clean && make
# must be EMPTY (no bare/unresolvable symbols):
x86_64-w64-mingw32-nm -u _bin/*.x64.o | awk '{print $2}' | grep -v '^__imp_'
i686-w64-mingw32-nm -u _bin/*.x86.o   | awk '{print $2}' | grep -v '^__imp_'
```

Only `__imp_Beacon*`, `__imp_KERNEL32$*`, `__imp_ADVAPI32$*`, `__imp_WS2_32$*`,
`__imp_MPR$*`, `__imp_NETAPI32$*` should remain — all resolved by the loader.

## Reporting reminder (OSAI exam)

Every prompt/query you issue must appear as text in the report. The BOFs print
the exact paths, crc32 fingerprints, and counts they touch so you can paste the
command + output verbatim and record timestamps for client cleanup.