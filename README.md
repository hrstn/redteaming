# redteaming

Personal red-team toolkit. Two themes:

1. **BOF ports to AdaptixC2** — Beacon Object Files (and a few helpers) adapted to
   the [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2) AxScript loader,
   plus original BOFs written for OSEP / CRTO / CRTL / OSAI exam prep.
2. **Misc tools for pentesting / red-teaming.**

> ⚠️ For authorized security testing and education only. Several modules are
> offensive in nature; only run them against labs you own or are authorized to test.

## Repository layout

| Path | What it is |
|---|---|
| `Extension-Kit/` | Vendored copy of the [AdaptixC2 Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit) (GPLv3) — see below. **Our active BOF build tree.** |
| `C2-Tool-Collection/` | Fork of [Outflank's C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection) ported to Adaptix AxScript (`.axs`), with extra BOFs (e.g. RBCD). OSEP/CRTO/CRTL coverage. |
| `BOFKatz/` | In-memory Mimikatz-as-a-BOF (process hollowing + argument spoofing). |
| `GodPotatoBOF/` | BOF port of [GodPotato](https://github.com/BeichenDream/GodPotato) (Windows potato privilege escalation). |
| `OSEP-ENUM/` | BOF port of `OSEP_enum.ps1` — single-pass local host enum, no child processes / no PowerShell. |
| `RemoteLoader/` | In-memory loader for .NET assemblies and x64 COFF/BOF objects, pulled over HTTPS from a GitHub repo (nothing touches disk). |
| `hostpayload/` | AdaptixPowerShell — PowerShell payload obfuscator/encryptor (.exe ↔ shellcode via Donut, AMSI bypass). |

## Extension-Kit (vendored)

`Extension-Kit/` is a vendored copy of
[Adaptix-Framework/Extension-Kit](https://github.com/Adaptix-Framework/Extension-Kit)
— the official extension kit for
[AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2). The vendored copy has
its `.git` history removed so it lives as a plain subtree of this repo; all upstream
suites (`AD-BOF`, `Creds-BOF`, `Elevation-BOF`, `Execution-BOF`, `Injection-BOF`,
`LateralMovement-BOF`, `Process-BOF`, `Postex-BOF`, `SAL-BOF`, `SAR-BOF`) are intact
and unmodified. See `Extension-Kit/README.md` for the upstream module list.

**Attribution & license:** the vendored Extension-Kit code is © the Adaptix-Framework
authors and licensed under **GPLv3** (`Extension-Kit/LICENSE`). This repo distributes
it unmodified (apart from the additions documented below) under the same license.

### Custom additions over upstream

On top of the upstream kit, this vendored copy adds two sets of original BOFs
(written for OSAI / OSEP / CRTO / CRTL exam prep). They build with the same suite
Makefiles and register through the same `extension-kit.axs` loader.

#### AI-BOF — OSAI (AI-300) suite  *(new, not in upstream)*

Beacon Object Files that help AdaptixC2 beacons **find AI content and solve the lab
tasks** in the OffSec OSAI (AI-300) course. Every BOF runs **in-process** in the
beacon thread — zero child processes — which is the OPSEC point for the SIEM-monitored
labs (`FindFirstFile` / `ReadProcessMemory` / raw-socket / `WNet` sweeps produce no
`CreateProcess` / `net use` / `curl` telemetry). Full design notes, build, and
loader-compatibility rules are in [`Extension-Kit/AI-BOF/README.md`](./Extension-Kit/AI-BOF/README.md).

| Command | Course | What it does | ATLAS |
|---|---|---|---|
| `aiHunter` | M2.4 | Recursive name+content hunt for AI artifacts & secrets on disk | T0040/T0051 |
| `credsMem` | M11.4 | `OpenProcess`+`ReadProcessMemory` secret sweep of a process's memory | T0024/T0025 |
| `credsLaunch` | M11.4 | Launch a short-lived binary & harvest its memory for creds (suspend-only or run+poll) | T0024/T0025 |
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

#### pth — Pass-the-Hash make-token / run-binary  *(added to LateralMovement-BOF)*

`pth <user> <domain> <nthash> [binary]` — mint a Windows **network-logon token from
an NT hash alone** via `LsaLogonUser` + `MSV1_0_LM20_LOGON` with a self-computed
NTLMv2 response (NT hash → NTOWFv2 → NTProofStr). No lsass patching, no driver,
Credential-Guard-safe, **admin-only (no SeTcb needed)**. With no binary it impersonates
the beacon thread as the hash-user (mirrors `token make`); with a binary it spawns
that binary as the hash-user (network logon — reaches SMB/etc as them). MITRE
**T1550.002**. Details: [`Extension-Kit/LateralMovement-BOF/pth/README.md`](./Extension-Kit/LateralMovement-BOF/pth/README.md).

## Building

```bash
# Extension-Kit (all suites + our additions)
cd Extension-Kit && make

# a single suite
make -C Extension-Kit/LateralMovement-BOF
make -C Extension-Kit/AI-BOF
```

Requires `x86_64-w64-mingw32-gcc` / `i686-w64-mingw32-gcc` (mingw-w64). Compiled
COFFs land in each suite's `_bin/` (git-ignored; regenerable). Load
`Extension-Kit/extension-kit.axs` in the AdaptixC2 client: **Main menu → AxScript →
Script manager → Load new**.