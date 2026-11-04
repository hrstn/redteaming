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
| `C2-Tool-Collection/` | Adaptix AxScript (`.axs`) port of [Outflank's C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection), © the OutflankNL authors (upstream ships no license file), with extra original BOFs (e.g. RBCD). OSEP/CRTO/CRTL coverage. |
| `BOFKatz/` | **[RETIRED — do not build/ship]** In-memory Mimikatz-as-a-BOF (process hollowing + argument spoofing). Port of [KrakenEU/BOFKatz](https://github.com/KrakenEU/BOFKatz), © KrakenEU — ported here for AdaptixC2 without modification to its licensing terms (upstream ships no license file; see `BOFKatz/Readme.md`). |
| `GodPotatoBOF/` | BOF port of [GodPotato](https://github.com/BeichenDream/GodPotato) (Windows potato privilege escalation). |
| `CS-Remote-OPs-BOF/` | Vendored copy of [TrustedSec's CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF) (GPLv2) — remote-execution BOFs (process injection, remote execution). |
| `OSEP-ENUM/` | BOF port of `OSEP_enum.ps1` — single-pass local host enum, no child processes / no PowerShell. |
| `OSAI-ENUM/` | Port of [`OSEP-ENUM`](./OSEP-ENUM) retuned for OSAI (AI-300) labs — the eight enum sections plus four AI-quick-win sections. |
| `OSAI-LINUX/` | Three-tool static-Linux kit for the AdaptixC2 gopher agent (OSAI labs): local enum, AI-service discovery, pickle RCE. |
| `PrivescCheckExe/` | Native C# (NativeAOT) re-implementation of selected [PrivescCheck](https://github.com/itm4n/PrivescCheck) checks plus a Windows hardening audit (BSD-3-Clause). |
| `ai-pentesting/` | Reference notes: AI-pentesting service overview (2026). |
| `RemoteLoader/` | In-memory loader for .NET assemblies and x64 COFF/BOF objects, pulled over HTTPS from a GitHub repo (nothing touches disk). |
| `hostpayload/` | **[RETIRED — do not build/ship]** AdaptixPowerShell — PowerShell payload obfuscator/encryptor (.exe ↔ shellcode via Donut, AMSI bypass). Superseded by `hostpayload_v2/`. |
| `NaX/` | Local fork of the AdaptixC2 framework: custom beacon (`src_beacon`), loaders (`src_loader`, `src_loader_adv`), sleepmask (`src_sleepmask`), and the Go server plugin (`src_server/agent_nonameax`). Architecture, build/deploy, and wire protocol live in `NaX/wiki/`. |
| `profiler/` | **OPSEC profile generator** (standalone): persona-based malleable agent-interaction profiles (Graph / OneDrive) emitting paste-ready NaX v2 profile JSON, with a built-in validator for the beacon's hard parser caps. Shared comms hygiene for the whole chain. |
| `tools/` | Repo-wide opsec merge gate (`opsec_scan.py`, used by `make audit` / `make history`) + COFF integrity manifest (`coff_manifest.py`). Exceptions documented in `tools/opsec_scan_exceptions.txt`. |
| `RUNBOOK.md` | Operational notes: deploy chain (profile → listener → build → delivery), session gates, persistence install/clear rule, burn response. |
| `Cenotaph/` | Zero-import disk host for NaX payloads: PEB-resolves its APIs, reads `<exe-stem>.dat` (ChaCha20 + HMAC-SHA256 blob), verifies + decrypts, RW→RX, hands off to the payload. `Cenotaph/README.md`. |
| `hostpayload_v2/` | Hardened delivery-payload generator: drop-and-stomp droppers with decryptor shellcode, fetch mode, delivery wrappers (ISO/LNK/HTA), test harness + build gates. `hostpayload_v2/README.md`. |
| `remote_bof_loader/` | Importless native x64 in-memory COFF/BOF loader (a PS1 cradle fetches the object, the loader BOF runs it). `remote_bof_loader/README.md`. |

## Attribution notes

- `BOFKatz/` ports [KrakenEU/BOFKatz](https://github.com/KrakenEU/BOFKatz) © KrakenEU. The upstream
  ships no license file; the port is published here with full credit (`BOFKatz/Readme.md`). Do not
  redistribute this directory without the corresponding credit.
- `C2-Tool-Collection/` ports [OutflankNL/C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection)
  © the OutflankNL authors. The upstream ships no license file; upstream credits and tool links are
  preserved throughout the port.

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

#### Persistence-BOF — persistence primitives + kit-wide inventory  *(new, not in upstream)*

In-process COM/registry persistence with paired cleanup: `wmi-sub`/`wmi-clear`
(permanent WMI event subscription, boot trigger), `task-create`/`task-delete`
(in-process COM `RegisterTask`, per-run random task-name suffix, no schtasks
child), `runkey`, `comhijack` (HKCU InprocServer32, user keys only), and a
read-only `persist-inventory` sweep (Run keys, startup folders, all four WMI
subscription classes, task tree, non-system service binaries, IFEO overrides,
Winlogon). OPSEC contract: install → verify → use → clear → verify zero in
`persist-inventory`. Telemetry per command documented in
[`Extension-Kit/Persistence-BOF/README.md`](./Extension-Kit/Persistence-BOF/README.md).

#### Capture-BOF — in-process input capture  *(new, not in upstream)*

`clipmon` (clipboard poll, no hooks / no window chain) and `keylog`
(`GetAsyncKeyState` poll decoded via `ToUnicode`) — one worker thread in the
beacon process, own-process only, output via the task result channel, no disk
writes. Short windows by design; never paired with unattended persistence.
Details: [`Extension-Kit/Capture-BOF/README.md`](./Extension-Kit/Capture-BOF/README.md).

## Building

### Retired & restricted components (verdicts of the 2026-11-04 OPSEC audit — internal notes, kept out of the repo)

**Retired (2026-11-04 audit verdict — do not build, do not ship, marked in-place with `RETIRED.md`):**

| Path | Reason |
|---|---|
| `hostpayload/` | Signatured `amsiInitFailed` bypass + RWX + CreateThread in every generated loader — superseded by `hostpayload_v2/` |
| `C2-Tool-Collection/Loaders/RemoteLoader/` | **Deleted** — stale divergent copy that in-process patched AMSI + ETW on every run; the hardened loader lives at `RemoteLoader/` (repo root) |
| `NaX/src_loader/` | Basic loader superseded by `NaX/src_loader_adv/` (Stardust: clean-ntdll, module stomp, threadpool exec) |

**Kept as-is (accepted risk, operator decision 2026-11-04):**

| Path | Standing |
|---|---|
| `BOFKatz/` | Kept unchanged per operator decision. Full Mimikatz PE in memory + svchost hollowing remain its detection surfaces (internal audit notes, CRITICAL). Use with that knowledge; quiet in-process paths (`nanodump`, `pth`, `lsadump`, Kerbeus) remain the default credential route |

**Restricted — keep, prefer alternatives, never ship on a default profile:**

| Path | Restriction |
|---|---|
| `C2-Tool-Collection/BOF-Sources/WdToggle/` | Patches live lsass Wdigest/CredGuard fields (`WdToggle.c:96-193`) — CRITICAL; use quiet credential paths instead |
| `Other/PetitPotam/` RDLL variant | Verbatim Stephen Fewer reflective loader + `ExitProcess(0)` host kill (`ReflectiveLoader.h:42-48`, `ReflectiveDll.c:156`) — rebuild on the NaX loader per fix plan; BOF variant (`BOF-Sources/PetitPotam/`) fine |
| `Injection-BOF/inject_32to64/` | RWX end-to-end — use `inject_poolparty` or `inject_cfg` |
| `Execution-BOF/execute-assembly/` | Byte-patches ETW through an RWX flip — use `No-Consolation` (HWBP console) |
| `Elevation-BOF/potato-dcom/` | `NetUserAdd` + admin-group add on success — account-creation burst alert; prefer `pth`-based token paths |
| `CS-Remote-OPs-BOF/src/Injection/` legacy classes (clipboard, dde, ctray, svcctrl, tooltip, uxsubclassinfo, kernelcallbacktable) | Superseded by `inject_poolparty` / `inject_cfg` / `No-Consolation` |

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