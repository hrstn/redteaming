# NoNameAx (NaX)

THIS IS PORT OF [https://github.com/MaorSabag/NaX/](https://github.com/MaorSabag/NaX) — full credits to MaorSabag.
Heavily extended since the port: full in-memory evasion stack (P1–P11), a
module-stomping BOF loader, tunnels, pivots, malleable C2 profiles, and an
AdaptixC2 plugin that builds, packs and delivers everything end to end.

NaX is a **custom AdaptixC2 agent**: a PIC (position-independent, single
`.text`, headerless, import-free) shellcode beacon with no CRT and no static
data — all state in a heap instance, all Win32 resolved at runtime by
FNV1a-32 PEB walk — plus a Go server plugin (`src_server/agent_nonameax/`)
that generates `Config.h`, compiles beacon + loader + sleepmask, packs the
payload (v2 header) and wraps it as bin/exe/dll/svc, driven fully from the
Adaptix operator UI.

---

## Feature matrix (at a glance)

| Area | Feature | State |
|---|---|---|
| Transport | HTTPS/HTTP beacon (WinHTTP, persistent handles) | ✅ working |
| Transport | SMB named-pipe peer transport (linked child) | ✅ working |
| Config | Malleable C2 profiles (HTTP), runtime refresh (`profile`) | ✅ working |
| Evasion | P1–P11 in-memory evasion stack (below) | ✅ compiled/validated, P1–P4 live-validated 2026-07-24 |
| Loader | Stardust-pattern UDRL (basic + advanced/AA/CleanNtdll lanes) | ✅ working |
| Memory | Module stomping + `.pdata/.xdata` unwind stomping + LDR patch | ✅ working |
| Exec | ThreadPool (`TppWorkerThread`) or CreateThread transfer | ✅ working |
| BOF | CS-ABI COFF loader, sync/async jobs, dedicated sleepmask slot | ✅ working |
| Session | Token store + impersonation/creation, interactive remote shell | ✅ working |
| Tunneling | SOCKS4/5, lportfwd, rportfwd, TCP tunnels, SMB pivots | ✅ working |
| Delivery | bin / exe / svc / dll wrappers (service-name hygiene enforced) | ✅ working |
| Hygiene | Kill date, pre-dwell zeroing, dev-lane sensor profile system | ✅ working |

Full docs live in [`wiki/`](wiki/): `Beacon-Architecture.md`,
`BeaconGate-Sleepmask.md`, `Module-Stomping.md`, `Stardust-Loader-Guide.md`,
`Tunneling.md`, `BOF-Execution.md`, `Wire-Protocol.md`, `Operator-Reference.md`,
`Malleable-C2-Profiles.md`, `Token-Commands.md`.

---

## Evasion (P1–P11)

Layered in-memory evasion hardening on top of the base beacon. Each layer is
independent and degrades gracefully (falls back to the non-evasive path on any
resolution/runtime failure — never crashes the beacon). The review that drove
P5–P11 lives in [`wiki/SelfTaught-Course-Gap-Analysis.md`](wiki/SelfTaught-Course-Gap-Analysis.md).

- **P1 — Indirect syscalls** ✅ *live-validated 2026-07-24.* HellsGate/HalosGate SSN
  extraction + a Tartarus in-ntdll `syscall;ret` gadget; the 12 direct `Nt*` calls
  execute `syscall` inside ntdll. `src_beacon/asm/Syscall.x64.asm` (raw-byte stubs),
  `src_beacon/include/Syscall.h`, `src_beacon/src/Core/Syscall.c`. Lane-dependent:
  elastic = direct ntdll stubs (`NAX_INDIRECT_SYSCALLS=0`), defender = indirect
  stubs (`NAX_INDIRECT_SYSCALLS=1`). **P8 hardening:** secondary SSN validation
  (`stub[6]==0 && stub[7]==0`) defeats partially-clobbered SSN reads; boot-time
  hooked-stub tally in the debug log (operator intel on which SSNs got hooked).
  Verified dual-layout against the Win11 24H2 VBS/HVCI branchy stub generation
  (clean `0F 05 C3` gadgets retained on the syscall branch).
- **P2 — Encrypted sleepmask** ✅ *live-validated 2026-07-24.* XOR-encrypts the
  beacon `.text` across each sleep with a per-sleep CSPRNG key (BCryptGenRandom,
  fallback derived key), flips to non-exec RW for the wait, restores on wake.
  `ActiveJobCount`/`SleepObf` guarded. `src_sleepmask/src/main.c`.
- **P5 — Full-wait stack spoof** ✅ `SpoofWait` trampoline: the same RBP-chain
  ret rewrite as P4 but applied across the **whole** `NtWaitForSingleObject`
  window, not only the VP syscalls — periodic stack sweeps of the sleeping
  thread (Hunt-Sleeping-Beacons / pe-sieve thread scans) see only image-backed
  ntdll frames for the entire dwell window. Saved real return addresses are
  stored XOR'd with the ntdll base, so no beacon addresses sit at rest on the
  sleeping thread's stack. Gated on `NAX_SM_WAIT_SPOOF` (default on; no effect
  when the P4 machinery is absent). CET-safe by design (same-thread WFSO wait,
  no ROP chains) — a deliberate divergence from Ekko/FOLIAGE which
  Hunt-Sleeping-Beacons v2 now fingerprints.
- **P6 — Private-heap masking + key obfuscation** ✅ busy blocks of the
  beacon-owned private heap are XOR-masked with the same per-sleep key
  (`RtlLockHeap`+`RtlWalkHeap`; the lock is held across the wait so the wake
  unmask is deterministic). Task buffers, results, tunnel state and strings no
  longer sit plaintext during dwell. The per-sleep key itself is obfuscated on
  the stack across the wait with a wake-recomputable seed
  (`BeaconBase ^ SpoofCount`) — a stack dump alone no longer decrypts the
  masked spans offline. Unmasking runs last on wake: threads blocked on the
  heap lock resume only into fully restored memory.
- **P4 — Stack / return-address spoofing** ✅ *shipped, on by default.* Spoofs
  the sleepmask's on-stack return addresses with image-backed ntdll addresses
  for the duration of each sleep-cycle `VirtualProtect` syscall
  (`SpoofedVirtualProtect` trampoline), defeating kernel call-stack
  `call_stack_contains_unbacked` checks. Default-on (`NAX_SPOOF_STACK ?= 1`).
- **P3 — AMSI/ETW patch** ✅ `src_beacon/src/Core/Patch.c`. Lane-gated
  (`NAX_LANE=defender` → on; `elastic` → off; override `NAX_ETW_PATCH=1`):
  `ntdll!EtwEventWrite` + `NtTraceEvent` → `33 C0 C3`,
  `amsi.dll!AmsiScanBuffer` → `31 C0 C3` (only when amsi is *already loaded*
  in the host — the beacon never self-loads amsi). Protect flips run through
  the stub-routed `NtProtectVirtualMemory`; verify-after-patch; every step
  fails soft. Honest scope: userland providers only — kernel ETW-TI is
  untouched by any userland patch.
- **P10 — Load-time call-stack hygiene** ✅ `NaxTpLoadLibraryW`
  (`Core/Bootstrap.c`): winhttp loads via a TpWork callback that JMPs to a
  `call r10; ret` call-gadget in dsdmo.dll (LibTPLoadLib pattern) — breaks
  BOTH the "network module from unbacked memory" and the "library loaded via
  a callback function" call-stack rule signatures. Runtime gadget validation
  (exact 10-byte sequence), CFG whitelisting of the callback, graceful plain
  `LoadLibraryW` fallback on any miss.
- **P11 — Encrypt-sleep threshold** ✅ `NAX_SM_MIN_SLEEP_MS` (default 1000,
  the FOLIAGE ≥1 s gate): sleeps below the threshold skip the P2 mask/protect
  cycle — short jitter sleeps stop burning VirtualProtect churn that
  correlates with beaconing without buying scanner evasion. Tunable at build
  and at runtime via `sleepobf-config {sleep_obf} [min_ms]`.

> Sensor-lane model: `NAX_LANE=elastic` (CRTL/Falcon/Elastic: direct stubs +
> stack spoof on + P3 off) vs `NAX_LANE=defender` (OSAI/Defender: indirect
> stubs + P3 on). The plugin wipes the beacon build dir on lane change.
> Rationale documented inline in `src_beacon/Makefile`.
>
> Note on Cloud Defender: Defender uses kernel ETW-TI + AMSI, not userland
> ntdll prologue hooks, so HellsGate reads every SSN directly (HalosGate is
> robustness for EDRs that *do* hook).

---

## Communications

- **HTTP(S) transport** — WinHTTP-based, persistent session/connection handles
  (recreated after 60 s staleness), malleable C2 profile pipeline (encoding,
  headers, URIs, per-payload watermark `X-Beacon-Id`), WS2 lazy-loading
  (`ws2_32` absent from imports until first tunnel use).
- **SMB transport** — named-pipe child transport with raw pipe framing; pivot
  routing watermarks; tunnel results flow through the parent pipe.
- **Malleable profiles** — JSON v2 profiles (headers, URIs, encode chain,
  404-detection, per-profile caps). Generator with `graph`/`onedrive` personas
  + beacon-cap validator: `../profiler/gen_profile.py`; hand templates:
  `profiles/jquery-stealth.json`, `profiles/aws-cloudfront.json`,
  `profiles/ms365-graph.json`. Profiles are served at REGISTER (`0x82`) and
  hot-swappable at runtime via `profile`.
- **Wire** — 6-byte frame header (type/flags/lenLE), AES-128-CBC body,
  kill-date + watermark baked in config. Full spec: `wiki/Wire-Protocol.md`.

---

## Command surface (agent-side, via Adaptix console)

Full operator reference: [`wiki/Operator-Reference.md`](wiki/Operator-Reference.md).

| Category | Commands |
|---|---|
| **Recon** | `whoami`, `screenshot` (GDI desktop), `ps list`, full host/user/network sysinfo at registration |
| **Navigation / file ops** | `cd`, `pwd`, `ls [-r]`, `cat`, `cp`, `mv`, `rm [-rf]`, `mkdir`, `rmdir [-rf]` |
| **Transfer** | `download {path} {chunk_size}` (chunked, resumable), `upload {file} {path} {chunk_size}`, `chunksize {size}` |
| **Execution** | `bof {file} {args}` / `execute bof` (Extension-Kit compatible), `ps run` (child process with output capture) |
| **Async BOF jobs** | `bof -a`, `job list`, `job kill {task_id}`, `watchdog on/off` (timeout-enforced BOFs) |
| **Process** | `ps list / ps kill {pid} / ps run` |
| **Tokens** | `token getuid / steal <pid> / impersonate / list / rm / revert / make -t <logon type> <domain> <user> <pass> / privs` (full store, thread-token impersonation, privilege enumeration) |
| **Session** | `sleep {ms} {jitter}`, `terminate thread / process`, interactive **Remote Shell** browser channel (`0x47–0x49`) |
| **Config (runtime)** | `profile {file}`, `bof-stomp sync/async/sleepmask/show`, `sleepmask-set [-debug]`, `sleepobf-config {on/off} [min_ms]`, `chunksize`, `watchdog` |
| **Pivoting** | `link smb {host} {pipe}`, `unlink {id}` — child SMB agents route all tasking/tunnel traffic through the parent |
| **Tunnels** | `socks start {port} [-auth user pass]` (SOCKS4/5), `lportfwd start {bind} {lport} {fwdhost} {fwdport}`, `rportfwd start {port} {target} {tport}` + `stop` per tunnel (four-phase tunnel pipeline: check → flush → recv → close, batched RESULT frames) |
| **Evasion (runtime)** | `dll-notify list` / `dll-notify remove` (enumerate + strip `LdrRegisterDllNotification` callbacks — kills EDR image-load hooking) |

---

## Loader and delivery architecture

- **UDRL loader** (Stardust pattern): PIC entry stub, TLS egghunter instance
  storage, PEB walk + export walk with **forwarded-export resolution**,
  compile-time FNV1a hashing (zero API-name strings), two variants:
  - `src_loader/` — plain (LoadLibraryExW-less paths)
  - `src_loader_adv/` — advanced: anti-analysis gates, clean-ntdll copy for
    SSN/gadget work, CFG whitelisting, staged-copy wipe (loader self-erasure)
- **Module stomping** (default) — sacrificial signed DLL (default `chakra.dll`;
  `mshtml`, `jscript9`, `d3d11`, operable via UI) stomped with the beacon;
  **no RWX at any point**; LDR entry patched (`LDRP_IMAGE_DLL | ENTRY_PROCESSED`);
  optional `.pdata/.xdata` unwind stomping for clean stack walks;
  execution via `TpAllocWork` (thread start = `TppWorkerThread`) or
  `CreateThread` fallback.
- **Packing** — NaxHeader v2 (magic/size/pdata/xdata/rva/flags/dll), staged
  via `scripts/pack_nax.py` or the plugin's Go packer (`nax_packer.go`),
  page-aligned so the loader can wipe the staged plaintext copy after placing
  the beacon (loader self-erasure).
- **Delivery wrappers** — bin (`nax.x64.bin`), exe, svc, dll (custom export),
  all with runtime service-name hygiene (rejects flagged short/system
  service names that trip 7045 rules).
- **Stage-0 material** — `hostpayload_v2` (native ChaCha20+HMAC dropper,
  no PowerShell) when the beacon is delivered staged.

---

## BOF execution stack

- CS-ABI compatible COFF loader (`src_beacon/src/Bof/`): 30+ entry Beacon API
  table (data/format/output/token/process/utility), `MODULE$Function` external
  resolution with lower-case `LoadLibraryA` fallback, `__imp_` →
  `mapFunctions` indirection, aux-record handling, per-section permissions
  (never RWX), full relocation matrix (ADDR64/ADDR32NB/REL32_0–5/i386).
- **Module-stomp slots**: dedicated sync slot, async pool (up to 4), and a
  **dedicated sleepmask slot** — BOFs run from image-backed memory with clean
  call stacks. Runtime reconfigurable via `bof-stomp`.
- **Compound results** — text + tagged media entries (screenshot 0x81,
  download 0x82, OEM/UTF-8 types).
- **Sleepmask BOF** — resident in its own stomp slot, implements P2/P5/P6/P11
  (see above), hot-reloadable via `sleepmask-set` without redeploying.

---

## Evasion-related runtime commands

| Command | What it does |
|---|---|
| `sleepobf-config {on/off} [min_ms]` | toggle P2 sleep obfuscation + tune the P11 threshold live |
| `sleepmask-set [-debug]` | rebuild + hot-load the sleepmask BOF in a running beacon |
| `bof-stomp sync/async/sleepmask {dll}` | swap sacrificial DLLs at runtime (re-wires stomp slots) |
| `dll-notify list` / `remove` | enumerate and strip DLL load notification callbacks (unhook the image-load path) |
| `profile {file}` | swap the malleable C2 profile live |

---

## Build system

```bash
make                                   # release payload (loader + v2 header + beacon + unwind)
make debug                             # debug beacon (console output)
make MODULE_STOMP=1 STOMP_DLL=mshtml.dll STOMP_PDATA=1
make beacon NAX_LANE=defender          # compile the beacon for one lane
make -C src_sleepmask all | debug      # sleepmask BOF only
```

| Key knobs | Values |
|---|---|
| `NAX_LANE` | `elastic` (default; direct stubs + spoof + no P3) / `defender` (indirect stubs + P3) |
| `NAX_STOMP_MODE` | `1` module stomp (default) / `0` VirtualAlloc |
| `NAX_EXEC_MODE` | `1` TpWork (default) / `0` CreateThread |
| `STOMP_DLL`, `STOMP_PDATA` | sacrificial DLL / unwind stomping |
| `NAX_TRANSPORT_PROFILE` | `0` HTTP / `1` SMB |
| `NAX_ETW_PATCH` | P3 override (`0`/`1`; defender lane defaults on) |
| `NAX_SM_MIN_SLEEP_MS`, `NAX_SM_WAIT_SPOOF` | P11/P5 build-time defaults |

The Adaptix plugin (`src_server/agent_nonameax`) drives the whole build from
the payload-generation dialog (sleep/jitter/killdate/watermark/profile,
transport, technique combo, BeaconGate tab with gated APIs + sleepmask DLL,
SleepObf toggle, svc/dll fields) and returns the packed payload in memory.

**Test contract** (Windows validation): `make clean && make MODULE_STOMP=1 `
should run clean on MinGW-w64 + nasm + objcopy cross-toolchains; Go plugin
needs Go 1.21+. `cd src_server/agent_nonameax && go test ./...`. The
Defender/OSAI live pass methodology lives in `tests/defender/METHODOLOGY.md`.

---

## Post-ex injection BOFs (separate tools)

Under `../C2-Tool-Collection/BOF-Sources/` — run via the agent's `bof`
command (or any CS-ABI COFF loader):

| Tool | Technique | Note |
|---|---|---|
| `ThreadlessInject/` | Hook a target export so an **existing** thread runs the payload — zero thread-creation telemetry (`PsSetCreateThreadNotifyRoutine` + ETW ThreadStart silent) | `threadlessinject <pid> <dll> <func> <shellcode>`; RW→RX, transient 14-byte hook window, readback-verified |
| `PoolPartyV7/` | TP_DIRECT injection via `NtSetIoCompletionEx` against the target's pool IOCP — threadless, no queue surgery, legitimate call stack (`TppDirectpExecuteCallback`) | `poolpartyv7 <pid> <shellcode>`; hangless type-index discovery + WorkerFactory↔IOCP kernel-object disambiguation |

Both are x64, compile via `cd SOURCE && make`, and ship OPSEC notes in their
READMEs.

---

## Repo layout

```
NaX/
  src_beacon/          PIC beacon (Core/Commands/Transport/Bof)
  src_loader/          basic UDRL
  src_loader_adv/      advanced UDRL (AA + CleanNtdll + staged wipe)
  src_sleepmask/       sleepmask BOF (P2/P5/P6/P11)
  src_server/          Adaptix plugin (Go) + listeners + store service
  profiles/            malleable C2 templates (see ../profiler/)
  scripts/             pack_nax.py, embed_sleepmask.py
  tests/defender/      live validation methodology
  wiki/                architecture + operator docs
```

## Operational notes

- **Kill date** — baked UTC-expiry; the beacon wipes its config span and exits
  when reached. Plaintext IO buffers are zeroed before every dwell cycle;
  env/resp buffers hold ciphertext only.
- **Watermark** — per-payload/listener watermark baked into config (SMB pivot
  routing uses the listener watermark).
- **Dev builds** — `Config.h / Config_sleepmask.h` are plugin-generated and
  gitignored; for local `make beacon`, a dev `Config.h` is expected
  (`make -C src_sleepmask all && python3 scripts/embed_sleepmask.py` first).
  Never commit either file.
- **Runtime validation caveat** — P5/P6/P10/P11 are compile/load-path verified
  locally; behavior on real sensors needs the Win11 Defender/OSAI pass
  (`tests/defender/METHODOLOGY.md`). Debug builds trace the gate/spoof path
  via `SpoofCount` (steady +3/cycle with the full stack live: +2 VP spoof,
  +1 wait spoof).
