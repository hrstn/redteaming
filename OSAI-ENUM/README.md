# osai-enum

A Beacon Object File (BOF) for **OSAI / AI-300** local-host enumeration — a port of
[osep-enum](../OSEP-ENUM) that keeps all eight original sections and adds four
AI-quick-win sections tuned to the recurring signals across the OSAI challenge
labs (Double Helix, Pipeline Breach, Iron Crown, Synthetic Siege). Part of the
[SAL-BOF](https://github.com/0xGunrunner/SAL-BOF) collection.

Runs **twelve** enumeration sections in a single BOF execution with no child
process spawns and no PowerShell — the same OPSEC point as osep-enum, just with
an AI/ML lens layered on top.

## What it does

### Ported from osep-enum (1–8)

| # | Section | Details |
|---|---------|---------|
| 1 | **Network shares** | `NetShareEnum` — name, type, remark |
| 2 | **Interesting files** | Recursive search under `C:\Users` (depth 6) for `.xml .txt .pdf .xls .xlsx .doc .docx .log .exe` + `id_rsa`, `authorized_keys` |
| 3 | **Directory listings** | One-level listing of `C:\`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData` |
| 4 | **Flag files** | `local.txt` / `proof.txt` under `C:\` (root) and `C:\Users` (depth 6) |
| 5 | **Listening TCP ports** | `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_LISTENER`) — address, port, PID, resolved process name |
| 6 | **IIS wwwroot write check** | Create+delete a test file in `C:\inetpub\wwwroot` — flags writable root as a `SeImpersonate → SYSTEM` path via an ASPX shell |
| 7 | **Sticky Notes + PS history** | Per-user `ConsoleHost_history.txt` (PSReadLine) + Sticky Notes `LocalState` SQLite store |
| 8 | **Installed services** | `HKLM\SYSTEM\CurrentControlSet\Services` registry enum (no SCM handle) |

### OSAI quick wins (9–12)

| # | Section | Details |
|---|---------|---------|
| 9 | **System & defenses** | Hostname + domain/workgroup (`NetWkstaGetInfo`), current user (`USERNAME`), arch (`GetNativeSystemInfo`), OS name/build/version (registry), Defender real-time state (registry), and **all token privileges** with enabled/disabled — the one-glance view that decides potato (SeImpersonate), dcsync/backup (SeBackup), LSA (SeTcb), etc. |
| 10 | **AI/ML artifacts & config secrets** | Recursive search (depth 6 under `C:\Users`/`C:\ProgramData`/`C:\opt`/`C:\AI`/`C:\ML`, depth 4 under Program Files) for **model files** (`.pt .pth .pkl .ckpt .safetensors .onnx .h5 .gguf .tflite .pb .npy .npz .joblib .keras .bin .mlmodel`), **AI-tool dirs** (`mlruns`, `ollama`, `n8n`, `langflow`, `huggingface`, `chroma`, `qdrant`, `weaviate`, `milvus`, `wandb`, `tensorboard`, …) and **AI config files** (`config.json`, `docker-compose.yml`, `.env`, `Modelfile`, `requirements.txt`, `Dockerfile`, `models.yaml`, `appsettings.json`, …). Small text configs (≤64 KB) are opened **in-process** and scanned for secret signatures: `sk-`, `glpat-`, `AKIA`/`ASIA`, `ghp_`/`gho_`/`github_pat_`, `xoxb-`/`xoxp-`, `-----BEGIN`, `eyJ`, `hvs.`, `AIza`, `password=`, `api_key=`, `token=`, `secret=`, `Authorization: Bearer`, `connection_string`, `mongodb://`/`postgresql://`/`redis://`/`amqp://`, `aws_secret` … Each hit prints the file, the matched signature, and a 64-byte context window. Capped at 300 files / 6 hits per file / 200 total hits. |
| 11 | **AI/ML listening services** | Re-runs the TCP listener enum and labels every port in the known AI/ML service table: `11434` Ollama, `5000`/`5001`/`5005` Flask/MLflow/Registry, `7860` Gradio, `3000` n8n/Gitea/Grafana, `8501` TF Serving, `8888` Jupyter, `6006` TensorBoard, `5432` Postgres, `6379` Redis, `7687` Neo4j Bolt, `9200` Elasticsearch, `27017` MongoDB, `19530` Milvus, `5672` RabbitMQ, `9090` Prometheus, `4317/4318` OTLP, `8086` InfluxDB, `5601` Kibana, `22` SSH, `5985/5986` WinRM … |
| 12 | **SSH keys + env secrets** | Per-user `.ssh\` contents (`id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `authorized_keys`, `known_hosts`, `config`, …) and `C:\ProgramData\ssh\` (`administrators_authorized_keys`, `ssh_host_*_key`, `sshd_config`); then scans the process environment block for variable names matching `*TOKEN*`/`*KEY*`/`*SECRET*`/`*PASSWORD*`/`*PASS*`/`VAULT*`/`*CREDENTIAL*`/`*API*`/`*CONN*`/`AWS_*`/`GITLAB_*`/`GITHUB_*`/`HUGGINGFACE*`/`HF_*`/`OPENAI*`/`ANTHROPIC*`/`AZURE*`/`REGISTRY*`/`MIRROR*`/`DEPLOY*`/`SA_KEY`/`SERVICE_ACCOUNT` and prints `NAME = VALUE` (values truncated to 260 chars). |

## Usage

```
osai-enum
```

No arguments. Runs all twelve sections sequentially and prints results inline.

### Example output (abridged)

```
==========================================
          OSAI Enumeration BOF
          (osep-enum + AI quick wins)
==========================================

========================================
[5] LISTENING TCP PORTS
========================================
  Address:Port           PID       Process / Service
  ------------           ---       ---------------
  0.0.0.0:445            4         System
  0.0.0.0:11434          1888      ollama.exe  [Ollama]
  127.0.0.1:5000         4012      python.exe  [Flask/MLflow/Registry]

========================================
[9] SYSTEM & DEFENSES (OSAI)
========================================
  Host   : RESEARCHWS01
  Domain : KETHALIS
  User   : p.nguyen
  Arch   : x64
  OS     : Windows Server 2022 Datacenter (build 20348, 21H2)
  Defender: real-time ENABLED
  Privileges (5):
    SeImpersonatePrivilege      ENABLED
    SeDebugPrivilege            ENABLED
    SeAssignPrimaryTokenPrivilege disabled
    ...

========================================
[10] AI/ML ARTIFACTS & CONFIG SECRETS (OSAI)
========================================
  [ai-dir] C:\Users\p.nguyen\.ollama
  [model]  C:\ProgramData\models\resnet18_epoch_040.pt
  [cfg]    C:\opt\mlflow\config.yaml
  [secret] C:\opt\mlflow\config.yaml  sig=glpat-
      glpat-7xY9q2mZvT4nK1pR8sH3aBcDeFgHiJkL
  [secret] C:\opt\n8n\.env  sig=sk-
      sk-proj-abc123...Xk9s2mZvT4nK1pR8sH3aBcD

========================================
[11] AI/ML LISTENING SERVICES (OSAI)
========================================
  127.0.0.1:11434  1888   ollama.exe   [Ollama]
  127.0.0.1:5000   4012   python.exe   [Flask/MLflow/Registry]

========================================
[12] SSH KEYS + ENV SECRETS (OSAI)
========================================
  [ssh] C:\Users\p.nguyen\.ssh\id_ed25519
  [ssh] C:\Users\p.nguyen\.ssh\known_hosts
  [ssh-sys] C:\ProgramData\ssh\sshd_config
  -- env secrets --
  [env] OPENAI_API_KEY = sk-proj-abc123...
  [env] VAULT_TOKEN = hvs.CAES...xyz
  [env] MLFLOW_TRACKING_URI = http://mlflow01:5000

[*] Enumeration complete.
```

## Building

Requires `mingw-w64` cross-compiler on Linux/macOS.

```bash
# x64
x86_64-w64-mingw32-gcc -c osai_enum.c -masm=intel -o osai_enum.x64.o

# x86
i686-w64-mingw32-gcc -c osai_enum.c -masm=intel -o osai_enum.x86.o
```

Then copy both `.o` files into `Extension-Kit/SAL-BOF/_bin/` and register the
command in `sal.axs` (the `cmd_osai_enum` block + `group_test` entry — already
wired in the canonical tree).

### Dependencies

- `beacon.h` — standard Cobalt Strike / AdaptixC2 BOF header (place alongside `osai_enum.c`)
- `KERNEL32` — file search, file read, heap, env, system info
- `IPHLPAPI` — `GetExtendedTcpTable`
- `NETAPI32` — `NetShareEnum`, `NetWkstaGetInfo`
- `ADVAPI32` — registry, token privileges
- `MSVCRT` — wide-string + memcmp/memcpy helpers

No external libraries beyond what is already present on any Windows installation.

## Integration — AdaptixC2 (SAL-BOF / sal.axs)

`osai-enum` is registered as a top-level command in the AXS extension file:

```javascript
var cmd_osai_enum = ax.create_command(
    "osai-enum",
    "OSAI local-host enum: osep-enum + AI quick wins",
    "osai-enum"
);
cmd_osai_enum.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/osai_enum." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "BOF implementation: osai-enum");
});
```

Scoped to `["beacon","gopher","NoNameAx"]` on `["windows"]` via the `SAL-BOF`
group (same as `osep-enum`).

## Technical notes

**No PowerShell, no child processes.** Everything runs in the beacon process —
the file search, the in-process config read+scan, the env-block walk, the token
query. No `cmd.exe` / `powershell.exe` spawned.

**`___chkstk_ms` stub.** The ported `findStickyAndHistory` (3× `WIN32_FIND_DATAW`
+ several `wchar[MAX_PATH]` arrays) and the AI walk push some frames past 4 KB,
so gcc emits a `___chkstk_ms` probe call. The AdaptixC2/Outflank loader does not
resolve `___chkstk_ms`, so a no-op stub is shipped (the beacon runs on a
pre-committed 1 MB stack — probing is unnecessary). The reference `osep-enum`
binary actually has the same unresolved `___chkstk_ms` and would fail to load
without it; `osai-enum` ships the stub and is audit-clean.

**Config-secret scan is conservative.** Only files with AI-config extensions
(`.env/.yml/.yaml/.json/.cfg/.ini/.conf/.toml/.properties`) or exact config
names are opened, and only the first 64 KB is scanned. Prefix signatures
(`sk-`, `glpat-`, …) require a ≥16-byte non-whitespace tail so DLL/string-table
noise doesn't flood output; `-----BEGIN` (PEM headers) is always reported.
Keyword signatures (`password=`, `connection_string`, `mongodb://`, …) are
always reported with a 64-byte context window. Caps: 300 files, 6 hits/file,
200 hits total.

**Program Files walked list-only.** `C:\Program Files` / `C:\Program Files (x86)`
are walked (depth 4) for model files and AI-tool dirs but **not** content-scanned,
to avoid noise from vendor JSON/config blobs. User + data roots are fully scanned.

**Listening-port labeling is a second pass.** Section 11 re-queries
`GetExtendedTcpTable` and only prints rows whose port is in the known AI/ML
table — it's a focused view alongside the full port list in section 5.

## Related

- `osep-enum` — the original 8-section BOF this ports
- `privcheck` / `tokenpriv` — deeper privilege checks
- `env` — raw process environment dump
- AI-BOF suite (`aiHunter`, `aiSvcProbe`, `configDump`, `envScraper`, `gitMine`,
  `picklePlant`, `shareWalk`, `vectorExport`, …) — deeper single-purpose AI BOFs

## Disclaimer

For authorized penetration testing and security research only. You are
responsible for ensuring you have explicit written permission before running this
or any offensive security tool against any system.