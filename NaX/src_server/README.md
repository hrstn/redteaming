# NaX Server Plugins

Go plugins for the [Adaptix Framework](https://github.com/Adaptix-Framework/Adaptix) teamserver. Built as `.so` shared libraries loaded by Adaptix at startup.

## Plugins

### agent_nonameax

Agent extender -- handles payload generation, command creation, and result processing for NaX beacons.

| File | Purpose |
|------|---------|
| `pl_main.go` | Plugin entry point, Adaptix callback registration, command ID constants |
| `pl_build.go` | Cross-compilation pipeline: MinGW beacon + loader → packed shellcode |
| `pl_build_payload.go` | `BuildPayload` callback: profile embedding, NaxHeader v2, PE wrapper modes |
| `pl_commands.go` | `CreateCommand` callback: serialize operator commands to wire format |
| `pl_results.go` | `ProcessTasksResult` callback: decode beacon results to operator-visible output |
| `pl_wire.go` | Wire protocol helpers: frame encode/decode, task packing |
| `pl_crypto.go` | AES-128-CBC encrypt/decrypt (mirrors beacon's BCrypt implementation) |
| `pl_profile.go` | Malleable C2 profile parsing and validation |
| `pl_format.go` | Output formatting (hex dumps, tables, structured text) |
| `pl_upload.go` | Chunked upload state machine |
| `pl_tunnels.go` | SOCKS/port-forward tunnel management via Adaptix tunnel API |
| `pl_agent.go` | Agent-level helpers (session metadata, console updates) |
| `nax_packer.go` | NaxHeader v2 builder: loader + header + beacon + .pdata + .xdata |
| `bof_args.go` | BOF argument packer (Beacon API compatible format) |
| `ax_config.axs` | AxScript UI: command definitions, parameter widgets, result rendering |
| `config.yaml` | Plugin metadata: agent name, watermark, OS/arch support |
| `pe_templates/` | PE wrapper templates for exe/dll/svc debug output formats |

### listener_nonameax_http

HTTP listener extender -- serves beacon traffic with profile-driven request/response transforms.

| File | Purpose |
|------|---------|
| `pl_main.go` | Plugin entry point, Adaptix callback registration |
| `pl_http.go` | HTTP handler: route requests, agent registration, task dispatch |
| `pl_http_profile.go` | Profile-driven request parsing and response building |
| `pl_http_profile_store.go` | Per-listener profile storage |
| `pl_http_transform.go` | Encoding pipeline: base64/hex/raw, XOR mask, body templates |
| `pl_wire.go` | Wire protocol helpers (shared with agent plugin) |
| `pl_crypto.go` | AES-128-CBC (shared with agent plugin) |
| `ax_config.axs` | AxScript UI: listener creation form, connection settings |
| `config.yaml` | Plugin metadata: listener name, protocol, default ports |

### listener_nonameax_smb

SMB listener extender -- named pipe listener for parent-child pivot chains.

| File | Purpose |
|------|---------|
| `pl_main.go` | Plugin entry point, pipe name configuration |
| `ax_config.axs` | AxScript UI: pipe name settings |
| `config.yaml` | Plugin metadata |

### service_nax_store

Service extender -- persistent storage for BOF files and sleepmask payloads via Adaptix's service API.

| File | Purpose |
|------|---------|
| `pl_main.go` | Plugin entry point, store/retrieve callbacks |
| `ax_config.axs` | AxScript UI: store browser widget |
| `config.yaml` | Plugin metadata |

### tools

Development utilities (not deployed as plugins):

| File | Purpose |
|------|---------|
| `gen_config_h.sh` | Generate `Config.h` from listener UI values (standalone testing) |
| `sim_register.py` | Simulate beacon registration without a Windows VM |

## Build

From repository root:

```bash
make -C src_server              # Build + deploy all plugins
make -C src_server agent        # Agent plugin only
make -C src_server listener     # HTTP listener only
make -C src_server listener-smb # SMB listener only
make -C src_server service      # Store service only
make -C src_server test         # Run Go tests
```

Or individually:

```bash
cd src_server/agent_nonameax && make
cd src_server/listener_nonameax_http && make
```

Plugins are built with `-buildmode=plugin` and deployed to `Server/extenders/`. Each plugin directory gets the `.so` binary plus `ax_config.axs` and `config.yaml`.

## Registration

All plugins must be listed in `Server/profile.yaml` for Adaptix to load them. The agent watermark must be exactly 8 hex characters and match across agent + listener configs.
