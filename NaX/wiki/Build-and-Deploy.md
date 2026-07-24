# Build and Deploy

This page covers the toolchain prerequisites, build commands, and deployment steps needed to compile the NaX beacon and loader, build the Go server plugins, and deploy everything to the Adaptix Framework.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| `x86_64-w64-mingw32-gcc` | MinGW-w64 | Cross-compile the PIC beacon (C, targeting Windows x64) |
| `x86_64-w64-mingw32-g++` | MinGW-w64 | Cross-compile the Stardust-pattern loader (compiled as C++ for `constexpr`) |
| `nasm` | any recent | Assemble `Entry.x64.asm` (beacon) and `Stardust.asm` (loader) |
| `objcopy` | binutils | Extract `.text`, `.pdata`, `.xdata` sections from linked PEs |
| Python 3 | 3.8+ | Build scripts (`pack_nax.py`, `build.py`, `pe_text_rva.py`) |
| Go | 1.21+ | Server plugins are built as Go shared libraries (`-buildmode=plugin`) |
| Adaptix Framework | latest | The C2 teamserver and operator client |

On Debian/Kali, install the cross-compilation toolchain with:

```bash
sudo apt install mingw-w64 nasm binutils python3
```

Go must be installed separately; the server Makefile expects it at `/usr/local/go/bin/go`.

## Repository Structure

```
Makefile                          # Top-level: beacon + loader -> nax.x64.bin
src_beacon/                       # PIC shellcode beacon (C, MinGW cross-compile)
  asm/Entry.x64.asm               #   NASM entry stub
  include/                        #   Instance.h, Wire.h, Config.h, Bof.h, Macros.h, ...
  src/Main.c                      #   Heartbeat loop
  src/Core/                       #   Bootstrap, Ldr, Config, Crypto, Packer
  src/Transport/                  #   Http, HttpCodec, Smb, Profile, PackerProfile, Pivot
  src/Commands/                   #   Dispatch, Whoami, Sleep, Screenshot, Download, ...
  src/Bof/                        #   Bof, BofStomp, Jobs, Loader
  Makefile                        #   Beacon sub-make
  Linker.ld                       #   Custom linker script
src_loader/                       # Stardust-pattern UDRL loader
  asm/x64/Stardust.asm            #   NASM entry + StRipStart/StRipEnd markers
  include/                        #   Common.h, Constexpr.h, Loader.h, Native.h, ...
  src/                            #   PreMain.c, Main.c, Ldr.c, Pe.c, Stomp.c, Exec.c, Utils.c
  scripts/                        #   Linker.ld, build.py, pe helpers
  Makefile                        #   Loader sub-make
src_server/                       # Go plugins
  agent_nonameax/                 #   Agent extender (build, commands, crypto, wire, format)
  listener_nonameax_http/         #   HTTP listener extender (transport, profile transforms)
  listener_nonameax_smb/          #   SMB listener extender
  service_nax_store/              #   Service plugin (NaX Store)
  Makefile                        #   Builds + deploys all plugins to Server/extenders/
scripts/                          # pack_nax.py (combine loader + header + beacon + unwind)
profiles/                         # Malleable C2 profile JSON files
build/                            # Output artifacts (gitignored)
```

## Build Commands

### Full Builds

All commands are run from the repository root.

```bash
make                    # Release build -> build/nax.x64.bin
make debug              # Debug build   -> build/nax.x64.debug.bin
make clean              # Remove all build artifacts (loader + beacon + output)
```

### Sub-Makes

Build individual components in isolation:

```bash
make beacon             # Beacon only (src_beacon/)
make loader             # Loader only (src_loader/)
```

### Incremental Builds

When only `Config.c` has changed (profile URL, sleep timer, C2 address), a link-only rebuild is much faster than a full build. The `link` target recompiles `Config.c` and re-links without touching other objects.

```bash
make link               # Release incremental: recompile Config.c + re-link + repack
make debug-link         # Debug incremental: same for debug variant
```

If any header besides `Config.h` has changed since the last build, both targets detect this and automatically fall back to a full rebuild with a warning:

```
  WARN  headers changed - full rebuild required
```

### Module Stomping

Module stomping loads the beacon into an image-backed memory region by overwriting a sacrificial DLL's `.text` section, avoiding the executable-private-memory detection heuristic.

```bash
make MODULE_STOMP=1                     # Enable module stomping (default DLL: chakra.dll)
make MODULE_STOMP=1 STOMP_DLL=mshtml.dll  # Custom sacrificial DLL
make MODULE_STOMP=1 STOMP_PDATA=1       # Include .pdata stomping for clean stack walks
```

By default, `MODULE_STOMP=0` and the loader uses `VirtualAlloc` for beacon memory.

### Technique Selection (Compile-Time Defines)

These flags are passed to the loader and control its runtime behavior:

| Flag | Values | Default | Effect |
|------|--------|---------|--------|
| `NAX_STOMP_MODE` | 0 / 1 | 1 | 0 = VirtualAlloc fallback, 1 = module stomp |
| `NAX_EXEC_MODE` | 0 / 1 | 1 | 0 = CreateThread, 1 = ThreadPool (TppWorkerThread) |

```bash
make NAX_STOMP_MODE=1 NAX_EXEC_MODE=1   # Module stomp + thread pool (default)
make NAX_STOMP_MODE=0 NAX_EXEC_MODE=0   # VirtualAlloc + CreateThread
```

### Transport Selection

The beacon supports multiple transport backends, selected at compile time:

| Flag | Value | Transport |
|------|-------|-----------|
| `NAX_TRANSPORT_PROFILE` | 0 (default) | HTTP (WinHTTP, proxy-aware) |
| `NAX_TRANSPORT_PROFILE` | 1 | SMB (named pipe, for peer-to-peer pivots) |

```bash
make NAX_TRANSPORT_PROFILE=0    # HTTP transport (default)
make NAX_TRANSPORT_PROFILE=1    # SMB transport
```

HTTP and SMB builds use separate object directories (`build/http/` and `build/smb/`) so they can coexist without `make clean` between switches.

### Go Server Plugins

Build and deploy all server plugins in one step from the repository root:

```bash
make -C src_server              # Build + deploy: agent, HTTP listener, SMB listener, service
```

Or build individual plugins:

```bash
make -C src_server agent        # Agent extender only
make -C src_server listener     # HTTP listener only
make -C src_server listener-smb # SMB listener only
make -C src_server service      # NaX Store service plugin only
```

Run plugin unit tests:

```bash
make -C src_server test
```

The server Makefile automatically copies `.so`, `config.yaml`, and `ax_config.axs` files to the deployment directories under `Server/extenders/`.

**GOEXPERIMENT**: The Go plugins must be compiled with the same `GOEXPERIMENT` flags used to build the Adaptix teamserver binary. The server Makefile sets `GOEXPERIMENT=jsonv2,greenteagc` by default. Verify against the deployed binary with:

```bash
strings Server/adaptixserver | grep '^go[0-9]'
```

## Build Pipeline

A `make` invocation runs three stages:

### Stage 1: Loader

```
Stardust.asm  --[nasm]--> asm_Stardust.x64.o
*.c           --[g++]---> nax_*.x64.o
              --[g++]---> nax_loader.x64.exe   (linked with Linker.ld)
              --[objcopy]--> nax_loader.x64.bin (.text section only)
```

The loader is compiled as C++ (`x86_64-w64-mingw32-g++`) to support `constexpr` hash computation. All functions use `extern "C"` linkage.

### Stage 2: Beacon

```
Entry.x64.asm --[nasm]--> Entry.obj
*.c           --[gcc]---> *.obj
              --[gcc]---> beacon.x64.exe       (linked with Linker.ld)
              --[objcopy]--> beacon.x64.bin     (.text section)
              --[objcopy]--> beacon.pdata.bin   (.pdata section)
              --[objcopy]--> beacon.xdata.bin   (.xdata section)
              --[python3]--> beacon.text_rva    (.text virtual address)
```

The beacon is compiled as C (`x86_64-w64-mingw32-gcc`) with aggressive size optimization (`-Os`), no CRT (`-nostdlib`), and position-independent code (`-fPIC`). The `.pdata` and `.xdata` sections carry structured exception handling (SEH) unwind data for clean stack walks.

### Stage 3: Pack

```
pack_nax.py combines:
  nax_loader.x64.bin              (loader shellcode)
  + NaxHeader v2 (160 bytes)      (magic "NAX2", flags, sizes, offsets, DLL name)
  + beacon.x64.bin                (beacon shellcode)
  + beacon.pdata.bin              (normalized .pdata entries)
  + beacon.xdata.bin              (unwind info)
  --> nax.x64.bin                 (final payload)
```

The NaxHeader v2 structure (160 bytes) includes:
- Magic bytes `0x4E415832` ("NAX2")
- Flags: `FLAG_MODULE_STOMP` (0x0001), `FLAG_STOMP_PDATA` (0x0002)
- Beacon size, .pdata size, .xdata size
- .text RVA (used to normalize .pdata entries to 0-based offsets)
- Sacrificial DLL name as a wide string (up to 64 WCHAR characters)

The `pack_nax.py` script normalizes `.pdata` RUNTIME_FUNCTION entries by converting absolute RVAs to 0-based offsets. The loader adds the target DLL's base RVA at runtime.

### Server-Side Build (BuildPayload)

The Go agent plugin's `BuildPayload()` function performs this same three-stage pipeline at runtime when an operator generates a payload through the Adaptix UI. It:

1. Generates `Config.h` from operator-selected options (C2 URL, sleep, jitter, profile, etc.)
2. Invokes the cross-compiler and packer
3. Returns the final `nax.x64.bin` blob to the teamserver

## Important Build Rules

**Always `make clean` after header changes.** If you modify any header file other than `Config.h` or `Config_profile.h`, you must run `make clean && make`. Stale object files compiled against old struct layouts cause silent runtime corruption (wrong offsets, garbage field reads, access violations in the beacon).

**`make link` is safe for Config.c-only changes.** Changing the C2 URL, sleep timer, jitter, or profile selection only touches `Config.c` / `Config.h`. The `link` target detects this case and avoids a full rebuild. If it detects that structural headers have changed, it falls back automatically.

**Debug builds include console output.** The `DEBUG` and `DEBUG_PIC` preprocessor defines gate `NaxDbg()` / `NaxDbgx()` output. Release builds strip all debug code. Debug output is visible in the Windows console, DebugView, and x64dbg's log window.

## Deployment to Adaptix

### 1. Build and Deploy Plugins

The server Makefile handles both compilation and deployment:

```bash
make -C src_server
```

This copies the following to `Server/extenders/`:

```
Server/extenders/
  agent_nonameax/
    agent_nonameax.so
    config.yaml
    ax_config.axs
  listener_nonameax_http/
    listener_nonameax_http.so
    config.yaml
    ax_config.axs
  listener_nonameax_smb/
    listener_nonameax_smb.so
    config.yaml
    ax_config.axs
  service_nax_store/
    nax_store.so
    config.yaml
    ax_config.axs
```

### 2. Register Extenders in profile.yaml

Adaptix only loads extenders that are explicitly listed in `Server/profile.yaml`. Add all NaX plugins:

```yaml
extenders:
  - agent_nonameax
  - listener_nonameax_http
  - listener_nonameax_smb
  - service_nax_store
```

### 3. Watermark

The agent watermark is configured in `src_server/agent_nonameax/config.yaml`:

```yaml
agent_watermark: "a04a4178"
```

This must be exactly 8 hex characters (4 bytes). It identifies NaX agents in the Adaptix teamserver and must match the value in `profile.yaml` if the server enforces watermark validation.

### 4. Start the Teamserver

```bash
cd Server && ./teamserver
```

The teamserver loads all registered extender `.so` files on startup. After launch:

1. Open the Adaptix client and connect to the teamserver
2. Create a listener (NoNameAxHTTP or NoNameAxSMB) through the Listeners panel
3. Generate a payload through the Payloads panel -- this triggers `BuildPayload()` server-side
4. Deploy the generated `nax.x64.bin` to the target

## Quick Reference

| Task | Command |
|------|---------|
| Full release build | `make` |
| Full debug build | `make debug` |
| Module stomp + pdata | `make MODULE_STOMP=1 STOMP_PDATA=1` |
| SMB transport | `make NAX_TRANSPORT_PROFILE=1` |
| Config-only rebuild | `make link` |
| Build all plugins | `make -C src_server` |
| Run plugin tests | `make -C src_server test` |
| Deploy + start server | `make -C src_server && cd Server && ./teamserver` |
| Clean everything | `make clean && make -C src_server clean` |
