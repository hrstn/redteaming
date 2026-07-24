# NaX Beacon

Position-independent C2 beacon compiled as a single `.text` section shellcode blob. No CRT, no imports, no global variables -- all APIs resolved at runtime via PEB walk using FNV1a-32 hashes.

## How It Works

1. **`NaxMain()`** (Entry point, called by the UDRL loader)
   - `NaxBootstrap()` resolves ~80 APIs from ntdll, kernel32, advapi32, bcrypt, winhttp and allocates `NAX_INSTANCE` on the process heap
   - Stores the instance pointer in `TEB->ArbitraryUserPointer` for recovery via `G_INSTANCE` macro
   - Initializes BOF module stomping pool, sleepmask gate, and DLL notification unhooking
   - Dispatches to `NaxHttpMain()` or `NaxSmbMain()` based on transport mode

2. **Heartbeat loop** (`NaxHttpMain` / `NaxSmbMain`)
   - Sends encrypted heartbeat, receives task batch
   - Decodes tasks, calls `NaxDispatch()` for each
   - Collects async results (downloads, jobs, pivots, tunnels, shells) and sends them back
   - Sleeps with jitter between cycles

3. **Command dispatch** (`NaxDispatch`)
   - Maps command IDs (defined in `Wire.h`) to handler functions
   - Each handler reads args from the wire buffer and writes results into the output buffer
   - 26 built-in commands covering file I/O, process management, token ops, screenshots, BOFs, pivoting, and tunneling

## PIC Constraints

- No `.rdata` strings -- all string constants are `char[]` on the stack or `_WRITE` macros (per-byte MOVs)
- No global/static variables -- everything lives in heap-allocated `NAX_INSTANCE`
- No CRT functions -- `MmCopy`, `MmZero`, `MmSet` replace memcpy/memset
- Stack buffers must stay under ~1KB; larger allocations go through `RtlAllocateHeap`
- All cross-TU function references must be in the same compilation unit or resolved via the instance struct

## Source Files

```
src/
  Main.c                          # NaxMain entry point, transport dispatch
  Core/
    Bootstrap.c                   # API resolution, NAX_INSTANCE allocation, sysinfo gathering
    Ldr.c                         # PEB walk (NaxGetModule), export walk (NaxGetProc), hashing, encoding
    Config.c                      # Embedded profile parsing (NaxInitConfig), runtime profile apply
    PackerProfile.c               # Profile binary decoder
    Crypto.c                      # AES-128-CBC encrypt/decrypt via BCrypt
    Packer.c                      # Wire framing: encode/decode frames, build register/heartbeat/result
    Cfg.c                         # Control Flow Guard: query status, whitelist targets
    Helpers.c                     # Win32 error formatting, string helpers
  Commands/
    Dispatch.c                    # Command ID → handler router
    Core.c                        # cd, pwd, mkdir, rmdir, cat, ls, rm
    Whoami.c                      # Current identity (domain\user)
    Sleep.c                       # Set callback interval + jitter
    Ps.c                          # Process list, kill, run
    Screenshot.c                  # GDI desktop capture
    Download.c                    # File download (chunked)
    Downloader.c                  # Download state machine
    Upload.c                      # File upload
    MemSave.c                     # In-memory file storage for BOF payloads
    Profile.c                     # Runtime C2 profile switch
    Token.c                       # Token steal/impersonate/make/revert/privs
    DllNotify.c                   # LdrDllNotification callback removal
    Sleepmask.c                   # BeaconGate wrappers + NaxGateRegister swap table
    Jobs.c                        # Async BOF job management
    Shell.c                       # Interactive remote shell
    Pivot.c                       # SMB pivot link/unlink, child data relay
    Tunnel.c                      # SOCKS4/5, local/reverse port forwarding
    BofStomp.c                    # BOF module stomping pool configuration
  Transport/
    Http.c                        # WinHTTP transport (proxy-aware, persistent handles)
    HttpCodec.c                   # Profile-driven encoding/decoding, header/URL builders
    Smb.c                         # Named pipe transport for SMB pivoting
  Bof/
    Loader.c                      # COFF loader: parse sections, relocate, resolve imports
    Api.c                         # Beacon API (29 functions exposed to BOFs)
    Stomp.c                       # BOF module stomping: image-backed .text, IFT .pdata injection
include/
  Instance.h                      # NAX_INSTANCE struct, API bundles, gate types
  Wire.h                          # Command IDs, message types, wire constants
  Config.h                        # Build-time profile/sleepmask embedding macros
  Macros.h                        # FUNC, G_INSTANCE, MmCopy, MmZero, NaxDbg
  Nax.h                           # Central forward declarations for all internal functions
  Bof.h                           # COFF structures, BOF_STOMP_POOL, Beacon API typedefs
  Gate.h                          # FUNCTION_CALL struct, GATE_API_* constants, SM_INFO
  Transport.h                     # Transport function prototypes
  WinApis.h                       # Function pointer typedefs for all resolved APIs
  Helpers.h                       # Helper function prototypes
  Common.h                        # Base types, compiler macros
  Defs.h                          # Hash constants (H_MODULE_*, H_FUNC_*)
  NaxConstants.h                  # Error codes, buffer sizes, feature flags
```

## Build

The beacon is built as part of the top-level `make` from the repository root. It cross-compiles with `x86_64-w64-mingw32-gcc`, links with `-nostdlib`, and extracts raw `.text` via `objcopy` to produce `beacon.x64.bin`.

```bash
make beacon          # Beacon only
make debug           # Debug build (enables NaxDbg output)
```
