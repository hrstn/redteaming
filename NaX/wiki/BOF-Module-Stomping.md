# BOF Module Stomping

BOF (Beacon Object File) execution normally allocates private memory with `PAGE_EXECUTE_READWRITE` for the BOF's `.text` section. Even when the beacon itself runs from image-backed memory via loader-phase module stomping, every BOF invocation creates a fresh private executable allocation -- a top indicator for EDR memory scanners. BOF module stomping eliminates this by running BOF code from the `.text` section of a pre-loaded sacrificial DLL, so execution happens from `IMAGE`-backed memory at `PAGE_EXECUTE_READ` with no RWX anywhere.

This is distinct from [loader-phase module stomping](Module-Stomping), which stomps the beacon shellcode itself into a DLL at load time. BOF module stomping operates per-execution at runtime, stomping and restoring DLL content around each BOF call.

## Architecture Overview

```
                       BOF_STOMP_POOL (in NAX_INSTANCE)
                      +-------------------------------+
                      |  SyncSlot                     |  <-- main thread BOFs
                      |    DllBase  = chakra.dll       |
                      |    TextBase = .text section    |
                      |    TextCap  = section size     |
                      |    TextBackup = original bytes |
                      |    PdataBase / PdataBackup     |
                      +-------------------------------+
                      |  AsyncSlots[0..3]             |  <-- thread pool BOFs
                      |    [0] jscript9.dll            |
                      |    [1] d3d11.dll               |
                      |    [2] (empty)                 |
                      |    [3] (empty)                 |
                      +-------------------------------+
                      |  AsyncCount = 2               |
                      |  Initialized = TRUE           |
                      +-------------------------------+
```

Each slot holds a handle to a sacrificial DLL loaded with `DONT_RESOLVE_DLL_REFERENCES` (no DllMain, no imports resolved). The sync slot serves the main heartbeat thread; async slots serve the BOF thread pool for concurrent `-a` (async) BOF jobs.

### Data Structures

From `Instance.h`:

```c
typedef struct {
    PVOID             DllBase;       /* LoadLibraryExW return value          */
    PVOID             TextBase;      /* DllBase + .text VirtualAddress       */
    ULONG             TextCap;       /* .text SizeOfRawData or VirtualSize   */
    PIMAGE_NT_HEADERS Nt;            /* cached PE headers                    */
    BYTE              InUse;         /* slot currently occupied by a BOF     */
    PVOID             TextBackup;    /* heap copy of original .text bytes    */
    PVOID             PdataBase;     /* DllBase + .pdata VirtualAddress      */
    ULONG             PdataSize;     /* .pdata section size                  */
    PVOID             PdataBackup;   /* heap copy of original .pdata bytes   */
} BOF_STOMP_SLOT;

typedef struct {
    BOF_STOMP_SLOT SyncSlot;
    BOF_STOMP_SLOT AsyncSlots[ BOF_STOMP_ASYNC_MAX ];   /* max 4 */
    BYTE           AsyncCount;
    BYTE           Initialized;
} BOF_STOMP_POOL;
```

## Build-Time Configuration

BOF stomping is controlled by compile-time macros in `Config.h`, generated from the Adaptix build UI:

| Macro | Purpose |
|-------|---------|
| `NAX_BOF_STOMP` | `1` to enable, `0` to disable |
| `NAX_BOF_SYNC_DLL_WRITE(p)` | Per-byte WCHAR MOVs for the sync DLL name |
| `NAX_BOF_ASYNC_COUNT` | Number of async DLLs (0-4) |
| `NAX_BOF_ASYNC_N_WRITE(p)` | Per-byte WCHAR MOVs for each async DLL name |

The `_WRITE` macro pattern is required because PIC shellcode cannot have string literals in `.rdata`. Each DLL name is written to the stack as individual `MOV` instructions:

```c
#define NAX_BOF_SYNC_DLL_WRITE( p ) do { \
    (p)[ 0]=L'w'; (p)[ 1]=L'm'; (p)[ 2]=L'p'; (p)[ 3]=L'.'; \
    (p)[ 4]=L'd'; (p)[ 5]=L'l'; (p)[ 6]=L'l'; \
    (p)[ 7]=L'\0'; \
} while(0)
```

Default DLL choices:
- **Sync**: `chakra.dll` (large .text, commonly present on Windows 10+)
- **Async pool**: `jscript9.dll`, `mshtml.dll`, `d3d11.dll` (large .text sections, common system DLLs)

## Lifecycle

Every BOF execution follows this six-stage pipeline. If stomping is disabled or fails at any point, the COFF loader falls back to private `PAGE_EXECUTE_READWRITE` allocations transparently.

```
 Init (once)      Alloc (per BOF)     Protect        Pdata         Execute       Free
 +-----------+    +---------------+   +-----------+  +----------+  +---------+   +-----------+
 | Load DLLs |    | Pick slot     |   | .text->RX |  | Inject   |  | Call    |   | Restore   |
 | Find .text|    | Stomp .text   |   | rest->RW  |  | into DLL |  | go()    |   | .text     |
 | Backup all| -> | Near-alloc    | ->| No RWX    |->| .pdata   |->|         |-> | .pdata    |
 | .text     |    | rest + mfuncs |   |           |  |          |  |         |   | Free priv |
 | Backup    |    | Zero .pdata   |   |           |  |          |  |         |   | Mark free |
 | .pdata    |    |               |   |           |  |          |  |         |   |           |
 +-----------+    +---------------+   +-----------+  +----------+  +---------+   +-----------+
```

### Stage 1: Init (`NaxBofStompInit`)

Called once during beacon bootstrap, after config init. Loads every configured DLL and initializes its slot:

1. `LoadLibraryExW(dllName, NULL, DONT_RESOLVE_DLL_REFERENCES)` -- loads the DLL into the process as a mapped image without calling DllMain or resolving imports
2. Walks the PE section headers to find `.text` -- caches `TextBase` and `TextCap`
3. Heap-allocates `TextBackup` and copies the original `.text` content
4. Locates `.pdata` via `IMAGE_DIRECTORY_ENTRY_EXCEPTION`, heap-allocates `PdataBackup` and copies it

Individual DLL failures do not disable the whole feature. If the sync DLL fails but two of three async DLLs succeed, async BOFs still stomp while sync BOFs fall back to private memory.

### Stage 2: Alloc (`NaxBofStompAlloc`)

Called per BOF execution from `NaxBofAllocSections`. Determines whether stomping is possible and sets up all memory.

**Slot selection:**
- If `CurrentJob == NULL` (main heartbeat thread) -- use `SyncSlot`
- If `CurrentJob != NULL` (async thread pool) -- scan `AsyncSlots[]` for the first slot where `InUse == FALSE` and `TextCap >= textNeed`

**If no slot is available** (all in use, or BOF .text exceeds capacity), returns `FALSE` and the COFF loader uses the private-memory path.

**Stomping .text:**
```
VirtualProtect(TextBase, TextCap, PAGE_READWRITE)
MmZero(TextBase, TextCap)              -- clear previous content
MmCopy(TextBase, bof_text, text_size)  -- write BOF .text bytes
```

**Near-allocating non-.text sections:** BOF sections other than `.text` (`.data`, `.bss`, `.rdata`, `.pdata`, `.xdata`) cannot be stomped into the DLL -- they need `PAGE_READWRITE` and may differ in size. These are allocated as private memory via `StompAllocNear`, which places them within +/-16MB of the DLL image.

**Near-allocating mapFunctions:** The external-symbol IAT (mapFunctions buffer, 4096 bytes) is also near-allocated so that REL32 displacements from `.text` to the IAT slots stay well within the +/-2GB limit.

**Zeroing .pdata:** The DLL's original `.pdata` is zeroed so stale exception data for the original DLL code does not interfere with BOF unwinding. (Restored in the Free stage.)

### The Near Allocator (`StompAllocNear`)

```
         256 x 64KB backward                DLL image               256 x 64KB forward
    <-------------------------->  |========================|  <-------------------------->
    scan direction: high->low     |  .text (BOF stomped)   |  scan direction: low->high
                                  |  .pdata (zeroed/injected)|
                                  |========================|
                                           |
                                    non-.text sections and
                                    mapFunctions allocated
                                    within this +/-16MB range
```

The allocator tries 256 slots (each 64KB aligned) forward from the DLL's image end, then 256 slots backward from the DLL's image base. This keeps all allocations within +/-16MB -- well inside the +/-2GB limit of x86-64 REL32 relocations, and also well within the +/-16MB range needed by some near-call patterns.

```c
/* Forward scan */
ULONG_PTR fwd_base = ( dll_end + 0xFFFF ) & ~(ULONG_PTR)0xFFFF;
for ( UINT32 i = 0; i < 256; i++ ) {
    PVOID base = (PVOID)( fwd_base + (ULONG_PTR)i * 0x10000 );
    /* NtAllocateVirtualMemory with MEM_COMMIT | MEM_RESERVE */
}

/* Backward scan */
ULONG_PTR bwd_base = (ULONG_PTR)slot->DllBase & ~(ULONG_PTR)0xFFFF;
for ( UINT32 i = 1; i <= 256; i++ ) {
    PVOID base = (PVOID)( bwd_base - (ULONG_PTR)i * 0x10000 );
    /* ... */
}
```

### Stage 3: Protect (`NaxBofStompProtect`)

After relocations are applied, flips the DLL's `.text` to `PAGE_EXECUTE_READ`:

```c
VirtualProtect( slot->TextBase, slot->TextCap, PAGE_EXECUTE_READ, &old );
```

Non-`.text` sections remain `PAGE_READWRITE`. There is no `RWX` memory at any point during stomped BOF execution. Compare this to the fallback path, which uses `PAGE_EXECUTE_READWRITE` on all sections.

### Stage 4: .pdata Injection (`NaxBofStompPdata`)

This is the key innovation for clean stack unwinding. Without proper `.pdata` registration, any exception during BOF execution (or an ETW stack walk) will fail to unwind through the BOF frame, potentially crashing the process or triggering EDR alerts.

**The IFT priority problem:**

Windows maintains an **Inverted Function Table** (IFT) in ntdll that caches `.pdata` pointers for all loaded modules. When `RtlLookupFunctionEntry` is called for an address, it checks the IFT first. Dynamic function tables registered via `RtlAddFunctionTable` are only consulted if the IFT does not cover the address range. Since our sacrificial DLL is a loaded module, the IFT already indexes it -- and will always handle lookups for addresses in the DLL's range. Any `RtlAddFunctionTable` entries for the same range are never consulted.

**The solution:** Write BOF `RUNTIME_FUNCTION` entries directly into the DLL's `.pdata` section. The IFT already points there, so the unwinder finds our entries through the normal lookup path.

```
DLL's .pdata section (after zeroing + injection):
+---------------------------------------------------+
| [0] BeginAddress=0, EndAddress=0, UnwindData=0    |  <- zeroed (original entries)
| [1] BeginAddress=0, EndAddress=0, UnwindData=0    |
| ...                                                |
| [N-k] BOF RUNTIME_FUNCTION entry 0 (adjusted RVA) |  <- injected at END
| [N-k+1] BOF RUNTIME_FUNCTION entry 1              |
| ...                                                |
| [N-1] BOF RUNTIME_FUNCTION entry k-1              |
+---------------------------------------------------+
```

Entries go at the **end** of the `.pdata` array. Zeroed entries (BeginAddress=0) sort before valid entries in the IFT's binary search, so appending BOF entries at the tail preserves correct ordering.

**RVA adjustment:** BOF COFF produces RVAs relative to `image_base` (the lowest allocated section address). The IFT expects RVAs relative to `DllBase`. The adjustment is:

```c
ULONG adj = (ULONG)( image_base - (ULONG_PTR)slot->DllBase );

for ( DWORD i = 0; i < srcCount; i++ ) {
    dst[startIdx + i].BeginAddress = src[i].BeginAddress + adj;
    dst[startIdx + i].EndAddress   = src[i].EndAddress   + adj;
    dst[startIdx + i].UnwindData   = src[i].UnwindData   + adj;
}
```

If injection fails (e.g., `.pdata` section too small to hold BOF entries), the loader falls back to `RtlAddFunctionTable` as a best-effort measure.

### Stage 5: Execute

The COFF loader calls the BOF's `go()` entry point. From the OS perspective, execution is happening inside a legitimate, signed DLL's `.text` section -- `IMAGE`-backed, `PAGE_EXECUTE_READ`, with valid `.pdata` entries in the IFT.

### Stage 6: Free (`NaxBofStompFree`)

Restores the DLL to pristine state so it looks completely stock between executions:

1. **Restore .text**: `VirtualProtect(RW)` -> `MmCopy(TextBackup)` -> `VirtualProtect(RX)`
2. **Restore .pdata**: `VirtualProtect(RW)` -> `MmCopy(PdataBackup)` -> `VirtualProtect(original)`
3. **Free private sections**: `NtFreeVirtualMemory` on every non-`.text` section and the mapFunctions buffer
4. **Mark slot free**: `InUse = FALSE`

**Why restore instead of zeroing:** A DLL with a zeroed `.text` section in memory is itself an indicator of compromise. Legitimate DLLs have valid code in `.text` at all times. By restoring the original content from the heap backup, the DLL's memory matches the on-disk image byte-for-byte. The same principle applies to `.pdata` -- zeroed exception entries in a signed DLL would stand out under inspection.

## Memory Layout Comparison

### Without BOF stomping (fallback path)

```
   Virtual Memory
   +---------------------------+
   | Private (PRV)             |
   | PAGE_EXECUTE_READWRITE    |  <-- BOF .text + all sections
   | Not backed by any file    |      Top EDR indicator
   +---------------------------+
```

### With BOF stomping

```
   Virtual Memory
   +---------------------------+
   | IMAGE (IMG) - chakra.dll  |
   | PAGE_EXECUTE_READ         |  <-- BOF .text (stomped into DLL)
   | Backed by chakra.dll      |      Looks like legitimate DLL code
   +---------------------------+

   +---------------------------+
   | Private (PRV)             |
   | PAGE_READWRITE            |  <-- .data, .bss, .rdata, mapFunctions
   | Near chakra.dll (+/-16MB) |      Non-executable, non-suspicious
   +---------------------------+
```

## Graceful Fallback

`NaxBofStompAlloc` returns `FALSE` whenever stomping is not possible:

| Condition | Behavior |
|-----------|----------|
| `NAX_BOF_STOMP == 0` | Feature compiled out |
| Pool not initialized | Init failed for all DLLs |
| No free slot (all `InUse`) | All async slots occupied by concurrent BOFs |
| BOF `.text` > slot `TextCap` | BOF too large for the sacrificial DLL |
| `VirtualProtect(RW)` fails | OS denied permission change |
| Near-alloc fails | No free virtual memory in +/-16MB range |

On fallback, the COFF loader allocates all sections as private `PAGE_EXECUTE_READWRITE` memory with `MEM_TOP_DOWN`. The operator sees `[stomp: private fallback]` in the BOF result output.

Cleanup on partial failure is thorough: if near-allocation fails for section N, sections 0..N-1 are freed, the DLL's `.text` is restored from backup, and the slot is not marked in-use.

## Operator Feedback

Each BOF result includes a 2-byte metadata header recording the stomp status:

| Byte 0 (`Stomped`) | Byte 1 (`StompSlot`) | Server-side display |
|---------------------|----------------------|---------------------|
| `0x01` | `0xFF` | `[stomp: chakra.dll]` (sync) |
| `0x01` | `0x00` | `[stomp: jscript9.dll (async slot 0)]` |
| `0x01` | `0x01` | `[stomp: d3d11.dll (async slot 1)]` |
| `0x00` | `0x00` | `[stomp: private fallback]` |

Set in `NaxBofExecute` after allocation:

```c
Nax->BofCtx.Stomped  = stomped ? 0x01 : 0x00;
Nax->BofCtx.StompSlot = stomped
    ? ( Nax->CurrentJob ? Nax->CurrentJob->StompSlotIdx : 0xFF )
    : 0x00;
```

## Runtime Reconfiguration

The `bof-stomp` command (`NAX_CMD_BOF_STOMP`, ID `0x31`) allows operators to swap sacrificial DLLs on a live beacon without redeployment.

### Wire Format

```
sub_cmd(1 byte) | payload...
```

| Sub-command | Code | Payload | Effect |
|-------------|------|---------|--------|
| sync | `0x00` | `wchar_len(4LE)` + WCHAR bytes | Replace the sync DLL |
| async | `0x01` | `count(1)` + `[wchar_len(4LE) + WCHAR bytes]...` | Replace entire async pool |
| show | `0x02` | (empty) | Display current config and slot status |

### Sync swap

Unloads the current sync DLL (frees backups, calls `FreeLibrary`), loads the new DLL, re-caches `.text` and `.pdata`, creates fresh backups. Updates `NAX_CONFIG.BofSyncDll` so the change persists across sleep cycles.

### Async pool swap

Unloads all async DLLs that are not currently `InUse`, resets the pool, then loads the new set. Slots that are currently occupied by a running async BOF are skipped (not unloaded) to avoid corrupting in-flight execution.

### Show output

```
BOF Stomping: enabled
Sync DLL: wmp.dll (.text cap=524288)
Async DLLs: 2
  [0] jscript9.dll (.text cap=1048576)
  [1] d3d11.dll (.text cap=786432 IN USE)
```

## DLL Selection Guidelines

The sacrificial DLL's `.text` section must be large enough to hold the BOF's `.text`. Good candidates:

| DLL | Typical .text size | Notes |
|-----|--------------------|-------|
| `chakra.dll` | ~2 MB | Edge Legacy JS engine, present on Win10+ |
| `jscript9.dll` | ~1 MB | IE JS engine, widely available |
| `mshtml.dll` | ~5 MB | IE HTML renderer, very large .text |
| `d3d11.dll` | ~800 KB | DirectX, common on desktops |
| `wmp.dll` | ~500 KB | Windows Media Player |

Criteria for choosing DLLs:
- **Large `.text` section** -- accommodates bigger BOFs without fallback
- **Commonly loaded** -- the DLL appearing in a process's module list should not be unusual
- **Rarely inspected** -- avoid DLLs that security tools specifically monitor
- **Stable across Windows versions** -- present on Win10 through Win11 23H2+

Use `bof-stomp show` on a live beacon to check actual `.text` capacity after loading.

## Integration with the COFF Loader

The COFF loader in `Bof/Loader.c` calls into stomping at well-defined points:

```
NaxBofExecute()
  |
  +-- NaxBofAllocSections()
  |     |
  |     +-- NaxBofStompAlloc()    -- try stomp; if FALSE, use private alloc
  |
  +-- NaxBofProcessRelocations()  -- same for both paths
  |
  +-- if stomped:
  |     +-- NaxBofStompProtect()  -- .text -> RX
  |     +-- NaxBofStompPdata()    -- inject into DLL .pdata (or RtlAddFunctionTable fallback)
  |   else:
  |     +-- NtProtectVirtualMemory(RWX) on all sections
  |
  +-- go(args, args_len)          -- call BOF entry point
  |
  +-- if stomped:
  |     +-- NaxBofStompFree()     -- restore DLL, free private sections
  |   else:
  |     +-- NtFreeVirtualMemory() on all sections
```

The stomping path and the private-memory path share the same relocation engine and entry-point resolution. The only differences are allocation strategy, memory protections, and `.pdata` handling.

## Source Files

| File | Purpose |
|------|---------|
| `src_beacon/src/Bof/Stomp.c` | Core stomping logic: init, alloc, protect, pdata, free |
| `src_beacon/src/Bof/Loader.c` | COFF loader (unity build includes Stomp.c and Api.c) |
| `src_beacon/src/Commands/BofStomp.c` | Runtime `bof-stomp` command handler |
| `src_beacon/include/Instance.h` | `BOF_STOMP_SLOT`, `BOF_STOMP_POOL`, `NAX_BOF_CTX` structs |
| `src_beacon/include/Config.h` | Build-time `NAX_BOF_STOMP`, `NAX_BOF_SYNC_DLL_WRITE` macros |
| `src_beacon/include/Wire.h` | `NAX_CMD_BOF_STOMP` (0x31) command ID |
