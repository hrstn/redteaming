# NaX UDRL Loader

Position-independent User Defined Reflective Loader for the NaX beacon, based on the [Stardust](https://github.com/Cracked5pider/Stardust) template by Paul Ungur.

## What It Does

The loader is the first code that runs when the shellcode is injected. It:

1. Resolves its own base address and size (Stardust RIP-relative technique)
2. Walks the PEB to find `ntdll.dll` and `kernel32.dll` by FNV1a hash
3. Resolves `RtlAllocateHeap` and TLS APIs via export table walk + compile-time hashes
4. Finds two consecutive TLS slots (egghunter) to store a global INSTANCE pointer
5. Parses the NaxHeader v2 (160-byte structure between loader and beacon) to extract beacon size, .pdata/.xdata offsets, stomp flags, and sacrificial DLL name
6. Places the beacon into executable memory (virtual allocation or module stomping)
7. Transfers execution to the beacon entry point (thread pool or CreateThread)

## Techniques

Technique selection is compile-time via preprocessor defines:

| Define | Value | Technique |
|--------|-------|-----------|
| `NAX_STOMP_MODE` | `NAX_STOMP_VIRTUAL` (0) | `NtAllocateVirtualMemory` -- private RWX allocation |
| `NAX_STOMP_MODE` | `NAX_STOMP_MODULE` (1) | Module stomp -- load sacrificial DLL, overwrite its `.text` section |
| `NAX_EXEC_MODE` | `NAX_EXEC_THREAD` (0) | `CreateThread` -- start address = beacon entry |
| `NAX_EXEC_MODE` | `NAX_EXEC_THREADPOOL` (1) | `TpAllocWork` + `TpPostWork` -- start address = `TppWorkerThread` |

### Module Stomping

When `NAX_STOMP_MODE == NAX_STOMP_MODULE`:

- Loads a sacrificial DLL with `LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES)` (no DllMain execution)
- Writes the beacon into the DLL's `.text` section so it appears as image-backed memory (MEM_IMAGE)
- Patches the LDR entry with flags: `ImageDll | LoadNotificationsSent | ProcessStaticImport | EntryProcessed`
- Stomps valid `.pdata` (RUNTIME_FUNCTION) and `.xdata` (UNWIND_INFO) into the DLL for clean stack walks

## Hashing

All API and module resolution uses FNV1a-32:

- **Seed:** `0x811c9dc5` (`H_MAGIC_KEY`)
- **Prime:** `0x01000193` (`H_MAGIC_PRIME`)
- **Algorithm:** `Hash ^= Char; Hash *= Prime;` (XOR then multiply)
- **Case-insensitive:** uppercased before hashing

Compile-time hashing via `HASH_STR()` (constexpr in C++ mode) ensures no API name strings appear in the shellcode.

## Source Files

```
src/
  Entry.asm        # NASM entry point, calls PreMain
  PreMain.c        # Stardust bootstrap: RIP calc, PEB walk, TLS egghunter
  Main.c           # API resolution, NaxHeader parsing, stomp/exec dispatch
  Ldr.c            # LdrModulePeb (PEB walk), LdrFunction (export walk + forwarding)
  Pe.c             # PE header helpers: NaxPeHeaders, NaxFindSection, NaxFindSectionByDir
  Stomp.c          # Module stomping: NaxModuleStomp, NaxPatchLdr
  Exec.c           # Execution transfer: NaxExecThreadPool, NaxExecThread
  Utils.c          # HashString (FNV1a, case-insensitive)
include/
  Common.h         # Base types, PEB structures, compiler macros
  Constexpr.h      # HASH_STR / ExprHashStringA (compile-time FNV1a)
  Defs.h           # Pre-computed module/API hashes, NaxHeader layout
  Loader.h         # Function prototypes for Stomp/Exec/Pe
  Macros.h         # FUNC, STARDUST_INSTANCE, MmCopy, MmZero
  Native.h         # NT structures (PEB, LDR, TEB, IMAGE_*)
  Utils.h          # HashString prototype
  Ldr.h            # LdrModulePeb, LdrFunction prototypes
scripts/
  Linker.ld        # Linker script for section ordering
  loader.c         # Dev launcher: load shellcode into RWX, execute
  stomper.c        # Dev launcher: load nax.bin, RX, CreateThread
```

## Build

The loader is built as part of the top-level `make` from the repository root. It is compiled as C++ (`x86_64-w64-mingw32-g++`) to enable constexpr hash evaluation, then linked with a custom linker script and extracted as raw `.text` via `objcopy`.
