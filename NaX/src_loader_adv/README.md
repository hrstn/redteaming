# NaX Advanced Loader (`src_loader_adv`)

A second-generation UDRL for the NaX/AdaptixC2 beacon. It keeps everything that works in the original loader (PEB walk, module stomping, thread-pool execution, TLS egghunter, .pdata/.xdata unwind stomping, CFG whitelisting) and adds a clean-ntdll + indirect-syscall layer so the **loader itself** is no longer the weak link in the chain.

Target: Win11 24H2 / 2025-era EDR that hooks userland `Nt*` stubs and watches `LoadLibrary`, `VirtualProtect`, and thread-start addresses.

---

## What "state of the art" means here

| Layer | Original NaX loader | This loader |
|-------|----------------------|-------------|
| API resolution | PEB walk against **currently loaded** ntdll/kernel32 (may be hooked) | Map a **fresh** ntdll from `\KnownDlls\ntdll.dll`; resolve from clean copy |
| Sensitive syscalls | Uses `VirtualProtect`, `LoadLibraryExW`, `NtAllocateVirtualMemory` directly (EDR-visible) | Uses **indirect syscalls** via `syscall;ret` gadget found in clean ntdll |
| Module stomp | `LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES)` — loader event | `LdrLoadDll` from clean ntdll or stomp an **already-loaded** DLL; optional manual file mapping |
| Anti-debug / anti-VM | None | Quiet checks with graceful exit |
| Stack spoofing | None | `NtContinue`-based stack pivot helper for sensitive calls |
| Loader footprint | Left in memory | Staged copy + header wiped at boot (loader stub code remains) |
| Sleep obfuscation | Beacon sleepmask BOF | Loader can pre-stage Ekko-style waitable-timer APC obfuscation |

---

## Architecture

```
[stomper.exe / initial process]  ->  CreateThread ->  src_loader_adv shellcode
                                                          |
    Stage 0: Entry.asm (align stack, call PreMain)          |
    Stage 1: PreMain.c                                       |
        - compute Base.Buffer / Base.Length                 |
        - resolve LdrLoadDll, NtOpenSection, NtMapViewOfSection, etc. from PEB
        - map clean ntdll via \KnownDlls\ntdll.dll          |
        - build SYSCALL_TABLE (SSNs + gadget) from clean ntdll |
        - TLS egghunter -> store INSTANCE                   |
    Stage 2: Main.c                                          |
        - anti-analysis (quiet bail)                        |
        - resolve remaining APIs from clean ntdll           |
        - parse NaxHeader v2                                |
        - allocation:                                        |
              * already-loaded module stomp (no load event) |
              * LdrLoadDll-based stomp (native loader)        |
              * NtAllocateVirtualMemory fallback            |
        - write beacon, fix .pdata/.xdata                   |
        - CFG whitelist                                     |
        - wipe staged copy + header (padded packs only)     |
        - execute via thread pool / CreateThread            |
```

---

## Files

```
src_loader_adv/
  asm/x64/Stardust.asm      # PIC entry / end marker
  include/
    Common.h                # INSTANCE struct (adds Syscall table, clean ntdll handle)
    Defs.h                  # technique defines, NaxHeader offsets, syscall constants
    Macros.h                # casting helpers, STARDUST_INSTANCE, syscall invoke
    Native.h                # PEB/LDR/TEB/NT structures
    Syscall.h               # indirect syscall machinery
    Ldr.h                   # PEB + export resolver
    Loader.h                # stomp / exec / anti-analysis prototypes
    Utils.h                 # hashing
  src/
    PreMain.c               # bootstrap, clean ntdll map, TLS egghunter
    Main.c                  # dispatch, anti-analysis, loader wipe
    Ldr.c                   # PEB module walk + export forwarding (uses clean ntdll)
    Pe.c                    # PE section helpers
    Syscall.c               # HellsGate/HalosGate, gadget find, SSN table build
    Stomp.c                 # module stomp via LdrLoadDll / already-loaded DLL
    Exec.c                  # thread pool / CreateThread execution transfer
    AntiAnalysis.c          # debugger/VM/sandbox checks (quiet exit)
    Utils.c                 # FNV1a hash
  scripts/
    Linker.ld               # single .text section linker script
    pack.py                 # pack loader + NaxHeader v2 + beacon + pdata + xdata
  Makefile
```

---

## Build

```bash
cd /Users/hstn/c2dev/redteaming/NaX
make -C src_loader_adv

# Pack into final shellcode (reuses existing beacon components)
python3 src_loader_adv/scripts/pack.py \
    --loader  src_loader_adv/bin/nax_adv_loader.x64.bin \
    --beacon  src_beacon/build/http/beacon.x64.bin \
    --pdata   src_beacon/build/http/beacon.pdata.bin \
    --xdata   src_beacon/build/http/beacon.xdata.bin \
    --text-rva src_beacon/build/http/beacon.text_rva \
    --stomp-dll chakra.dll \
    --module-stomp --stomp-pdata \
    --output build/nax_adv.x64.bin
```

---

## Integration with existing NaX

This loader emits the same 160-byte NaxHeader v2 and expects the same beacon layout, so it is a drop-in replacement for `src_loader/bin/nax_loader.x64.bin`. The existing Adaptix server plugin does not need changes unless you want to expose new build flags.

---

## Audit of other projects in the repo

### Flagged for rework / deprecation

- **`RemoteLoader/`**: .NET 8 single-file self-contained binary is enormous and unusual. `Assembly.Load` + GitHub fetch is a very signatured pattern. The companion `AmsiBypass` still relies on reflection-based `amsiInitFailed` which is heavily logged and caught by modern AMSI. **Recommendation**: rewrite as a small native stager (C/C++ or Nim) that fetches a payload over HTTPS/DoH and injects into a sacrificial process; move AMSI/ETW patching to a rotating native BOF or keep it entirely out of the loader.
- **`hostpayload/` (AdaptixPowerShell)**: PowerShell cradles are under heavy defensive scrutiny (Script Block Logging, Constrained Language Mode, AMSI, ETW). RWX `VirtualAlloc`, Donut, and the reflection AMSI bypass are all well-known. **Recommendation**: keep only as a legacy phishing option; do not treat it as state-of-the-art initial access. A modern delivery should be a small native dropper or a macro/HTA that runs shellcode directly.

### Keep / already strong

- **`NaX/src_beacon/`**: Strong PIC beacon. P1 indirect syscalls, P2 sleepmask, module-stomped BOF loading. Finish P3 (AMSI/ETW patch) and P4 (stack spoofing) for it to stay current.
- **`BOFKatz/`, `C2-Tool-Collection/adaptix-ported-scripts/`, `Cenotaph/`, etc.**: These are post-ex BOFs and tooling. They are fine as long as they are delivered through an evasive loader/stage.

