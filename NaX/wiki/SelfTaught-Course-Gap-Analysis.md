# Self-Taught Course → Redteam Arsenal Gap Analysis

Senior-OPSEC review of the [Self-Taught Course](https://racoten.github.io/Self-Taught-Course/index.html)
(material downloaded to a local scratch copy; 19 projects, ~160 modules) mapped against the
current state of this repo — NaX first, then the surrounding tooling. External detection-landscape
research (Nov 2025–2026) is folded in where it changes priorities.

Companion documents: `Beacon-Architecture.md`, `BeaconGate-Sleepmask.md`, `Module-Stomping.md`,
`Stardust-Loader-Guide.md`, `../RUNBOOK.md`.

---

## 1. Method

1. Inventory of current NaX posture from source + wiki (P1–P4 layers, sleepmask, loader, BOF
   stack, transports, server plugin).
2. Extraction of every course project's mechanism, production-grade deltas, detection surfaces,
   and self-declared limitations (four parallel deep reads: sleep/memory, stack/syscall, loaders/
   PIC, injection/payload).
3. External validation of the load-bearing detection claims (Hunt-Sleeping-Beacons v2, Elastic
   call-stack research + Nov-2025 call-gadget cat-and-mouse, pe-sieve/moneta module-stomp IOCs).
4. Delta ranking: what is genuinely *new* for us vs. what NaX already does better than the
   courses' PoCs.

## 2. Current NaX posture (baseline for this review)

| Layer | State |
|---|---|
| Indirect syscalls (P1) | HellsGate/HalosGate SSN + Tartarus in-ntdll `syscall;ret` gadget; 12 Nt* calls; build-lane select (elastic=direct stubs, defender=indirect) |
| Sleepmask (P2) | XOR beacon .text + instance private span per sleep, key = BCryptGenRandom 16B held on sleepmask stack; region left **RW** during wait; WFSO dummy-event wait; ActiveJobCount==0 guard |
| Stack spoof (P4) | `SpoofedVirtualProtect` naked-asm trampoline: RBP-chain ret rewrite to ntdll .text filler + `FF E3` ntdll gadget as VP return, **only for the VP.syscall window** |
| Loader | Stardust-pattern PIC UDRL, TLS egghunter, module stomp (chakra default) + .pdata/.xdata unwind stomping + LDR entry patch, TpWork exec transfer |
| BeaconGate | Sleep/WFSO/WFMO/VP proxied through resident sleepmask BOF in dedicated stomp slot (msxml6 default) |
| Beacon | PIC .text-only, FNV1a PEB-walk resolution, WinHTTP persistent handles, private heap, WS2 lazy-load, kill-date + pre-dwell zeroing |
| Missing | P3 AMSI/ETW patch (planned, not built); no heap masking; no load-time spoofing; loader blob freed only by the host runner |

## 3. Detection landscape deltas (external, 2025–2026)

Things published *after* the course material that change our ranking:

1. **Hunt-Sleeping-Beacons v2** now fingerprints sleep-obfuscation machinery itself: wait-reason
   `UserRequest` + `KiUserApcDispatcher` on stack (FOLIAGE/APC chains) and **timer-callback
   signatures (Ekko's NtContinue chains)**, plus unbacked/gadget/spoof stack checks.
   → Our same-thread WFSO-dummy-event wait avoids both the APC and timer fingerprints. Keep it
   as the primary path; do **not** migrate to Ekko/FOLIAGE machinery (§8).
2. **Elastic** maintains rules for spoofed call stacks, API proxying via callbacks, and
   "Shellcode Fluctuation via CallBack"
   (`elastic/protections-artifacts`: `defense_evasion_library_loaded_from_a_spoofed_call_stack`,
   `defense_evasion_library_loaded_via_a_callback_function`,
   `defense_evasion_shellcode_fluctuation_via_callback`). The Nov-2025
   [Almond/LibTPLoadLib](https://github.com/AlmondOffSec/LibTPLoadLib) post shows the current
   workaround (inserting a *call gadget* from an unrelated signed DLL — e.g. dsdmo `call r10; ret`)
   and confirms Elastic is closing this hole.
   → Our P4 trampoline's shape — RBP-chain rets overwritten with **arbitrary ntdll offsets**
   (filler), returning through an `FF E3` gadget — is exactly the class these rules hunt.
   It held against 2025-07 Cloud Defender validation; assume it expires.
3. **pe-sieve / HSB sleep-thread scans** flag return addresses pointing into **private commit**
   pages even when the address falls inside a stomped module's range. Module-stomped pages are
   CoW-private at page level (our own P4 note documents Elastic's per-frame
   `allocation_private_bytes` check). → Sleep-time stack hygiene must survive the *whole wait*,
   not just the VP syscall instant.

## 4. NaX improvements — prioritized

### P5 (new roadmap tier): full-duration sleep stack hygiene — highest OPSEC ROI

**Problem.** During the masked wait the sleeping thread's stack still reads:
`ntdll!NtWaitForSingleObject ← sleep_mask (stomp slot, CoW-private) ← NaxGateSleep ← heartbeat (beacon .text) ← …`
P4 only rewrites frames **across the two VirtualProtect calls**. Any periodic stack sweep
(HSB, pe-sieve, EDR kernel stackwalk on an unrelated event) during dwell sees private/unbacked
frames above the wait — the single largest remaining exposure. pe-sieve explicitly flags
sleeping threads with rets into private memory.

**Fix — two tiers, both reusing existing P4 machinery:**

- **Tier 1 (cheap, do first):** extend `SpoofedVirtualProtect`'s save/spoof walk to bracket the
  whole `NtWaitForSingleObject` in `HandleSleep` (`src_sleepmask/src/main.c`): spoof → wait →
  restore. The beacon .text is encrypted-and-RW during the wait, so nobody executes through
  those frames; the saved-real-ret restore is the same loop already written. Same guard set
  (`SleepObf && ActiveJobCount==0`).
- **Tier 2 (correct, anti-expiry):** upgrade filler-rets to **unwind-consistent synthetic frames**
  (Draugr-course pattern — minimal implementable form):
  - terminal frames `kernel32!BaseThreadInitThunk+0x14` and `ntdll!RtlUserThreadStart+0x21`
    (offsets land on real `CALL` sites; frame sizes parsed from their `.pdata` — we already
    parse `.pdata` in `NaxModuleStomp`/`pack_nax.py`),
  - return the callee through a `jmp [rbx]` trampoline with fixup slot at `PRM+0`
    (RBX survives the kernel transition — same invariant as our existing gadget),
  - `add rsp,N; ret` gadget N matching the `UNWIND_INFO` alloc of the chosen gadget module
    (scan kernelbase/ntdll `.text` only; validate `RtlLookupFunctionEntry` != NULL and reject
    `UNW_FLAG_CHAININFO` or offsets < `SizeOfProlog`),
  - optional self-check: `RtlVirtualUnwind` the fabricated chain once and assert the expected
    frame sequence before committing (a few µs, debug-only).

**Anti-IOC note (Tier 2):** ret addrs must point **past `SizeOfProlog` and ideally post-`CALL`**
into the target function, and the frame must sit inside `TEB.StackBase/Limit` — build the
synthetic frames on the real stack, not in a heap buffer. Both are the two cheapest detections
of naive spoofing; the course material documents both, Elastic implements them.

### P6: private-heap masking during sleep (FOLIAGE's second half, adapted)

We own `Nax->Heap` (`NaxBootstrap`, HeapCreate) — no foreign allocator. Anything allocated at
dwell time (task JSON, results buffers, tunnel state, BOF arg buffers, DNS/pivot strings)
currently sits **plaintext on private pages** through the whole sleep. `SmEncrypt` already
masks the instance span; extend to the heap:

- `RtlLockHeap(Nax->Heap)` → `RtlWalkHeap` → mask busy blocks (`PROCESS_HEAP_ENTRY_BUSY`)
  with the existing per-sleep key → `RtlUnlockHeap`; `SmDecrypt` un-masks before
  `RtlUnlockHeap` ordering symmetric (walk is deterministic pre/post).
- **Guard:** skip blocks whose first QWORD falls inside beacon .text or the gate originals
  (callback pointers in `JobHead`/`GateSwaps`/`BofStompPool`). Cheaper variant: relocate
  pointer-bearing structures out of the encrypted heap at design time.

Sleepmask key-at-rest hardening in the same pass: the 16B key currently sits plaintext on the
sleepmask stack for the entire wait — a stack-dump-and-decrypt offline attack becomes trivial.
Store the key XOR-obfuscated with a wake-recomputable value (e.g. `BeaconBase ^ SpoofCount`)
and un-obfuscate into stack locals only at use points.

### P7: P3 (AMSI/ETW) — build as planned, with course-corrected specifics

P3 is on our roadmap and the course material confirms and corrects it:

- **AMSI:** `amsi.dll!AmsiScanBuffer` → `31 C0 C3`; alternate `AmsiInitialize` →
  `mov eax,0x80070057; ret` (never initializes — survives ASB integrity checks). Patch
  **before** anything loads CLR/PowerShell content order-matters — we never host managed
  tooling in-agent, so this is really for post-ex `inline-exec` tooling.
- **ETW:** `ntdll!EtwEventWrite` → `33 C0 C3`; alternate `NtTraceEvent` (same bytes) for
  vendors that integrity-check EEW. **Honest scoping (course-confirmed, matches our existing
  note): none of this touches kernel ETW-TI** — it closes userland provider visibility only,
  and a process emitting *no* ETW events is itself a hunting signal. Do not gate P3's value
  narrative on TI blindness.
- Sequence both at bootstrap *before* the first `LoadLibraryW(WINHTTP)` emit — patch-then-load,
  not load-then-patch.
- Lane-aware: elastic lane keeps direct ntdll stubs (no hooks to defeat), defender lane gets the
  patches — mirror the P1 `NAX_LANE` pattern.

### P8: syscall-layer hardening (small diffs, high value)

All from the HellsGate/Draugr courses; deltas on what we already run:

1. **Secondary SSN validation:** `stub[6]==0 && stub[7]==0` — SSN high bytes are always zero;
   catches partially-clobbered SSNs (e.g. `E9` displacement bytes) that byte-0/byte-3 checks
   miss. One `if` per gate entry in `Syscall.c`.
2. **VBS/HVCI branch:** guest stubs can dispatch via `int 0x2e`
   (`test byte ptr [SharedUserData+0x308],1 / jnz / syscall / int 0x2e`). Two effects: the
   `syscall;ret` gadget scan offset shifts, and on pure-`int 0x2e` guests our gadget search
   must accept the `int 0x2e; ret` form. Add the branch detection and a fallback; otherwise a
   VBS-enabled target (server 2025 defaults, Win11 HVCI) is a crash lane.
3. **EAT-order neighbor stepping** (SysWhispers2-style) as the HalosGate stride fallback when
   the fixed 0x20 assumption breaks on a build — neighbors come from `AddressOfFunctions`
   adjacency, not byte math.
4. **Third SSN path:** `.pdata` Zw-counting (MDSec method) — parse the exception directory,
   cross-match `BeginAddress` against EAT RVAs, count `Zw*` exports; never reads stub bytes,
   works with every stub hooked. Natural fit: the beacon already links `.pdata` blobs and the
   loader parses them.
5. **Spoof the 12 Nt* call sites** (Draugr-grade): one gadget-fixup PRM per call, reusing P4's
   gadget hunt. Cost per call is microseconds; kernel-side stackwalk of e.g. our
   `NtAllocateVirtualMemory` during BOF stomping currently shows only our own frames.
6. **In-use stub hygiene:** keep `.text` encryption during sleep (already done); additionally
   zero/regenerate the `wSystemCall`-equivalent stashed SSNs after each use (course OPSEC note:
   stub bytes and SSN globals are signature surface; ours are compile-time hashed so the win is
   small but free).

### P9: loader staging self-erasure

The packed blob (`loader + NaxHeader + plaintext beacon + pdata/xdata`) stays resident until
the host runner cleans it. Forensically that is a plaintext copy of the whole beacon sitting in
private memory for the lifetime of the session. Port CrystalLoaders' contract pattern:

- beacon init receives the staging span (`Base.Buffer/Length` already computed by PreMain),
  and after `NaxBootstrap` completes: `VirtualFree(staging, MEM_RELEASE)` — or at minimum
  `RtlSecureZeroMemory` the staged beacon bytes + header before parking it.
- The loader copy is never executed again once the threadpool callback transferred control.
  Confirm no fallback path needs it before freeing.

### P10: winhttp load-time stack hygiene

`NaxBootstrap` does `LoadLibraryW("WINHTTP")` from stomped-but-coercible frames; the
image-load event's kernel call stack is currently: our frames → kernelbase → ntdll. This is the
exact use-case of the Elastic "network module loaded from suspicious unbacked memory" rule and
the exact target of LibTPLoadLib. Options in order of preference:

1. Route the load through `TpAllocWork/TpPostWork` (frames read `TppWorkerThread → kernelbase → ntdll`)
   — we already use TpWork for exec transfer; ~5 lines.
2. Break the signature with a **`call r10; ret` call-gadget** in an unrelated signed DLL
   (dsdmo-pattern; validate gadget candidates across builds with Winbindex before bake-in) —
   this survives the "library loaded via a callback function" rule that Tp-loads themselves hit.
3. Spoof the load call via the P8 spoof machinery.

### P11: encrypt-sleep threshold knob (FOLIAGE <1000ms bypass)

`HandleSleep` encrypts/decrypts (2 VP calls + full-region XOR) every gated sleep once SleepObf
is on. At short sleeps (operator sleeps 2–5s, jitter 50%) this is heavy VP churn and
correlates with beaconing timing without buying scanner evasion worth the flip rate. Add
`NAX_SM_MIN_SLEEP_MS` (default 1000, operator-tunable, `sleepobf-config`-extensible): sleeps
below it fall through to the plain dummy-event wait. Aligns with FOLIAGE's ≥1s gate.

### P12: build-system — constexpr FNV1a (kills the hash workflow)

The loader already compiles as C++ for constexpr hashing; the beacon does not, so every new
API needs `tools/hash.py` and a pasted constant in `Macros.h`. Move the beacon to
`x86_64-w64-mingw32-g++` + constexpr FNV1a
(`HASH_STR("NewFunc")` → constant; `RESOLVE_TYPE(...)`-style `#s` stringification). Same
hash algo, same wire behavior, one workflow deleted. Optional: Maru-style combined
(module, function) hash if we ever add a second resolution namespace.

### P13: BOF loader hardening (COFF-loader course deltas)

- Register stomped-slot `.pdata` via `RtlAddFunctionTable` when `STOMP_PDATA`-style unwind data
  ships with a BOF; today an exception inside a BOF escalates to host-process death (unwinder
  has no frames). Decide per-slot: register for our authored BOFs (we control .pdata), leave
  unregistered for third-party BOFs and document why.
- Bounds-check `BeaconDataExtract`-style parsing in our Beacon API stub table (CS's own loader
  returns past-buffer pointers on malformed args — do not inherit that class of bug).
- REL32 reach: keep BOF slots and the compat layer within 2GB of their targets; document the
  constraint in `BOF-Execution.md` (module-stomped slots give us contiguity control — pick
  sacrificial DLLs in the System32 neighborhood).
- Aux-symbol records: confirm our symbol walk skips `NumberOfAuxSymbols` (COFF course's #1
  corruption vector for third-party BOFs).

### P14: SmInfo → BUD-style structured handoff

Our `NAX_SM_INFO` + shared `NAX_SM_CONFIG` is a hand-rolled subset of Cobalt Strike 4.11's
Beacon User Data. When touching the sleepmask again, formalize:

- region list (not fixed `BeaconBase/PrivateBase` fields): each entry
  `{purpose, base, size, sections[] each with label, CurrentProtect, PreviousProtect, MaskSection}`,
- cleanup-method tags (VirtualAlloc→NtFree, ModuleStomp→unwind owner module),
- pre-resolved syscalls for the sleepmask's own VP/wait path
  (removes the sleepmask's load-time API resolution entirely),
- `custom[]` channel for future loader→BOF contracts.

This is what makes P5/P6 composable: the mask masks exactly what the loader told it to and
never masks itself.

### P15: guardrails + delivery key binding (hostpayload_v2)

- Beacon config ciphertext: bind decryption to host properties (volume serial via
  `GetVolumeInformationW("C:\\")`-derived key component, RC4/SystemFunction033 or reuse our
  ChaCha20 KDF with a volume-serial input). Captured payload = forensically inert off-target.
  Fits `hostpayload_v2`'s existing ChaCha20+HMAC staging (add the binding factor at pack time).
- Keep delivery-stage sandbox checks modest (RAM/cores/uptime/username patterns) — quiet-exit,
  no artifacts; the v2 dropper already has an anti-analysis hook.

## 5. Post-ex tooling — add as BOFs / server-side generators

| Technique | Form | Why us | Course |
|---|---|---|---|
| **ThreadlessInject** | BOF (course documents a CS-BOF port; maps 1:1 to our ABI) | Zero thread-creation telemetry; syscall surface = exactly our 4 gated `Nt{Read/Write/Allocate/Protect}VirtualMemory`; one-shot + self-restore + 60s byte-poll confirmation fits our tasking | ThreadlessInject m1–8 |
| **PoolParty V7 → V4** | BOFs | `NtSetIoCompletionEx` / `NtSetIoCompletion`: no queue surgery, no build-specific `TP_POOL` offsets, legitimate full stack (`TppDirectpExecuteCallback ← TppWorkerThread ← BaseThreadInitThunk`); diversifies exec trigger per target | PoolParty m1–8 |
| **ProcessGhosting spawn** | spawn-command + injector BOF | File-free satellite/sacrificial processes (execute-assembly host, PPID-spoofed child); chain is pure NT APIs in our gate; combine with in-child module stomp | ProcessGhosting m1–8 |
| **Perun's Fart cleanse** | bootstrap option | `NtOpenSection(\KnownDlls\ntdll.dll)` map → copy clean .text → unmap: no disk reads (classic unhook is logged), keeps any non-syscall ntdll calls clean | Hooka m4 |
| **DetectHooks recon** | bootstrap command | Scan ntdll first-5-bytes (`E9@0`, `4C 8B D1 E9@3`) → report which SSNs are hooked → operator intel + lane selection evidence | HellsGate m7 / Hooka m4 |
| **ACG + BlockDLLs** | session-hygiene command | After mapping, `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` + `BLOCK_NON_MICROSOFT_BINARIES` — kills EDR post-injection installs; timing invariant: after payload mapped, before first load | Hooka m5 |
| **Shoggoth wrap** | offline build step | Wrap stager/BOF/loader artifacts pre-delivery: RC4 + random 3–5-op QWORD block cipher chain, randomized regs, junk blocks; `--encrypt-only-decryptor` when layered; kills static signatures per-build | Shoggoth m1–8 |

Deliberately **not** adopting from the injection cluster: PoolParty V1 (StartRoutine stays
overwritten for all future pool threads), V8 (highest queue-corruption risk), ShellGhost as a
full-loop runtime (1,500–20,000× slowdown; init-stager-only at most), Nidhogg (separate
kernel-stage capability, see §8).

## 6. Sleep-state option matrix (what to keep, what to add)

| Option | Status | Verdict |
|---|---|---|
| Same-thread WFSO dummy-event wait (current) | keep as default | CET-safe, no APC/timer fingerprints, frames fixed by P5 |
| PAGE_NOACCESS + VEH wake (Fluctuation Mode 2) | optional add | unreadable by pe-sieve; wake via AV handler; watch VEH enumeration + fault discrimination; behind a config flag |
| Ekko timer chain (NtContinue contexts) | **do not adopt** | `NtContinue`-as-callback is the single most distinctive IOC + HSB v2 timer-callback check + CET shadow-stack #CP |
| FOLIAGE 10-APC chain | **do not adopt as-is** | HSB v2 fingerprints `KiUserApcDispatcher` waits; adopt only its *ideas* (fresh key per cycle: done; heap masking: P6) |
| Per-function masking (FunctionPeekaboo/Evanesco) | long-term | the only course answer to the *active window* (~98% encrypted while awake, sleep-0-safe, CET-safe); requires custom LLVM pass — schedule as a research spike, not a sprint item |
| Cronos/DropSleep/DeathSleep variants | future reference | different API-monitor surface; revisit only if P5+P6 fail an engagement |

## 7. Cross-tool deltas

**hostpayload_v2** — already aligned with course best practice (ChaCha20+HMAC, RW→RX, PEB/FNV1a,
no PS). Add: Shoggoth pass (§5), volume-serial binding (P15), PE-header wipe in self-decrypting
shellcode path, and keep decompression in-payload if staging grows (aPLib depack ≈150B vs
`RtlDecompressBuffer` needs ntdll export).

**remote_bof_loader** — inherits the §4 P13 list; also verify `BeaconFormatInt` big-endian and
the CS 4-byte-arg-prefix semantics for CS-sourced BOFs.

**C2-Tool-Collection / adaptix-ported-scripts** — the ETW/AMSI patch scripts should adopt the
*AmsiInitialize* variant as default (survives ASB integrity checks) and drop any disk-copy
unhooking in favor of KnownDlls mapping.

**tools/opsec_scan.py** — extend the merge gate with: entropy-step check on staged blobs
(~6.0–6.5 code → 7.9 ciphertext transitions), a `0F 05`-in-extracted-.text sweep, and a CI
harness wired to the existing `tests/defender/METHODOLOGY.md` running **moneta + pe-sieve
(incl. thread scans) + Hunt-Sleeping-Beacons v2** against built payloads; regression-gate
release builds on their output like the current Defender methodology does.

## 8. What NOT to adopt (with reasoning)

| Course technique | Reason to skip |
|---|---|
| Ekko timer-queue NtContinue chain | most-monitored single IOC; HSB v2 timer check; CET-fragile; our Tier-1/Tier-2 stack fix achieves the same scanner surface on current CET-safe machinery |
| FOLIAGE APC chain | HSB v2's `KiUserApcDispatcher` fingerprint post-dates it; APC ordering + CFG (`VmCfgCallTargetInformation`) plumbing for equivalent coverage of what P5+P6 give us |
| LayeredSyscall VEH/HWBP/TF engine | TF exception-frequency is unfixable per its own course; thousands of SINGLE_STEPs per syscall; incompatible with our threadpool/sleep machinery; keep as a reference for rare high-scrutiny ops only if ever needed |
| Draugr as a whole-runtime layer | adopt the pattern, not the runtime — our 12 Nt* calls get targeted PRM spoofing (P8.5); full-process spoof adds overhead without covering anything our stack hygiene doesn't |
| Nidhogg-class kernel work | needs BYOVD/kdmapper lane, BSOD/PatchGuard arms race, separate engagement stage; if the kernel lane ever opens: ObCallbacks handle-stripping for the agent and the ETW user-vs-kernel scoping notes transfer |
| Donut CLR hosting in-agent | `clr.dll` load in non-hosting processes is a primary signal; keep execute-assembly in sacrificial/satellite processes (ghosting/PPIV hosts) |
| Disk-copy unhooking | logged reads + periodic re-scan detection; KnownDlls mapping only |

## 9. Suggested sequencing

| Sprint | Items |
|---|---|
| 1 | P5-Tier-1 (full-wait spoof), P11 (min-sleep threshold), P8.1–8.2 (SSN validation + int 0x2e), P9 (staging self-erasure) |
| 2 | P6 (heap mask + key obfuscation), P3 (AMSI/ETW per lane), P10 (Tp-load winhttp) |
| 3 | P5-Tier-2 (unwind-consistent frames + self-check), P8.3–8.5 (EAT neighbors, .pdata SSN, Nt* spoof), ThreadlessInject BOF |
| 4 | PoolParty V7/V4 BOFs, ProcessGhosting spawn, P13 (BOF loader hardening), opsec_scan CI extension |
| 5+ | P12 (constexpr beacon build), P14 (BUD-style handoff), P15 (guardrails), Shoggoth in pipeline, FunctionPeekaboo research spike |

## 10. Sources

- Course: racoten/Self-Taught-Course (AceLdr, Stardust, CrystalLoaders, Donut, COFFLoader,
  HellsGate, LayeredSyscall, Hooka, PoolParty, ThreadlessInject, ProcessGhosting, ShellGhost,
  Ekko, ShellcodeFluctuation, FunctionPeekaboo, SilentMoonwalk, Draugr, Shoggoth, Nidhogg).
- Hunt-Sleeping-Beacons (thefLink) v2 detection set — APC/timer-callback/spoof IOCs.
- Elastic Security Labs call-stack series + `elastic/protections-artifacts` rule set.
- Almond OffSec, "Evading Elastic EDR's call stack signatures with call gadgets" (Nov 2025,
  LibTPLoadLib) — and Elastic's stated follow-up work.
- ZeroPoint Security UDRL course framing (referenced by the Stardust/CrystalLoaders courses).

## 11. Implementation status (post-review sprint)

Implemented after this review (see git log):

| Item | State | Notes |
|---|---|---|
| P8.1 SSN high-byte validation | ✅ | `Syscall.c` + hooked-stub tally (DetectHooks-lite) |
| P5-T1 full-wait spoof | ✅ | `SpoofWait` trampoline; saved rets XOR'd with ntdll base |
| P6 heap masking + key obfuscation | ✅ | lock held across wait; key XOR'd with `BeaconBase ^ SpoofCount` |
| P11 min-sleep threshold | ✅ | build `NAX_SM_MIN_SLEEP_MS` + runtime `sleepobf-config [min_ms]` |
| P3 AMSI/ETW patch | ✅ | `Core/Patch.c`, lane-gated, NtProtect-routed, fails soft |
| P10 TpLoadLibraryW | ✅ | TpWork + dsdmo call-gadget, CFG whitelisted, plain fallback |
| P9 staging self-erasure | n/a | already existed in BOTH loaders (`NaxWipeStaged`, padded packs) |
| P8.3 EAT-order neighbors | n/a | HalosGate already walks export-table order |
| ThreadlessInject BOF | ✅ | `C2-Tool-Collection/BOF-Sources/ThreadlessInject/` |
| PoolParty V7 BOF | ✅ | `C2-Tool-Collection/BOF-Sources/PoolPartyV7/` (sandbox-validate on target builds) |
| P5-T2 synthetic unwind-consistent frames | deferred | biggest remaining item; Tier-1 ships now |
| P12 constexpr FNV1a build | deferred | build-QoL, no OPSEC gain |
| P14 BUD-style SmInfo handoff | deferred | formalize when the sleepmask ABI is next touched |

Validation performed locally (macOS cross-compile; runtime lanes validated on
Win11 in the usual Defender/OSAI pass): beacon compile on both lanes × both
transports, sleepmask release+debug COFF, loader build, end-to-end `pack_nax.py`
packing with header verification, Go plugin vet + full test suite.
