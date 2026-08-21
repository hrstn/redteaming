# Defender characterization — root-causing "ls triggers Defender"

**Goal:** map an exact Cloud-Defender `ThreatName` to each beacon/command combo so we
know whether the fix is beacon-level (binary signature — already solved by cenotaph+NaX)
or command-level (a behavior signature on a specific native command / BOF).

## Static analysis already done (2026-08-21, this branch)

1. **Stock `bacon.exe` is signatured `AdaptixC2:Win32`** and burns on the OSAI Win11
   Cloud-Defender box. **SOLVED** by the cenotaph + NaX path: cenotaph loads
   `nax.x64.bin`, Stardust module-stomps the beacon into `chakra.dll` (image-backed),
   and the beacon registers + heartbeats. **LIVE-VALIDATED 2026-08-21** — cenotaph
   lands where stock bacon dies. (LESSONS `stealthy-agentbuilder` Cenotaph section.)
2. **The current NaX blob (`beacon.x64.bin`, 87 295 B) is string-clean:** zero API-name
   strings (`VirtualAlloc/NtAllocate/LoadLibrary/GetProcAddress/VirtualProtect/AmsiScan/
   EtwEvent/FindFirstFile/FindNextFile/FindClose` all absent). `ls`'s enumeration APIs
   are FNV1a-hash-resolved, NOT name-carried. → **A NaX-blob static string signature
   is NOT the cause of any `ls` detection.**
3. **`ls` has two runtime modes** (`src_beacon/src/Commands/Core.c:270`):
   - **Flat** (no flag): one `FindFirstFileA("*")` + iterate. Single dir, low noise.
   - **Tree** (`flags & 0x01`, `NaxLsTreeWrite`): recursive to `LS_TREE_MAX_DEPTH = 16`,
     walking EVERY subdirectory. Against `C:\` that is a depth-16 enumeration —
     potentially hundreds of thousands of FindFirst/FindNext calls. **The loudest
     native command by behavior, and the prime suspect for any behavior-based
     detection.**
4. **Most likely root cause (hypothesis to confirm on-box):** the "ls triggers
   Defender" report was observed on the **stock bacon** (already signatured), so any
   command tripped it and `ls` was simply what was running. The NaX beacon's `ls`
   may be entirely clean. **This is what the on-box experiment settles.**

## Hypotheses to confirm/refute on an admin Win11+Defender box

| # | Hypothesis | Experiment | Expected if true |
|---|------------|------------|------------------|
| H1 | Stock bacon signatured; `ls` irrelevant | Run stock bacon, `ls` flat → snapshot | `ThreatName=AdaptixC2:Win32` (or similar) fires regardless of command |
| H2 | NaX beacon binary is clean (no sig) | Run cenotaph+NaX, idle heartbeat 60s → snapshot | NO detection |
| H3 | NaX flat `ls` is clean | NaX, `ls` (flat) on C:\Users → snapshot | NO detection |
| H4 | NaX tree `ls` trips a behavior sig | NaX, `ls -tree` on C:\ (depth-16 walk) → snapshot | A behavior/heuristic ThreatName fires (e.g. Trojan:Win32/Wacatac generic, or ASR 1125/1126) |
| H5 | A BOF trips a sig independent of beacon | NaX, run whoami BOF → snapshot | detection tied to the BOF, not the beacon |
| H6 | Detection is memory-scan-at-rest (beacon in chakra) | NaX idle, then trigger a real-time scan `Start-MpScan` → snapshot | detection on the stomped chakra region, not command-tied |

## Test environment (THE blocker) — RESOLVED 2026-08-21

**Chosen: bare Win11 Pro host** (the WSL2 host machine), reached via WSL2→Windows
PowerShell interop (`/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`).
Host Defender state confirmed (read-only `Get-MpComputerStatus`/`Get-MpPreference`):

| Setting | Value | OK? |
|---|---|---|
| RealTimeProtectionEnabled | True | ✅ catches signatures |
| BehaviorMonitorEnabled | True | ✅ catches behavior heuristics |
| IoavProtectionEnabled | True | ✅ |
| AntivirusEnabled | True | ✅ |
| IsTamperProtected | **True** | ⚠️ blocks history reset → use time-windowing |
| SubmitSamplesConsent | **0 (Never send)** | ✅ cenotaph NOT uploaded → can't be burned |
| MAPSReporting | 2 (advanced metadata) | ⚠ but consent=0 → no FILE upload, safe |
| CloudBlockLevel | 0 | fine for local-sig + behavior hypotheses |
| SigLastUpdated | 2026-08-21 | ✅ current |

**Tamper-protection adaptation (IMPORTANT):** because `IsTamperProtected=True`,
`Remove-Item HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats` and
`Set-MpPreference -DisableRealtimeMonitoring` are BLOCKED. We CANNOT reset threat
history between combos. Instead, **isolate each combo by `InitialDetectionTime`**:
record the combo start time, run the combo, snapshot, then filter the snapshot's
`ThreatDetections` to those with `InitialDetectionTime >= comboStart`. The existing
`Get-DetectionState.ps1` already captures `InitialDetectionTime` per detection, so
the diff is just a time filter on the JSON. (No script change needed — just note the
combo start time in the `-Tag` or alongside the snapshot.)

**Sample-upload safety:** `SubmitSamplesConsent=0` means Defender sends NO file
samples to MS — only metadata/hash lookups (MAPSReporting=2). So running the novel
cenotaph+NaX beacon on this host **cannot** get cenotaph signatured in MS's cloud
DB. Stock bacon is already signatured (`AdaptixC2:Win32`) so it just gets
quarantined — that's H1's expected result.

## Run procedure (per combo)

1. On the admin box, reset Defender threat state:
   ```powershell
   Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats" -Recurse -Force -EA SilentlyContinue
   Set-MpPreference -DisableRealtimeMonitoring $false   # RT must be ON
   Get-MpComputerStatus | Select RealTimeProtectionEnabled,BehaviorMonitorEnabled
   ```
2. Deploy the beacon combo (stock bacon OR cenotaph+`nax.x64.bin`).
3. Run the command under test (flat `ls` / tree `ls` on C:\ / a BOF / idle).
4. Immediately snapshot:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Get-DetectionState.ps1 -Tag <combo>
   ```
5. Read `out\<ts>-<combo>.txt` — the `ThreatName` line is the answer. If `(none)`,
   that combo is clean.
6. Record the ThreatName + combo in `RESULTS.md` (create from the table below).

## Results table (filled in on-box 2026-08-21, host Win11 Pro, CloudBlockLevel=High)

| Combo | Beacon | Command | ThreatName | EventID | Verdict |
|-------|--------|---------|-----------|---------|---------|
| H1 | stock bacon (normalbacon.exe / normal.exe) | (at rest, WSL share scan) | `Backdoor:Win64/AdaptixC2.MKA!MTB` | — | **SIGNATURED** — the real burn; caught at rest, status REMOVED |
| H2 | nax.exe (release) | idle / running | (none) | — | **CLEAN** — no detection on the binary or at runtime |
| H3 | nax.exe | flat `ls C:\` | (none) | — | **CLEAN** at CloudBlockLevel=High (0 detections, 0 events) |
| H4 | nax.exe | tree `ls C:\` (depth-16) | N/A | N/A | **UNREACHABLE** — NoNameAx client `ls` is flat-only (no recursive bool, unlike `rmdir -rf`); tree mode (`flags & 0x01`) is dead code |
| H5 | nax.exe | BOF `privcheck all` (309 KB COFF) | (none) | — | **CLEAN** at CloudBlockLevel=High (0 detections, 0 events; also clean at Level 0). Beacon survived. |
| H6 | nax.exe | Start-MpScan (memory scan) | (not run) | — | deferred — nax.exe is a normal process (CRT-linked EXE, not UDRL-stomped); no static sig so memory scan unlikely to fire |

**Posture during H3/H5:** CloudBlockLevel=2 (High), CloudExtendedTimeout=50,
MAPSReporting=Advanced, SubmitSamplesConsent=0 (nax.exe NOT uploaded), RT+behavior+IOAV ON.
Tamper-protected → combos isolated by `InitialDetectionTime` windowing, not history reset.

## What the outcome means for the exam

- **NaX release beacon + flat `ls` + BOFs are exam-ready at the cloud-ML tier.**
  The "ls/bofs trigger Defender" on the lab was NOT reproduced at High cloud block.
- The lab trigger was most likely one of: (a) the **stock bacon signature**
  (`AdaptixC2.MKA!MTB`, confirmed) — operator may have been running stock bacon,
  not NaX; (b) a **debug-build NaX beacon** (debug EXE/BOF carry `MSVCRT$printf` +
  `[sleepmask]`/`[spoof]` debug strings that can trip a signature/behavior); (c) a
  **stricter-than-High lab posture** (HighPlus via MDM / ASR block / CFA). **Always
  deploy the RELEASE build on Defender-on exam hosts, never the debug build.**
- **AMSI is NOT a factor for native COFF BOFs** — AMSI scans PowerShell/.NET/JS/VBS
  script content, not in-process COFF calling Win32 directly. AMSI only matters if
  a BOF spawns PowerShell or loads .NET (avoid that on Defender-on hosts, or patch
  AMSI — the optional P3 Defender-lane toggle).
- **Exam-day rules (codify in runbook Defender-evasion-mode):** use release NaX
  (never stock bacon, never debug build); flat `ls` per dir (tree is unreachable
  anyway); audit BOFs for signatured strings (Task #4); don't leave signatured
  tools/loose payloads in the WSL `\\wsl.localhost` share (host Defender indexes it).
- **Residual (can't resolve without the lab box):** the exact lab ThreatName +
  whether the lab was stricter-than-High or used a debug build. If a lab box with
  admin becomes available, re-run H3/H5 there at the lab's real posture to confirm.