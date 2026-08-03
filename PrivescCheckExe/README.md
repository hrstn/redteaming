# HostAudit (PrivescCheckExe)

A **native C#** re-implementation of selected [PrivescCheck](https://github.com/itm4n/PrivescCheck)
checks plus a Windows hardening/configuration audit, compiled with **NativeAOT** to a single
true-native `.exe` (~3.4 MB).

Why native AOT (not the original self-contained single-file build):
- **No IL to reflectively scan** — there is no managed assembly for AMSI/AV to introspect.
- **No single-file temp extraction** — the original build dropped bundled files to
  `%TEMP%\.net\<exe>\` and ran from there (a classic heuristic). AOT is one native PE.
- **No PowerShell anywhere** — AMSI and ScriptBlock logging are never engaged.
- **No WMI** — `System.Management` is not AOT/trim-friendly, so all WMI calls were replaced
  with native SCM APIs and registry reads.

> **For authorized pentest use only.** The tool performs discovery and reads credential
> stores; AV/EDR will still see this *behavior*. AOT/renaming/string cleanup reduce static
> and some heuristic scoring, not a determined EDR.

## Build (NativeAOT)

Requirements:
- .NET 8 SDK (or the .NET 10 SDK installed here, which also builds net8.0 AOT).
- The **MSVC C++ build tools** (linker) — installed with Visual Studio's "Desktop development with C++" workload. The ILCompiler locates them via `vswhere.exe` (in `C:\Program Files (x86)\Microsoft Visual Studio\Installer`); add that dir to PATH if the publish step can't find `link.exe`.

```powershell
cd PrivescCheckExe
$env:PATH = "C:\Program Files (x86)\Microsoft Visual Studio\Installer;$env:PATH"
dotnet publish -c Release -r win-x64 -o publish
```

Output: `publish\HostAudit.exe` — a single native PE, no runtime install needed on target.

## Sign (optional, reduces "unknown publisher" heuristics)

```powershell
# elevated prompt
.\Sign-SelfSigned.ps1
```
A self-signature does not earn Defender trust, but removes the unsigned/unknown-publisher
flag and gives the binary a stable identity. For a real engagement, sign with your org cert.

## Usage

```text
HostAudit.exe                # console output + TXT and CSV report next to the exe
HostAudit.exe --console-only # stdout only, no report files
HostAudit.exe --silent       # no console output, report files only (stealthier)
```

Reports are written next to the exe:
- `HostAudit_<HOST>_<timestamp>.txt` — human-readable
- `HostAudit_<HOST>_<timestamp>.csv` — one row per finding (Id,Category,Title,Severity,Description,Evidence,Remediation)

## What it checks

### Privilege-escalation vectors (PrivescCheck-style)
| ID        | Check |
|-----------|-------|
| TOKEN-00x | Identity/integrity, privileged group membership, dangerous token privileges (SeImpersonate, SeDebug, SeLoadDriver, …) |
| REG-00x   | AlwaysInstallElevated, AutoLogon credentials, AutoRun entries (Run keys, Winlogon, Startup) + writability |
| SVC-00x   | Unquoted service paths w/ writable parent, writable service binaries, services reconfigurable by current user (native SCM), startable services |
| DLL-00x   | Writable dirs on PATH, writable System32/Windows dirs (DLL planting) |
| TASK-00x  | Scheduled tasks whose action binary is writable |
| SW-00x    | Installed software, updates via CBS registry, WSUS (HTTP-only update spoofing) |

### Configuration issues (4 categories)
- **Hardening** (CFG-HARD): LAPS, BitLocker, Defender real-time/anti-spyware (registry), ASR rules, Exploit Protection, Firewall profiles
- **Audit & Logging** (CFG-AUD): advanced audit policy (auditpol), PowerShell ScriptBlock/Module/Transcription logging, Security Event Log config, Sysmon presence
- **Network & Services** (CFG-NET): listening TCP ports, service binary paths (native SCM), SMB (SMB1/signing), RDP (NLA/SecurityLayer), WinRM (AllowUnencrypted), shares
- **Creds & Tokens** (CFG-CRED): Credential Manager, saved RDP files, Chromium Login Data/Cookies, AutoLogon, PowerShell command history

## Severity mapping
`Critical > High > Medium > Low > Info`, color-coded on the console (red/magenta/yellow/cyan/gray).

## OPSEC notes
- Discovery groups run with a small jittered delay between them (not a tight burst of child processes).
- The string table no longer contains tool names / offensive terms (e.g. replaced `payload`, `trojan`, `SharpChrome`, `dpapi::cred`, `Potato`) that static ML classifiers key on.
- Several checks still shell out to read-only OS binaries (`whoami`, `netstat`, `auditpol`, `netsh`, `schtasks`, `manage-bde`, `cmdkey`, `net`, `winrm`). These spawn child processes that EDR can log.
- Writable-directory/binary probes create and delete a probe file (a benign write).
- This is a subset of PrivescCheck's full suite focused on highest-value vectors; extend `Checks/` and `Config/` as needed.
```