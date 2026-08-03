# PrivescCheckExe

A **native C#** re-implementation of selected [PrivescCheck](https://github.com/itm4n/PrivescCheck)
checks plus a Windows hardening/configuration audit, compiled to a single self-contained `.exe`.
No PowerShell is used, so the tool does not touch AMSI or PowerShell ScriptBlock logging.

> **For authorized pentest use only.**

## Build

Requires the .NET 8 SDK (or .NET 10 SDK, which also builds net8.0-windows).

```powershell
cd PrivescCheckExe
dotnet publish -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o publish
```

Output: `publish\PrivescCheckExe.exe` (~34 MB, fully self-contained, no runtime install needed on target).

## Usage

```text
PrivescCheckExe.exe              # console output + writes TXT and CSV report next to the exe
PrivescCheckExe.exe --console-only   # stdout only, no report files
PrivescCheckExe.exe --silent      # no console output, report files only (stealthier)
```

Reports are written next to the exe:
- `PrivescCheck_<HOST>_<timestamp>.txt` — human-readable
- `PrivescCheck_<HOST>_<timestamp>.csv` — one row per finding (Id,Category,Title,Severity,Description,Evidence,Remediation)

## What it checks

### PrivescCheck-style (privilege escalation)
| ID        | Check |
|-----------|-------|
| TOKEN-00x | Identity/integrity, privileged group membership, dangerous token privileges (SeImpersonate, SeDebug, SeLoadDriver, …) |
| REG-00x   | AlwaysInstallElevated, AutoLogon credentials, AutoRun entries (Run keys, Winlogon, Startup) + writability |
| SVC-00x   | Unquoted service paths w/ writable parent, writable service binaries, services reconfigurable by current user (native SCM), startable services |
| DLL-00x   | Writable dirs on PATH, writable System32/Windows dirs (DLL planting) |
| TASK-00x  | Scheduled tasks whose action binary is writable |
| SW-00x    | Installed software, hotfixes (patch gaps), WSUS (HTTP-only update spoofing) |

### Configuration issues (4 categories)
- **Hardening** (CFG-HARD): LAPS, BitLocker, Defender real-time/anti-spyware, ASR rules, Exploit Protection, Firewall profiles
- **Audit & Logging** (CFG-AUD): advanced audit policy (auditpol), PowerShell ScriptBlock/Module/Transcription logging, Security Event Log config, Sysmon presence
- **Network & Services** (CFG-NET): listening TCP ports, service binary paths, SMB (SMB1/signing), RDP (NLA/SecurityLayer), WinRM (AllowUnencrypted), shares
- **Creds & Tokens** (CFG-CRED): Credential Manager, saved RDP files, Chromium Login Data/Cookies, AutoLogon, PowerShell command history

## Severity mapping
`Critical > High > Medium > Low > Info`, color-coded on the console (red/magenta/yellow/cyan/gray).

## Notes / limitations
- Several checks shell out to read-only OS binaries (`whoami`, `netstat`, `auditpol`, `netsh`,
  `schtasks`, `manage-bde`, `cmdkey`, `net`, `winrm`, `sc`-equivalent via native API). No PowerShell.
- Writable-directory/binary probes create and delete a probe file; this is a benign write.
- WMI may be unavailable on hardened hosts — affected checks degrade gracefully and report "unavailable".
- This is a subset of PrivescCheck's full suite focused on highest-value vectors; extend `Checks/` and `Config/` as needed.
```