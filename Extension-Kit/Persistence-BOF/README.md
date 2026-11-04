# Persistence-BOF — persistence primitives + kit-wide persistence inventory

In-process COM/reg persistence primitives with paired cleanup, plus a read-only
inventory sweep of every location the kit (and IR lookups) care about. All BOFs
run in the beacon process on the beacon thread — no child processes, no
PowerShell, no schtasks.exe.

## Commands

| Command | What | Cleanup |
|---|---|---|
| `wmi-sub <subName> <command>` | `__EventFilter` + `__CommandLineEventConsumer` + `__FilterToConsumerBinding` in `root\subscription`, boot trigger (~4 min after boot) | `wmi-clear <subName>` |
| `wmi-clear <subName>` | removes binding + `__CommandLineEventConsumer` / `__ActiveScriptEventConsumer` + `__EventFilter` by name | — |
| `task-create <name> <cmd> [-mode N] [-every N] [-hours N]` | task via in-process COM `RegisterTask` (XML); `1`=LogonTrigger (default), `2`=BootTrigger (SYSTEM, admin), `3`=TimeTrigger repeating | task name gets a **per-run random suffix** — read it from the task output; remove with `task-delete <name>.<suffix>` |
| `task-delete <name>` | `ITaskFolder::DeleteTask` in-process | — |
| `runkey <name> <cmd> [-mode N] [-hklm N]` | Run value set/delete, HKCU default | `runkey <name> - -mode 0 [-hklm 1]` |
| `comhijack <clsid> <dll> [-mode N]` | HKCU `Software\Classes\CLSID\{...}\InprocServer32` (+ `ThreadingModel=Both`) set/delete — user keys only | `comhijack <clsid> - -mode 0` |
| `persist-inventory [-cap N]` | read-only sweep: Run/RunOnce (HKCU/HKLM/W6432), startup folders, all four subscription classes, task tree (Commands parsed from XML), non-C:\Windows service binaries, IFEO `Debugger`/`GlobalFlag`, Winlogon overrides | — |

## OPSEC notes

- **Pair every install with a planned clear in the same session.** The suite's
  contract: `persist-inventory` shows zero leftovers before the operator leaves
  the box; nothing here auto-hides (no timestomping on keys, no name confusion
  beyond the task-name suffix).
- Telemetry per command (Windows event logs): WMI-Activity 5857-5861
  (wmi-sub/wmi-clear/inventory WMI section), Task Scheduler
  4698/4699 + 106/200/201 (task-create/task-delete/launches), Sysmon 12/13 on
  registry writes (runkey/comhijack), 7045-analogue none (no services created
  here — use `LateralMovement-BOF/psexec` for that, its cleanup flag).
- COM paths run in-process: same beacon process, no children — the in-process
  COM connection is the expected footprint; there is no schtasks/reg add LOB.
- `task-create` mode 2 (boot, SYSTEM) requires admin; wrappers report the
  failure codes clearly.
- `comhijack` touches only `HKCU\Software\Classes\...` — system classes stay
  untouched; the delete path removes exactly the `InprocServer32` subtree and
  leaves the `{clsid}` parent for IR to see the removal.
- The whole suite is read/write on keys/values only where specified; nothing
  drops files (the executable referenced by task/wmi-sub/runkey/comhijack must
  already be on disk by the operator's choice).

## Build

```bash
cd Extension-Kit/Persistence-BOF && make   # -> _bin/*.x64.o + *.x86.o (stripped)
```

Requires `x86_64-w64-mingw32-gcc` / `i686-w64-mingw32-gcc`. Load
`Extension-Kit/extension-kit.axs` (registers the seven commands above for
`beacon`, `gopher`, `NoNameAx`).

## Notes

- WMI consumption executes `CommandLineTemplate` as a shell command at each
  trigger (boot) — keep it short, neutral and paired with `wmi-clear`.
- Consumer execution is visible in 5861 with the literal command: choose task
  names/paths that read like system maintenance material.
- The suite writes no files itself; where a dropped binary is referenced, its
  hygiene (timestamp, deletion) is the operator's separate step.