# NoNameAx (NaX) Wiki

Position-independent C2 beacon for the [Adaptix Framework](https://github.com/Adaptix-Framework/Adaptix) with module stomping, malleable C2 profiles, BOF execution, and a Stardust-pattern UDRL loader.

## Pages

### Core Documentation
- **[Beacon Architecture](Beacon-Architecture.md)** -- NAX_INSTANCE, bootstrap, heartbeat loop, command dispatch
- **[Wire Protocol](Wire-Protocol.md)** -- Frame format, message types, command IDs
- **[Malleable C2 Profiles](Malleable-C2-Profiles.md)** -- OutputConfig encoding pipeline, profile JSON format, runtime switching
- **[Module Stomping](Module-Stomping.md)** -- Loader-phase beacon stomping, DLL selection, LDR patching, stack unwinding

### BOF System
- **[BOF Execution](BOF-Execution.md)** -- COFF loader, sync vs async dispatch, thread pool, media callbacks
- **[BOF Module Stomping](BOF-Module-Stomping.md)** -- Image-backed BOF .text, near-allocator, .pdata injection, backup/restore

### Evasion
- **[BeaconGate & Sleepmask](BeaconGate-Sleepmask.md)** -- API call proxy, WFSO PoC sleepmask, extensible gate architecture

### Post-Exploitation
- **[Token Commands](Token-Commands.md)** -- Token theft, impersonation, credential logon, privilege listing

### Networking
- **[Tunneling](Tunneling.md)** -- Local/reverse port forwarding, wire protocol, OPSEC, flow control, SMB transport support

### Extending NaX
- **[Adding Commands](Adding-Commands.md)** -- End-to-end walkthrough: Wire.h to AxScript
- **[Stardust Loader Guide](Stardust-Loader-Guide.md)** -- How the UDRL works, how to write your own from scratch following ZPS course material

### Operations
- **[Build and Deploy](Build-and-Deploy.md)** -- Prerequisites, build commands, server plugin deployment, Adaptix setup
- **[Operator Reference](Operator-Reference.md)** -- All commands: navigation, file ops, recon, tokens, BOF, pivoting, tunneling, runtime config (sleep, profile, bof-stomp, sleepmask-set, sleepobf-config, chunksize, dll-notify)
