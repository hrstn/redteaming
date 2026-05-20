# Outflank C2-Tool-Collection — Adaptix C2 ASX Port

Adaptix C2 ports of all tools from [Outflank's C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection).
Each `.axs` file is a self-contained AxScript extension that loads the appropriate compiled BOF (or reflective DLL / .NET assembly) and exposes the tool as a native Adaptix command.

---

## Installation

1. **Compile the BOFs** for each tool (see _Dependencies_ below).
2. Copy the contents of this directory into your Adaptix extensions folder:
   ```
   ~/.adaptix/extensions/outflank-c2tc/
   ├── askcreds.axs
   ├── machineaccounts.axs
   ├── ...
   ├── Askcreds.x64.o
   ├── Askcreds.x86.o
   └── ...
   ```
3. In the Adaptix client, open **Script Manager → Load** and select each `.axs` file you want to activate.
4. Commands become available immediately in the beacon console.

---

## Script Files and Commands

| Script File | Commands Registered |
|-------------|---------------------|
| `askcreds.axs` | `askcreds` |
| `machineaccounts.axs` | `GetMachineAccountQuota`, `AddMachineAccount`, `DelMachineAccount` |
| `cve-2022-26923.axs` | `CVE-2022-26923` |
| `domaininfo.axs` | `domaininfo` |
| `findobjects.axs` | `FindProcHandle`, `FindModule` |
| `kerberoast.axs` | `kerberoast` |
| `kerbhash.axs` | `kerbhash` |
| `klist.axs` | `klist` |
| `lapsdump.axs` | `lapsdump` |
| `petitpotam.axs` | `petitpotam` (BOF) |
| `petitpotam_rdll.axs` | `petitpotam-rdll` (Reflective DLL) |
| `psc.axs` | `psc` |
| `psw.axs` | `psw` |
| `psk.axs` | `psk` |
| `psm.axs` | `psm` |
| `psx.axs` | `psx`, `psxx` |
| `reconad.axs` | `ReconAD`, `ReconAD-Users`, `ReconAD-Computers`, `ReconAD-Groups` |
| `remotepipelist.axs` | `remotepipelist` (x64, .NET assembly) |
| `smbinfo.axs` | `smbinfo` |
| `sprayad.axs` | `sprayad` |
| `startwebclient.axs` | `startwebclient` |
| `wdtoggle.axs` | `wdtoggle` |
| `winver.axs` | `winver` |

---

## Command Reference

### askcreds
```
askcreds [reason]
```
Spawns a Windows credential prompt via `CredUIPromptForWindowsCredentialsName`. Waits up to 60 seconds for user input. `reason` is optional display text in the prompt.

---

### GetMachineAccountQuota / AddMachineAccount / DelMachineAccount
```
GetMachineAccountQuota
AddMachineAccount <computername> [password]
DelMachineAccount <computername>
```
Abuses the default Active Directory `ms-DS-MachineAccountQuota` to add or remove rogue machine accounts via ADSI.

---

### CVE-2022-26923
```
CVE-2022-26923 <computername> [password]
```
ADCS domain privilege escalation. Creates a machine account whose `dNSHostName` matches the DC FQDN, enabling certificate-based domain admin escalation.

---

### domaininfo
```
domaininfo
```
Enumerates domain information (domain name, forest, DCs, functional level, etc.) via Active Directory Domain Services.

---

### FindProcHandle / FindModule
```
FindProcHandle <process.exe>
FindModule <module.dll>
```
Uses direct syscalls to enumerate all processes. `FindProcHandle` finds processes holding a handle to the named process; `FindModule` finds processes with the named DLL loaded.

---

### kerberoast
```
kerberoast <action> [sAMAccountName]
```
Actions: `list`, `list-no-aes`, `roast`, `roast-no-aes`.
Lists SPN-enabled accounts or requests TGS tickets for offline cracking with Hashcat.

> **OPSEC WARNING**: Using without a `sAMAccountName` filter requests tickets for all SPN accounts and is highly visible.

---

### kerbhash
```
kerbhash <password> <username> <domain.fqdn>
```
Calculates `rc4_hmac`, `aes128_cts_hmac_sha1`, `aes256_cts_hmac_sha1`, and `des_cbc_md5` Kerberos key hashes for the given credentials.

---

### klist
```
klist
klist purge
klist get <SPN>
```
Without arguments: lists all cached Kerberos tickets.
`purge`: purges all cached tickets.
`get <SPN>`: requests a new TGS ticket for the specified Service Principal Name.

---

### lapsdump
```
lapsdump <target>
```
Reads the LAPS `ms-Mcs-AdmPwd` attribute from the target computer object in AD. Requires sufficient AD read permissions.

---

### petitpotam (BOF)
```
petitpotam <capture-server> <target-server>
```
BOF implementation of PetitPotam. Coerces `<target-server>` to authenticate to `<capture-server>` via MS-EFSRPC. Use with Responder or ntlmrelayx.

---

### petitpotam-rdll (Reflective DLL)
```
petitpotam-rdll <capture-server> <target-server>
```
Reflective DLL variant of PetitPotam. Requires `PetitPotam.dll` next to the script. Prefer the BOF variant for lower footprint.

---

### psc
```
psc
```
Lists all processes that have at least one established TCP or RDP connection, with connection details.

---

### psw
```
psw
```
Lists all processes with visible windows, showing the window title.

---

### psk
```
psk
```
Lists the Windows kernel and all loaded kernel-mode driver modules. Includes a summary of detected AV/EDR drivers.

---

### psm
```
psm <pid>
```
Shows detailed information for a single process by PID: loaded modules, TCP connections, handles, etc.

---

### psx / psxx
```
psx
psxx
```
`psx`: standard process list with security product summary.
`psxx`: extended process list with additional detail columns.

---

### ReconAD / ReconAD-Users / ReconAD-Computers / ReconAD-Groups
```
ReconAD <ldap-filter> [attributes|-all] [-max|count] [-usegc|-ldap] [server:port]
ReconAD-Users <username> [attributes|-all] [-max|count] [-usegc|-ldap] [server:port]
ReconAD-Computers <computername> [attributes|-all] [-max|count] [-usegc|-ldap] [server:port]
ReconAD-Groups <groupname> [attributes|-all] [-max|count] [-usegc|-ldap] [server:port]
```
ADSI-based AD enumeration. All four commands use the same BOF (`ReconAD.{arch}.o`).

| Argument | Default | Notes |
|----------|---------|-------|
| attributes | `-all` | Comma-separated LDAP attribute names, or `-all` |
| maxresults | `-max` | Integer or `-max` for unlimited |
| usegc | (LDAP) | Pass `-usegc` to query the Global Catalogue |
| server | (auto-discover) | Optional `server:port` for explicit DC binding |

---

### remotepipelist
```
remotepipelist <targetIP> [username] [password]
```
Enumerates named pipes on a remote system by connecting to the IPC$ share. Runs inline as a .NET assembly (x64 only).

---

### smbinfo
```
smbinfo <target>
```
Retrieves remote system OS version, hostname, and domain info via `NetWkstaGetInfo` — no CS port scanner required.

---

### sprayad
```
sprayad <password> [filter] [ldap]
```
Sprays a single password against all (or filtered) enabled AD accounts.
- Omit `filter` to target all accounts.
- Pass `ldap` as the third argument to use LDAP authentication (faster; generates event 4625 instead of 4771).
- With `filter`, optionally append `ldap` as `authmethod` to use LDAP.

> **WARNING**: Always check the domain password lockout policy before spraying.

---

### startwebclient
```
startwebclient
```
Starts the WebClient (WebDAV) service from user context using a service trigger. Required for WebDAV-based relay attacks.

---

### wdtoggle
```
wdtoggle
```
Patches lsass to re-enable WDigest credential caching. Also circumvents Credential Guard if active. After the next interactive logon, plaintext credentials will be cached in LSASS memory.

---

### winver
```
winver
```
Displays the running Windows version, build number, and Update Build Revision (UBR patch level).

---

## Dependencies

Each command requires its compiled BOF object files placed in the same directory as the `.axs` script. Naming convention: `<ToolName>.<arch>.o` (e.g., `Askcreds.x64.o`, `Askcreds.x86.o`).

| Tool | Required Files |
|------|---------------|
| askcreds | `Askcreds.x64.o`, `Askcreds.x86.o` |
| machineaccounts | `GetMachineAccountQuota.x64.o`, `GetMachineAccountQuota.x86.o`, `AddMachineAccount.x64.o`, `AddMachineAccount.x86.o`, `DelMachineAccount.x64.o`, `DelMachineAccount.x86.o` |
| cve-2022-26923 | `CVE-2022-26923.x64.o`, `CVE-2022-26923.x86.o` |
| domaininfo | `Domaininfo.x64.o`, `Domaininfo.x86.o` |
| findobjects | `FindProcHandle.x64.o`, `FindProcHandle.x86.o`, `FindModule.x64.o`, `FindModule.x86.o` |
| kerberoast | `Kerberoast.x64.o`, `Kerberoast.x86.o` |
| kerbhash | `KerbHash.x64.o`, `KerbHash.x86.o` |
| klist | `Klist.x64.o`, `Klist.x86.o` |
| lapsdump | `Lapsdump.x64.o`, `Lapsdump.x86.o` |
| petitpotam | `PetitPotam.x64.o`, `PetitPotam.x86.o` |
| petitpotam_rdll | `PetitPotam.dll` |
| psc | `Psc.x64.o`, `Psc.x86.o` |
| psw | `Psw.x64.o`, `Psw.x86.o` |
| psk | `Psk.x64.o`, `Psk.x86.o` |
| psm | `Psm.x64.o`, `Psm.x86.o` |
| psx / psxx | `Psx.x64.o`, `Psx.x86.o` |
| reconad | `ReconAD.x64.o`, `ReconAD.x86.o` |
| remotepipelist | `RemotePipeList.exe` (x64 only) |
| smbinfo | `Smbinfo.x64.o`, `Smbinfo.x86.o` |
| sprayad | `SprayAD.x64.o`, `SprayAD.x86.o` |
| startwebclient | `StartWebClient.x64.o`, `StartWebClient.x86.o` |
| wdtoggle | `WdToggle.x64.o`, `WdToggle.x86.o` |
| winver | `Winver.x64.o`, `Winver.x86.o` |

### Compiling BOFs

```bash
# Compile all BOFs at once
cd /path/to/C2-Tool-Collection/BOF
make

# Or compile individually
cd /path/to/C2-Tool-Collection/BOF/Askcreds/SOURCE
make
```

Requires `mingw-w64` with `x86_64-w64-mingw32-gcc` and `i686-w64-mingw32-gcc` on the PATH.

---

## Cobalt Strike → Adaptix ASX Mapping Reference

| Cobalt Strike Concept | Adaptix ASX Equivalent | Notes |
|----------------------|------------------------|-------|
| `beacon_command_register("name","desc","synopsis")` | `ax.register_command({name, description, synopsis, handler, args})` | Registered in `RegisterCommands()` |
| `alias cmd { $bid = $1; ... }` | `handler: function(args) { ... }` | `args` is a named object, not positional |
| `beacon_inline_execute($bid, $data, "go", $args)` | `ax.execute_bof(bof_data, "go", bof_args)` | BOF entry point is always `"go"` |
| `bof_pack($bid, "Z", val)` | `ax.pack_arguments([{type:"string", value:val}])` | See type table below |
| `blog($bid, "msg")` | `ax.log("msg")` | Info-level console output |
| `berror($bid, "msg")` | `ax.error("msg")` | Error-level console output |
| `script_resource("file.o")` | `ax.read_bof_file("file.o")` | Reads relative to script directory |
| `barch($bid)` | `ax.get_agent_arch()` | Returns `"x64"` or `"x86"` |
| `-is64 $bid` | `ax.get_agent_arch() === "x64"` | Architecture predicate |
| `$null` | `null` | No-argument BOF call |
| `bdllspawn($bid, path, params, desc, timeout, cleanup)` | `ax.inject_dll(dll_data, params, desc, timeout)` | Reflective DLL injection |
| `bexecute_assembly($bid, path, args)` | `ax.execute_assembly(exe_data, args)` | Inline .NET assembly execution |
| `openf(path)` + `readb(h,-1)` + `closef(h)` | `ax.read_bof_file(name)` / `ax.read_file(path)` | File reading abstracted into one call |

### bof_pack Format → ax.pack_arguments Type

| `bof_pack` format char | C type | ASX `type` value |
|------------------------|--------|-----------------|
| `Z` | `wchar_t*` (wide string) | `"string"` |
| `i` | `int` (32-bit) | `"int"` |
| `s` | `short` (16-bit) | `"short"` |
| `b` | `BYTE` / boolean | `"bool"` |
| (file) | byte buffer | `"file"` |

---

## Notes on Fidelity

- **Argument packing**: Cobalt Strike's `"Z"` format packs a null-terminated UTF-16LE string. The `"string"` type in Adaptix should match this behaviour; verify with the Adaptix documentation if BOFs read `wchar_t*` arguments.
- **`"short"` type**: The `psx`/`psxx` BOF expects a 16-bit integer. If Adaptix does not have a native `"short"` type, use `"int"` with the same value — the BOF reads it as a `short` from the packed buffer regardless.
- **PetitPotam RDLL** (`petitpotam_rdll.axs`): Uses `ax.inject_dll()` which maps to `bdllspawn`. Verify the exact Adaptix API name for reflective DLL injection in your version.
- **RemotePipeList** (`remotepipelist.axs`): Uses `ax.execute_assembly()` which maps to `bexecute_assembly`. This is a .NET assembly, not a BOF. Verify the exact Adaptix API name for inline .NET execution.
- **SprayAD filter shorthand**: The original CNA allows `sprayad <password> ldap` (passing `"ldap"` as the filter argument as a shorthand for LDAP mode). This shorthand is preserved in `sprayad.axs`.
