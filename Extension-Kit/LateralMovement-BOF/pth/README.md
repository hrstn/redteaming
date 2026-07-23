# pth — Pass-the-Hash make-token / run-binary (BOF)

Mint a Windows network-logon token from an **NT hash alone** — no plaintext, no
lsass patching, no driver — then either impersonate the beacon as that user or
spawn a binary as that user. Pure in-process; replaces `mimikatz sekurlsa::pth`
(lsass-patch), `runas /netonly` (plaintext), and `netexec`/`psexec.py --hashes`
for local-token PTH use.

## Usage
```
pth <user> <domain> <nthash> [binary]
```
- `nthash` — 32 hex chars, or full `lmhash:nthash` form (the right half is used).
- **binary omitted** → the beacon thread impersonates the hash-user (like `token make`);
  subsequent beacon commands authenticate as that user.
- **binary given** → that binary is spawned as the hash-user (network logon).

```
pth svc-sql DEV 31d6cfe0d16ae931b73c59d7e0c089c0                       # impersonate
pth svc-sql DEV 31d6cfe0d16ae931b73c59d7e0c089c0 C:\Windows\Temp\a.exe # spawn a.exe as svc-sql
```

## How it works
1. Derive `NTOWFv2 = HMAC-MD5(NThash, UNICODE(ToUpper(user) || domain))` (BCrypt).
2. Build the NTLMv2 blob (`0x01010000 | 0 | timestamp | clientChallenge | 0 | targetInfo`).
3. `NTProofStr = HMAC-MD5(NTOWFv2, serverChallenge || blob)`; NTLMv2 response = `NTProofStr || blob`.
4. LMv2 = `HMAC-MD5(NTOWFv2, serverChallenge || clientChallenge) || clientChallenge` (24 B).
5. `LsaConnectUntrusted` → `LsaLookupAuthenticationPackage("MSV1_0")` →
   `LsaLogonUser(Network, MSV1_0_LM20_LOGON, LocalGroups=NULL)` → network logon token.
6. Impersonate: `BeaconUseToken`. Spawn: `DuplicateTokenEx(TokenPrimary)` + `CreateProcessWithTokenW`.

`MSV1_0_LM20_LOGON` with `LocalGroups=NULL` and no subauth needs **no SeTcbPrivilege** →
`LsaConnectUntrusted` suffices → works from an **admin** beacon (not just SYSTEM).
`CreateProcessWithTokenW` needs `SeImpersonate` (admin has it).

## Caveat
A `Network` logon yields a **network** token: the spawned binary runs and authenticates
to network resources as the hash-user, but has **no interactive desktop session**.
Fine for an agent / recon tool; not for "pop interactive cmd as them". For an
interactive/primary token from a hash you'd need lsass patching (mimikatz
`sekurlsa::pth`) — declined for stealth; this network token is the clean substitute.

## Requirements / OPSEC
- Admin beacon (SeImpersonate). No SeTcb, no SYSTEM required. Not blocked by Credential Guard.
- No `runas.exe` / `psexec.exe` / `netexec` / fork&run. No lsass memory write. No driver.
- MITRE **T1550.002** (Use Alternate Auth Material: Pass the Hash).

## Build
Part of the `LateralMovement-BOF` suite: `make -C LateralMovement-BOF` →
`_bin/pth.x64.o` + `_bin/pth.x32.o`. Audit gate: `nm -u _bin/pth.x64.o | awk
'{print $2}' | grep -v '^__imp_'` empty (only `__imp_*$` + `__imp_Beacon*`).

## References
- LSA Whisperer (SpecterOps, 2024) — `LsaCallAuthenticationPackage` / `MSV1_0_LM20_LOGON`.
- Microsoft: `MSV1_0_LM20_LOGON`, `LsaLogonUser` (SeTcb required only for subauth / S4U-impersonation / non-NULL LocalGroups).
- MazX0p/mssqlbof (MIT) — NTLMv2 HMAC-MD5 via BCrypt in a BOF.