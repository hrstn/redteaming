# BOF ideas — OSEP / CRTO / CRTL (AdaptixC2, in-process)

Design catalog of **new** Beacon Object Files to add to this Collection, grounded
in the OSEP / CRTO / CRTL syllabi and the BOFs already present here. The unifying
thesis (same as the OSAI suite): **every action runs in-process inside the beacon
thread — zero child processes** — so it produces no `powershell.exe`, `Rubeus.exe`,
`net.exe`, `netexec`, or `execute-assembly` (fork&run) telemetry. That OPSEC
property is exactly what the proctored/SIEM-graded labs reward.

Existing Collection BOFs (don't duplicate): AddMachineAccount, Askcreds,
CVE-2022-26923, Domaininfo, FindObjects (FindModule/FindProcHandle), Icacls,
KerbHash, Kerberoast, Klist, Lapsdump, PetitPotam, Psc/Psm/Psk/Psw/Psx, RBCD,
ReconAD, Smbinfo, SprayAD, StartWebClient, WdToggle, adPEAS.

Conventions for new BOFs here: per-BOF `BOF-Sources/<Name>/SOURCE/` (own
`beacon.h` + `Makefile`), compiled `.o` + `.axs` flat in `adaptix-ported-scripts/`.
`bof_path = ax.script_dir() + "<Name>." + ax.arch(id) + ".o"`. Apply the universal
loader rules in `~/.claude/skills/bof-builder/LESSONS.md` (only `__imp_`-prefixed
symbols resolve; no bare libc / `htonl`/`htons` / compiler `memset`; `___chkstk_ms`
stub for >4 KB frames; `nm -u | grep -v '^__imp_'` must be empty after build).

Legend: **GAP** = not covered here; **ENHANCE** = extends an existing BOF;
**KIT-COVERED** = already provided by a loaded AdaptixC2 BOF group (do NOT build —
see the reconciliation table in `bofbuild-roadmap.md`, 2026-07-23).
Difficulty: ◂ easy · ◂◂ medium · ◂◂◂ heavy (COM/RPC/ASN.1 — roadmap, build last).

---

## OSEP — AD evasion, Kerberos, trust, ADCS, MS-SQL

| BOF | Status | What it does | Key APIs (MODULE$) | OPSEC note |
|---|---|---|---|---|
| **icacls** | DONE ◂ | Quick in-process DACL/rights enumeration for a file or directory: owner + every DACL ACE, icacls-style rights letters (F/M/RX/R/W composites else bit decomposition), inheritance flags (OI/CI/IO/NP/ID), DENY marked, optional `-r N` recursive descent (capped at 2000 entries). Privesc recon: find writable / FullControl / Delete-Child paths without `icacls.exe` or `cmd`. | `ADVAPI32$GetNamedSecurityInfoW`, `GetAclInformation`, `GetAce`, `LookupAccountSidW`, `ConvertSidToStringSidW`; `KERNEL32$FindFirstFileW/Next/Close`, `GetFileAttributesW`, `LocalFree`; `MSVCRT$memset/wcscpy_s/wcscat_s` | Pure in-process; no `icacls.exe`/`cmd` child. Built at `BOF-Sources/Icacls/`, registered as `icacls.axs`. |
| **adcsEnum** | KIT-COVERED ◂◂ | Enumerate AD CS templates + CAs via LDAP against `CN=Public Key Services,CN=Services,CN=Configuration,…`; flag ESC1–ESC8 conditions (ENROLLEE_SUPPLIES_SUBJECT, Client Auth EKU, low-priv enroll, no manager approval, EDITF_ATTRIBUTESUBJECTALTNAME2 on CA). | `WLDAP32$ldap_search_ext_s`, `ldap_next_entry`, `ldap_get_values` | ✅ Loaded `certi enum` covers this. Do NOT rebuild. |
| **adcsRequest** | KIT-COVERED ◂◂◂ | Request a cert from a vulnerable template in-process (MS-WCCE over RPC or `ICertRequest2` COM). The payoff BOF for adcsEnum. | `CERTCLI`/`CERTENROLL` COM (CoCreateInstance) or raw `RpcBinding` | ✅ Loaded `certi request`/`request_on_behalf` cover this. Do NOT rebuild. |
| **shadowCreds** | KIT-COVERED ◂◂ | Write `msDS-KeyCredentialLink` on a target user/computer via LDAP → shadow-credentials attack (get TGT with the device's key). Pairs with RBCD. | `WLDAP32$ldap_modify_ext_s` (build KEY_ID link value per MS-DRTC) | ✅ Loaded `certi shadow` covers this. Do NOT rebuild. |
| **s4u** | KIT-COVERED ◂◂◂ | S4U2self + S4U2proxy TGS-Request over raw Kerberos for constrained-delegation / RBCD exploitation. | raw Kerberos (ASN.1 encoder) + KerbHash for keys | ✅ Loaded `kerbeus s4u`/`cross_s4u` cover this. Do NOT rebuild. |
| **printerBug** | GAP ◂ (low) | MS-RPRN `RpcRemoteFindFirstPrinterChangeNotificationEx` to coerce DC NTLM to attacker. Complements PetitPotam. | RPC `spoolss` (bind via `RpcBindingFromStringBinding`) | Low value — PetitPotam (`petitpotam`) already gives a coerce primitive. Build only if you need a spoolss-specific coerce. |
| **dfsCoerce** | GAP ◂ (low) | MS-DFSNM `NetrDfsAddRemoteRoot`/`NetrDfsRemove` coerce auth. Third coerce primitive alongside PetitPotam/PrinterBug. | RPC `dfs` (`netapi32`/`samr`-style bind) | Low value — PetitPotam already covers coerce. Build only if you need a dfs-specific coerce. |
| **mssqlTrust** | KIT-COVERED ◂◂ | MS-SQL abuse via ODBC in-process: connect, enumerate linked servers, enable `xp_cmdshell`, `xp_dirtree \\attacker\share` for NTLM capture, exec via linked chain. Big OSEP topic. | `ODBC32$SQLDriverConnect`, `SQLExecDirect`, `SQLMoreResults` | ✅ Loaded MSSQL-BOF group (`mssql query`/`links`/`enablexp`/`xpcmd`/`olecmd`/`clr`/`smb`/`impersonate`/`agentcmd`) covers this and more. Do NOT rebuild. |
| **dpapiBackup** | GAP ◂◂◂ | Fetch DPAPI domain backup key from AD (`BCKUPKEY_*` secretDomain via LDAP) and decrypt user masterkeys. | `WLDAP32$` + DPAPI crypto | ⬜ Real gap. Heavy crypto; build last. Note `lsadump_secrets` is local SECURITY hive, NOT the AD backup-key fetch. |

## CRTO — Kerberos, delegation, gMSA, ACL/LAPS abuse

| BOF | Status | What it does | Key APIs (MODULE$) | OPSEC note |
|---|---|---|---|---|
| **gmsaRead** | GAP ◂◂ (partial) | Read `msDS-ManagedPassword` for a gMSA via LDAP, derive the gMSA AES key (pwd + salt) and compute the NT hash. | `WLDAP32$ldap_search_ext_s` + crypto (HMAC-SHA + AES) | ⬜ Partial gap: `ldap get-attribute` fetches the blob, but NO key derivation. A pure-crypto helper taking the blob via `bytes` is the only missing piece. |
| **aclAbuse** | KIT-COVERED ◂◂ | Apply a GenericAll/WriteDacl/WriteOwner/GenericWrite win on a target: set `unicodePwd` (force change), add group member, set `servicePrincipalName`, write `msDS-AllowedToActOnBehalfOfOtherIdentity`. Configurable action arg. | LDAP `ldap_modify_ext_s` (ADSI) | ✅ LDAP-BOF `add-*` set (`add-genericall`/`genericwrite`/`dcsync`/`rbcd`/`sidhistory`/`ace`/`unconstrained`/`constrained`/`asreproastable`, `set-password`, `set-owner`, `add-groupmember`) covers this and far more. Do NOT rebuild. |
| **addSpn** | KIT-COVERED ◂ (subset of aclAbuse) | Add an SPN to a user to make it Kerberoastable, then run the existing Kerberoast BOF. Tiny, high-value. | `WLDAP32$ldap_modify_ext_s` | ✅ Loaded `ldap add-spn`/`set-spn` cover this. Do NOT rebuild. |
| **lapsV2** | KIT-COVERED ◂◂ | Read Windows LAPS (`msLAPS-EncryptedPassword`, `msLAPS-PasswordExpirationTime`) and decrypt via the LAPS routine. The existing Lapsdump is legacy LAPS (`ms-Mcs-AdmPwd`). | `WLDAP32$` + LAPS decryption (AES-GCM with domain-derived key) | ✅ Verified 2026-07-23: loaded `readlaps` (AD-BOF) already reads BOTH `msLAPS-EncryptedPassword` (v2, decrypts via NCrypt callback) and `ms-Mcs-AdmPwd` (legacy). Do NOT rebuild. |
| **gmsaMap** | ENHANCE ◂ (partial) | Enumerate which principals can retrieve each gMSA (`msDS-GroupMSAMembership`) and which hosts a gMSA runs on. Recon aid feeding gmsaRead. | `WLDAP32$ldap_search_ext_s` | ⚠️ Partial — `ldap get-attribute`/`get-writable` cover most of it; low value to build. |

## CRTL — tradecraft, evasion, session recon (detection-aware)

| BOF | Status | What it does | Key APIs (MODULE$) | OPSEC note |
|---|---|---|---|---|
| **amsiEtwPatch** | GAP ◂ | Patch `amsi.dll!AmsiScanBuffer` and `ntdll!EtwEventWrite` (first bytes → `ret`/`xor eax,eax;ret`) in the current process; optional restore. Complements WdToggle. | `KERNEL32$LoadLibraryA`, `VirtualProtect`, `memcpy`-free byte patch | ⬜ Real gap. **First confirm the loaded kit doesn't already patch AMSI/ETW internally.** If not, this is a cheap high-value CRTL primitive — top build priority. |
| **injectBOF** | KIT-COVERED ◂◂ | Process-injection primitives (APC queue / thread-hijack / `CreateRemoteThread`) given PID + shellcode bytes (`bytes` via `addArgFile`). (Note: Extension-Kit/Injection-BOF already has this for the Extension home — this fills the Collection gap.) | `KERNEL32$OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `QueueUserAPC`/`CreateRemoteThread` | ✅ Loaded Injection-BOF (`inject-cfg`/`sec`/`poolparty`/`32to64`) covers this. Do NOT rebuild. |
| **tokenImpersonate** | KIT-COVERED ◂ | Take a PID (or handle from FindProcHandle), `DuplicateTokenEx` + `ImpersonateLoggedOnUser` to act as that user in the beacon thread; make-token style pivots without `runas`/`net use`. | `ADVAPI32$OpenProcessToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser` | ✅ Loaded `token make`/`steal` + `getsystem token` + `runas-user` cover this. Do NOT rebuild. |
| **netSessions** | GAP ◂ | `NetSessionEnum` / `NetWkstaUserEnum` / `NetWkstaUserGetInfo` to find who's logged on where (session recon). | `NETAPI32$NetSessionEnum`, `NetWkstaUserEnum` | ⬜ Real gap. `quser` covers terminal sessions and `smbinfo` covers NetWkstaGetInfo, but no `NetSessionEnum`/`NetWkstaUserEnum`. Worth building for SMB-session recon feeding relay decisions (complements `relay-informer`). |
| **opsecAudit** | GAP ◂ | Self-hygiene: list EDR/Sysmon DLLs loaded in the beacon, recent process creation via `NtQuerySystemInformation`, EventLog service state, AMSI/ETW live state. CRTL-flavored "know your footprint" before acting. | `NTDLL$NtQuerySystemInformation`, `KERNEL32$EnumProcessModules` | ⬜ Real gap (low). `privcheck *` covers local privesc footprint; this adds EDR/Sysmon/AMSI/ETW live-state narrative. Optional — nice for the report's OPSEC section. |

---

## Suggested build order (max exam value per effort)

**Reconciled 2026-07-23 against the loaded beacon `help`** — most of the original
list is now KIT-COVERED (see `bofbuild-roadmap.md` "Coverage reconciliation").
Only the real gaps remain, in priority order:

1. **amsiEtwPatch** (◂) — **verify first** the loaded kit doesn't already patch
   AMSI/ETW; if not, cheap + high-value CRTL primitive. Top priority.
2. **gmsaRead derivation** (◂◂) — fetch is covered by `ldap get-attribute`; the
   gap is deriving the gMSA NT/AES key from the `msDS-ManagedPassword` blob. Could
   ship as a pure-crypto helper taking the blob via `bytes`.
3. **netSessions** (◂) — `NetSessionEnum`/`NetWkstaUserEnum` for SMB-session recon
   feeding relay decisions (complements `relay-informer`).
4. **opsecAudit** (◂, low) — EDR/Sysmon/AMSI/ETW live-state narrative for the
   report's OPSEC section. Optional.
5. *Verified — drop:* **lapsV2** — `readlaps` already reads v2 + legacy (confirmed
   2026-07-23). No longer a gap.
6. **dpapiBackup** (◂◂◂) — fetch AD domain backup key + decrypt masterkeys; heavy,
   build last, only if a lab needs the DPAPI loot chain.
7. Only if you need a non-PetitPotam coerce: **printerBug** / **dfsCoerce** (both
   low — PetitPotam already covers coerce).

**Do NOT rebuild** the KIT-COVERED set (`addSpn`, `shadowCreds`, `aclAbuse`,
`mssqlTrust`, `injectBOF`, `tokenImpersonate`, `adcsEnum`, `adcsRequest`, `s4u`) —
use the loaded `ldap *` / `certi *` / `kerbeus *` / `mssql *` / `token *` /
`inject-*` commands instead.

Each new BOF: follow `~/.claude/skills/bof-builder/SKILL.md` (build → `nm` audit →
go-check → `.axs`), and append real findings to that skill's `LESSONS.md`.