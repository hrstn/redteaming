# bofbuild-roadmap.md — OSEP / CRTO / CRTL BOF build plan

Sequenced build plan for the candidate BOFs in `BOF-IDEAS-OSEP-CRTO-CRTL.md`.
This is the *how/when*, not the *what* — read the ideas doc for technique/API
detail, and `~/.claude/skills/bof-builder/SKILL.md` + `LESSONS.md` for the
universal loader/build rules that gate every entry below.

Convention target: **this Collection** (`/mnt/e/hacking/redteaming/C2-Tool-Collection`).

## Build mechanics in this home (confirmed)

- New BOF → create `BOF-Sources/<Name>/SOURCE/` containing `beacon.h` (copy from
  an existing SOURCE), a `Makefile` (copy RBCD's), `<name>.c`, optional `<name>.h`.
- The SOURCE `Makefile` compiles both arches to `../<name>.x64.o` + `../<name>.x86.o`
  with `-masm=intel` (x86: `-DWOW64 -fno-leading-underscore`), then strips.
- `make` from `BOF-Sources/` runs `make -C ./*/SOURCE` over all BOFs.
- Distribute: copy the two `.o` into `adaptix-ported-scripts/` **capitalized**
  (`rbcd.x64.o` → `RBCD.x64.o`) and add a flat `<name>.axs` there.
- **This home's CFLAGS is `-masm=intel` only** — it does NOT include the
  loader-safety flags. For every NEW BOF here, add to its SOURCE `Makefile`
  `CFLAGS`: `-Os -fno-tree-loop-distribute-patterns`, and ensure no bare libc /
  `htonl`/`htons` / partial `={0}` inits, and ship a `___chkstk_ms` no-op stub if
  any frame exceeds ~4 KB. (See LESSONS.md U1–U3.)
- Reuse a shared helper header to avoid redoing the AI-BOF work in C: keep a
  `BOF-Sources/_common/bof_common.h` template (`xlen/xcmp/xmemcmp/xmemcpy/xstrcpy/
  xstricmp/xstrstr/xstrncmp/xmemset/bs16/bs32` + the `___chkstk_ms` stub) and
  `#include "../../_common/bof_common.h"` (add `-I../../_common` to CFLAGS), OR
  copy it into each SOURCE dir. Prefer the `-I` shared form so fixes propagate.

## Definition of Done — every BOF, no exceptions

1. Compiles both arches (`make -C BOF-Sources/<Name>/SOURCE`).
2. **Audit gate empty**: `x86_64-w64-mingw32-nm -u ../<name>.x64.o | awk '{print $2}' | grep -v '^__imp_'` prints nothing; same for x86. Only `__imp_*$` + `__imp_Beacon*` remain.
3. Exports `go` (x64 ` T go`, x86 ` T go` — the Collection Makefile passes `-fno-leading-underscore` on x86, so there is NO leading underscore).
4. `.axs` added in `adaptix-ported-scripts/` with `bof_pack` types matching `go()` arg order; registered `["beacon","gopher","NoNameAx"],["windows"]`.
5. `.o` copied (capitalized) into `adaptix-ported-scripts/`.
6. README stub (one-liner usage + the technique/cert/ATT&CK mapping) in the SOURCE dir.
7. Append any new gotcha to `~/.claude/skills/bof-builder/LESSONS.md`.
8. Smoke-test plan noted (lab target + expected output) even if not run yet.

Status legend: ⬜ not started · 🟧 in progress · ✅ done · ⛔ blocked/roadmap.
Status (loaded-kit reconciliation): ✅kit = already covered by a loaded AdaptixC2
command (do NOT rebuild — that is the whole point of this check).

---

## Coverage reconciliation (2026-07-23) — check before building ANYTHING

The beacon `help` now lists a large BOF pack beyond this Collection's `(client)`
groups: AD-BOF, ADCS-BOF, Kerbeus-BOF, LDAP-BOF, MSSQL-BOF, Injection-BOF,
LateralMovement, Creds-BOF, Elevation-BOF, SAL-BOF, SAR-BOF, RelayInformer-BOF,
Process-BOF, PostEx-BOF. **Most planned BOFs below are already covered by it.**
Mapped every roadmap entry to what is now loaded:

| Planned BOF | Loaded equivalent | Verdict |
|---|---|---|
| addSpn (1.1) | `ldap add-spn`, `ldap set-spn` | ✅kit — skip |
| amsiEtwPatch (1.2) | — (not loaded; verify the kit doesn't patch AMSI internally first) | ⬜ real gap (small) |
| printerBug (1.3) | `petitpotam` (MS-EFSRPC coerce); `potato-print` is local LPE, not MS-RPRN coerce | ⬜ low — coerce already covered by PetitPotam |
| netSessions (1.4) | `quser` (terminal sessions), `smbinfo` (NetWkstaGetInfo) — no `NetSessionEnum`/`NetWkstaUserEnum` | ⬜ partial gap (SMB-session recon for relay) |
| icacls (1.5) | `cacls` (SAL-BOF, cacls.exe port; wildcard globs, NO recursion) | ⚠️ overlap — `icacls` adds recursive `-r N` + owner/NULL-DACL/OBJECT-ACE; keep only for recursion |
| shadowCreds (2.1) | `certi shadow` (write KeyCredentialLink + get cert) | ✅kit — skip |
| aclAbuse (2.2) | LDAP-BOF: `ldap set-password`, `add-groupmember`, `add-spn`/`set-spn`, `add-rbcd`, `add-genericall`/`add-genericwrite`/`add-dcsync`, `set-owner`, `add-ace`/`remove-ace`, `add-sidhistory`, `add-unconstrained`/`add-constrained`, `add-asreproastable` | ✅kit — skip (far beyond plan) |
| gmsaRead (3.1) | `ldap get-attribute` can fetch `msDS-ManagedPassword` but NO key derivation (NT/AES) | ⬜ partial gap — derivation only |
| lapsV2 (3.2) | `readlaps` (AD-BOF) — reads BOTH `msLAPS-EncryptedPassword` (v2, decrypts via NCrypt callback) AND `ms-Mcs-AdmPwd` (legacy) | ✅kit — skip (verified 2026-07-23: `readlaps.c` line 82 tries v2 first, falls back to legacy) |
| mssqlTrust (3.3) | full MSSQL-BOF group (`mssql query`/`links`/`enablexp`/`xpcmd`/`olecmd`/`clr`/`smb`(xp_dirtree)/`impersonate`/`agentcmd`) | ✅kit — skip (far beyond plan) |
| tokenImpersonate (4.1) | `token make`, `token steal`, `getsystem token`, `runas-user` + `findobj prochandle` | ✅kit — skip |
| injectBOF (4.2) | Injection-BOF: `inject-cfg`, `inject-sec`, `inject-poolparty`, `inject-32to64` | ✅kit — skip |
| pth (4.3) | — (`token make` / `runas-user` need **plaintext**; no hash→token primitive loaded) | ✅ done 2026-07-23 — built in Extension-Kit/LateralMovement-BOF (other home) |
| adcsEnum (5.1) | `certi enum` (CAs + templates, ESC conditions) | ✅kit — skip |
| adcsRequest (5.2) | `certi request`, `certi request_on_behalf` (ESC3) | ✅kit — skip |
| s4u (5.3) | `kerbeus s4u`, `kerbeus cross_s4u` | ✅kit — skip |
| dfsCoerce (5.4) | — (not loaded) | ⬜ low — coerce already covered by PetitPotam |
| dpapiBackup (5.5) | `lsadump_secrets` is local SECURITY hive, NOT the AD domain backup-key fetch | ⬜ real gap (heavy crypto) |
| gmsaMap (5.6) | `ldap get-attribute`, `ldap get-writable` (partial) | ⚠️ partial — low value to build |

**Net result — only these are still worth building** (in priority order):
1. **amsiEtwPatch** (◂) — first confirm the loaded kit doesn't already patch
   AMSI/ETW; if not, this is a cheap, high-value CRTL primitive.
2. **gmsaRead derivation** (◂◂) — the *fetch* is covered by `ldap get-attribute`;
   the gap is deriving the gMSA NT/AES key from `msDS-ManagedPassword`. Could ship
   as a pure-crypto helper that takes the blob via `bytes`.
3. **netSessions** (◂) — `NetSessionEnum`/`NetWkstaUserEnum` for SMB-session recon
   feeding relay decisions (complements `relay-informer *`).
4. **dpapiBackup** (◂◂◂) — fetch AD domain backup key + decrypt masterkeys; heavy,
   build last, only if a lab needs the DPAPI loot chain.
5. *(optional, low)* **opsecAudit** — EDR/Sysmon/AMSI/ETW live-state for the
   report's OPSEC narrative; **printerBug**/**dfsCoerce** only if you need a
   coerce primitive other than PetitPotam.

`lapsV2` was on this list as "verify" — **verified 2026-07-23**: `readlaps`
(AD-BOF) already reads both `msLAPS-EncryptedPassword` (v2, decrypts via NCrypt
callback) and `ms-Mcs-AdmPwd` (legacy). Drop 3.2 entirely — covered.

Everything else in the original roadmap is **moot — covered by the loaded kit**.
Do not rebuild `addSpn`, `shadowCreds`, `aclAbuse`, `mssqlTrust`,
`tokenImpersonate`, `injectBOF`, `adcsEnum`, `adcsRequest`, `s4u` — use the
loaded `ldap *` / `certi *` / `kerbeus *` / `mssql *` / `token *` / `inject-*`
commands instead. `printerBug`/`dfsCoerce` are only worth it if you specifically
need a coerce primitive other than PetitPotam.

Bonus loaded coverage not in the original plan (use these, don't duplicate):
`dcsync single/all`, `badtakeover` (BadSuccessor), `ldap get-writable` (AD-side
writable hunt — pairs with host-side `icacls`/`cacls`), `privcheck *` (full
local privesc suite incl. `hijackablepath`/`modsvc`/`unquotedsvc`/`autologon`/
`credmanager`), `osep-enum` (local host enum), `sauroneye` (file keyword search),
`taskhound` (scheduled tasks), `relay-informer *` (relay-enforcement recon).

---

## Phase 0 — Foundations (do first, once)

| # | Task | Effort | Status |
|---|---|---|---|
| 0.1 | Create `BOF-Sources/_common/bof_common.h` (loader-safe libc + byte-swap + `___chkstk_ms` stub) | ◂ | ⬜ |
| 0.2 | Decide include style (`-I../../_common` vs copy-in); lock the new-BOF `CFLAGS` string | ◂ | ⬜ |
| 0.3 | Copy an existing SOURCE (RBCD) → `_template/SOURCE/` as the canonical starting skeleton | ◂ | ⬜ |

**Deliverable:** a repeatable "new BOF" scaffold so Phase 1+ is mechanical.
**Verify:** the template compiles and passes the audit gate empty.

## Phase 1 — Cheap, high-coverage (OSEP/CRTL)

| # | BOF | Cert | Deps | Effort | Status |
|---|---|---|---|---|---|
| 1.1 | **addSpn** — add SPN to a user (LDAP write) | CRTO/OSEP | none | ◂ | ✅kit (`ldap add-spn`/`set-spn`) |
| 1.2 | **amsiEtwPatch** — patch AmsiScanBuffer + EtwEventWrite | CRTL | none | ◂ | ⬜ real gap |
| 1.3 | **printerBug** — MS-RPRN coerce auth | OSEP | none | ◂ | ⬜ low (PetitPotam covers coerce) |
| 1.4 | **netSessions** — NetSessionEnum/NetWkstaUserEnum | CRTL | none | ◂ | ⬜ partial gap |
| 1.5 | **icacls** — quick DACL/rights enum on a path (+ optional `-r N` recurse) | OSEP/CRTL | none | ◂ | ✅ (⚠️ overlaps `cacls`; keep for recursion) |

**Deliverable:** four small BOFs covering Kerberoast-enablement, AV/telemetry
evasion, a coerce primitive, and session recon — all in-process.
**Verify:** DoD 1–6 each; `addSpn` then run the existing **Kerberoast** BOF
end-to-end against a test user (dependency proves out).
**OPSEC win logged:** replaces `Set-DomainObject`, `powershell -ep`, SpoolSample,
`net session`.

## Phase 2 — Core "no-PowerShell" AD abuse (CRTO/OSEP)

| # | BOF | Cert | Deps | Effort | Status |
|---|---|---|---|---|---|
| 2.1 | **shadowCreds** — write msDS-KeyCredentialLink | CRTO/OSEP | write perm on target | ◂◂ | ✅kit (`certi shadow`) |
| 2.2 | **aclAbuse** — set password / add member / set RBCD attr (configurable action) | CRTO | write perm on target | ◂◂ | ✅kit (LDAP-BOF `add-*` set) |

**Deliverable:** the central AD-abuse toolkit replacing PowerView/Whisker.
**Verify:** DoD each; cross-check `aclAbuse action=setpwd` against `Klist`/a
fresh TGT; `shadowCreds` output → request TGT (note: full TGT-from-shadowcred
may need the Phase 5 `s4u`/Kerberos path — record as a known follow-up).
**Note:** `aclAbuse` subsumes `addSpn`; keep `addSpn` as the thin standalone
for Phase 1's Kerberoast pairing.

## Phase 3 — Credential loot + SQL trust chain (OSEP/CRTO)

| # | BOF | Cert | Deps | Effort | Status |
|---|---|---|---|---|---|
| 3.1 | **gmsaRead** — read+decrypt gMSA managed password → NT hash | CRTO | gMSA retrieval right | ◂◂ | ⬜ partial (fetch covered; derivation gap) |
| 3.2 | **lapsV2** — read+decrypt Windows LAPS encrypted password | CRTO/OSEP | read perm | ◂◂ | ✅kit (`readlaps` — verified v2+legacy) |
| 3.3 | **mssqlTrust** — ODBC connect/linked/xp_cmdshell/xp_dirtree | OSEP | valid SQL login | ◂◂ | ✅kit (MSSQL-BOF group) |

**Deliverable:** credential harvest (gMSA, LAPSv2) + the MS-SQL trust-chain
abuse path, all without `netexec`/`sqlcmd`.
**Verify:** DoD each; `gmsaRead` hash validated against a known gMSA;
`lapsV2` vs the legacy **Lapsdump** on a host that has migrated to LAPSv2;
`mssqlTrust` `xp_dirtree \\attacker\share` → catch the hash in responder.

## Phase 4 — Execution & pivot primitives (CRTL/OSEP)

| # | BOF | Cert | Deps | Effort | Status |
|---|---|---|---|---|---|
| 4.1 | **tokenImpersonate** — DuplicateTokenEx + ImpersonateLoggedOnUser | CRTL/OSEP | handle from FindProcHandle or PID | ◂ | ✅kit (`token make`/`steal`) |
| 4.2 | **injectBOF** — APC / thread-hijack / CreateRemoteThread (bytes via addArgFile) | CRTL/OSEP | PID + shellcode file | ◂◂ | ✅kit (Injection-BOF `inject-*`) |
| 4.3 | **pth** — Pass-the-Hash: make a token from an NT hash + optionally run a binary as that user (`LsaLogonUser`+`MSV1_0_LM20_LOGON`+NTLMv2; no lsass patch, CG-safe, admin-only, no SeTcb) | CRTL/OSEP | admin (SeImpersonate) + NT hash | ◂◂ | ✅ done 2026-07-23 (Extension-Kit/LateralMovement-BOF) |

**Deliverable:** in-process execution + make-token-style pivot (no `runas`/`net use`/fork&run).
**Verify:** DoD each; `tokenImpersonate` against a PID found via the existing
**FindProcHandle** (proves the FindObjects→pivot pairing); `injectBOF` against a
sacrificial `notepad` with a known-good calc/shellcode blob.
**Note:** `injectBOF` overlaps Extension-Kit/Injection-BOF — this one exists so
the Collection is self-contained; reuse techniques, don't copy the object.
**Note (pth):** built in the **Extension-Kit** home (`LateralMovement-BOF/pth/`),
not this Collection, because the loaded kit had no hash→token primitive —
`token make` and `runas-user` both take plaintext. `pth` closes that gap: NT hash →
network-logon token via `LsaLogonUser`+`MSV1_0_LM20_LOGON`+self-computed NTLMv2,
then impersonate or `CreateProcessWithTokenW`. MITRE T1550.002. Details:
`Extension-Kit/LateralMovement-BOF/pth/README.md`.

## Phase 5 — Roadmap / heavy (COM · RPC · ASN.1)

| # | BOF | Cert | Deps | Effort | Status |
|---|---|---|---|---|---|
| 5.1 | **adcsEnum** — LDAP ESC1–8 classification | OSEP | none | ◂◂ | ✅kit (`certi enum`) |
| 5.2 | **adcsRequest** — request cert from vulnerable template (COM/MS-WCCE) | OSEP | 5.1 output | ◂◂◂ | ✅kit (`certi request`) |
| 5.3 | **s4u** — S4U2self/S4U2proxy raw Kerberos | OSEP/CRTO | KerbHash keys | ◂◂◂ | ✅kit (`kerbeus s4u`/`cross_s4u`) |
| 5.4 | **dfsCoerce** — MS-DFSNM coerce auth | OSEP | none | ◂◂ | ⬜ low (PetitPotam covers coerce) |
| 5.5 | **dpapiBackup** — fetch AD backup key + decrypt masterkeys | OSEP | DA | ◂◂◂ | ⬜ real gap (heavy) |
| 5.6 | **gmsaMap** — who-can-retrieve / where-it-runs recon (could fold into ReconAD) | CRTO | none | ◂ | ⚠️ partial (low value) |

**Deliverable:** the hard, high-impact tail (ADCS RCE-from-ESC, delegation
abuse, DPAPI loot chain). Build only after Phases 1–4 are solid and load-tested.
**Why last:** COM init, RPC interface stubs, and ASN.1 Kerberos encoding are the
most likely to surface new loader/COFF gotchas — tackle them once the easy BOFs
have validated the whole pipeline and stocked `LESSONS.md`.

---

## Dependency graph

```
Phase 0 (scaffold) ──► every BOF
addSpn ─────────────► Kerberoast (existing)        [Phase 1]
aclAbuse ───────────► RBCD attr path / Kerberoast   [Phase 2]
gmsaMap ────────────► gmsaRead                      [Phase 5→3]
adcsEnum ───────────► adcsRequest                   [Phase 5]
FindProcHandle (existing) ─► tokenImpersonate       [Phase 4]
KerbHash (existing) ─► s4u                          [Phase 5]
DA / backup-key ────► dpapiBackup                   [Phase 5]
```

## Milestones / checkpoints

- **M1 — Pipeline proven:** Phase 0 + 1.1 (addSpn) done; the scaffold → build →
  audit → `.axs` → Adaptix load path works end-to-end for one new BOF.
- **M2 — Cheap set live:** Phase 1 complete (4 BOFs load-tested in Adaptix).
- **M3 — AD-abuse core:** Phase 2 complete; a full Kerberoast path that needs no
  PowerShell runs from beacon alone (addSpn → Kerberoast → crack).
- **M4 — Loot chain:** Phase 3 complete (gMSA + LAPSv2 + SQL hashes captured).
- **M5 — Full tradecraft kit:** Phases 4 + (selected) 5 complete.

## Cross-cutting rules (carry into every entry)

- Run the `bof-builder` skill for each BOF; it enforces the DoD audit gate.
- Every BOF's docstring names: cert objective, MITRE ATT&CK (or ATLAS) technique,
  the existing tool it replaces, and the OPSEC delta (which child process / log
  it eliminates). Paste command + output verbatim into exam reports.
- If a BOF proves a new universal gotcha, append to `LESSONS.md` U-section; if
  it's exam-specific, append to the per-exam section. This is the
  self-improvement loop that makes each subsequent BOF cheaper.
- Realistic scope: COM/RPC/ASN.1 BOFs (Phase 5 ✕) are genuinely hard in a COFF —
  if a lab deadline is near, prefer the Phase 1–4 BOFs and use an existing
  tool (Rubeus/certreq) for the Phase 5 technique, recording the BOF as
  "roadmap" rather than blocking on it.