# RUNBOOK — portfolio operations

Operator notes for running the full chain, in order, with the gates that must
pass at each step. Per-tool usage lives in each tool's README; the detailed
per-tool detection-surface audit and the remediation plan are internal notes
kept out of the repo (never committed). If a fresh clone references one, it is
stale documentation — the audit trail lives in the operator's local notes.

---

## 0. Daily hygiene gates

```bash
make audit               # opsec merge gate — must be exit 0 before any push/build
make history             # full git-history secret sweep — run before releases
python3 tools/coff_manifest.py --check       # COFF integrity vs committed manifest
```

If `--check` fails: a COFF drifted — rebuild the suite from source and confirm
the drift is a rebuild artifact (`--check --write` to re-baseline), or treat as
tampering.

Before any payload build: regenerate session parameters — never reuse old
AES keys, profile UUIDs, or listener certs across engagements (`profiler/`
randomizes per run; NaX payload build regenerates the key per build).

---

## 1. Comms setup

1. **Profile** — `python3 profiler/gen_profile.py --persona graph|onedrive
   --host <listener>[:port] --ssl --out out/<name>.json`
   - validator must exit 0 (beacon-cap violations hard-fail)
   - paste into listener `profile_json` field (or ax import)
2. **Listener** — `NoNameAxHTTP`, TLS on; real leaf certificate on the
   redirector (self-signed acceptance is a lab-only mode)
3. **Payload build** — NaX build dialog: sleep 30-60s, jitter ≥ 20
   (empty jitter field now defaults to 20), kill-date **set to op end + 48h**
   (never blank on a live op), profile = same JSON as step 1
4. Verify the built blob at rest: release build (never debug), strings sweep
   clean (`Cenotaph/Makefile` audit pattern applies to any built artifact)

---

## 2. Delivery

| Path | Tool | When |
|---|---|---|
| Native dropper (embed/fetch) | `hostpayload_v2/pack.py` | primary; fetch mode for staging |
| ISO/LNK wrapper | `hostpayload_v2/delivery/iso_lnk.py` | email/portal delivery |
| HTA/VBA | `hostpayload_v2/delivery/{hta,vba}.py` | only where ISO/LNK is filtered; HTA/VBA are the most-scan'd wrappers — last resort |
| Disk-host fallback | `Cenotaph` + encrypted `.dat` | when no C2 fetch is possible |
| In-memory toolchain | `RemoteLoader` (token via `RL_GH_TOKEN` env), `remote_bof_loader` | post-foothold |

Delivery gates (per tool README): `validate.py` pass on the built dropper,
benign-payload VM run, no `.ps1`-cradle paths in the final flow.

---

## 3. Foothold → sessions

- Beacon first actions: `persist-inventory` BEFORE installing any persistence,
  so the inventory snapshot is the baseline.
- Credential ops: quiet paths first (`pth`, `lsadump`, `nanodump` seclogon
  modes, Kerbeus); cross-process sweeps (`cookie-monster` mass mode,
  `credsMem -loud`) are announced-only: the framework-attribution behavior
  verdict comes from that volume (see audit §1.2.3 — validated).
- Exec: `No-Consolation` for .NET; BOFs from all suites via the kit;
  `inject-poolparty` over every other injector.
- Capture (`clipmon`/`keylog`): short windows, own-process only; never pair
  with unattended persistence.

---

## 4. Persistence (if required)

Suite: `Extension-Kit/Persistence-BOF` — the rule is **install → verify → use →
clear → verify**, in-session:

```text
wmi-sub <name> <cmd>       # then:  persist-inventory   (see the new entry)
... use ...
wmi-clear <name>           # then:  persist-inventory   (must show zero)
```

Same pair for `task-create`/`task-delete` (note the per-run suffix in the
task-create output — the delete needs the full name with suffix),
`runkey`, `comhijack`.

- Leave nothing installed across sessions unless the op plan explicitly
  carries it (and then: kill-date on the beacon + documented in the op log).
- The inventory also catches artifacts from *other* tool paths
  (nanodump WER/IFEO leftovers, non-C:\Windows services, stale Run values).

---

## 5. Tooling boundaries

- Restricted-use tools (never on default profiles): `BOFKatz` (kept as-is,
  accepted risk — see README), WdToggle, PetitPotam RDLL until rebuilt,
  `execute-assembly` (byte-patch; prefer No-Consolation), `inject-32to64`,
  DCOMPotato (account creation).
- Retired and gated in the README: `hostpayload/` (v1), `NaX/src_loader/`.

---

## 6. Burn response

When a build/technique gets flagged:

1. Kill beacons: they self-expire at kill-date; `sleep 1 0` + task the exit
   where needed (`exit` kills process).
2. Revoke infrastructure: drop the listener cert (the cert chain is burned
   with the verdict), retire used URIs/persona (regenerate the profile with
   fresh UUIDs — `profiler` does per-run), new callback host.
3. Rotate: AES keys (rebuild), profile persona if the shape was captured,
   UA/version ranges in `profiler` if UA was flagged.
4. Update the audit doc: which tool/technique was flagged, the verdict string,
   and the replacement plan — the portfolio memory is the point of the doc.
5. Re-run `make audit` before the next build; treat any burned binary as
   unreusable (never re-obfuscate a flagged build).

---

## 7. Not verified / open experiments

- H4 (tree `ls` depth-16) and H6 (`Start-MpScan` at rest) from
  `NaX/tests/defender/METHODOLOGY.md` — run before the next live engagement.
- New suites' artifacts (`Persistence-BOF`, `Capture-BOF`) have not been run
  against a full EDR set yet — the expected event maps are in their READMEs;
  validate in the lab VM and record verdicts in the audit doc.