# profiler — OPSEC agent-interaction profile generator

Standalone profile tool for the red-team toolchain. Generates paste-ready
**NaX v2 profile JSON** ("callbacks" schema — see `NaX/src_server/agent_nonameax/pl_profile.go`
/ `NaX/src_server/listener_nonameax_http/pl_http_profile.go`) with realistic
per-persona request/response shapes instead of generic 404 pages.

Kept out of the NaX tree deliberately: the generator is shared comms hygiene
(beacon traffic, dropper fetch URLs, future redirector/TLS configs), and its
identity should not be coupled to any one C2 frame.

## Usage

```bash
python3 gen_profile.py --persona graph    --host 203.0.113.7:443 --ssl --out out/graph.json
python3 gen_profile.py --persona onedrive --host cdn.example.com --ssl --out out/od.json
```

(see `gen_profile.py --help`; generated output goes to `out/`, git-ignored)

## What it enforces (NaX beacon contract)

The validator encodes the beacon's **hard parser caps** — the source of truth is
the beacon profile decoder and wire encoder; if either changes, update the cap
table in `gen_profile.py`:

| Contract (source) | Limit |
|---|---|
| `NaX/src_beacon/src/Core/PackerProfile.c` | hosts ≤ 4 (≤127 ch), URIs ≤ 8/dir (≤127 ch, no baked `?query`), client headers ≤ 8/dir (≤255), params ≤ 8 (≤127), UA ≤ 255, meta `name` ≤ 127, `prepend`/`append`/`empty_resp` ≤ 511 B — **truncated**, not rejected |
| `NaX/src_server/agent_nonameax/pl_wire.go` | `format` ∈ `raw\|base64\|base64url\|hex`, `placement` ∈ `body\|header\|cookie\|parameter`, mask = bool |
| Generator policy (hard-fail) | envelopes capped 480 B for truncation head-room; brand/tool strings rejected; persona-native `beacon_id_header` (not `X-Beacon-Id`); non-generic `server_error` (realistic 403/429 bodies); `rotation: random`; `mask: true` on metadata (warns) |
| Generator policy (warns) | <3 URIs/direction, missing `empty_resp` |

## Personas

- **graph** — Microsoft Graph API client (Chrome/Edge UA pinned to a plausible
  stable build; OData `@odata.context` envelopes; Graph-spec
  `Authorization_RequestDenied` 403 with `innerError{date,request-id,
  client-request-id}`; `client-request-id`/`Sec-Fetch-*` headers;
  `X-MS-Correlation-Id` beacon header).
- **onedrive** — OneDrive sync client (`Microsoft OneDrive 25.x.y.z` UA;
  sync-shaped JSON `@odata.deltaLink`/uploadSession; `429 activityLimitReached`
  + `Retry-After`; `X-Ms-Client-Request-Id` beacon header).

## Operational notes

- The beacon gets the profile twice: baked at build (`NAX_PROFILE_WRITE`, via
  `pl_build_payload.go` → `parseProfileFromListenerConfig`) and refreshed on the
  wire (`PROFILE` frame after REGISTER). Import the same generated file into the
  listener `profile_json` field **and** use it for the payload build — renaming
  URIs between the two breaks the lane.
- Keep `empty_resp` on every direction: a zero-length "no tasks" body is itself
  a beacon fingerprint.
- Regenerate per build cycle (UUIDs/versions randomize per run).
- Extension path (not yet implemented): second emitter backend for other C2
  wire formats; redirector/fronting provider configs; TLS pin-list output.

## Layout

```
profiler/
  gen_profile.py   personas + NaX v2 emitter + validator (single-file CLI)
  out/             generated profiles (git-ignored)
```