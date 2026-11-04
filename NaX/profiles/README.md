# NaX profiles

Malleable-C2 profile material for the HTTP lane (Paste into the listener
`profile_json` field → **rebuild the payload** so the baked beacon profile
matches: `pl_build_payload.go` re-parses this same JSON at build time).

> The OPSEC profile generator now lives in its own project:
> [`../profiler/`](../profiler/) (`gen_profile.py`, personas `graph` / `onedrive`,
> built-in beacon-cap validator). The JSON hand templates below remain for
> reference/adaptation.

## Files

| File | What |
|---|---|
| `../profiler/gen_profile.py` | **OPSEC profile generator** (own project now — `graph` / `onedrive` personas + validator) |
| `ms365-graph.json` | Hand-written M365 Graph example (legacy template) |
| `aws-cloudfront.json` | CloudFront/S3-style static template |
| `jquery-stealth.json` | jQuery CDN-style template |

## Generator

```bash
python3 ../profiler/gen_profile.py --persona graph    --host 203.0.113.7:443 --ssl --out /tmp/graph.json
python3 ../profiler/gen_profile.py --persona onedrive --host cdn.example.com --ssl --out /tmp/od.json
```

The generator enforces the beacon's hard parser caps and rejects brand
strings / generic-404 patterns — the full contract table lives in
[`../profiler/README.md`](../profiler/README.md).

What it enforces (from the beacon's hard parser caps,
`src_beacon/src/Core/PackerProfile.c` + `src_server/agent_nonameax/pl_wire.go`):

- hosts ≤ 4 (≤127 chars), URIs ≤ 8/direction (≤127 chars, no baked `?query`),
- client headers ≤ 8/direction (≤255 chars), parameters ≤ 8 (≤127),
- user_agent ≤ 255, metadata `name` ≤ 127,
- `prepend`/`append`/`empty_resp` ≤ 480 B (beacon truncates at 511 — an
  oversized envelope silently corrupts the frame),
- `format` ∈ `raw|base64|base64url|hex`, `placement` ∈ `body|header|cookie|parameter`,
- no brand/tool strings anywhere in values (`/nax`, `nonameax`, `submit.php`, …),
- non-generic `server_error` (persona-realistic 403 / 429 bodies instead of a
  default 404 page),
- `rotation: random` and persona-native `beacon_id_header` (e.g.
  `X-MS-Correlation-Id`), `mask: true` on all metadata/output encodings.

Warnings vs errors: caps/format/placement/brand-strings are hard errors; low
URI diversity and missing `empty_resp` are warnings. Exit code 1 on errors.

## Persona notes

- **graph**: Chrome/Edge UA pinned to a plausible stable build; OData-shaped
  envelopes (`@odata.context`), Graph `Authorization_RequestDenied` 403 with
  `innerError{date,request-id,client-request-id}` per the official Graph error
  spec; `client-request-id`/`Return-Client-Request-Id`/`Sec-Fetch-*` request
  headers.
- **onedrive**: OneDrive sync-client UA (`Microsoft OneDrive 25.x.y.z`),
  sync-shaped JSON (`@odata.deltaLink`, uploadSession), `429 activityLimitReached`
  + `Retry-After` error response.

## Operational notes

- The beacon gets the profile twice: baked at build (`NAX_PROFILE_WRITE`) and
  refreshed on the wire (`PROFILE` frame after REGISTER). Import the same file
  for both; renaming URIs in a template is only consistent if both sides use it.
- Keep at least one `empty_resp` per direction: a zero-length "no tasks" body is
  itself a beacon fingerprint.
- `mask: true` randomizes the encoding so wire bytes don't sit as clean base64
  blobs of binary — recommended everywhere, validator warns otherwise.
- Rotating: regenerate with a new `client-request-id`-equivalent UUID every N
  beacon rebuilds (the generator randomizes per run).