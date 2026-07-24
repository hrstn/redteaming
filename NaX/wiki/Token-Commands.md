# Token Commands

NaX supports Windows access token manipulation for impersonation, privilege escalation, and lateral movement. Eight commands cover the full token lifecycle: query identity, steal tokens from processes, impersonate, create tokens from credentials, and manage the token store.

---

## Architecture

### Token Store

The beacon maintains an in-memory linked list of stolen/created tokens (`NAX_TOKEN_NODE`). Each entry holds the token handle, a numeric ID, and the resolved `DOMAIN\user` string. The store persists across heartbeats until explicitly cleared.

### Impersonation Model

When a token is activated (via `token steal` with auto-impersonate, `token use`, or `token make`), the beacon calls `ImpersonateLoggedOnUser` on its main thread. All subsequent operations (file I/O, network access, process creation) run under the impersonated identity. The Adaptix console header updates to show the impersonated user with a `*` prefix.

### Command IDs

Each token operation has its own command ID (Adaptix pattern), not a single command with sub-command dispatch:

| Command | ID | Description |
|---------|----|-------------|
| `token getuid` | `0x50` | Current identity (process or impersonated) |
| `token steal` | `0x51` | Duplicate token from a running process |
| `token use` | `0x52` | Impersonate a stored token by ID |
| `token list` | `0x53` | List all tokens in the store |
| `token rm` | `0x54` | Remove a token from the store |
| `token revert` | `0x55` | Drop impersonation, revert to process token |
| `token make` | `0x56` | Create token from credentials (LogonUserA) |
| `token privs` | `0x57` | List privileges on the current token |

---

## Commands

### token getuid

Return the current effective identity. If impersonating, returns the impersonated user; otherwise returns the process token user.

```
token getuid
```

**Result:** `DOMAIN\username` with an elevated flag (`Yes`/`No`).

**Implementation detail:** Uses `OpenThreadToken(..., OpenAsSelf=TRUE)` to avoid `ERROR_ACCESS_DENIED` when impersonating a non-admin user. Falls back to `OpenProcessToken` if no thread token exists.

### token steal

Duplicate a token from a target process and optionally impersonate it immediately.

```
token steal <pid> [impersonate]
```

| Argument | Description |
|----------|-------------|
| `pid` | Target process ID |
| `impersonate` | If present (any value), auto-impersonate the stolen token |

```
token steal 4832
token steal 4832 true
```

Opens the process with `PROCESS_QUERY_INFORMATION`, duplicates the token with `TOKEN_ALL_ACCESS`, resolves the token's user/domain via `GetTokenInformation`, and stores it. If `impersonate` is set, calls `ImpersonateLoggedOnUser` and updates the console header.

### token use

Impersonate a previously stored token by its numeric ID.

```
token use <token_id>
```

```
token use 1
token use 3
```

Looks up the token in the store, calls `ImpersonateLoggedOnUser`, and updates the console header with the token's `DOMAIN\user`.

### token list

List all tokens currently in the store.

```
token list
```

Output is a table with columns: ID, Handle, User, Domain.

### token rm

Remove a token from the store and close its handle.

```
token rm <token_id>
```

```
token rm 2
```

If the removed token was the currently impersonated one, impersonation is NOT automatically reverted -- use `token revert` separately.

### token revert

Drop impersonation and revert to the process token.

```
token revert
```

Calls `RevertToSelf()` and clears the console header's impersonation indicator.

### token make

Create a new token from plaintext credentials using `LogonUserA`. Supports multiple logon types for different use cases.

```
token make [-t <type>] <domain> <username> <password>
```

| Argument | Description |
|----------|-------------|
| `-t <type>` | Logon type (optional, default: `new_credentials`) |
| `domain` | Target domain (e.g., `CORP`, `sevenkingdoms.local`, `.` for local) |
| `username` | Account username |
| `password` | Account password |

#### Logon Types

| Type | Value | Behavior |
|------|-------|----------|
| `interactive` | 2 | Full logon. Token SID shows the actual user. Local and network access as the target user. Requires the password to be valid. |
| `network` | 3 | Network logon. Token valid for network resources only. |
| `network_cleartext` | 8 | Like network but credentials available for delegation. Useful for Kerberos double-hop. |
| `new_credentials` | 9 | (Default) Network-only credentials. Token SID remains the caller's identity locally, but network access uses the supplied credentials. Does NOT validate the password locally. |

```
token make sevenkingdoms.local cersei.lannister il0vejaime
token make -t interactive CORP admin P@ssw0rd!
token make -t network_cleartext . svc_account SecretPass
```

**Type 9 vs Type 2:** With `new_credentials` (default), `token getuid` still shows the original user because the token SID isn't changed -- only outbound network authentication uses the new credentials. Use `-t interactive` when you need the token to fully reflect the target identity.

### token privs

List all privileges on the current effective token (thread token if impersonating, process token otherwise).

```
token privs
```

Output is a table with columns: Privilege Name, Status (Enabled/Disabled).

Uses `OpenThreadToken(..., OpenAsSelf=TRUE)` like `token getuid` for the same access-check safety.

---

## Console Header

When impersonation is active, the Adaptix console header shows the impersonated identity with a `*` prefix:

```
*SEVENKINGDOMS\cersei.lannister
```

This is updated via `TsAgentUpdateDataPartial` with the `Impersonated` field. Commands that set impersonation (`token steal` with impersonate flag, `token use`, `token make`) set the header. `token revert` clears it.

---

## Wire Format

### Task (server -> beacon)

All token commands use the standard task frame: `cmdId(1) | taskId(4) | args(variable)`.

| Command | Args format |
|---------|-------------|
| `token getuid` | (none) |
| `token steal` | `pid(4LE) \| impersonate(1)` |
| `token use` | `tokenId(4LE)` |
| `token list` | (none) |
| `token rm` | `tokenId(4LE)` |
| `token revert` | (none) |
| `token make` | `logonType(4LE) \| domainLen(4LE) \| domain \| userLen(4LE) \| user \| passLen(4LE) \| pass` |
| `token privs` | (none) |

### Result (beacon -> server)

| Command | Success data |
|---------|-------------|
| `token getuid` | `userLen(4LE) \| user \| domainLen(4LE) \| domain \| elevated(1)` |
| `token steal` | `tokenId(4LE) \| userLen(4LE) \| user \| domainLen(4LE) \| domain \| impersonate(1)` |
| `token use` | `userLen(4LE) \| user \| domainLen(4LE) \| domain` |
| `token list` | `count(4LE) \| [tokenId(4LE) \| handle(8LE) \| userLen(4LE) \| user \| domainLen(4LE) \| domain] * count` |
| `token rm` | (empty) |
| `token revert` | (empty) |
| `token make` | `tokenId(4LE) \| userLen(4LE) \| user \| domainLen(4LE) \| domain` |
| `token privs` | `count(4LE) \| [nameLen(4LE) \| name \| status(4LE)] * count` |

On error (`status=0x01`), all token commands return the Win32 error code as `errorCode(4LE)` in the result data.

---

## Files

| File | Role |
|------|------|
| `src_beacon/include/Wire.h` | `NAX_CMD_TOKEN_GETUID` through `NAX_CMD_TOKEN_PRIVS` (0x50-0x57) |
| `src_beacon/include/Nax.h` | Forward declarations for all 8 `CmdToken*` functions |
| `src_beacon/src/Commands/Token.c` | Beacon-side implementations |
| `src_beacon/src/Commands/Dispatch.c` | 8 separate `case` entries routing to each handler |
| `src_server/agent_nonameax/pl_main.go` | `CMD_TOKEN_*` Go constants |
| `src_server/agent_nonameax/pl_commands.go` | Command packing (args -> wire format) |
| `src_server/agent_nonameax/pl_format.go` | Result decoders (`decodeTokenGetUidResult`, etc.) |
| `src_server/agent_nonameax/pl_results.go` | Result processing + console header updates |
| `src_server/agent_nonameax/ax_config.axs` | AxScript command registration + UI |
