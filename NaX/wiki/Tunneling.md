# Tunneling

NaX supports TCP tunneling through the Adaptix tunnel system: local port forwarding (lportfwd) and reverse port forwarding (rportfwd). Tunnels work on both HTTP and SMB transports.

## Data Flow

### Local Port Forward (lportfwd)

```
Operator tool -> server:lport -> Adaptix -> CONNECT_TCP task
  -> beacon connects to target:tport
  -> bidirectional relay: WRITE_TCP <-> recv each heartbeat
```

The teamserver listens on a local port. When a client connects, Adaptix sends a `CONNECT_TCP` command to the beacon with the target address and port. The beacon creates a non-blocking TCP socket, connects to the target, and relays data bidirectionally.

### Reverse Port Forward (rportfwd)

```
Adaptix -> REVERSE task -> beacon bind(127.0.0.1, port) + listen()
  -> remote client connects -> ACCEPT(tunnelId, newChannelId)
  -> Adaptix connects to operator-specified target
  -> bidirectional relay
```

The beacon binds a listening socket on loopback. When a remote client connects, the beacon accepts the connection and notifies Adaptix via an ACCEPT entry. Adaptix then connects to the operator-specified destination and starts the relay.

## Wire Protocol

Tunnel commands use CmdIds `0x3E`--`0x46`, delivered as `TASK_TYPE_PROXY_DATA` tasks. See [Wire Protocol](Wire-Protocol.md) for the full format.

Tunnel results are sent as a RESULT frame with `TaskId=0`, `Status=0x20` (STATUS_TUNNEL). The body contains concatenated entries, each prefixed with `entryLen(4LE) | cmdId(4LE)`.

## Beacon Implementation

All tunnel logic lives in `src_beacon/src/Commands/Tunnel.c`.

### NAX_TUNNEL Struct

Each tunnel channel is tracked by a `NAX_TUNNEL` node in a singly-linked list headed by `Nax->TunnelHead`:

| Field | Purpose |
|-------|---------|
| `ChannelId` | Unique channel ID assigned by the server |
| `Sock` | Winsock SOCKET handle |
| `State` | CLOSE=0, READY=1, CONNECT=2 |
| `Mode` | TCP=0, REVERSE=2 |
| `WriteBuf` / `WriteBufSize` | Pending outbound data buffer |
| `Paused` | We sent PAUSE to the server (output buffer full) |
| `SrvPaused` | Server sent PAUSE to us |

### NaxProcessTunnels Pipeline

Called once per heartbeat iteration. Four phases:

1. **Check** -- `select()` with `tv=0` (instant poll). Connecting sockets checked via writefds; on success transition to READY, on timeout or error transition to CLOSE. Reverse listeners checked via readfds; `accept()` new connections and generate ACCEPT entries.

2. **Flush** -- Attempt `send()` on READY sockets with buffered write data. If the buffer drops below LOW_WATERMARK (1MB) and we previously sent PAUSE, send RESUME.

3. **Recv** -- Read from READY sockets: up to 16 reads per socket, 4MB total output cap, 2.5-second time budget. Data is packed directly into WRITE_TCP entries in the output buffer. If total output exceeds HIGH_WATERMARK (4MB), send PAUSE to the server.

4. **Cleanup** -- Channels in CLOSE state go through a 3-tick lifecycle: mark for drain, `shutdown(SD_BOTH)`, then `closesocket()` + free + remove from list.

### Flow Control

| Threshold | Value | Action |
|-----------|-------|--------|
| HIGH_WATERMARK | 4MB | Send PAUSE to server |
| LOW_WATERMARK | 1MB | Send RESUME to server |
| HARD_CAP | 16MB | Force close the channel |

## Server Plugin

The Go plugin (`src_server/agent_nonameax/pl_tunnels.go`) implements the Adaptix `TunnelCallbacks` interface:

- **8 callback functions** build NaX wire-format task data for each tunnel operation
- **`processTunnelResult()`** parses the concatenated entry format and calls Adaptix APIs (`TsTunnelConnectionResume`, `TsTunnelConnectionData`, `TsTunnelConnectionClose`, `TsTunnelConnectionAccept`, `TsTunnelPause`, `TsTunnelResume`, `TsTunnelUpdateRportfwd`)

UDP callbacks (`ConnectUDP`, `WriteUDP`) return empty TaskData (no-op).

## Transport Differences

### HTTP Beacon

Tunnel results are sent via HTTP POST in a separate request after the heartbeat. The heartbeat loop processes tunnels every iteration.

### SMB Beacon (Linked)

Tunnel results are sent through the parent agent's named pipe via `SmbPipeWrite`. The `WaitForMultipleObjects` timeout is capped to 100ms when tunnels are active, ensuring socket polling even at sleep 0. Heartbeat frames are suppressed during tunnel-only poll wakeups to reduce pipe traffic.

The parent HTTP agent relays tunnel data alongside regular pivot traffic. After delivering tasks to the child pipe, the parent's `NaxProcessPivots` drops its read timeout from 2 seconds to 100ms after receiving the first response, keeping round-trip latency low.

## SOCKS Proxy

SOCKS4 and SOCKS5 (with optional username/password auth) are supported via the `socks start` command. The Adaptix server handles all SOCKS protocol negotiation - the beacon receives the same `CONNECT_TCP` commands used by lportfwd. No beacon-side SOCKS parsing is needed.

```
socks start [-h <address>] <port> [-socks4] [-auth <username> <password>]
socks stop <port>
```

| Argument | Description |
|----------|-------------|
| `-h <address>` | Listening interface (default: `0.0.0.0`) |
| `port` | Listen port |
| `-socks4` | Use SOCKS4 instead of SOCKS5 |
| `-auth` | Enable username/password auth (SOCKS5 only) |
| `username` | Auth username (required with `-auth`) |
| `password` | Auth password (required with `-auth`) |

UDP SOCKS5 (`CONNECT` command type 0x03) is not supported - the beacon's UDP tunnel callbacks are no-ops.

## OPSEC

- **No static ws2_32 import**: `ws2_32.dll` is loaded lazily via PEB walk + `LoadLibraryW` on the first tunnel command. The PE import table has no winsock dependency.
- **Loopback-only rportfwd**: `bind()` uses `127.0.0.1`, not `0.0.0.0`. Binding all interfaces is an EDR detection vector.
- **Non-blocking I/O**: All sockets use `ioctlsocket(FIONBIO, 1)`. No socket operation blocks the heartbeat.
- **Short timeouts**: `SO_RCVTIMEO` and `SO_SNDTIMEO` set to 100ms.
- **Graceful shutdown**: `shutdown(SD_BOTH)` before `closesocket()` with a 1-second drain period.

## Files

| File | Role |
|------|------|
| `src_beacon/src/Commands/Tunnel.c` | Beacon tunnel implementation (connect, write, recv, close, reverse, flow control) |
| `src_beacon/include/Instance.h` | NAX_WS2, NAX_TUNNEL structs |
| `src_beacon/include/Wire.h` | Tunnel command IDs (0x3E--0x46) |
| `src_beacon/include/Macros.h` | FNV1a hashes for ws2_32 APIs |
| `src_beacon/src/Main.c` | HTTP heartbeat tunnel processing block |
| `src_beacon/src/Transport/Smb.c` | SMB tunnel processing + WFMO timeout cap |
| `src_beacon/src/Commands/Pivot.c` | Adaptive pivot read timeout (fast after first response) |
| `src_server/agent_nonameax/pl_tunnels.go` | Go TunnelCallbacks + result parser |
| `src_server/agent_nonameax/pl_main.go` | Wires TunnelCallbacks into Adaptix |
| `src_server/agent_nonameax/pl_results.go` | Routes STATUS_TUNNEL results to processTunnelResult |
| `src_server/listener_nonameax_http/pl_http.go` | POST response no longer delivers tasks (prevents task loss) |
