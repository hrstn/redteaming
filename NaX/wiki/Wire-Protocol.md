# Wire Protocol

Binary framed protocol. All frames are AES-128-CBC encrypted before transmission, then passed through the malleable C2 profile's encoding pipeline.

## Frame Format

```
+----------+----------+--------------+------------------+
| Type (1) | Flags (1)| BodyLen (4LE)| Body (variable)  |
+----------+----------+--------------+------------------+
<---------- 6-byte header ---------->
```

## Message Types

| Type | Value | Direction | Purpose |
|------|-------|-----------|---------|
| REGISTER | `0x01` | beacon -> server | First contact with sysinfo payload |
| HEARTBEAT | `0x02` | beacon -> server | Periodic check-in |
| RESULT | `0x03` | beacon -> server | Command output |
| NO_TASKS | `0x80` | server -> beacon | Nothing queued |
| TASK | `0x81` | server -> beacon | Command to execute |
| PROFILE | `0x82` | server -> beacon | Malleable C2 profile update |

## Command IDs

| Command | ID | Description |
|---------|------|-------------|
| `whoami` | `0x10` | Current Windows identity (domain\user) |
| `sleep` | `0x11` | Set callback interval and jitter % |
| `terminate thread` | `0x12` | Exit beacon thread (`RtlExitUserThread`) |
| `terminate process` | `0x13` | Kill beacon process (`ExitProcess`) |
| `cd` | `0x14` | Change working directory |
| `pwd` | `0x15` | Print working directory |
| `mkdir` | `0x16` | Create directory |
| `rmdir` | `0x17` | Remove directory |
| `cat` | `0x18` | Read file contents |
| `ls` | `0x19` | List directory (table or recursive tree) |
| `cp` | `0x1A` | Copy a file |
| `mv` | `0x1B` | Move or rename a file |
| `bof` | `0x20` | Execute BOF (in-process COFF loader) |
| `screenshot` | `0x21` | GDI desktop capture |
| `download` | `0x22` | Download file from target to operator |
| `ps list` | `0x23` | Process list with tree view |
| `ps kill` | `0x24` | Terminate process by PID |
| `ps run` | `0x25` | Run program (`-s` suspend, `-o` capture output) |
| `upload` | `0x26` | Upload file from operator to target |
| `rm` | `0x27` | Delete a file |
| `savememory` | `0x2A` | Accumulate upload data chunks in memory |
| `chunksize` | `0x2B` | Set download chunk size |
| `watchdog` | `0x2C` | Toggle the async job watchdog |
| `profile` | `0x30` | Update malleable C2 profile at runtime |
| `bof-stomp` | `0x31` | Reconfigure BOF module stomping DLLs |
| `sleepmask-set` | `0x32` | Rebuild + hot-load the sleepmask BOF |
| `sleepobf-config` | `0x33` | Toggle sleep obfuscation |
| `link smb` | `0x38` | Connect to child beacon's SMB pipe |
| `unlink` | `0x39` | Disconnect a linked child beacon |
| `dll-notify list` | `0x3A` | List DLL load notification callbacks |
| `dll-notify remove` | `0x3B` | Remove DLL load notification callbacks |
| `shell start` | `0x47` | Start remote shell (program path) |
| `shell write` | `0x48` | Write input to a remote shell |
| `shell close` | `0x49` | Close a remote shell |

### Token Commands (0x50--0x57)

Each token operation has its own command ID -- no sub-command dispatch byte.

| Command | ID | Description |
|---------|------|-------------|
| `token getuid` | `0x50` | Current effective identity (process or impersonated) |
| `token steal` | `0x51` | Duplicate token from a running process |
| `token use` | `0x52` | Impersonate a stored token by ID |
| `token list` | `0x53` | List all tokens in the store |
| `token rm` | `0x54` | Remove a token from the store |
| `token revert` | `0x55` | Drop impersonation, revert to process token |
| `token make` | `0x56` | Create token from credentials (`LogonUserA`) |
| `token privs` | `0x57` | List privileges on the current token |

See [Token Commands](Token-Commands.md) for full wire format details (args and result layouts).

### Tunnel Commands (0x3E--0x46)

Tunnel commands are delivered as `TASK_TYPE_PROXY_DATA` tasks. Results are batched per heartbeat and sent as a RESULT frame with `TaskId=0`, `Status=0x20` (STATUS_TUNNEL).

| Command | ID | Direction | Args format |
|---------|----|-----------|-------------|
| CONNECT_TCP | `0x3E` | server -> beacon | channelId(4) \| type(4) \| addrLen(4) \| addr \| port(4) |
| CONNECT_UDP | `0x3F` | server -> beacon | (reserved, no-op) |
| WRITE_TCP | `0x40` | server -> beacon | channelId(4) \| dataLen(4) \| data |
| WRITE_UDP | `0x41` | server -> beacon | (reserved, no-op) |
| CLOSE | `0x42` | both | channelId(4) |
| REVERSE | `0x43` | server -> beacon | tunnelId(4) \| port(4) |
| ACCEPT | `0x44` | beacon -> server | tunnelId(4) \| newChannelId(4) |
| PAUSE | `0x45` | both | channelId(4) |
| RESUME | `0x46` | both | channelId(4) |

### Tunnel Result Body

Tunnel results use a concatenated entry format inside a single RESULT frame:

```
+---------------+-------------+---------------------------+
| entryLen (4LE)| cmdId (4LE) | cmd-specific payload      |
+---------------+-------------+---------------------------+
| ...next entry...                                        |
```

| Cmd | Response payload |
|-----|------------------|
| CONNECT_TCP | channelId(4) \| type(4) \| result(4) -- result=0 success |
| WRITE_TCP | channelId(4) \| dataLen(4) \| data |
| CLOSE | channelId(4) \| type(4) \| result(4) |
| REVERSE | tunnelId(4) \| type(4) \| result(4) -- result!=0 success |
| ACCEPT | tunnelId(4) \| newChannelId(4) |
| PAUSE | channelId(4) |
| RESUME | channelId(4) |

## TASK Frame Body

```
+--------------+-----------+------------------+------------------+
| TaskId (4LE) | CmdId (1) | ArgsLen (4LE)    | Args (variable)  |
+--------------+-----------+------------------+------------------+
```

`TaskId` is a random 32-bit integer assigned by the server. The beacon includes it in the RESULT frame so the server can match results to tasks. `ArgsLen` is a 4-byte little-endian length prefix for the arguments that follow.

## RESULT Frame Body

```
+--------------+------------+-----------------+------------------+
| TaskId (4LE) | Status (1) | DataLen (4LE)   | Data (variable)  |
+--------------+------------+-----------------+------------------+
```

`Status` is `0x00` for success, non-zero for errors. `DataLen` is a 4-byte little-endian length prefix for the output that follows. The output format depends on the command - most return UTF-8 text, some return structured binary (screenshots, downloads, BOF media).

## Commands with Flags Byte

`rm` (`0x27`), `rmdir` (`0x17`), and `ls` (`0x19`) use a flags byte as the first byte of args:

```
flags(1) | path(variable)
```

| Bit | Command | Meaning |
|-----|---------|---------|
| `0x01` | `rm`, `rmdir` | Recursive force delete (`-rf`) |
| `0x01` | `ls` | Recursive tree listing (`-r`) |

When `path` is empty (flags byte only, `argsLen=1`), the command targets the current working directory.

### ls Result Formats

The `ls` result uses two formats, distinguished by the first byte:

**Normal listing** (first byte != `0xFF`):

```
pathLen(2LE) | path | count(2LE) | entries[]
```

Each entry: `isDir(1) | attrs(1) | size(4LE) | mtime(4LE) | nameLen(1) | name`

**Recursive tree** (first byte == `0xFF`):

```
0xFF | tree_text_utf8
```

The tree text is pre-rendered with Unicode box-drawing characters (`├─`, `└─`, `│`) and newlines. The server displays it as plain text.

## Encryption

All frames are encrypted with AES-128-CBC using the shared key configured at build time. The IV is prepended to the ciphertext (16 bytes). The server and beacon use the same key; the listener plugin handles encryption/decryption transparently.
