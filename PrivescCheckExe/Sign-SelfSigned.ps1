<#
.SYNOPSIS
  Creates a self-signed code-signing certificate and signs HostAudit.exe.
  A self-signature does NOT make the binary trusted by Windows / Defender,
  but it removes the "Unknown publisher" / unsigned heuristic and gives the
  binary a stable identity, which can reduce some confidence-based detections.

  For a real assessment, sign with your engagement's org certificate.

.NOTES
  Run from an elevated prompt. Requires signtool.exe (Windows SDK).
#>
param(
    [string]$Exe = (Join-Path $PSScriptRoot "publish\HostAudit.exe"),
    [string]$Subject = "HostAudit Engagement Signing"
)

$ErrorActionPreference = "Stop"

# 1. Create the self-signed code-signing cert in the current user store.
$existing = Get-ChildItem "Cert:\CurrentUser\My" -CodeSigningCert -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -eq "CN=$Subject" } | Select-Object -First 1

$cert = $existing
if (-not $cert) {
    Write-Host "Creating self-signed code-signing certificate..." -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=$Subject" `
        -KeyUsage DigitalSignature `
        -FriendlyName $Subject `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA -KeyLength 4096 `
        -NotAfter (Get-Date).AddYears(3)
}

# 2. Add it to the Trusted Root + Trusted People stores so the signature
#    is considered valid on this build host (does NOT propagate to targets).
foreach ($store in @("Root","TrustedPeople")) {
    $path = "Cert:\LocalMachine\$store"
    if (-not (Get-ChildItem $path -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
        $storeObj = [System.Security.Cryptography.X509Certificates.X509Store]::new($store, "LocalMachine")
        $storeObj.Open("ReadWrite")
        $storeObj.Add($cert)
        $storeObj.Close()
    }
}

# 3. Locate signtool.exe
$signtool = @(
    "$env:WINDIR\System32\signtool.exe",
    (Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1).FullName,
    (Get-ChildItem "$env:ProgramFiles\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1).FullName
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if (-not $signtool) {
    Write-Warning "signtool.exe not found (install Windows SDK 'ClickOnce' feature). The certificate was created; sign manually later."
    return
}

if (-not (Test-Path $Exe)) {
    Write-Error "Target not found: $Exe"
}

Write-Host "Signing $Exe with $Subject ..." -ForegroundColor Cyan
& $signtool sign /fd SHA256 /f "Cert:\CurrentUser\My\$($cert.Thumbprint)" $Exe
& $signtool verify /pa $Exe
Write-Host "Done." -ForegroundColor Green