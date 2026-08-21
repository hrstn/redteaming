# Get-DetectionState.ps1 — Cloud Defender characterization harness for the NaX beacon
#
# Run AS ADMIN on the Win11 + Cloud-Defender test box. Pulls every detection signal
# so we can map an exact ThreatName to each beacon/command combo. Use the -Tag param
# to label which test step produced the snapshot (e.g. -Tag "nax_ls_flat",
# "nax_ls_tree_Croot", "nax_bof_whoami", "stock_bacon_ls").
#
# Usage:
#   # 0. reset Defender history before a clean run:
#   Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats" -Recurse -Force -EA SilentlyContinue
#   Set-MpPreference -DisableRealtimeMonitoring $false   # ensure RT is ON
#   # 1. run the beacon command, then immediately:
#   powershell -ExecutionPolicy Bypass -File .\Get-DetectionState.ps1 -Tag nax_ls_tree_Croot
#
# Output: a timestamped .json + .txt next to this script under out\.

param(
    [Parameter(Mandatory=$true)]
    [string]$Tag,
    [string]$OutDir = "$PSScriptRoot\out"
)

$ErrorActionPreference = 'SilentlyContinue'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$base = Join-Path $OutDir ("$ts-$Tag")

$report = [ordered]@{
    Tag         = $Tag
    Timestamp   = (Get-Date).ToString('o')
    Computer    = $env:COMPUTERNAME
    OSBuild     = (Get-CimInstance Win32_OperatingSystem).BuildNumber
}

# --- real-time / platform status ---
$report['MpComputerStatus'] = Get-MpComputerStatus | Select-Object `
    AMRunningMode, AntivirusEnabled, AntivirusSignatureLastUpdated, `
    BehaviorMonitorEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, `
    IsTamperProtected, NISEnabled, OnAccessProtectionEnabled, `
    QuickScanEndTime, QuickScanAge, FullScanAge, AMServiceEnabled

$report['MpPreference'] = Get-MpPreference | Select-Object `
    DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection, `
    DisableScriptScanning, EnableControlledFolderAccess, AttackSurfaceReductionRules_Ids, `
    AttackSurfaceReductionRules_Actions, MAPSReporting, SubmitSamplesConsent

# --- THE LOAD-BEARING PART: threat detections with ThreatName ---
$threats = Get-MpThreatDetection
$dets = foreach ($d in $threats) {
    $t = Get-MpThreat | Where-Object { $_.ThreatID -eq $d.ThreatID }
    [ordered]@{
        ThreatName            = $t.ThreatName
        ThreatID              = $d.ThreatID
        ProcessName           = $d.ProcessName
        Resources             = $d.Resources
        InitialDetectionTime  = $d.InitialDetectionTime
        LastThreatStatusChange = $d.LastThreatStatusChange
        ThreatStatusID        = $d.ThreatStatusID   # 0=active,1=cleaned,etc
        ActionSuccess         = $d.ActionSuccess
        CleaningActionID      = $d.CleaningActionID
        CureID                = $d.CureID
    }
}
$report['ThreatDetections'] = @($dets)

# --- threat catalog hits (signature IDs that fired) ---
$report['ThreatCatalog'] = @(Get-MpThreatCatalog | Select-Object ThreatName, SeverityID, CategoryID, ThreatID)

# --- ASR / attack-surface-reduction event log (rules that blocked/audited) ---
$asr = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 200 |
    Where-Object { $_.Id -in 1121,1122,1125,1126,5007,1116,1117 } |
    Select-Object TimeCreated, Id, LevelDisplayName, @{n='Msg';e={$_.Message}}
$report['DefenderEventLog'] = @($asr)

# --- write it out ---
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath "$base.json" -Encoding utf8

# human-readable summary to console + .txt
$lines = @()
$lines += "=== Defender detection snapshot: $Tag ($($report.Timestamp)) ==="
$lines += "RT=$($report.MpComputerStatus.RealTimeProtectionEnabled)  Behavior=$($report.MpComputerStatus.BehaviorMonitorEnabled)  Build=$($report.OSBuild)"
$lines += ""
$lines += "ThreatDetections ($(@($report.ThreatDetections).Count)):"
if (@($report.ThreatDetections).Count -eq 0) {
    $lines += "  (none)"
} else {
    foreach ($d in $report.ThreatDetections) {
        $lines += "  [$($d.ThreatName)] proc=$($d.ProcessName) t=$($d.InitialDetectionTime) status=$($d.ThreatStatusID) res=$($d.Resources -join '; ')"
    }
}
$lines += ""
$lines += "Defender event log (last 200, ids 1121/1122/1125/1126/5007/1116/1117) — $(@($report.DefenderEventLog).Count) hits:"
foreach ($e in $report.DefenderEventLog) {
    $lines += "  $($e.TimeCreated) [$($e.Id)] $($e.Msg)".Substring(0, [Math]::Min(240, ("  $($e.TimeCreated) [$($e.Id)] $($e.Msg)").Length))
}
$sum = $lines -join "`r`n"
$sum | Out-File -FilePath "$base.txt" -Encoding utf8
Write-Output $sum
Write-Output ""
Write-Output "Wrote: $base.json + $base.txt"