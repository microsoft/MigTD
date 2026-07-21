<#
.SYNOPSIS
  Run one TDX LM repro and capture timestamp-bounded Hyper-V diagnostics.

.EXAMPLE
  .\Invoke-TdxLmDiagnosticCapture.ps1 -OutputDir .\diag -EnableAnalytic `
      -SerialLogPath .\tipmigtd.serial.log `
      -ReproCommand { .\Invoke-TdxLmLoopback.ps1 ... -CaptureSerial }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [scriptblock]$ReproCommand,
    [Parameter(Mandatory)] [string]$OutputDir,
    [string[]]$SerialLogPath,
    [switch]$EnableAnalytic,
    [switch]$CaptureEtw,
    [string]$WprProfilePath = (Join-Path $PSScriptRoot 'TdxLmTraceProfile.wprp')
)

$ErrorActionPreference = 'Stop'
$channels = @(
    'Microsoft-Windows-Hyper-V-VMMS-Admin',
    'Microsoft-Windows-Hyper-V-VMMS-Operational',
    'Microsoft-Windows-Hyper-V-Worker-Admin',
    'Microsoft-Windows-Hyper-V-Worker-Operational'
)
$analyticChannels = @(
    'Microsoft-Windows-Hyper-V-VMMS-Analytic',
    'Microsoft-Windows-Hyper-V-Worker-Analytic'
)
$changedChannels = [System.Collections.Generic.List[string]]::new()

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path $OutputDir).Path
$start = Get-Date
$reproError = $null
$wprStarted = $false

Get-Process -Name igvmagent -ErrorAction SilentlyContinue |
    Select-Object Id, ProcessName, Path, StartTime, Responding |
    Format-List |
    Out-File (Join-Path $OutputDir 'igvmagent-before.txt')

try {
    if ($EnableAnalytic) {
        foreach ($channel in $analyticChannels) {
            $log = Get-WinEvent -ListLog $channel -ErrorAction Stop
            if (-not $log.IsEnabled) {
                & wevtutil.exe sl $channel /e:true
                if ($LASTEXITCODE -ne 0) {
                    throw "Failed to enable event channel: $channel"
                }
                $changedChannels.Add($channel)
            }
        }
        $channels += $analyticChannels
    }

    if ($CaptureEtw) {
        if (-not (Test-Path $WprProfilePath)) {
            throw "WPR profile not found: $WprProfilePath"
        }
        $WprProfilePath = (Resolve-Path $WprProfilePath).Path
        & wpr.exe -start "$WprProfilePath!TdxLm" -filemode
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to start WPR capture. Stop any existing WPR session and run from elevated PowerShell."
        }
        $wprStarted = $true
    }

    try {
        & $ReproCommand *>&1 | Tee-Object -FilePath (Join-Path $OutputDir 'repro-console.txt')
    } catch {
        $reproError = $_
        $_ | Format-List * -Force | Out-File (Join-Path $OutputDir 'repro-error.txt')
    }
} finally {
    $end = Get-Date

    if ($wprStarted) {
        $etlPath = Join-Path $OutputDir 'tdxlm.etl'
        & wpr.exe -stop $etlPath
        if ($LASTEXITCODE -ne 0) {
            & wpr.exe -cancel | Out-Null
            Write-Warning "Failed to stop WPR capture cleanly; tdxlm.etl may be incomplete."
        }
    }

    # Analytic/direct channels must be read oldest-first and are most reliably
    # readable after capture stops. Only disable channels this script enabled,
    # preserving any channel that was already enabled by the operator.
    foreach ($channel in $changedChannels) {
        & wevtutil.exe sl $channel /e:false
    }

    foreach ($channel in $channels) {
        $safeName = $channel -replace '[^A-Za-z0-9.-]', '_'
        $filter = @{
                LogName = $channel
                StartTime = $start.AddSeconds(-2)
                EndTime = $end.AddSeconds(2)
        }
        if ($analyticChannels -contains $channel) {
            $events = @(Get-WinEvent -FilterHashtable $filter -Oldest -ErrorAction SilentlyContinue)
        } else {
            $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
        }
        $events |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
            Export-Clixml (Join-Path $OutputDir "$safeName.clixml")
        $events |
            Format-List TimeCreated, Id, LevelDisplayName, ProviderName, Message |
            Out-File (Join-Path $OutputDir "$safeName.txt")
    }

    foreach ($logPath in $SerialLogPath) {
        if ($logPath -and (Test-Path $logPath)) {
            Copy-Item $logPath (Join-Path $OutputDir (Split-Path $logPath -Leaf)) -Force
        }
    }

    Get-Process -Name igvmagent -ErrorAction SilentlyContinue |
        Select-Object Id, ProcessName, Path, StartTime, Responding |
        Format-List |
        Out-File (Join-Path $OutputDir 'igvmagent-after.txt')
}

$allText = Get-ChildItem $OutputDir -Filter '*.txt' |
    Where-Object Name -ne 'summary.txt' |
    Get-Content
$summary = [System.Collections.Generic.List[string]]::new()
$summary.Add("Capture start: $start")
$summary.Add("Capture end:   $end")

if ($allText -match 'tdxprotocol\.cpp\(\d+\)') {
    $summary.Add('Boundary: VidTdxBind failed before MigTD approval.')
}
if ($allText -match '(?i)C0350071|0xC0350071') {
    $summary.Add('Status 0xC0350071: ERROR_HV_OPERATION_FAILED (generic); inspect tdxlm.etl for the lower-level bind reason.')
}
if ($allText -match 'Failed to receive compatibility info') {
    $summary.Add('VMMS: failed to receive compatibility info; inspect Worker events for the first error.')
}
if ($allText -match '(?i)20960|TDX LM approval failed') {
    $summary.Add('MigTD approval path was reached; inspect event 20960 reason/details.')
}
if ($allText -match '(?i)20999|not yet fully implemented') {
    $summary.Add('Host reported the TDX LM path as not fully implemented.')
}
$startVtl0TimedOut = (($allText -match 'StartVtl0') -and ($allText -match '(?i)800704C7|operation was canceled'))
if ($startVtl0TimedOut) {
    $summary.Add('Boundary: management VTL did not signal VTL0 readiness before the 60-second worker timeout.')
}
if ($startVtl0TimedOut -and ($allText -match '(?im)^ProcessName\s*:\s*igvmagent')) {
    $summary.Add('IGVMAgent was running during the StartVtl0 timeout. Verify that its RPC endpoint responds promptly, or use -NoPersistentSecrets to bypass target-VM attestation.')
}
if (($allText -match '(?i)get quote request failed') -and ($allText -match '(?i)80072F78')) {
    $summary.Add('MigTD GetQuote reached IGVMAgent, but the response failed V2 validation with WININET_E_INVALID_SERVER_RESPONSE (0x80072F78). Check that the agent binary matches the host build and supports GetQuote V2.')
}

$summary | Set-Content (Join-Path $OutputDir 'summary.txt')
$summary | ForEach-Object { Write-Host $_ }
Write-Host "Diagnostic bundle: $OutputDir"

if ($reproError) {
    throw $reproError
}
