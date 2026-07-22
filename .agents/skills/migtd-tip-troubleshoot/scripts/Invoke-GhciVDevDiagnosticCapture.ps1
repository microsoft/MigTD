<#
.SYNOPSIS
  Capture Microsoft.Windows.HyperV.GhciVDev ETW events around one repro.

.EXAMPLE
  .\Invoke-GhciVDevDiagnosticCapture.ps1 -OutputDir .\diag-ghci `
      -ReproCommand { .\Test-TdxLmRebind.ps1 ... }
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [scriptblock]$ReproCommand,
    [Parameter(Mandatory)] [string]$OutputDir,
    [string]$WprProfilePath = (Join-Path $PSScriptRoot 'TdxLmTraceProfile.wprp'),
    [string]$ExporterPath = (Join-Path $PSScriptRoot 'Export-GhciVDevEvents.ps1')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $WprProfilePath -PathType Leaf)) {
    throw "WPR profile not found: $WprProfilePath"
}
if (-not (Test-Path -LiteralPath $ExporterPath -PathType Leaf)) {
    throw "GHCI VDev exporter not found: $ExporterPath"
}
$WprProfilePath = (Resolve-Path -LiteralPath $WprProfilePath).Path
$ExporterPath = (Resolve-Path -LiteralPath $ExporterPath).Path

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

$etlPath = Join-Path $OutputDir 'ghcivdev.etl'
$reproError = $null
$wprStarted = $false
$traceStopped = $false
$start = Get-Date

try {
    & logman.exe query providers 'Microsoft.Windows.HyperV.GhciVDev' *>&1 |
        Out-File -LiteralPath (Join-Path $OutputDir 'provider-before.txt')

    & wpr.exe -start "$WprProfilePath!GhciVDev" -filemode
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start GHCI VDev WPR capture. Stop any existing WPR session and run from elevated PowerShell."
    }
    $wprStarted = $true

    try {
        & $ReproCommand *>&1 |
            Tee-Object -FilePath (Join-Path $OutputDir 'repro-console.txt')
    }
    catch {
        $reproError = $_
        $_ | Format-List * -Force |
            Out-File -LiteralPath (Join-Path $OutputDir 'repro-error.txt')
    }
}
finally {
    $end = Get-Date
    if ($wprStarted) {
        & wpr.exe -stop $etlPath
        if ($LASTEXITCODE -eq 0) {
            $traceStopped = $true
        }
        else {
            & wpr.exe -cancel | Out-Null
            Write-Warning "Failed to stop WPR capture cleanly; $etlPath may be incomplete."
        }
    }

    @(
        "Capture start: $start"
        "Capture end:   $end"
        'Provider:      Microsoft.Windows.HyperV.GhciVDev'
        'Provider GUID: AEFC8638-19A2-553A-06CB-C3984FFC7EE8'
    ) | Set-Content -LiteralPath (Join-Path $OutputDir 'capture.txt')
}

if ($traceStopped) {
    & $ExporterPath -EtlPath $etlPath -OutputDir (Join-Path $OutputDir 'events')
}

Write-Host "GHCI VDev diagnostic bundle: $OutputDir"
if ($reproError) {
    throw $reproError
}
