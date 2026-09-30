<#
.SYNOPSIS
  Export Microsoft.Windows.HyperV.GhciVDev events from an ETL trace.

.DESCRIPTION
  Creates raw tracerpt CSV/XML output and, when Get-WinEvent can decode the
  ETL, provider-filtered CLIXML and text files. The GHCI VDev provider GUID is
  AEFC8638-19A2-553A-06CB-C3984FFC7EE8.

.EXAMPLE
  .\Export-GhciVDevEvents.ps1 -EtlPath .\ghcivdev.etl
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$EtlPath,
    [string]$OutputDir,
    [string]$ProviderName = 'Microsoft.Windows.HyperV.GhciVDev',
    [string]$ProviderGuid = 'AEFC8638-19A2-553A-06CB-C3984FFC7EE8'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $EtlPath -PathType Leaf)) {
    throw "ETL file not found: $EtlPath"
}
$EtlPath = (Resolve-Path -LiteralPath $EtlPath).Path

if (-not $OutputDir) {
    $OutputDir = Join-Path (Split-Path -Parent $EtlPath) 'ghcivdev-events'
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

$providerQueryPath = Join-Path $OutputDir 'provider-query.txt'
$providerQuery = [System.Collections.Generic.List[string]]::new()
foreach ($provider in @($ProviderName, "{$ProviderGuid}")) {
    $providerQuery.Add("=== logman query providers $provider ===")
    $queryOutput = & logman.exe query providers $provider 2>&1
    $queryExitCode = $LASTEXITCODE
    foreach ($line in $queryOutput) {
        $providerQuery.Add([string]$line)
    }
    $providerQuery.Add("Exit code: $queryExitCode")
    if ($queryExitCode -eq 0) {
        break
    }
}
$providerQuery | Set-Content -LiteralPath $providerQueryPath

$tracerptLog = Join-Path $OutputDir 'tracerpt.txt'
$csvPath = Join-Path $OutputDir 'ghcivdev-tracerpt.csv'
$xmlPath = Join-Path $OutputDir 'ghcivdev-tracerpt.xml'

& tracerpt.exe $EtlPath -of CSV -o $csvPath -y *> $tracerptLog
if ($LASTEXITCODE -ne 0) {
    throw "tracerpt failed to export CSV from $EtlPath. See $tracerptLog."
}
& tracerpt.exe $EtlPath -of XML -o $xmlPath -y *>> $tracerptLog
if ($LASTEXITCODE -ne 0) {
    throw "tracerpt failed to export XML from $EtlPath. See $tracerptLog."
}

$providerGuidValue = [guid]$ProviderGuid
$decodeErrorPath = Join-Path $OutputDir 'get-winevent-error.txt'
try {
    $events = @(
        Get-WinEvent -Path $EtlPath -Oldest -ErrorAction Stop |
            Where-Object {
                $_.ProviderName -eq $ProviderName -or
                $_.ProviderId -eq $providerGuidValue
            }
    )

    $eventProjection = $events |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, ProviderId,
            TaskDisplayName, OpcodeDisplayName, KeywordsDisplayNames, Message,
            Properties
    $eventProjection |
        Export-Clixml -LiteralPath (Join-Path $OutputDir 'ghcivdev-events.clixml')
    $eventProjection |
        Format-List * |
        Out-File -LiteralPath (Join-Path $OutputDir 'ghcivdev-events.txt')
    "Decoded GHCI VDev events: $($events.Count)" |
        Set-Content -LiteralPath (Join-Path $OutputDir 'summary.txt')
}
catch {
    $_ | Format-List * -Force | Out-File -LiteralPath $decodeErrorPath
    @(
        'Get-WinEvent could not decode or filter the ETL on this host.'
        'Use ghcivdev-tracerpt.csv/xml or inspect the ETL in WPA.'
    ) | Set-Content -LiteralPath (Join-Path $OutputDir 'summary.txt')
    Write-Warning "Get-WinEvent decoding failed; raw tracerpt exports are available in $OutputDir."
}

Write-Host "GHCI VDev event export: $OutputDir"
