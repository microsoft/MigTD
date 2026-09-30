#Requires -Version 7.0

<#
.SYNOPSIS
  Start a prebound TDX VM and validate its runtime ServTdExt layout.

.DESCRIPTION
  Uses Invoke-TdxLmLoopback.ps1 to start MigTD, register the prebind hash,
  create and start the target TD, then validate Get-VmServTdExt without
  initiating migration. All created state is cleaned up afterwards.

.EXAMPLE
  .\Test-TdxServTdExtPrebind.ps1 `
      -IgvmFilePath .\test-migtd-accept-all_mock_quote.igvm `
      -PowerTestPath 'C:\Program Files\PowerShell\Modules\PowerTest' `
      -NoPersistentSecrets
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$IgvmFilePath,
    [string]$HashFilePath = "$IgvmFilePath.hash",
    [string]$MigTdId = 'tipmigtd',
    [string]$VmName = 'tiptd',
    [string]$PowerTestPath = "$env:ProgramFiles\PowerShell\Modules\PowerTest",
    [switch]$NoPersistentSecrets,
    [switch]$CaptureSerial,
    [ValidateRange(0, 60)] [int]$SerialDrainTimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'
$driver = Join-Path $PSScriptRoot 'Invoke-TdxLmLoopback.ps1'
if (-not (Test-Path $driver)) {
    throw "Loopback driver not found: $driver"
}

$parameters = @{
    IgvmFilePath = $IgvmFilePath
    HashFilePath = $HashFilePath
    MigTdId = $MigTdId
    VmName = $VmName
    PowerTestPath = $PowerTestPath
    ServTdExtOnly = $true
    NoPersistentSecrets = $NoPersistentSecrets
    CaptureSerial = $CaptureSerial
    SerialDrainTimeoutSeconds = $SerialDrainTimeoutSeconds
}

& $driver @parameters
