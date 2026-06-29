<#
.SYNOPSIS
  Run one TDX MigTD loopback live-migration on a labblade.

.DESCRIPTION
  Starts the given MigTD IGVM, registers its hash, creates a TDX guest, migrates
  it to localhost (loopback), and asserts the outcome. Cleans up afterwards.
  Mirrors the Azure OS PR gate (Invoke-TdxLmE2ETest). Requires PowerTest's
  TdxLiveMigrationUtilities for New-TestHcsMigTd; pass -PowerTestPath to import it.

.EXAMPLE
  .\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-accept-all.igvm
  .\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-reject-all.igvm -ExpectReject
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$IgvmFilePath,
    [string]$HashFilePath = "$IgvmFilePath.hash",
    [string]$MigTdId = 'tipmigtd',
    [string]$VmName = 'tiptd',
    [switch]$ExpectReject,
    [string]$PowerTestPath
)
$ErrorActionPreference = 'Stop'

if ($PowerTestPath) {
    Import-Module (Join-Path $PowerTestPath 'TdxLiveMigrationUtilities.psm1') -Force
}
if (-not (Test-Path $IgvmFilePath)) { throw "IGVM not found: $IgvmFilePath" }
if (-not (Test-Path $HashFilePath)) { throw "Hash file not found: $HashFilePath" }
$MigTdHash = (Get-Content $HashFilePath -Raw).Trim()
Write-Host "MigTD: $IgvmFilePath  hash=$MigTdHash"

$migTd = $null; $td = $null
try {
    $migTd = New-TestHcsMigTd -Id $MigTdId -IgvmFilePath (Resolve-Path $IgvmFilePath) -GuestStateDirectory . -Force
    $migTd | Start-HcsSystem
    Add-VmHostMigrationTdMapping -MigTdHash $MigTdHash -VmId $migTd.Id
    Set-VMHostMigrationPolicy EnabledByDefault $MigTdHash

    $td = New-VM -Name $VmName -GuestStateIsolation TDX -Generation 2 -NoVHD
    $td | Start-VM
    Start-Sleep -Seconds 5

    $moveErr = $null
    Move-VM -Name $VmName -DestinationHost localhost -ErrorVariable moveErr -ErrorAction SilentlyContinue

    if ($ExpectReject) {
        if (-not $moveErr) { throw "FAIL: migration succeeded but rejection expected" }
        Write-Host "PASS: migration rejected as expected ($($moveErr[0]))"
    } else {
        if ($moveErr)     { throw "FAIL: migration failed: $($moveErr[0])" }
        Write-Host "PASS: migration succeeded"
    }
}
finally {
    if ($td)    { $td | Stop-VM -Force -ErrorAction SilentlyContinue; $td | Remove-VM -Force -ErrorAction SilentlyContinue }
    Set-VMHostMigrationPolicy AlwaysDisabled -ErrorAction SilentlyContinue
    if ($MigTdHash) { Remove-VmHostMigrationTdMapping -MigTdHash $MigTdHash -ErrorAction SilentlyContinue }
    if ($migTd)  { Stop-HcsSystem $migTd -ErrorAction SilentlyContinue; $migTd.Close() }
}
