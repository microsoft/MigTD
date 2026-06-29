<#
.SYNOPSIS
  Run the TiP loopback test suite over a built package directory.

.DESCRIPTION
  Discovers test-migtd-*.igvm images in the package folder and runs each through
  Invoke-TdxLmLoopback. accept-all/real expect success; reject-all expects reject.
  Run from an elevated PowerShell on a TDX labblade with PowerTest installed.

.EXAMPLE
  .\Run-TipTests.ps1 -PackageDir . -PowerTestPath C:\PowerTest
#>
[CmdletBinding()]
param(
    [string]$PackageDir = $PSScriptRoot,
    [string]$PowerTestPath,
    [switch]$InitializeHost
)
$ErrorActionPreference = 'Stop'

if ($PowerTestPath) { Import-Module (Join-Path $PowerTestPath 'TdxLiveMigrationUtilities.psm1') -Force }
if ($InitializeHost) { Initialize-TdxLmMachine }

$cases = @(
    @{ Name = 'accept-all';   Reject = $false },
    @{ Name = 'real';         Reject = $false },
    @{ Name = 'reject-all';   Reject = $true  }
)
$loopback = Join-Path $PSScriptRoot 'Invoke-TdxLmLoopback.ps1'
$results = @()
foreach ($c in $cases) {
    $igvm = Join-Path $PackageDir "test-migtd-$($c.Name).igvm"
    if (-not (Test-Path $igvm)) { Write-Warning "skip $($c.Name): $igvm not found"; continue }
    Write-Host "`n=== $($c.Name) ==="
    try {
        & $loopback -IgvmFilePath $igvm -ExpectReject:$c.Reject -PowerTestPath $PowerTestPath
        $results += [pscustomobject]@{ Case = $c.Name; Result = 'PASS' }
    } catch {
        $results += [pscustomobject]@{ Case = $c.Name; Result = "FAIL: $_" }
    }
}
$results | Format-Table -AutoSize
if ($results.Result -match 'FAIL') { exit 1 }
