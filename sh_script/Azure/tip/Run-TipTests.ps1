<#
.SYNOPSIS
  Run the TiP loopback test suite over a built package directory.

.DESCRIPTION
  Runs an agent-independent mock-quote migration and ServTdExt prebind check.
  Optionally installs bundled dependencies, configures the host, and runs the
  regular IGVMAgent-dependent policy cases.

.EXAMPLE
  .\Run-TipTests.ps1 -InstallDependencies -ConfigureHost
#>
[CmdletBinding()]
param(
    [string]$PackageDir = $PSScriptRoot,
    [string]$PowerTestPath = "$env:ProgramFiles\WindowsPowerShell\Modules\PowerTest",
    [switch]$InstallDependencies,
    [switch]$ConfigureHost,
    [switch]$IncludeAgentCases,
    [switch]$CaptureSerial
)
$ErrorActionPreference = 'Stop'

if ($InstallDependencies) {
    $installer = Join-Path $PackageDir 'Install-TipDependencies.ps1'
    if (-not (Test-Path $installer)) {
        throw "Dependency installer not found: $installer"
    }
    $setupOutput = @(& $installer -PackageDir $PackageDir `
        -ConfigureHost:$ConfigureHost -Force)
    $setupResult = $setupOutput |
        Where-Object { $_.PSObject.Properties.Name -contains 'RebootRequired' } |
        Select-Object -Last 1
    if (-not $setupResult) {
        throw 'Dependency installer did not return setup status.'
    }
    $setupOutput | Where-Object { $_ -ne $setupResult } | Out-Host
    $setupResult | Format-List | Out-Host
    $PowerTestPath = $setupResult.PowerTestPath
    if ($setupResult.RebootRequired) {
        throw 'Dependency installation changed Secure Firmware. Reboot the host, then rerun Run-TipTests.ps1 without -InstallDependencies.'
    }
} elseif ($ConfigureHost) {
    $validator = Join-Path $PackageDir 'troubleshooting\Test-TdxLmLabBlade.ps1'
    & $validator -PowerTestPath $PowerTestPath -Configure
}

$cases = @(
    @{ Name = 'accept-all_mock_quote'; Reject = $false; NoSecrets = $true }
)
if ($IncludeAgentCases) {
    $cases += @(
        @{ Name = 'accept-all'; Reject = $false; NoSecrets = $false },
        @{ Name = 'real'; Reject = $false; NoSecrets = $false },
        @{ Name = 'reject-all'; Reject = $true; NoSecrets = $false }
    )
}

$loopback = Join-Path $PSScriptRoot 'Invoke-TdxLmLoopback.ps1'
if (-not (Test-Path $loopback)) {
    throw "Loopback driver not found: $loopback"
}
$results = @()
foreach ($c in $cases) {
    $igvm = Join-Path $PackageDir "test-migtd-$($c.Name).igvm"
    if (-not (Test-Path $igvm)) { Write-Warning "skip $($c.Name): $igvm not found"; continue }
    Write-Host "`n=== $($c.Name) ==="
    try {
        & $loopback -IgvmFilePath $igvm -ExpectReject:$c.Reject `
            -PowerTestPath $PowerTestPath -NoPersistentSecrets:$c.NoSecrets `
            -CaptureSerial:$CaptureSerial
        $results += [pscustomobject]@{ Case = $c.Name; Result = 'PASS' }
    } catch {
        $results += [pscustomobject]@{ Case = $c.Name; Result = "FAIL: $_" }
    }
}

$prebindIgvm = Join-Path $PackageDir 'test-migtd-accept-all_mock_quote.igvm'
if (Test-Path $prebindIgvm) {
    Write-Host "`n=== ServTdExt prebind ==="
    try {
        $prebindScript = Join-Path $PackageDir 'Test-TdxServTdExtPrebind.ps1'
        if (-not (Test-Path $prebindScript)) {
            throw "ServTdExt test script not found: $prebindScript"
        }
        & $prebindScript `
            -IgvmFilePath $prebindIgvm -PowerTestPath $PowerTestPath `
            -NoPersistentSecrets -CaptureSerial:$CaptureSerial
        $results += [pscustomobject]@{ Case = 'ServTdExt prebind'; Result = 'PASS' }
    } catch {
        $results += [pscustomobject]@{ Case = 'ServTdExt prebind'; Result = "FAIL: $_" }
    }
}

$results | Format-Table -AutoSize
if ($results.Result -match 'FAIL') { exit 1 }
