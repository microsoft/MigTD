#Requires -Version 7.0

<#
.SYNOPSIS
  Run the TiP loopback test suite over a built package directory.

.DESCRIPTION
  Runs MigTD startup and post-start WaitForRequest coverage,
  agent-independent mock-quote migration, ServTdExt prebind, and bidirectional
  policy leaf-key rotation rebind checks.
  Optionally installs bundled dependencies, configures the host, and runs the
  regular IGVMAgent-dependent policy cases.

.EXAMPLE
  .\Run-TipTests.ps1 -InstallDependencies -ConfigureHost
#>
[CmdletBinding()]
param(
    [string]$PackageDir = $PSScriptRoot,
    [string]$PowerTestPath = "$env:ProgramFiles\PowerShell\Modules\PowerTest",
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

$results = @()
$requestCoverage = @()
$startupRequestScript = Join-Path $PackageDir 'Test-TdxMigTdStartupRequests.ps1'
if (-not (Test-Path $startupRequestScript)) {
    throw "Startup request test script not found: $startupRequestScript"
}

$startupRequestIgvm = Join-Path $PackageDir 'test-migtd-accept-all_mock_quote.igvm'
if (Test-Path $startupRequestIgvm) {
    Write-Host "`n=== wait_for_requests startup and post-start operations ==="
    try {
        & $startupRequestScript `
            -IgvmFilePath $startupRequestIgvm `
            -PowerTestPath $PowerTestPath `
            -OutputDir (Join-Path $PackageDir 'request-coverage\startup')
        $results += [pscustomobject]@{
            Case = 'wait_for_requests startup and GetTDReport'
            Result = 'PASS'
        }
        $requestCoverage += @(
            [pscustomobject]@{
                Operation = '4 EnableLogArea'
                Trigger = 'MigTD startup'
                Result = 'PASS'
                Notes = 'GHCI EnableLogAreaRequest_Success'
            },
            [pscustomobject]@{
                Operation = '3 GetTDReport'
                Trigger = 'Post-start HCS query'
                Result = 'PASS'
                Notes = 'External request; nonce, report hashes, and image hash validated'
            }
        )
    } catch {
        $results += [pscustomobject]@{
            Case = 'wait_for_requests startup and GetTDReport'
            Result = "FAIL: $_"
        }
        $requestCoverage += @(
            [pscustomobject]@{
                Operation = '4 EnableLogArea'
                Trigger = 'MigTD startup'
                Result = 'FAIL'
                Notes = [string]$_
            },
            [pscustomobject]@{
                Operation = '3 GetTDReport'
                Trigger = 'Post-start HCS query'
                Result = 'FAIL'
                Notes = [string]$_
            }
        )
    }
} else {
    Write-Warning "skip wait_for_requests startup: $startupRequestIgvm not found"
    $requestCoverage += @(
        [pscustomobject]@{
            Operation = '4 EnableLogArea'
            Trigger = 'MigTD startup'
            Result = 'SKIP'
            Notes = 'mock-quote image missing'
        },
        [pscustomobject]@{
            Operation = '3 GetTDReport'
            Trigger = 'Post-start HCS query'
            Result = 'SKIP'
            Notes = 'mock-quote image missing'
        }
    )
}

if ($IncludeAgentCases) {
    $getQuoteIgvm = Join-Path $PackageDir 'test-migtd-getquote-all.igvm'
    if (Test-Path $getQuoteIgvm) {
        Write-Host "`n=== GetQuote initialization ==="
        try {
            & $startupRequestScript `
                -IgvmFilePath $getQuoteIgvm `
                -PowerTestPath $PowerTestPath `
                -ExpectedGetQuoteResult Success `
                -OutputDir (Join-Path $PackageDir 'request-coverage\getquote')
            $results += [pscustomobject]@{
                Case = 'GetQuote initialization'
                Result = 'PASS'
            }
        } catch {
            $results += [pscustomobject]@{
                Case = 'GetQuote initialization'
                Result = "FAIL: $_"
            }
        }
    } else {
        Write-Warning "skip GetQuote initialization: $getQuoteIgvm not found"
    }
}

$cases = @(
    @{ Name = 'accept-all_mock_quote'; File = 'test-migtd-accept-all_mock_quote.igvm'; Reject = $false; NoSecrets = $true }
)
if ($IncludeAgentCases) {
    $cases += @(
        @{ Name = 'accept-all'; File = 'test-migtd-accept-all.igvm'; Reject = $false; NoSecrets = $false },
        @{ Name = 'policy'; File = 'test-migtd.igvm'; Reject = $false; NoSecrets = $false },
        @{ Name = 'reject-all'; File = 'test-migtd-reject-all.igvm'; Reject = $true; NoSecrets = $false }
    )
}

$loopback = Join-Path $PSScriptRoot 'Invoke-TdxLmLoopback.ps1'
if (-not (Test-Path $loopback)) {
    throw "Loopback driver not found: $loopback"
}
foreach ($c in $cases) {
    $igvm = Join-Path $PackageDir $c.File
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

$migrationResults = @(
    $results | Where-Object { $_.Case -in $cases.Name }
)
$migrationCoverage = if ($migrationResults.Result -match '^FAIL') {
    'FAIL'
} elseif ($migrationResults.Result -contains 'PASS') {
    'PASS'
} else {
    'SKIP'
}
$requestCoverage += [pscustomobject]@{
    Operation = '1 StartMigration'
    Trigger = 'Move-VM loopback'
    Result = $migrationCoverage
    Notes = 'Invoke-TdxLmLoopback.ps1'
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

$rebindScript = Join-Path $PackageDir 'Test-TdxLmRebind.ps1'
if (-not (Test-Path $rebindScript)) {
    throw "Rebind test script not found: $rebindScript"
}
$rotationCases = @(
    @{
        Name = 'mock-quote key rotation forward'
        Old = 'test-migtd_mock_quote.igvm'
        New = 'test-migtd_mock_quote_key_rotation.igvm'
    },
    @{
        Name = 'mock-quote key rotation backward'
        Old = 'test-migtd_mock_quote_key_rotation.igvm'
        New = 'test-migtd_mock_quote.igvm'
    }
)
if ($IncludeAgentCases) {
    $rotationCases += @(
        @{
            Name = 'key rotation forward'
            Old = 'test-migtd.igvm'
            New = 'test-migtd_key_rotation.igvm'
        },
        @{
            Name = 'key rotation backward'
            Old = 'test-migtd_key_rotation.igvm'
            New = 'test-migtd.igvm'
        }
    )
}

foreach ($c in $rotationCases) {
    $oldIgvm = Join-Path $PackageDir $c.Old
    $newIgvm = Join-Path $PackageDir $c.New
    if (-not (Test-Path $oldIgvm) -or -not (Test-Path $newIgvm)) {
        Write-Warning "skip $($c.Name): required image missing"
        continue
    }
    Write-Host "`n=== $($c.Name) ==="
    try {
        & $rebindScript -OldIgvmFilePath $oldIgvm -NewIgvmFilePath $newIgvm `
            -PowerTestPath $PowerTestPath -CaptureSerial:$CaptureSerial
        $results += [pscustomobject]@{ Case = $c.Name; Result = 'PASS' }
    } catch {
        $results += [pscustomobject]@{ Case = $c.Name; Result = "FAIL: $_" }
    }
}

$rebindResults = @(
    $results | Where-Object { $_.Case -in $rotationCases.Name }
)
$rebindCoverage = if ($rebindResults.Result -match '^FAIL') {
    'FAIL'
} elseif ($rebindResults.Result -contains 'PASS') {
    'PASS'
} else {
    'SKIP'
}
$requestCoverage += [pscustomobject]@{
    Operation = '2 StartRebinding'
    Trigger = 'Update-VmMigrationPolicy'
    Result = $rebindCoverage
    Notes = 'Test-TdxLmRebind.ps1'
}
$requestCoverage += [pscustomobject]@{
    Operation = '5 GetMigtdData'
    Trigger = 'None on current Host OS'
    Result = 'UNAVAILABLE'
    Notes = 'Host GHCI VDev GhciRequestOperation exposes operations 1-4 only'
}

$results | Format-Table -AutoSize
Write-Host "`n=== wait_for_requests coverage ==="
$requestCoverage |
    Sort-Object { [int]($_.Operation.Split(' ')[0]) } |
    Format-Table -AutoSize -Wrap
if ($results.Result -match 'FAIL') { exit 1 }
