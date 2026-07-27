#Requires -RunAsAdministrator

<#
.SYNOPSIS
  TiP package harness with explicit zip/unzip/run modes.

.DESCRIPTION
  Provides a reusable CI/release entrypoint for TiP hardware validation:
    - Zip: package an existing TiP directory as a single archive.
    - Unzip: expand a package archive on the blade.
    - Run: execute deterministic suites and emit machine-readable results.json.
#>
[CmdletBinding()]
param(
    [ValidateSet('Run', 'Zip', 'Unzip')]
    [string]$Mode = 'Run',

    [string]$PackageDir = $PSScriptRoot,
    [string]$ArchivePath,
    [string]$ExpandDir,

    [ValidateSet('PrFast', 'ReleaseDeep')]
    [string]$Suite = 'PrFast',

    [string]$PowerTestPath = "$env:ProgramFiles\WindowsPowerShell\Modules\PowerTest",
    [switch]$InstallDependencies,
    [switch]$ConfigureHost,
    [switch]$CaptureSerial = $true,
    [string]$ResultsPath,
    [string]$EvidenceDir,
    [switch]$SkipHashEvidenceValidation,

    [string]$RebindOldIgvm = 'test-migtd_mock_quote.igvm',
    [string]$RebindNewIgvm = 'test-migtd_mock_quote_rebind.igvm'
)

$ErrorActionPreference = 'Stop'
$commonScript = Join-Path $PSScriptRoot 'TipHarness.Common.ps1'
if (-not (Test-Path $commonScript)) {
    throw "Harness helper not found: $commonScript"
}
. $commonScript

function New-CaseResult {
    param(
        [Parameter(Mandatory)] [hashtable]$Case,
        [Parameter(Mandatory)] [datetime]$StartUtc,
        [Parameter(Mandatory)] [datetime]$EndUtc,
        [Parameter(Mandatory)] [string]$Status,
        [string]$Category,
        [string]$Message,
        [string]$Outcome,
        [string[]]$SerialLogs,
        [string[]]$HashEvidenceFiles,
        [string[]]$ExpectedMigTdHashes,
        [string[]]$RuntimeMigTdHashes,
        [bool]$RuntimeHashReconciled = $false,
        [string]$CaseLogDir
    )

    [ordered]@{
        name = $Case.Name
        script = $Case.Script
        expectedOutcome = $Case.ExpectedOutcome
        status = $Status
        category = if ($Category) { $Category } else { 'PASS' }
        outcome = $Outcome
        startedUtc = $StartUtc.ToString('o')
        endedUtc = $EndUtc.ToString('o')
        durationSeconds = [Math]::Round(($EndUtc - $StartUtc).TotalSeconds, 3)
        caseLogDir = $CaseLogDir
        serialLogs = @($SerialLogs)
        hashEvidenceFiles = @($HashEvidenceFiles)
        expectedMigTdHashes = @($ExpectedMigTdHashes)
        runtimeMigTdHashes = @($RuntimeMigTdHashes)
        runtimeHashReconciled = $RuntimeHashReconciled
        message = if ($Message) { $Message } else { '' }
    }
}

function Get-EvidenceList {
    param([object]$InvocationResult)

    $hashEvidence = [System.Collections.Generic.List[string]]::new()
    foreach ($propertyName in @('HashEvidencePath', 'OldHashEvidencePath', 'NewHashEvidencePath')) {
        $property = $InvocationResult.PSObject.Properties[$propertyName]
        if ($property -and $property.Value) {
            $hashEvidence.Add([string]$property.Value)
        }
    }

    $serialLogs = [System.Collections.Generic.List[string]]::new()
    $serialProperty = $InvocationResult.PSObject.Properties['SerialLogs']
    if ($serialProperty -and $serialProperty.Value) {
        foreach ($entry in @($serialProperty.Value)) {
            if ($entry) {
                $serialLogs.Add([string]$entry)
            }
        }
    }

    $expectedHashes = [System.Collections.Generic.List[string]]::new()
    foreach ($propertyName in @('MigTdHash', 'OldMigTdHash', 'NewMigTdHash')) {
        $property = $InvocationResult.PSObject.Properties[$propertyName]
        if ($property -and $property.Value) {
            $hash = ([string]$property.Value).ToLowerInvariant()
            if ($hash -match '^[0-9a-f]{96}$') {
                $expectedHashes.Add($hash)
            }
        }
    }

    $runtimeHashes = [System.Collections.Generic.List[string]]::new()
    foreach ($propertyName in @('RuntimeMigTdHash', 'OldRuntimeMigTdHash', 'NewRuntimeMigTdHash')) {
        $property = $InvocationResult.PSObject.Properties[$propertyName]
        if ($property -and $property.Value) {
            $hash = ([string]$property.Value).ToLowerInvariant()
            if ($hash -match '^[0-9a-f]{96}$') {
                $runtimeHashes.Add($hash)
            }
        }
    }

    [pscustomobject]@{
        HashEvidenceFiles = @($hashEvidence | Select-Object -Unique)
        SerialLogs = @($serialLogs | Select-Object -Unique)
        ExpectedMigTdHashes = @($expectedHashes | Select-Object -Unique)
        RuntimeMigTdHashes = @($runtimeHashes | Select-Object -Unique)
    }
}

function Resolve-CaseArgs {
    param(
        [Parameter(Mandatory)] [hashtable]$Case,
        [Parameter(Mandatory)] [string]$PackageRoot,
        [Parameter(Mandatory)] [string]$RunPowerTestPath,
        [Parameter(Mandatory)] [bool]$RunCaptureSerial,
        [Parameter(Mandatory)] [bool]$RunSkipHashEvidenceValidation
    )

    $args = @{}
    foreach ($kvp in $Case.Args.GetEnumerator()) {
        $value = $kvp.Value
        if ($value -is [string] -and $value.StartsWith('pkg:')) {
            $args[$kvp.Key] = Join-Path $PackageRoot $value.Substring(4)
        } else {
            $args[$kvp.Key] = $value
        }
    }
    $args['PowerTestPath'] = $RunPowerTestPath
    $args['CaptureSerial'] = $RunCaptureSerial
    $args['SkipHashEvidenceValidation'] = $RunSkipHashEvidenceValidation
    return $args
}

function Invoke-TipCase {
    param(
        [Parameter(Mandatory)] [hashtable]$Case,
        [Parameter(Mandatory)] [string]$PackageRoot,
        [Parameter(Mandatory)] [string]$RunPowerTestPath,
        [Parameter(Mandatory)] [bool]$RunCaptureSerial,
        [Parameter(Mandatory)] [bool]$RunSkipHashEvidenceValidation,
        [Parameter(Mandatory)] [string]$LogRoot
    )

    $scriptPath = Join-Path $PackageRoot $Case.Script
    if (-not (Test-Path $scriptPath)) {
        throw (New-TipHarnessException 'PRECONDITION' "Case script not found: $scriptPath")
    }

    $caseLogDir = Join-Path $LogRoot $Case.Name
    New-Item -ItemType Directory -Path $caseLogDir -Force | Out-Null

    $startUtc = (Get-Date).ToUniversalTime()
    $status = 'PASS'
    $category = 'PASS'
    $message = ''
    $outcome = ''
    $serialLogs = @()
    $hashEvidenceFiles = @()
    $expectedMigTdHashes = @()
    $runtimeMigTdHashes = @()
    $runtimeHashReconciled = $false

    try {
        $caseArgs = Resolve-CaseArgs -Case $Case -PackageRoot $PackageRoot `
            -RunPowerTestPath $RunPowerTestPath `
            -RunCaptureSerial $RunCaptureSerial `
            -RunSkipHashEvidenceValidation $RunSkipHashEvidenceValidation
        Push-Location $caseLogDir
        try {
            $invokeResult = & $scriptPath @caseArgs
        } finally {
            Pop-Location
        }
        if ($invokeResult -is [System.Array]) {
            $invokeResult = @($invokeResult |
                Where-Object { $_ -and $_.PSObject -and $_.PSObject.Properties['Outcome'] }) |
                Select-Object -Last 1
        }
        if (-not $invokeResult) {
            $invokeResult = [pscustomobject]@{}
        }

        $evidence = Get-EvidenceList -InvocationResult $invokeResult
        $serialLogs = @($evidence.SerialLogs | ForEach-Object {
            if ([System.IO.Path]::IsPathRooted($_)) { $_ } else { Join-Path $caseLogDir $_ }
        })
        $hashEvidenceFiles = @($evidence.HashEvidenceFiles | ForEach-Object {
            if ([System.IO.Path]::IsPathRooted($_)) { $_ } else { Join-Path $caseLogDir $_ }
        })
        $expectedMigTdHashes = @($evidence.ExpectedMigTdHashes)
        $runtimeMigTdHashes = @($evidence.RuntimeMigTdHashes)

        $outcome = [string]$invokeResult.Outcome
        if (-not $outcome) {
            $outcome = if ($Case.ExpectedOutcome -eq 'ExpectedRejection') {
                'ExpectedRejection'
            } else {
                'Success'
            }
        }

        if ($Case.ExpectedOutcome -eq 'ExpectedRejection' -and $outcome -ne 'ExpectedRejection') {
            throw (New-TipHarnessException 'TEST_FAILURE' "Case '$($Case.Name)' did not report expected rejection outcome.")
        }
        if ($Case.ExpectedOutcome -eq 'Success' -and $outcome -eq 'ExpectedRejection') {
            throw (New-TipHarnessException 'TEST_FAILURE' "Case '$($Case.Name)' reported expected rejection unexpectedly.")
        }

        $evidenceFailures = [System.Collections.Generic.List[string]]::new()
        if (-not $RunSkipHashEvidenceValidation) {
            if ($hashEvidenceFiles.Count -eq 0) {
                $evidenceFailures.Add('No hash evidence paths were returned.')
            }
            foreach ($path in $hashEvidenceFiles) {
                if (-not (Test-Path $path)) {
                    $evidenceFailures.Add("Hash evidence file missing: $path")
                }
            }
        }

        if ($RunCaptureSerial) {
            if ($serialLogs.Count -eq 0) {
                $evidenceFailures.Add('No serial logs were returned.')
            }
            foreach ($path in $serialLogs) {
                if (-not (Test-Path $path)) {
                    $evidenceFailures.Add("Serial log missing: $path")
                }
            }
        }

        if ($evidenceFailures.Count -gt 0) {
            throw (New-TipHarnessException 'MISSING_EVIDENCE' ($evidenceFailures -join '; '))
        }

        if ($RunCaptureSerial) {
            if ($runtimeMigTdHashes.Count -eq 0) {
                throw (New-TipHarnessException 'MISSING_EVIDENCE' "No runtime TD Info Hash observed from serial logs for case '$($Case.Name)'.")
            }

            $reconciliationExpected = [System.Collections.Generic.List[string]]::new()
            foreach ($hash in $expectedMigTdHashes) {
                if ($hash -match '^[0-9a-f]{96}$') { $reconciliationExpected.Add($hash) }
            }
            if (-not $RunSkipHashEvidenceValidation) {
                foreach ($path in $hashEvidenceFiles) {
                    try {
                        $evidenceJson = Get-Content $path -Raw | ConvertFrom-Json
                        $evHash = ([string]$evidenceJson.migTdInfoHash).ToLowerInvariant()
                        if ($evHash -match '^[0-9a-f]{96}$') {
                            $reconciliationExpected.Add($evHash)
                        }
                    } catch {
                        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Hash evidence JSON parse failed for reconciliation: $path")
                    }
                }
            }
            $reconciliationExpected = @($reconciliationExpected | Select-Object -Unique)
            if ($reconciliationExpected.Count -eq 0) {
                throw (New-TipHarnessException 'MISSING_EVIDENCE' "No expected MigTD hash available to reconcile runtime serial evidence for case '$($Case.Name)'.")
            }

            $mismatches = @($runtimeMigTdHashes | Where-Object { $reconciliationExpected -notcontains $_ })
            if ($mismatches.Count -gt 0) {
                throw (New-TipHarnessException 'MISSING_EVIDENCE' "Runtime TD Info Hash mismatch for case '$($Case.Name)'. Expected one of [$($reconciliationExpected -join ', ')], observed [$($runtimeMigTdHashes -join ', ')].")
            }
            $runtimeHashReconciled = $true
        }
    } catch {
        $status = 'FAIL'
        $category = Get-TipErrorCategory -ErrorRecord $_
        $message = Convert-TipErrorRecordToString -ErrorRecord $_
        if (-not $outcome) {
            $outcome = 'Failure'
        }
    }

    $endUtc = (Get-Date).ToUniversalTime()
    return (New-CaseResult -Case $Case -StartUtc $startUtc -EndUtc $endUtc `
        -Status $status -Category $category -Message $message `
        -Outcome $outcome -SerialLogs $serialLogs -HashEvidenceFiles $hashEvidenceFiles `
        -ExpectedMigTdHashes $expectedMigTdHashes `
        -RuntimeMigTdHashes $runtimeMigTdHashes `
        -RuntimeHashReconciled $runtimeHashReconciled `
        -CaseLogDir $caseLogDir)
}

function Get-RunCases {
    param([Parameter(Mandatory)] [string]$SelectedSuite)

    $fast = @(
        @{ Name = 'pr-mock-quote-migration'; Script = 'Invoke-TdxLmLoopback.ps1'; ExpectedOutcome = 'Success'; Args = @{ IgvmFilePath = 'pkg:test-migtd-accept-all_mock_quote.igvm'; MigTdId = 'tipmigtd-pr-mock'; VmName = 'tiptd-pr-mock'; NoPersistentSecrets = $true } },
        @{ Name = 'pr-servtdext-prebind'; Script = 'Test-TdxServTdExtPrebind.ps1'; ExpectedOutcome = 'Success'; Args = @{ IgvmFilePath = 'pkg:test-migtd-accept-all_mock_quote.igvm'; MigTdId = 'tipmigtd-pr-prebind'; VmName = 'tiptd-pr-prebind'; NoPersistentSecrets = $true } }
    )

    if ($SelectedSuite -eq 'PrFast') {
        return $fast
    }

    $releaseExtras = @(
        @{ Name = 'release-accept-all'; Script = 'Invoke-TdxLmLoopback.ps1'; ExpectedOutcome = 'Success'; Args = @{ IgvmFilePath = 'pkg:test-migtd-accept-all.igvm'; MigTdId = 'tipmigtd-rel-accept'; VmName = 'tiptd-rel-accept'; NoPersistentSecrets = $false } },
        @{ Name = 'release-policy'; Script = 'Invoke-TdxLmLoopback.ps1'; ExpectedOutcome = 'Success'; Args = @{ IgvmFilePath = 'pkg:test-migtd.igvm'; MigTdId = 'tipmigtd-rel-policy'; VmName = 'tiptd-rel-policy'; NoPersistentSecrets = $false } },
        @{ Name = 'release-reject-all'; Script = 'Invoke-TdxLmLoopback.ps1'; ExpectedOutcome = 'ExpectedRejection'; Args = @{ IgvmFilePath = 'pkg:test-migtd-reject-all.igvm'; MigTdId = 'tipmigtd-rel-reject'; VmName = 'tiptd-rel-reject'; ExpectReject = $true; NoPersistentSecrets = $false } },
        @{ Name = 'release-rebind'; Script = 'Test-TdxLmRebind.ps1'; ExpectedOutcome = 'Success'; Args = @{ OldIgvmFilePath = "pkg:$RebindOldIgvm"; NewIgvmFilePath = "pkg:$RebindNewIgvm"; OldMigTdId = 'tipmigtd-rel-rebind-old'; NewMigTdId = 'tipmigtd-rel-rebind-new'; VmName = 'tiptd-rel-rebind' } }
    )

    return @($fast + $releaseExtras)
}

function Invoke-RunMode {
    param()

    if (-not (Test-Path $PackageDir)) {
        throw (New-TipHarnessException 'PRECONDITION' "PackageDir not found: $PackageDir")
    }

    $runPackageDir = (Resolve-Path $PackageDir).Path

    if (-not $EvidenceDir) {
        $EvidenceDir = Join-Path $runPackageDir 'test-results'
    }
    New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null

    if (-not $ResultsPath) {
        $ResultsPath = Join-Path $EvidenceDir 'results.json'
    }
    $ResultsPath = [System.IO.Path]::GetFullPath($ResultsPath)

    $logRoot = Join-Path $EvidenceDir 'serial'
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null

    $runStartUtc = (Get-Date).ToUniversalTime()
    $caseResults = [System.Collections.Generic.List[object]]::new()
    $harnessError = $null
    try {
        if ($InstallDependencies) {
            $installer = Join-Path $runPackageDir 'Install-TipDependencies.ps1'
            if (-not (Test-Path $installer)) {
                throw (New-TipHarnessException 'PRECONDITION' "Dependency installer not found: $installer")
            }
            $setupOutput = @(& $installer -PackageDir $runPackageDir -ConfigureHost:$ConfigureHost -Force)
            $setupResult = $setupOutput |
                Where-Object { $_.PSObject.Properties.Name -contains 'RebootRequired' } |
                Select-Object -Last 1
            if (-not $setupResult) {
                throw (New-TipHarnessException 'PRECONDITION' 'Dependency installer did not return setup status.')
            }
            $PowerTestPath = $setupResult.PowerTestPath
            if ($setupResult.RebootRequired) {
                throw (New-TipHarnessException 'PRECONDITION' 'Dependency installation changed Secure Firmware. Reboot the host, then rerun the harness without -InstallDependencies.')
            }
        } elseif ($ConfigureHost) {
            $validator = Join-Path $runPackageDir 'troubleshooting/Test-TdxLmLabBlade.ps1'
            if (-not (Test-Path $validator)) {
                throw (New-TipHarnessException 'PRECONDITION' "Host validation script not found: $validator")
            }
            & $validator -PowerTestPath $PowerTestPath -Configure
        }

        $cases = Get-RunCases -SelectedSuite $Suite
        foreach ($case in $cases) {
            $caseResult = Invoke-TipCase -Case $case -PackageRoot $runPackageDir `
                -RunPowerTestPath $PowerTestPath `
                -RunCaptureSerial $CaptureSerial.IsPresent `
                -RunSkipHashEvidenceValidation $SkipHashEvidenceValidation.IsPresent `
                -LogRoot $logRoot
            $caseResults.Add($caseResult)
        }
    } catch {
        $harnessError = $_
    }

    $runEndUtc = (Get-Date).ToUniversalTime()
    if ($harnessError) {
        $setupCase = @{
            Name = 'harness-setup'
            Script = 'Invoke-TipHarness.ps1'
            ExpectedOutcome = 'Success'
        }
        $setupResult = New-CaseResult -Case $setupCase `
            -StartUtc $runStartUtc `
            -EndUtc $runEndUtc `
            -Status 'FAIL' `
            -Category (Get-TipErrorCategory -ErrorRecord $harnessError) `
            -Message (Convert-TipErrorRecordToString -ErrorRecord $harnessError) `
            -Outcome 'Failure' `
            -SerialLogs @() `
            -HashEvidenceFiles @() `
            -CaseLogDir $logRoot
        $caseResults.Add($setupResult)
    }

    $failedCases = @($caseResults | Where-Object { $_.status -eq 'FAIL' })

    $summary = [ordered]@{
        total = $caseResults.Count
        passed = @($caseResults | Where-Object { $_.status -eq 'PASS' }).Count
        failed = $failedCases.Count
        runtimeHashReconciledCases = @($caseResults | Where-Object { $_.runtimeHashReconciled -eq $true }).Count
        runtimeHashesObserved = @($caseResults |
            ForEach-Object { @($_.runtimeMigTdHashes) } |
            Where-Object { $_ } |
            Select-Object -Unique)
        expectedRejections = @($caseResults | Where-Object { $_.outcome -eq 'ExpectedRejection' -and $_.status -eq 'PASS' }).Count
        preconditionFailures = @($failedCases | Where-Object { $_.category -eq 'PRECONDITION' }).Count
        transportFailures = @($failedCases | Where-Object { $_.category -eq 'TRANSPORT' }).Count
        testFailures = @($failedCases | Where-Object { $_.category -eq 'TEST_FAILURE' }).Count
        cleanupFailures = @($failedCases | Where-Object { $_.category -eq 'CLEANUP' }).Count
        missingEvidenceFailures = @($failedCases | Where-Object { $_.category -eq 'MISSING_EVIDENCE' }).Count
        genericFailures = @($failedCases | Where-Object { $_.category -eq 'GENERIC_FAILURE' }).Count
        result = if ($failedCases.Count -eq 0) { 'PASS' } else { 'FAIL' }
        startedUtc = $runStartUtc.ToString('o')
        endedUtc = $runEndUtc.ToString('o')
        durationSeconds = [Math]::Round(($runEndUtc - $runStartUtc).TotalSeconds, 3)
    }

    $results = [ordered]@{
        schemaVersion = 1
        harness = 'tip-hardware-ci'
        mode = 'Run'
        suite = $Suite
        packageDir = $runPackageDir
        evidenceDir = (Resolve-Path $EvidenceDir).Path
        captureSerial = $CaptureSerial.IsPresent
        hashEvidenceValidation = -not $SkipHashEvidenceValidation.IsPresent
        resultsPath = $ResultsPath
        summary = $summary
        cases = @($caseResults)
    }

    $resultsParent = Split-Path -Parent $ResultsPath
    if ($resultsParent) {
        New-Item -ItemType Directory -Path $resultsParent -Force | Out-Null
    }
    $results | ConvertTo-Json -Depth 8 | Set-Content -Path $ResultsPath
    Write-Host "Wrote results: $((Resolve-Path $ResultsPath).Path)"

    if ($failedCases.Count -gt 0) {
        exit 1
    }
}

function Invoke-ZipMode {
    param()

    if (-not (Test-Path $PackageDir)) {
        throw (New-TipHarnessException 'PRECONDITION' "PackageDir not found: $PackageDir")
    }

    if (-not $ArchivePath) {
        $parent = Split-Path -Parent (Resolve-Path $PackageDir).Path
        $ArchivePath = Join-Path $parent 'tip-package.zip'
    }

    $archiveParent = Split-Path -Parent $ArchivePath
    if ($archiveParent) {
        New-Item -ItemType Directory -Path $archiveParent -Force | Out-Null
    }

    if (Test-Path $ArchivePath) {
        Remove-Item $ArchivePath -Force
    }
    Compress-Archive -Path (Join-Path (Resolve-Path $PackageDir).Path '*') -DestinationPath $ArchivePath -Force

    [pscustomobject]@{
        Mode = 'Zip'
        PackageDir = (Resolve-Path $PackageDir).Path
        ArchivePath = (Resolve-Path $ArchivePath).Path
    }
}

function Invoke-UnzipMode {
    param()

    if (-not $ArchivePath) {
        throw (New-TipHarnessException 'PRECONDITION' '-ArchivePath is required for -Mode Unzip.')
    }
    if (-not (Test-Path $ArchivePath)) {
        throw (New-TipHarnessException 'PRECONDITION' "Archive not found: $ArchivePath")
    }
    if (-not $ExpandDir) {
        throw (New-TipHarnessException 'PRECONDITION' '-ExpandDir is required for -Mode Unzip.')
    }

    New-Item -ItemType Directory -Path $ExpandDir -Force | Out-Null
    Expand-Archive -LiteralPath $ArchivePath -DestinationPath $ExpandDir -Force

    [pscustomobject]@{
        Mode = 'Unzip'
        ArchivePath = (Resolve-Path $ArchivePath).Path
        ExpandDir = (Resolve-Path $ExpandDir).Path
    }
}

switch ($Mode) {
    'Zip' { Invoke-ZipMode; break }
    'Unzip' { Invoke-UnzipMode; break }
    'Run' { Invoke-RunMode; break }
    default {
        throw (New-TipHarnessException 'PRECONDITION' "Unsupported mode: $Mode")
    }
}
