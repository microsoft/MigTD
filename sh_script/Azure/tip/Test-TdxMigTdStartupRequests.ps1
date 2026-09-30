#Requires -Version 7.0

<#
.SYNOPSIS
  Validate MigTD startup and post-start WaitForRequest operations.

.DESCRIPTION
  Starts one MigTD HCS system under a focused Microsoft.Windows.HyperV.GhciVDev
  trace and verifies that the host successfully completes:

    * EnableLogArea (the first WaitForRequest)
    * The internal startup GetTDReport used to cache TDINFO
    * A separate post-start GetTDReport HCS query matching IGVMAgent health checks

  The external GetTDReport test sends a fresh 64-byte REPORTDATA nonce, validates
  the returned nonce and TDREPORT hashes, and compares TEE_INFO_HASH with the
  image's .hash file.

  With -ExpectedGetQuoteResult, also follows the Host OS
  Tdx.Ghci.GetQuote.TestMD.Tests.ps1 pattern and validates the Worker Analytic
  event for a test-get-quote image.

.EXAMPLE
  .\Test-TdxMigTdStartupRequests.ps1 `
      -IgvmFilePath .\test-migtd-accept-all_mock_quote.igvm

.EXAMPLE
  .\Test-TdxMigTdStartupRequests.ps1 `
      -IgvmFilePath .\test-migtd-getquote-all.igvm `
      -ExpectedGetQuoteResult Success
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$IgvmFilePath,
    [string]$HashFilePath,
    [string]$MigTdId = 'tipmigtd-startup',
    [string]$PowerTestPath = "$env:ProgramFiles\PowerShell\Modules\PowerTest",
    [string]$OutputDir = (Join-Path (Get-Location) 'tipmigtd-startup-requests'),
    [ValidateSet('None', 'Success', 'Failure')]
    [string]$ExpectedGetQuoteResult = 'None',
    [ValidateRange(1, 600)]
    [int]$TimeoutSeconds = 300,
    [ValidateRange(0, 30)]
    [int]$StartupSettleSeconds = 2
)

$ErrorActionPreference = 'Stop'

function Import-PowerTestFile {
    param([Parameter(Mandatory)] [string]$Name)

    $path = Join-Path $PowerTestPath $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "PowerTest file not found: $path"
    }
    Import-Module $path -Force
}

function Initialize-TipHostModules {
    Import-PowerTestFile 'TdxLiveMigrationUtilities.psm1'
    Import-PowerTestFile 'HCSUtilities.psm1'
    Import-PowerTestFile 'VmgsUtilities.psm1'

    $hcsTest = Get-Module HCSTest
    if ($hcsTest -and $hcsTest.NestedModules[0].Name -notlike '*.v2') {
        throw 'HCSTest v1 is already loaded. Close this PowerShell process and retry.'
    }
    if (-not $hcsTest) {
        Import-Module HCSTest -ArgumentList @{ UseVersion2 = $true } `
            -Global -Force -ErrorAction SilentlyContinue
        if (-not (Get-Module HCSTest)) {
            if (Get-Command Import-HcsTestModule -ErrorAction SilentlyContinue) {
                Import-HcsTestModule -UseVersion2
            } else {
                throw 'HCSTest is unavailable and HCSUtilities did not provide Import-HcsTestModule.'
            }
        }
    }
    if (-not (Get-Command New-HcsSystemDocument -ErrorAction SilentlyContinue)) {
        throw 'HCSTest v2 did not provide New-HcsSystemDocument.'
    }

    if (-not (Get-Command New-VmStateFile -ErrorAction SilentlyContinue)) {
        function global:New-VmStateFile {
            param(
                [Parameter(Mandatory)] [string]$GuestStateFilePath,
                [int]$FileSize = 16MB
            )

            $tool = Get-Command vmgstool.exe -ErrorAction SilentlyContinue
            if ($tool) {
                $tool = $tool.Source
            } elseif (Test-Path (Join-Path $env:SystemRoot 'System32\vmgstool.exe')) {
                $tool = Join-Path $env:SystemRoot 'System32\vmgstool.exe'
            }

            if ($tool) {
                & $tool -Create -FilePath $GuestStateFilePath "-FileSize=$FileSize" | Out-Null
            } elseif (Get-Command New-GuestStateFile -ErrorAction SilentlyContinue) {
                New-GuestStateFile -FilePath $GuestStateFilePath -FileSize $FileSize | Out-Null
            } else {
                throw 'Cannot create the MigTD guest state file: vmgstool.exe and New-GuestStateFile are unavailable.'
            }
        }
    }
}

function Test-TraceMarker {
    param(
        [Parameter(Mandatory)] [string]$TraceOutputDir,
        [Parameter(Mandatory)] [string[]]$Marker,
        [Parameter(Mandatory)] [string]$Operation
    )

    $traceFiles = @(
        Join-Path $TraceOutputDir 'ghcivdev-tracerpt.csv'
        Join-Path $TraceOutputDir 'ghcivdev-tracerpt.xml'
        Join-Path $TraceOutputDir 'ghcivdev-events.txt'
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }

    foreach ($candidate in $Marker) {
        if ($traceFiles -and
            (Select-String -LiteralPath $traceFiles -Pattern $candidate -SimpleMatch -Quiet)) {
            Write-Host "PASS: $Operation observed as GHCI event '$candidate'."
            return
        }
    }

    throw "$Operation was not observed in the GHCI trace. Expected one of: $($Marker -join ', ')"
}

function Get-QuoteEvent {
    param(
        [Parameter(Mandatory)] [int]$EventId,
        [Parameter(Mandatory)] [datetime]$StartTime,
        [Parameter(Mandatory)] [string]$VmName
    )

    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Hyper-V-Worker-Analytic'
        Id = $EventId
        StartTime = $StartTime
    } -Oldest -ErrorAction SilentlyContinue |
        Where-Object { ([string]$_.Message).Contains($VmName) } |
        Select-Object -First 1
}

function ConvertTo-HexString {
    param([Parameter(Mandatory)] [byte[]]$Bytes)

    return -join ($Bytes | ForEach-Object { $_.ToString('x2') })
}

function Test-ByteArrayEqual {
    param(
        [Parameter(Mandatory)] [byte[]]$Left,
        [Parameter(Mandatory)] [byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    for ($i = 0; $i -lt $Left.Length; $i++) {
        if ($Left[$i] -ne $Right[$i]) {
            return $false
        }
    }
    return $true
}

function Get-Sha384 {
    param([Parameter(Mandatory)] [byte[]]$Bytes)

    $sha384 = [System.Security.Cryptography.SHA384]::Create()
    try {
        return [byte[]]$sha384.ComputeHash($Bytes)
    }
    finally {
        $sha384.Dispose()
    }
}

function Invoke-MigTdGetReportHealthCheck {
    param(
        [Parameter(Mandatory)] $MigTd,
        [Parameter(Mandatory)] [string]$ExpectedTdInfoHash
    )

    [byte[]]$nonce = New-Object byte[] 64
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    $query = @{
        Queries = @{
            MigTdReport = @{
                ReportData = [Convert]::ToBase64String($nonce)
            }
        }
    } | ConvertTo-Json -Depth 4 -Compress

    $response = (Get-HcsSystemProperties `
        -System $MigTd `
        -Query $query `
        -RawJson `
        -ErrorAction Stop) | ConvertFrom-Json
    $property = $response.PropertyResponses.MigTdReport
    if (-not $property) {
        throw 'GetTDReport response did not contain PropertyResponses.MigTdReport.'
    }
    if ($property.Error) {
        throw "GetTDReport property failed: $($property.Error | ConvertTo-Json -Depth 8 -Compress)"
    }

    $reportResponse = $property.Response
    if (-not $reportResponse) {
        throw 'GetTDReport response did not contain MigTdReport.Response.'
    }
    $completionStatus = $reportResponse.CompletionStatus
    $completionText = ([string]$completionStatus).Trim()
    if ($completionStatus -ne 0 -and $completionText -notmatch '^0x0+$') {
        throw "GetTDReport completed with failure status $completionText."
    }
    if (-not $reportResponse.ReportData) {
        throw 'GetTDReport returned empty ReportData.'
    }

    try {
        [byte[]]$report = [Convert]::FromBase64String([string]$reportResponse.ReportData)
    }
    catch {
        throw "GetTDReport returned invalid base64 ReportData: $_"
    }
    if ($report.Length -lt 4 -or $report[0] -ne 0x81) {
        throw 'GetTDReport did not return a TDX TDREPORT.'
    }

    $tdInfoSize = if ($report[2] -le 1) {
        512
    } elseif ($report[2] -eq 2) {
        768
    } else {
        throw "Unsupported TDREPORT version $($report[2])."
    }
    $expectedReportSize = 512 + $tdInfoSize
    if ($report.Length -ne $expectedReportSize) {
        throw "TDREPORT length $($report.Length) does not match version $($report[2]) length $expectedReportSize."
    }

    [byte[]]$returnedNonce = $report[128..191]
    if (-not (Test-ByteArrayEqual -Left $returnedNonce -Right $nonce)) {
        throw 'TDREPORT REPORTDATA did not echo the health-check nonce.'
    }

    [byte[]]$teeInfoHash = $report[80..127]
    [byte[]]$tdInfo = $report[512..(511 + $tdInfoSize)]
    [byte[]]$computedTdInfoHash = Get-Sha384 -Bytes $tdInfo
    if (-not (Test-ByteArrayEqual -Left $teeInfoHash -Right $computedTdInfoHash)) {
        throw 'TDREPORT TEE_INFO_HASH does not match SHA384(TDINFO).'
    }

    [byte[]]$teeTcbInfoHash = $report[32..79]
    if (($teeTcbInfoHash | Where-Object { $_ -ne 0 }).Count -gt 0) {
        [byte[]]$teeTcbInfo = $report[256..494]
        [byte[]]$computedTcbInfoHash = Get-Sha384 -Bytes $teeTcbInfo
        if (-not (Test-ByteArrayEqual -Left $teeTcbInfoHash -Right $computedTcbInfoHash)) {
            throw 'TDREPORT TEE_TCB_INFO_HASH does not match SHA384(TEE_TCB_INFO[239]).'
        }
    }

    $actualTdInfoHash = ConvertTo-HexString -Bytes $teeInfoHash
    if ($actualTdInfoHash -ne $ExpectedTdInfoHash) {
        throw "TDREPORT TEE_INFO_HASH $actualTdInfoHash does not match image hash $ExpectedTdInfoHash."
    }

    Write-Host "PASS: Post-start GetTDReport returned a valid report for TD Info Hash $actualTdInfoHash."
}

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'This test requires PowerShell 7.'
}
if (-not (Test-Path -LiteralPath $IgvmFilePath -PathType Leaf)) {
    throw "IGVM file not found: $IgvmFilePath"
}
$IgvmFilePath = (Resolve-Path -LiteralPath $IgvmFilePath).Path
if (-not $HashFilePath) {
    $HashFilePath = "$IgvmFilePath.hash"
}
if (-not (Test-Path -LiteralPath $HashFilePath -PathType Leaf)) {
    throw "IGVM hash file not found: $HashFilePath"
}
$HashFilePath = (Resolve-Path -LiteralPath $HashFilePath).Path
$expectedTdInfoHash = (Get-Content -LiteralPath $HashFilePath -Raw).Trim().ToLowerInvariant()
if ($expectedTdInfoHash -notmatch '^[0-9a-f]{96}$') {
    throw "IGVM hash file must contain exactly 48 bytes of hexadecimal data: $HashFilePath"
}

$troubleshootingDir = Join-Path $PSScriptRoot 'troubleshooting'
$captureScript = Join-Path $troubleshootingDir 'Invoke-GhciVDevDiagnosticCapture.ps1'
if (-not (Test-Path -LiteralPath $captureScript -PathType Leaf)) {
    throw "GHCI diagnostic capture script not found: $captureScript"
}

Initialize-TipHostModules

$workerAnalytic = 'Microsoft-Windows-Hyper-V-Worker-Analytic'
$workerChannelChanged = $false
if ($ExpectedGetQuoteResult -ne 'None') {
    $log = Get-WinEvent -ListLog $workerAnalytic -ErrorAction Stop
    if (-not $log.IsEnabled) {
        & wevtutil.exe sl $workerAnalytic /e:true
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to enable event channel: $workerAnalytic"
        }
        $workerChannelChanged = $true
    }
}

$igvmPathForClosure = $IgvmFilePath
$migTdIdForClosure = $MigTdId
$expectedQuoteForClosure = $ExpectedGetQuoteResult
$timeoutForClosure = $TimeoutSeconds
$settleForClosure = $StartupSettleSeconds
$expectedTdInfoHashForClosure = $expectedTdInfoHash
$quoteStartTime = Get-Date

$reproCommand = {
    $migTd = $null
    try {
        # The bundled Host OS helper configures GhciDevice.LogLevel=Trace,
        # causing the host to issue EnableLogArea on the first WaitForRequest.
        $migTd = New-TestHcsMigTd `
            -Id $migTdIdForClosure `
            -IgvmFilePath $igvmPathForClosure `
            -GuestStateDirectory . `
            -Force
        $migTd | Start-HcsSystem -ErrorAction Stop

        $properties = (Get-HcsSystemProperties -System $migTd -RawJson) |
            ConvertFrom-Json
        if ([string]$properties.State -ne 'Running' -or -not $properties.RuntimeId) {
            throw "MigTD did not reach a running HCS state. State=$($properties.State) RuntimeId=$($properties.RuntimeId)"
        }

        if ($settleForClosure -gt 0) {
            Start-Sleep -Seconds $settleForClosure
        }
        Invoke-MigTdGetReportHealthCheck `
            -MigTd $migTd `
            -ExpectedTdInfoHash $expectedTdInfoHashForClosure

        if ($expectedQuoteForClosure -ne 'None') {
            $expectedEventId = if ($expectedQuoteForClosure -eq 'Success') { 18670 } else { 18672 }
            $unexpectedEventId = if ($expectedQuoteForClosure -eq 'Success') { 18672 } else { 18670 }
            $deadline = (Get-Date).AddSeconds($timeoutForClosure)
            do {
                $unexpected = Get-QuoteEvent `
                    -EventId $unexpectedEventId `
                    -StartTime $quoteStartTime `
                    -VmName $migTdIdForClosure
                if ($unexpected) {
                    throw "GetQuote produced unexpected Worker event $unexpectedEventId`: $($unexpected.Message)"
                }
                $expected = Get-QuoteEvent `
                    -EventId $expectedEventId `
                    -StartTime $quoteStartTime `
                    -VmName $migTdIdForClosure
                if ($expected) {
                    Write-Host "PASS: GetQuote $expectedQuoteForClosure observed as Worker event $expectedEventId."
                    break
                }
                Start-Sleep -Seconds 2
            } while ((Get-Date) -lt $deadline)

            if (-not $expected) {
                throw "GetQuote $expectedQuoteForClosure event $expectedEventId was not observed within $timeoutForClosure seconds."
            }
        }

    }
    finally {
        if ($migTd) {
            Stop-HcsSystem $migTd -ErrorAction SilentlyContinue
            $migTd.Close()
        }
    }
}.GetNewClosure()

try {
    & $captureScript `
        -OutputDir $OutputDir `
        -ReproCommand $reproCommand
}
finally {
    if ($workerChannelChanged) {
        & wevtutil.exe sl $workerAnalytic /e:false
    }
}

$eventOutputDir = Join-Path $OutputDir 'events'
Test-TraceMarker `
    -TraceOutputDir $eventOutputDir `
    -Marker @('EnableLogAreaRequest_Success') `
    -Operation 'wait_for_requests operation 4 (EnableLogArea)'
Test-TraceMarker `
    -TraceOutputDir $eventOutputDir `
    -Marker @('InternalGetReport_TdInfoCached') `
    -Operation 'startup internal TDINFO cache'
Test-TraceMarker `
    -TraceOutputDir $eventOutputDir `
    -Marker @('CreateMigTdGetReportRequest') `
    -Operation 'post-start external GetTDReport creation'
Test-TraceMarker `
    -TraceOutputDir $eventOutputDir `
    -Marker @('GetTdReportRequest_Success') `
    -Operation 'wait_for_requests operation 3 (external GetTDReport)'

[pscustomobject]@{
    MigTdId = $MigTdId
    EnableLogArea = 'PASS'
    InternalTDInfoCache = 'PASS'
    ExternalGetTDReport = 'PASS'
    GetQuote = $ExpectedGetQuoteResult
    DiagnosticBundle = (Resolve-Path -LiteralPath $OutputDir).Path
} | Format-List
