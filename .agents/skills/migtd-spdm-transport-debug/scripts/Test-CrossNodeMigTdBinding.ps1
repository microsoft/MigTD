<#
.SYNOPSIS
  Preflight a destination host's cross-node MigTD hash binding.

.DESCRIPTION
  Run this on the destination node before Move-VM. It verifies that the source
  VM's required MigTdHash matches the destination MigTD hash evidence, that the
  destination host mapping contains the hash, and that the mapping points to
  the intended running MigTD HCS instance.

.EXAMPLE
  .\Test-CrossNodeMigTdBinding.ps1 `
      -SourceHashFilePath .\source-migtd.igvm.hash `
      -DestinationSerialLogPath .\destination-migtd.serial.log `
      -DestinationMigTdHcsId 9DC12BB6-66F9-5D1A-BB9C-B7A887C4DE34 `
      -PowerTestPath 'C:\Program Files\WindowsPowerShell\Modules\PowerTest'

.EXAMPLE
  .\Test-CrossNodeMigTdBinding.ps1 `
      -SourceMigTdHash 2f4214e871fd6037a95f71fe9f03a16ae8e0e0c34245acf026538a6db57f0d4145ffb780f25914c44b1484b70d0901a7 `
      -DestinationHashFilePath .\destination-migtd.igvm.hash `
      -DestinationMigTdHcsId 9DC12BB6-66F9-5D1A-BB9C-B7A887C4DE34 `
      -MappingJsonPath .\destination-mappings.json `
      -SkipRunningCheck
#>
[CmdletBinding()]
param(
    [string]$SourceMigTdHash,
    [string]$SourceHashFilePath,
    [string]$DestinationTdInfoHash,
    [string]$DestinationSerialLogPath,
    [string]$DestinationHashFilePath,
    [Parameter(Mandatory)] [string]$DestinationMigTdHcsId,
    [string]$MappingJsonPath,
    [string]$PowerTestPath,
    [string]$HcsTestPath,
    [string]$OutputPath,
    [switch]$RequireRuntimeHash,
    [switch]$SkipRunningCheck
)

$ErrorActionPreference = 'Stop'

function Normalize-MigTdHash {
    param(
        [Parameter(Mandatory)] [string]$Value,
        [Parameter(Mandatory)] [string]$Description
    )

    $normalized = $Value.Trim().ToLowerInvariant()
    if ($normalized -notmatch '^[0-9a-f]{96}$') {
        throw "$Description must contain exactly 96 hexadecimal characters."
    }
    return $normalized
}

function Read-MigTdHashFile {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description not found: $Path"
    }
    return Normalize-MigTdHash `
        -Value (Get-Content -LiteralPath $Path -Raw) `
        -Description $Description
}

function Read-SerialTdInfoHash {
    param([Parameter(Mandatory)] [string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Destination serial log not found: $Path"
    }
    $match = Select-String `
        -LiteralPath $Path `
        -Pattern 'TD Info Hash:\s*([0-9a-fA-F]{96})' |
        Select-Object -Last 1
    if (-not $match) {
        throw "No TD Info Hash was found in destination serial log: $Path"
    }
    return Normalize-MigTdHash `
        -Value $match.Matches[0].Groups[1].Value `
        -Description 'Destination TD Info Hash'
}

function Import-PowerTestMappingModule {
    if (Get-Command Get-VmHostMigrationTdMapping -ErrorAction SilentlyContinue) {
        return
    }
    if (-not $PowerTestPath) {
        throw 'Get-VmHostMigrationTdMapping is unavailable and -PowerTestPath was not supplied.'
    }
    $modulePath = Join-Path $PowerTestPath 'LiveMigrationUtilities.psm1'
    if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
        throw "PowerTest module file not found: $modulePath"
    }
    Import-Module $modulePath -Global -Force -DisableNameChecking
}

function Get-MappingJson {
    if ($MappingJsonPath) {
        if (-not (Test-Path -LiteralPath $MappingJsonPath -PathType Leaf)) {
            throw "Mapping JSON file not found: $MappingJsonPath"
        }
        return (Get-Content -LiteralPath $MappingJsonPath -Raw)
    }

    Import-PowerTestMappingModule
    return (@(Get-VmHostMigrationTdMapping) -join '').Trim()
}

function Import-HcsTestModule {
    if (Get-Command Get-HcsSystem -ErrorAction SilentlyContinue) {
        return
    }
    if ($HcsTestPath) {
        Import-Module $HcsTestPath `
            -ArgumentList @{ UseVersion2 = $true } `
            -Global `
            -Force
    } else {
        Import-Module HCSTest `
            -ArgumentList @{ UseVersion2 = $true } `
            -Global `
            -Force
    }
}

if (-not $SourceMigTdHash) {
    if (-not $SourceHashFilePath) {
        throw 'Provide -SourceMigTdHash or -SourceHashFilePath.'
    }
    $SourceMigTdHash = Read-MigTdHashFile `
        -Path $SourceHashFilePath `
        -Description 'Source MigTD hash file'
} else {
    $SourceMigTdHash = Normalize-MigTdHash `
        -Value $SourceMigTdHash `
        -Description 'Source MigTdHash'
}

$destinationHashEvidence = $null
if ($DestinationTdInfoHash) {
    $DestinationTdInfoHash = Normalize-MigTdHash `
        -Value $DestinationTdInfoHash `
        -Description 'Destination TD Info Hash'
    $destinationHashEvidence = 'ExplicitRuntimeTdInfoHash'
} elseif ($DestinationSerialLogPath) {
    $DestinationTdInfoHash =
        Read-SerialTdInfoHash -Path $DestinationSerialLogPath
    $destinationHashEvidence = 'SerialRuntimeTdInfoHash'
} elseif ($DestinationHashFilePath) {
    $DestinationTdInfoHash = Read-MigTdHashFile `
        -Path $DestinationHashFilePath `
        -Description 'Destination MigTD hash file'
    $destinationHashEvidence = 'BuildArtifactExpectedHash'
} else {
    throw 'Provide destination hash evidence through -DestinationTdInfoHash, -DestinationSerialLogPath, or -DestinationHashFilePath.'
}

$runtimeHashVerified =
    $destinationHashEvidence -in @(
        'ExplicitRuntimeTdInfoHash',
        'SerialRuntimeTdInfoHash'
    )
$hashesMatch = $SourceMigTdHash -eq $DestinationTdInfoHash

$mappingRaw = Get-MappingJson
if (-not $mappingRaw) {
    throw 'Destination host returned empty MigTD mapping data.'
}
$mappingObject =
    $mappingRaw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
if (-not $mappingObject.ContainsKey('mappings') -or
    -not $mappingObject.mappings) {
    throw 'Destination mapping JSON does not contain a mappings object.'
}

$mappingValue = $null
foreach ($entry in $mappingObject.mappings.GetEnumerator()) {
    if ([string]$entry.Key -ieq $SourceMigTdHash) {
        $mappingValue = [string]$entry.Value
        break
    }
}
$mappingExists = $null -ne $mappingValue
$mappingTargetMatches =
    $mappingExists -and
    $mappingValue -ieq $DestinationMigTdHcsId

$runningState = 'Skipped'
$runtimeId = $null
$runningCheckPassed = $true
if (-not $SkipRunningCheck) {
    $system = $null
    try {
        Import-HcsTestModule
        $system = Get-HcsSystem -Id $DestinationMigTdHcsId -ErrorAction Stop
        $properties = (Get-HcsSystemProperties -System $system -RawJson) |
            ConvertFrom-Json
        $runningState = [string]$properties.State
        $runtimeId = [string]$properties.RuntimeId
        $runningCheckPassed =
            $runningState -eq 'Running' -and [bool]$runtimeId
    }
    catch {
        $runningState = "Unavailable: $($_.Exception.Message)"
        $runningCheckPassed = $false
    }
    finally {
        if ($system -and -not $system.IsClosed) {
            $system.Close()
        }
    }
}

$checks = [ordered]@{
    SourceAndDestinationHashesMatch = $hashesMatch
    MappingKeyExists = $mappingExists
    MappingTargetsExpectedMigTd = $mappingTargetMatches
    DestinationMigTdRunning = if ($SkipRunningCheck) {
        $null
    } else {
        $runningCheckPassed
    }
    RunningCheckSkipped = [bool]$SkipRunningCheck
    RuntimeHashVerified = $runtimeHashVerified
}
$requiredChecksPassed =
    $hashesMatch -and
    $mappingExists -and
    $mappingTargetMatches -and
    $runningCheckPassed -and
    (-not $RequireRuntimeHash -or $runtimeHashVerified)

$result = [pscustomobject]@{
    Passed = $requiredChecksPassed
    SourceRequiredMigTdHash = $SourceMigTdHash
    DestinationMigTdHash = $DestinationTdInfoHash
    DestinationHashEvidence = $destinationHashEvidence
    DestinationMigTdHcsId = $DestinationMigTdHcsId
    MappingValue = $mappingValue
    DestinationHcsState = $runningState
    DestinationRuntimeId = $runtimeId
    Checks = [pscustomobject]$checks
}

$result | Format-List
$result.Checks | Format-List
if ($OutputPath) {
    $parent = Split-Path -Parent $OutputPath
    if ($parent) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath
    Write-Host "Binding preflight result: $OutputPath"
}

if (-not $runtimeHashVerified) {
    Write-Warning 'Destination hash came from a build artifact, not runtime TD Info Hash evidence. Add -RequireRuntimeHash to make that a required check.'
}
if (-not $requiredChecksPassed) {
    throw 'Cross-node MigTD binding preflight failed.'
}

Write-Host 'PASS: cross-node MigTD hash, mapping, and destination instance checks succeeded.'
