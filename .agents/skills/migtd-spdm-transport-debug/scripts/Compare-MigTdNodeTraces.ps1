<#
.SYNOPSIS
  Align normalized source and destination MigTD migration timelines.

.DESCRIPTION
  Consumes CSV files created by Export-MigTdMigrationTimeline.ps1. It selects
  a request-centered time window, applies an optional destination clock
  correction, marks the first destination failure candidate and source
  cancellation, and calculates their time difference.

.EXAMPLE
  .\Compare-MigTdNodeTraces.ps1 `
      -SourceTimelinePath .\source\migtd-migration-timeline.csv `
      -DestinationTimelinePath .\destination\migtd-migration-timeline.csv `
      -RequestId 19 `
      -OutputDir .\comparison
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$SourceTimelinePath,
    [Parameter(Mandatory)] [string]$DestinationTimelinePath,
    [string]$RequestId,
    [string]$OutputDir,
    [ValidateRange(0, 600)] [int]$SecondsBefore = 5,
    [ValidateRange(1, 3600)] [int]$SecondsAfter = 90,
    [ValidateRange(-3600000, 3600000)]
    [int]$DestinationClockOffsetMilliseconds = 0
)

$ErrorActionPreference = 'Stop'

function Convert-ToTimelineEvent {
    param(
        [Parameter(Mandatory)] [object]$Row,
        [Parameter(Mandatory)] [string]$Role,
        [int]$ClockOffsetMilliseconds = 0
    )

    $rawTimestamp = if ($Row.TimestampUtc) {
        [string]$Row.TimestampUtc
    } else {
        [string]$Row.TimeCreated
    }
    $timestamp = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParse(
            $rawTimestamp,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AllowWhiteSpaces,
            [ref]$timestamp)) {
        throw "Unable to parse timeline timestamp '$rawTimestamp'."
    }
    $timestamp = $timestamp.AddMilliseconds($ClockOffsetMilliseconds)

    return [pscustomobject]@{
        Timestamp = $timestamp
        TimeCreated = $timestamp.ToString('o')
        OriginalTimeCreated = [string]$Row.TimeCreated
        Role = $Role
        Node = [string]$Row.Node
        Provider = [string]$Row.Provider
        EventId = [string]$Row.EventId
        Level = [string]$Row.Level
        LevelName = [string]$Row.LevelName
        Task = [string]$Row.Task
        Opcode = [string]$Row.Opcode
        Data = [string]$Row.Data
        Marker = ''
    }
}

function Test-RequestMatch {
    param(
        [Parameter(Mandatory)] [object]$Event,
        [Parameter(Mandatory)] [string]$Id
    )

    $escaped = [regex]::Escape($Id)
    $text = "$($Event.Task) $($Event.Data)"
    if ($text -match "(?i)(RequestId|MigRequestID)\s*=\s*$escaped(?:\D|$)") {
        return $true
    }

    $numericId = 0L
    if ([long]::TryParse($Id, [ref]$numericId)) {
        $hex = '0x{0:X}' -f $numericId
        if ($text -match "(?i)(RequestId|MigRequestID)\s*=\s*$([regex]::Escape($hex))(?:\D|$)") {
            return $true
        }
    }
    return $false
}

function Test-FailureEvent {
    param([Parameter(Mandatory)] [object]$Event)

    if ($Event.Level -in @('1', '2')) {
        return $true
    }
    $text = "$($Event.Task) $($Event.Data)"
    if ($text -match '(?i)\b(fail(?:ed|ure)?|error|timed?\s*out|timeout|unexpected|cancel(?:ed|led|lation)?)\b') {
        return $true
    }
    if ($text -match '(?i)0x(?:8|c)[0-9a-f]{7,15}') {
        return $true
    }
    if ($text -match '(?i)(hresult|resulthr|status)\s*=\s*-\d+') {
        return $true
    }
    return $false
}

foreach ($path in @($SourceTimelinePath, $DestinationTimelinePath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Timeline CSV not found: $path"
    }
}
$SourceTimelinePath = (Resolve-Path -LiteralPath $SourceTimelinePath).Path
$DestinationTimelinePath =
    (Resolve-Path -LiteralPath $DestinationTimelinePath).Path

if (-not $OutputDir) {
    $OutputDir = Join-Path (Get-Location) 'migtd-trace-comparison'
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

$source = @(Import-Csv -LiteralPath $SourceTimelinePath | ForEach-Object {
    Convert-ToTimelineEvent -Row $_ -Role Source
})
$destination = @(Import-Csv -LiteralPath $DestinationTimelinePath |
    ForEach-Object {
        Convert-ToTimelineEvent `
            -Row $_ `
            -Role Destination `
            -ClockOffsetMilliseconds $DestinationClockOffsetMilliseconds
    })

if (-not $source.Count) {
    throw "Source timeline has no events: $SourceTimelinePath"
}
if (-not $destination.Count) {
    throw "Destination timeline has no events: $DestinationTimelinePath"
}

$sourceCreateEvents = @($source | Where-Object {
    $_.Task -match '(?i)CreateTdxPrepare(Migration|Rebinding)Request'
})
$anchor = $null
if ($RequestId) {
    $anchor = @($sourceCreateEvents |
        Where-Object { Test-RequestMatch -Event $_ -Id $RequestId } |
        Sort-Object Timestamp |
        Select-Object -First 1)
    if (-not $anchor.Count) {
        $anchor = @($source |
            Where-Object { Test-RequestMatch -Event $_ -Id $RequestId } |
            Sort-Object Timestamp |
            Select-Object -First 1)
    }
} else {
    $anchor = @($sourceCreateEvents | Sort-Object Timestamp |
        Select-Object -First 1)
}

if (-not $anchor.Count) {
    throw 'No source migration/rebinding request anchor was found.'
}
$anchor = $anchor[0]

if (-not $RequestId) {
    $requestMatch = [regex]::Match(
        "$($anchor.Task) $($anchor.Data)",
        '(?i)RequestId\s*=\s*(\d+)'
    )
    if ($requestMatch.Success) {
        $RequestId = $requestMatch.Groups[1].Value
    }
}

$windowStart = $anchor.Timestamp.AddSeconds(-$SecondsBefore)
$windowEnd = $anchor.Timestamp.AddSeconds($SecondsAfter)
$selectedSource = @($source | Where-Object {
    $_.Timestamp -ge $windowStart -and $_.Timestamp -le $windowEnd
})
$selectedDestination = @($destination | Where-Object {
    $_.Timestamp -ge $windowStart -and $_.Timestamp -le $windowEnd
})

$destinationFailure = @($selectedDestination |
    Where-Object { $_.Timestamp -ge $anchor.Timestamp } |
    Where-Object { Test-FailureEvent $_ } |
    Sort-Object Timestamp |
    Select-Object -First 1)
if ($destinationFailure.Count) {
    $destinationFailure = $destinationFailure[0]
    $destinationFailure.Marker = 'FIRST_DESTINATION_FAILURE_CANDIDATE'
} else {
    $destinationFailure = $null
}

$sourceCancelCandidates = @($selectedSource | Where-Object {
    $_.Task -match '(?i)(PrepareMigrationRequest_Cancel|CancelRequest)'
} | Sort-Object Timestamp)
$sourceCancel = @()
if ($RequestId) {
    $sourceCancel = @($sourceCancelCandidates |
        Where-Object { Test-RequestMatch -Event $_ -Id $RequestId } |
        Select-Object -First 1)
}
if (-not $sourceCancel.Count) {
    $sourceCancel = @($sourceCancelCandidates | Select-Object -First 1)
}
if ($sourceCancel.Count) {
    $sourceCancel = $sourceCancel[0]
    $sourceCancel.Marker = 'SOURCE_CANCELLATION'
} else {
    $sourceCancel = $null
}

foreach ($event in @($selectedSource | Where-Object {
        $_.Task -eq 'MigTdLog' -and
        (-not $RequestId -or (Test-RequestMatch -Event $_ -Id $RequestId) -or
            $_.Data -match 'MigRequestID=0xFFFFFFFFFFFFFFFF')
    })) {
    if (-not $event.Marker) {
        $event.Marker = 'MIGTD_LOG'
    }
}

$combined = @($selectedSource + $selectedDestination |
    Sort-Object Timestamp, Role)
$csvPath = Join-Path $OutputDir 'combined-timeline.csv'
$textPath = Join-Path $OutputDir 'combined-timeline.txt'
$summaryPath = Join-Path $OutputDir 'summary.json'

$combined | Select-Object TimeCreated, OriginalTimeCreated, Role, Node,
    Provider, EventId, Level, LevelName, Task, Data, Marker |
    Export-Csv -LiteralPath $csvPath -NoTypeInformation
$combined | ForEach-Object {
    '{0} | {1} | {2} | L{3} {4} | {5} | {6} | {7}' -f
        $_.TimeCreated, $_.Role, $_.Marker, $_.Level, $_.LevelName,
        $_.Provider, $_.Task, $_.Data
} | Set-Content -LiteralPath $textPath

$delayMilliseconds = $null
if ($destinationFailure -and $sourceCancel) {
    $delayMilliseconds =
        ($sourceCancel.Timestamp - $destinationFailure.Timestamp).TotalMilliseconds
}

$summary = [ordered]@{
    RequestId = $RequestId
    AnchorTime = $anchor.TimeCreated
    WindowStart = $windowStart.ToString('o')
    WindowEnd = $windowEnd.ToString('o')
    DestinationClockOffsetMilliseconds = $DestinationClockOffsetMilliseconds
    SourceEventCount = $selectedSource.Count
    DestinationEventCount = $selectedDestination.Count
    FirstDestinationFailureCandidate = if ($destinationFailure) {
        [ordered]@{
            Time = $destinationFailure.TimeCreated
            Provider = $destinationFailure.Provider
            Task = $destinationFailure.Task
            Data = $destinationFailure.Data
        }
    } else {
        $null
    }
    SourceCancellation = if ($sourceCancel) {
        [ordered]@{
            Time = $sourceCancel.TimeCreated
            Task = $sourceCancel.Task
            Data = $sourceCancel.Data
        }
    } else {
        $null
    }
    FailureToCancellationDelayMilliseconds = $delayMilliseconds
    Warning = 'The first destination failure is a candidate. Confirm it against the exact matching Windows OS source branch before assigning root cause.'
    CombinedTimelineCsv = $csvPath
    CombinedTimelineText = $textPath
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $summaryPath

Write-Host "Request anchor: $($anchor.TimeCreated)  RequestId=$RequestId"
if ($destinationFailure) {
    Write-Host "First destination failure candidate: $($destinationFailure.TimeCreated) $($destinationFailure.Task)"
} else {
    Write-Warning 'No destination failure candidate was found in the selected window.'
}
if ($sourceCancel) {
    Write-Host "Source cancellation: $($sourceCancel.TimeCreated)"
}
if ($null -ne $delayMilliseconds) {
    Write-Host ('Failure-to-cancellation delay: {0:N3} ms' -f $delayMilliseconds)
}
Write-Host "Cross-node comparison: $OutputDir"
