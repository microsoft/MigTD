<#
.SYNOPSIS
  Export a normalized MigTD/Hyper-V migration timeline from an ETL trace.

.DESCRIPTION
  Uses tracerpt.exe to decode an ETL, then streams the XML and writes selected
  Hyper-V events as CSV, CLIXML, JSON summary, and compact text. By default,
  only migration-relevant events from Hyper-V and GHCI providers are retained.

.EXAMPLE
  .\Export-MigTdMigrationTimeline.ps1 `
      -EtlPath .\td_source.etl `
      -Node Source `
      -OutputDir .\source-timeline

.EXAMPLE
  .\Export-MigTdMigrationTimeline.ps1 `
      -EtlPath .\td_dest.etl `
      -Node Destination `
      -OutputDir .\destination-timeline `
      -IncludeAllEvents `
      -KeepXml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$EtlPath,
    [string]$OutputDir,
    [string]$Node = $env:COMPUTERNAME,
    [string]$ProviderPattern = '(?i)(Hyper|Ghci)',
    [string]$EventPattern = '(?i)(mig|tdx|servtd|ghci|bind|compat|request|send|receive|cancel|timeout|error|fail|connect|message|report|status|prebind|rebind)',
    [switch]$IncludeAllEvents,
    [switch]$KeepXml,
    [ValidateRange(64, 65536)] [int]$MaxDataValueLength = 1024
)

$ErrorActionPreference = 'Stop'

function Get-XmlChildText {
    param(
        [AllowNull()] [System.Xml.XmlNode]$Parent,
        [Parameter(Mandatory)] [string]$Name
    )

    if (-not $Parent) {
        return ''
    }
    $child = @($Parent.ChildNodes | Where-Object LocalName -eq $Name |
        Select-Object -First 1)
    if ($child.Count -eq 0) {
        return ''
    }
    return [string]$child[0].InnerText
}

function Get-XmlAttribute {
    param(
        [AllowNull()] [System.Xml.XmlNode]$Node,
        [Parameter(Mandatory)] [string]$Name
    )

    if (-not $Node -or -not $Node.Attributes) {
        return ''
    }
    $attribute = $Node.Attributes[$Name]
    if (-not $attribute) {
        return ''
    }
    return [string]$attribute.Value
}

function Convert-DataValue {
    param([AllowNull()] [string]$Value)

    if ($null -eq $Value) {
        return ''
    }
    $normalized = $Value -replace '[\r\n\t]+', ' '
    if ($normalized.Length -gt $MaxDataValueLength) {
        return $normalized.Substring(0, $MaxDataValueLength) + '...'
    }
    return $normalized
}

if (-not (Test-Path -LiteralPath $EtlPath -PathType Leaf)) {
    throw "ETL file not found: $EtlPath"
}
$EtlPath = (Resolve-Path -LiteralPath $EtlPath).Path

if (-not $OutputDir) {
    $OutputDir = Join-Path `
        (Split-Path -Parent $EtlPath) `
        ((Split-Path -LeafBase $EtlPath) + '-migration-timeline')
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

$tracerpt = Get-Command tracerpt.exe -ErrorAction Stop
$xmlPath = Join-Path $OutputDir 'tracerpt.xml'
$tracerptLogPath = Join-Path $OutputDir 'tracerpt.log'
$csvPath = Join-Path $OutputDir 'migtd-migration-timeline.csv'
$clixmlPath = Join-Path $OutputDir 'migtd-migration-timeline.clixml'
$textPath = Join-Path $OutputDir 'migtd-migration-timeline.txt'
$summaryPath = Join-Path $OutputDir 'summary.json'

& $tracerpt.Source $EtlPath -of XML -o $xmlPath -y *> $tracerptLogPath
if ($LASTEXITCODE -ne 0) {
    throw "tracerpt failed to decode $EtlPath. See $tracerptLogPath."
}

$events = [System.Collections.Generic.List[object]]::new()
$decodedEventCount = 0
$readerSettings = [System.Xml.XmlReaderSettings]::new()
$readerSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
$readerSettings.XmlResolver = $null
$reader = [System.Xml.XmlReader]::Create($xmlPath, $readerSettings)

try {
    while ($reader.Read()) {
        if ($reader.NodeType -ne [System.Xml.XmlNodeType]::Element -or
            $reader.LocalName -ne 'Event') {
            continue
        }

        $eventXml = $reader.ReadOuterXml()
        if (-not $eventXml) {
            continue
        }
        $decodedEventCount++

        try {
            [xml]$document = $eventXml
        }
        catch {
            Write-Warning "Skipping malformed event XML at decoded event $decodedEventCount."
            continue
        }

        $event = $document.DocumentElement
        $system = @($event.ChildNodes | Where-Object LocalName -eq 'System' |
            Select-Object -First 1)
        if ($system.Count -eq 0) {
            continue
        }
        $system = $system[0]

        $providerNode = @($system.ChildNodes | Where-Object LocalName -eq 'Provider' |
            Select-Object -First 1)
        $timeNode = @($system.ChildNodes | Where-Object LocalName -eq 'TimeCreated' |
            Select-Object -First 1)
        $executionNode = @($system.ChildNodes | Where-Object LocalName -eq 'Execution' |
            Select-Object -First 1)

        $provider = if ($providerNode.Count) {
            Get-XmlAttribute $providerNode[0] 'Name'
        } else {
            ''
        }
        $providerGuid = if ($providerNode.Count) {
            Get-XmlAttribute $providerNode[0] 'Guid'
        } else {
            ''
        }
        if ($provider -notmatch $ProviderPattern -and
            $providerGuid -notmatch $ProviderPattern) {
            continue
        }

        $dataPairs = [System.Collections.Generic.List[string]]::new()
        $eventData = @($event.ChildNodes | Where-Object LocalName -eq 'EventData' |
            Select-Object -First 1)
        if ($eventData.Count) {
            $unnamedIndex = 0
            foreach ($dataNode in @($eventData[0].GetElementsByTagName('Data'))) {
                $name = Get-XmlAttribute $dataNode 'Name'
                if (-not $name) {
                    $name = "Data$unnamedIndex"
                    $unnamedIndex++
                }
                $value = Convert-DataValue ([string]$dataNode.InnerText)
                $dataPairs.Add("$name=$value")
                $signedValue = 0L
                if ($name -match '(?i)(hresult|resulthr)$' -and
                    [int64]::TryParse($value.Trim(), [ref]$signedValue)) {
                    $numericValue = if ($signedValue -lt 0) {
                        [uint64]($signedValue + 0x100000000)
                    } else {
                        [uint64]$signedValue
                    }
                    $dataPairs.Add(
                        ('{0}Hex=0x{1:X8}' -f $name, $numericValue)
                    )
                }
            }
        }

        $userData = @($event.ChildNodes | Where-Object LocalName -eq 'UserData' |
            Select-Object -First 1)
        if ($userData.Count) {
            foreach ($dataNode in @($userData[0].GetElementsByTagName('*') |
                    Where-Object {
                        $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and
                        -not @($_.ChildNodes | Where-Object {
                            $_.NodeType -eq [System.Xml.XmlNodeType]::Element
                        }).Count
                    })) {
                $name = [string]$dataNode.LocalName
                $value = Convert-DataValue ([string]$dataNode.InnerText)
                $dataPairs.Add("$name=$value")
            }
        }

        $renderingInfo = @($event.ChildNodes |
            Where-Object LocalName -eq 'RenderingInfo' |
            Select-Object -First 1)
        $renderingInfo = if ($renderingInfo.Count) {
            $renderingInfo[0]
        } else {
            $null
        }
        $renderedTask = Get-XmlChildText $renderingInfo 'Task'
        $renderedOpcode = Get-XmlChildText $renderingInfo 'Opcode'
        $renderedLevel = Get-XmlChildText $renderingInfo 'Level'
        $message = Get-XmlChildText $renderingInfo 'Message'
        if ($message) {
            $dataPairs.Add('Message=' + (Convert-DataValue $message))
        }

        $task = if ($renderedTask) {
            $renderedTask
        } else {
            Get-XmlChildText $system 'Task'
        }
        $opcode = if ($renderedOpcode) {
            $renderedOpcode
        } else {
            Get-XmlChildText $system 'Opcode'
        }
        $level = Get-XmlChildText $system 'Level'
        $eventId = Get-XmlChildText $system 'EventID'
        $data = $dataPairs -join '; '
        $relevanceText = "$provider $task $opcode $data"
        $isErrorLevel = $level -in @('1', '2')
        if (-not $IncludeAllEvents -and
            -not $isErrorLevel -and
            $relevanceText -notmatch $EventPattern) {
            continue
        }

        $timeCreated = if ($timeNode.Count) {
            Get-XmlAttribute $timeNode[0] 'SystemTime'
        } else {
            ''
        }
        $timestamp = [datetimeoffset]::MinValue
        if ($timeCreated) {
            [datetimeoffset]::TryParse(
                $timeCreated,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AllowWhiteSpaces,
                [ref]$timestamp
            ) | Out-Null
        }

        $processId = if ($executionNode.Count) {
            Get-XmlAttribute $executionNode[0] 'ProcessID'
        } else {
            ''
        }
        $threadId = if ($executionNode.Count) {
            Get-XmlAttribute $executionNode[0] 'ThreadID'
        } else {
            ''
        }

        $events.Add([pscustomobject]@{
            TimeCreated = $timeCreated
            TimestampUtc = if ($timestamp -ne [datetimeoffset]::MinValue) {
                $timestamp.UtcDateTime.ToString('o')
            } else {
                ''
            }
            Node = $Node
            Provider = $provider
            ProviderGuid = $providerGuid
            EventId = $eventId
            Level = $level
            LevelName = $renderedLevel
            Task = $task
            Opcode = $opcode
            ProcessId = $processId
            ThreadId = $threadId
            Data = $data
        })
    }
}
finally {
    $reader.Dispose()
}

$orderedEvents = @($events | Sort-Object {
    if ($_.TimestampUtc) {
        [datetimeoffset]::Parse($_.TimestampUtc)
    } else {
        [datetimeoffset]::MaxValue
    }
})

$orderedEvents | Export-Csv -LiteralPath $csvPath -NoTypeInformation
$orderedEvents | Export-Clixml -LiteralPath $clixmlPath
$orderedEvents | ForEach-Object {
    '{0} | {1} | L{2} {3} | {4} | {5} | {6}' -f
        $_.TimeCreated, $_.Node, $_.Level, $_.LevelName, $_.Provider,
        $_.Task, $_.Data
} | Set-Content -LiteralPath $textPath

$summary = [ordered]@{
    EtlPath = $EtlPath
    Node = $Node
    DecodedEventCount = $decodedEventCount
    SelectedEventCount = $orderedEvents.Count
    ProviderPattern = $ProviderPattern
    EventPattern = if ($IncludeAllEvents) { $null } else { $EventPattern }
    FirstEvent = if ($orderedEvents.Count) { $orderedEvents[0].TimeCreated } else { $null }
    LastEvent = if ($orderedEvents.Count) { $orderedEvents[-1].TimeCreated } else { $null }
    CsvPath = $csvPath
    ClixmlPath = $clixmlPath
    TextPath = $textPath
}
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $summaryPath

if (-not $KeepXml) {
    Remove-Item -LiteralPath $xmlPath -Force
}

Write-Host "Selected $($orderedEvents.Count) of $decodedEventCount decoded events."
Write-Host "Migration timeline: $OutputDir"
