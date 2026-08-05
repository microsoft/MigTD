function New-TipHarnessException {
    param(
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [string]$Message
    )

    return [System.Exception]::new("[$Category] $Message")
}

function Get-TipHashEvidencePath {
    param([Parameter(Mandatory)] [string]$HashFilePath)

    return "$HashFilePath.evidence.json"
}

function Get-TipErrorCategory {
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord]$ErrorRecord)

    $text = [string]$ErrorRecord.Exception.Message
    $match = [regex]::Match($text, '^\[(?<category>[A-Z_]+)\]\s+')
    if ($match.Success) {
        return $match.Groups['category'].Value
    }
    return 'GENERIC_FAILURE'
}

function Convert-TipErrorRecordToString {
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord]$ErrorRecord)

    return ($ErrorRecord | Format-List * -Force | Out-String).Trim()
}

function Test-TipExpectedRejectionError {
    param([Parameter(Mandatory)] [object]$ErrorDetail)

    $text = [string]$ErrorDetail
    return $text -match 'MIGPOLICY_UNSATISFIED_ERROR|0x800721CE|external policy|policy unsatisfied|host permits'
}

function Resolve-TipMigTdHashFromFiles {
    param(
        [Parameter(Mandatory)] [string]$IgvmFilePath,
        [Parameter(Mandatory)] [string]$HashFilePath,
        [switch]$SkipHashEvidenceValidation
    )

    if (-not (Test-Path $IgvmFilePath)) {
        throw (New-TipHarnessException 'PRECONDITION' "IGVM file not found: $IgvmFilePath")
    }
    if (-not (Test-Path $HashFilePath)) {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Sibling hash file not found: $HashFilePath")
    }

    $migTdHash = (Get-Content $HashFilePath -Raw).Trim().ToLowerInvariant()
    if ($migTdHash -notmatch '^[0-9a-f]{96}$') {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Sibling hash must be exactly 96 hexadecimal characters: $HashFilePath")
    }

    $evidencePath = Get-TipHashEvidencePath -HashFilePath $HashFilePath
    if ($SkipHashEvidenceValidation) {
        return [pscustomobject]@{
            MigTdHash = $migTdHash
            HashFilePath = $HashFilePath
            HashEvidencePath = $evidencePath
            IgvmSha256 = $null
            EvidenceVerified = $false
        }
    }

    if (-not (Test-Path $evidencePath)) {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Hash evidence file not found: $evidencePath")
    }

    try {
        $evidence = Get-Content $evidencePath -Raw | ConvertFrom-Json
    } catch {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Hash evidence is not valid JSON: $evidencePath")
    }

    if ([int]$evidence.schemaVersion -ne 1 -or [string]$evidence.evidenceType -ne 'igvm-sibling-hash') {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Unsupported hash evidence schema in $evidencePath")
    }

    $evidenceHash = [string]$evidence.migTdInfoHash
    $evidenceSha256 = [string]$evidence.igvmSha256
    $evidenceIgvmName = [string]$evidence.igvmFileName

    if ($evidenceHash.ToLowerInvariant() -notmatch '^[0-9a-f]{96}$') {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Evidence migTdInfoHash is invalid in $evidencePath")
    }
    if ($evidenceSha256.ToLowerInvariant() -notmatch '^[0-9a-f]{64}$') {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Evidence igvmSha256 is invalid in $evidencePath")
    }
    if ($evidenceIgvmName -and $evidenceIgvmName -ne (Split-Path $IgvmFilePath -Leaf)) {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Evidence igvmFileName mismatch in $evidencePath. Expected $(Split-Path $IgvmFilePath -Leaf) Found $evidenceIgvmName")
    }

    $igvmSha256 = (Get-FileHash -Path $IgvmFilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($igvmSha256 -ne $evidenceSha256.ToLowerInvariant()) {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "IGVM SHA256 mismatch for $IgvmFilePath. Evidence=$evidenceSha256 Actual=$igvmSha256")
    }
    if ($migTdHash -ne $evidenceHash.ToLowerInvariant()) {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Sibling hash mismatch for $IgvmFilePath. HashFile=$migTdHash Evidence=$evidenceHash")
    }

    return [pscustomobject]@{
        MigTdHash = $migTdHash
        HashFilePath = $HashFilePath
        HashEvidencePath = $evidencePath
        IgvmSha256 = $igvmSha256
        EvidenceVerified = $true
    }
}

function Get-TipRuntimeHashRegexes {
    return @(
        'Current TDX migration policy hash:\s*([0-9a-fA-F]{96})',
        'TD Info Hash:\s*([0-9a-fA-F]{96})',
        'Current migration policy:\s*([0-9a-fA-F]{96})'
    )
}

function Get-TipRuntimeHashesFromSerialText {
    param([Parameter(Mandatory)] [string]$Text)

    $hashes = [System.Collections.Generic.List[string]]::new()
    foreach ($pattern in (Get-TipRuntimeHashRegexes)) {
        foreach ($match in [regex]::Matches($Text, $pattern)) {
            if ($match.Success) {
                $hash = $match.Groups[1].Value.ToLowerInvariant()
                if ($hash -match '^[0-9a-f]{96}$') {
                    $hashes.Add($hash)
                }
            }
        }
    }
    return @($hashes | Select-Object -Unique)
}

function Wait-TipRuntimeHashFromSerialLog {
    param(
        [Parameter(Mandatory)] [string]$LogPath,
        [Parameter(Mandatory)] [int]$TimeoutSeconds,
        [string]$ExpectedHash,
        [string]$Context = 'MigTD'
    )

    $expected = if ($ExpectedHash) { $ExpectedHash.Trim().ToLowerInvariant() } else { $null }
    if ($expected -and $expected -notmatch '^[0-9a-f]{96}$') {
        throw (New-TipHarnessException 'PRECONDITION' "ExpectedHash must be 96 hex chars for $Context.")
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path $LogPath) {
            $text = Get-Content $LogPath -Raw -ErrorAction SilentlyContinue
            if ($text) {
                $hashes = Get-TipRuntimeHashesFromSerialText -Text $text
                if ($hashes.Count -gt 0) {
                    $actual = $hashes[-1]
                    if ($expected -and $actual -ne $expected) {
                        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Runtime TD Info Hash mismatch for '$Context'. Expected=$expected Runtime=$actual Log=$LogPath")
                    }
                    return $actual
                }
            }
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    throw (New-TipHarnessException 'MISSING_EVIDENCE' "Runtime TD Info Hash not found for '$Context' in $LogPath within $TimeoutSeconds seconds.")
}
