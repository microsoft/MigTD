<#
.SYNOPSIS
  Verify that the host MigTdHash equals the runtime TD Info Hash.
#>
[CmdletBinding()]
param(
    [string]$SerialLogPath,
    [string]$HashFilePath,
    [string]$TdInfoHash,
    [string]$MigTdHash,
    [uint16]$ServTdType = 0,
    [uint64]$ServTdAttr = 0
)

$ErrorActionPreference = 'Stop'

function Convert-HexToBytes {
    param([Parameter(Mandatory)] [string]$Hex)
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return $bytes
}

function Convert-BytesToHex {
    param([Parameter(Mandatory)] [byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

if (-not $TdInfoHash) {
    if (-not $SerialLogPath -or -not (Test-Path $SerialLogPath)) {
        throw 'Provide -TdInfoHash or an existing -SerialLogPath'
    }
    $match = Select-String -Path $SerialLogPath -Pattern 'TD Info Hash:\s*([0-9a-fA-F]{96})' |
        Select-Object -Last 1
    if (-not $match) {
        throw "No 96-hex-digit TD Info Hash found in $SerialLogPath"
    }
    $TdInfoHash = $match.Matches[0].Groups[1].Value
}

if (-not $MigTdHash) {
    if (-not $HashFilePath -or -not (Test-Path $HashFilePath)) {
        throw 'Provide -MigTdHash or an existing -HashFilePath'
    }
    $MigTdHash = (Get-Content $HashFilePath -Raw).Trim()
}

if ($TdInfoHash -notmatch '^[0-9a-fA-F]{96}$') {
    throw 'TD Info Hash must be exactly 96 hexadecimal characters'
}
if ($MigTdHash -notmatch '^[0-9a-fA-F]{96}$') {
    throw 'MigTdHash must be exactly 96 hexadecimal characters'
}

$tdInfoHashNormalized = $TdInfoHash.ToLowerInvariant()
$migTdHashNormalized = $MigTdHash.ToLowerInvariant()

# The composite SERVTD_HASH is useful in TDREPORT verification, but Hyper-V's
# MigTdHash is passed directly to TDH.SERVTD.PREBIND and must be SERVTD_INFO_HASH.
$inner = Convert-HexToBytes $tdInfoHashNormalized
$typeBytes = [BitConverter]::GetBytes($ServTdType)
$attrBytes = [BitConverter]::GetBytes($ServTdAttr)
if (-not [BitConverter]::IsLittleEndian) {
    [Array]::Reverse($typeBytes)
    [Array]::Reverse($attrBytes)
}

$buffer = [byte[]]::new($inner.Length + $typeBytes.Length + $attrBytes.Length)
[Array]::Copy($inner, 0, $buffer, 0, $inner.Length)
[Array]::Copy($typeBytes, 0, $buffer, $inner.Length, $typeBytes.Length)
[Array]::Copy($attrBytes, 0, $buffer, $inner.Length + $typeBytes.Length, $attrBytes.Length)

$sha384 = [System.Security.Cryptography.SHA384]::Create()
try {
    $computed = Convert-BytesToHex ($sha384.ComputeHash($buffer))
} finally {
    $sha384.Dispose()
}

[pscustomobject]@{
    TdInfoHash = $tdInfoHashNormalized
    HostMigTdHash = $migTdHashNormalized
    Match = ($tdInfoHashNormalized -eq $migTdHashNormalized)
    ServTdType = $ServTdType
    ServTdAttr = ('0x{0:x}' -f $ServTdAttr)
    CompositeServTdHash = $computed
} | Format-List

if ($tdInfoHashNormalized -ne $migTdHashNormalized) {
    if ($computed -eq $migTdHashNormalized) {
        Write-Error 'MigTdHash is the composite SERVTD_HASH. Use the direct TD Info Hash for Hyper-V prebind.'
    }
    exit 1
}
