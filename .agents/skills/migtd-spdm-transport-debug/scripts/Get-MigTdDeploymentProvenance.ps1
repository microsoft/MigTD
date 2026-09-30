<#
.SYNOPSIS
  Capture MigTD deployment, host, repository, image, hash, and mapping provenance.

.DESCRIPTION
  Writes a reusable JSON/CLIXML/text bundle describing the host build, supplied
  repositories, IGVM artifacts, `.igvm.hash` files, serial TD Info Hash values,
  host MigTD mappings, and optional running HCS systems.

.EXAMPLE
  .\Get-MigTdDeploymentProvenance.ps1 `
      -MigTdRepoPath C:\src\MigTD `
      -OsRepoPath C:\src\os.2020 `
      -IgvmFilePath .\test-migtd-accept-all.igvm `
      -HashFilePath .\test-migtd-accept-all.igvm.hash `
      -SerialLogPath .\tipmigtd.serial.log `
      -MigTdHcsId 9DC12BB6-66F9-5D1A-BB9C-B7A887C4DE34 `
      -PowerTestPath 'C:\Program Files\WindowsPowerShell\Modules\PowerTest'
#>
[CmdletBinding()]
param(
    [string[]]$IgvmFilePath,
    [string[]]$HashFilePath,
    [string[]]$SerialLogPath,
    [string[]]$MigTdHcsId,
    [string]$MigTdRepoPath,
    [string]$OsRepoPath,
    [string]$IgvmAgentRepoPath,
    [string]$PowerTestPath,
    [string]$HcsTestPath,
    [string]$OutputDir,
    [switch]$SkipHostMappings,
    [switch]$SkipHcsSystems
)

$ErrorActionPreference = 'Stop'

function Get-ResolvedPathOrNull {
    param([AllowNull()] [string]$Path)

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    $resolved = Resolve-Path -LiteralPath $Path
    if ($resolved.ProviderPath) {
        return $resolved.ProviderPath
    }
    return $resolved.Path
}

function Invoke-GitText {
    param(
        [Parameter(Mandatory)] [string]$RepositoryPath,
        [Parameter(Mandatory)] [string[]]$GitArguments
    )

    $wrapper = Join-Path $RepositoryPath 'git.cmd'
    $stderrPath = [System.IO.Path]::GetTempFileName()
    try {
        if (Test-Path -LiteralPath $wrapper -PathType Leaf) {
            Push-Location $RepositoryPath
            try {
                $output = @(& $wrapper @GitArguments 2> $stderrPath)
                $exitCode = $LASTEXITCODE
            }
            finally {
                Pop-Location
            }
        } else {
            $git = Get-Command git -ErrorAction Stop
            $output = @(& $git.Source -C $RepositoryPath @GitArguments 2> $stderrPath)
            $exitCode = $LASTEXITCODE
        }
        $stderr = if (Test-Path -LiteralPath $stderrPath) {
            @(Get-Content -LiteralPath $stderrPath)
        } else {
            @()
        }
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Text = $null
            Error = $_.Exception.Message
        }
    }
    finally {
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }

    $text = ($output | ForEach-Object { [string]$_ } |
        Where-Object { $_.Trim() } | Select-Object -Last 1)
    return [pscustomobject]@{
        Success = ($exitCode -eq 0)
        Text = if ($exitCode -eq 0) { $text } else { $null }
        Error = if ($exitCode -eq 0) {
            $null
        } else {
            (@($stderr + $output) -join [Environment]::NewLine)
        }
    }
}

function Get-GitProvenance {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [AllowNull()] [string]$Path
    )

    $resolvedPath = Get-ResolvedPathOrNull $Path
    if (-not $resolvedPath) {
        return [pscustomobject]@{
            Name = $Name
            Path = $Path
            Available = $false
            Remote = $null
            Branch = $null
            Commit = $null
            Dirty = $null
            Error = if ($Path) { 'Repository path not found.' } else { 'Not supplied.' }
        }
    }

    $gitPath = $resolvedPath
    if ((Test-Path -LiteralPath (Join-Path $resolvedPath 'git.cmd') -PathType Leaf) -and
        (Test-Path -LiteralPath (Join-Path $resolvedPath 'src') -PathType Container)) {
        $gitPath = Join-Path $resolvedPath 'src'
    }
    $remote = Invoke-GitText $gitPath @('remote', 'get-url', 'origin')
    $branch = Invoke-GitText $gitPath @('branch', '--show-current')
    $commit = Invoke-GitText $gitPath @('rev-parse', 'HEAD')
    $status = Invoke-GitText $gitPath @('status', '--porcelain')
    $errors = @(@($remote, $branch, $commit, $status) |
        Where-Object { -not $_.Success -and $_.Error } |
        ForEach-Object { $_.Error })

    return [pscustomobject]@{
        Name = $Name
        Path = $resolvedPath
        Available = ($commit.Success)
        Remote = $remote.Text
        Branch = $branch.Text
        Commit = $commit.Text
        Dirty = if ($status.Success) { [bool]$status.Text } else { $null }
        Error = if ($errors.Count) { $errors -join ' | ' } else { $null }
    }
}

function Get-FileProvenance {
    param(
        [Parameter(Mandatory)] [string]$Kind,
        [Parameter(Mandatory)] [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{
            Kind = $Kind
            Path = $Path
            Available = $false
            Length = $null
            LastWriteTimeUtc = $null
            Sha256 = $null
            MigTdHash = $null
            Error = 'File not found.'
        }
    }

    $resolvedPath = Get-ResolvedPathOrNull $Path
    $item = Get-Item -LiteralPath $resolvedPath
    $sha256 = ((Get-FileHash `
        -LiteralPath $resolvedPath `
        -Algorithm SHA256).Hash).ToLowerInvariant()
    $migTdHash = $null
    $errorMessage = $null
    if ($Kind -eq 'HashFile') {
        $value = (Get-Content -LiteralPath $resolvedPath -Raw).Trim()
        if ($value -match '^[0-9a-fA-F]{96}$') {
            $migTdHash = $value.ToLowerInvariant()
        } else {
            $errorMessage = 'Hash file does not contain exactly 96 hexadecimal characters.'
        }
    }

    return [pscustomobject]@{
        Kind = $Kind
        Path = $resolvedPath
        Available = $true
        Length = $item.Length
        LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString('o')
        Sha256 = $sha256
        MigTdHash = $migTdHash
        Error = $errorMessage
    }
}

function Get-SerialHashProvenance {
    param([Parameter(Mandatory)] [string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{
            Path = $Path
            Available = $false
            TdInfoHashes = @()
            LastTdInfoHash = $null
            Error = 'Serial log not found.'
        }
    }

    $resolvedPath = Get-ResolvedPathOrNull $Path
    $matches = @(Select-String `
        -LiteralPath $resolvedPath `
        -Pattern 'TD Info Hash:\s*([0-9a-fA-F]{96})')
    $hashes = @($matches | ForEach-Object {
        $_.Matches[0].Groups[1].Value.ToLowerInvariant()
    })
    return [pscustomobject]@{
        Path = $resolvedPath
        Available = $true
        TdInfoHashes = $hashes
        LastTdInfoHash = if ($hashes.Count) { $hashes[-1] } else { $null }
        Error = if ($hashes.Count) {
            $null
        } else {
            'No TD Info Hash line was found.'
        }
    }
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

function Get-MappingProvenance {
    try {
        Import-PowerTestMappingModule
        $raw = (@(Get-VmHostMigrationTdMapping) -join '').Trim()
        if (-not $raw) {
            return [pscustomobject]@{
                Available = $true
                RawJson = $raw
                Entries = @()
                Error = $null
            }
        }

        $parsed = $raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        $entries = [System.Collections.Generic.List[object]]::new()
        if ($parsed.ContainsKey('mappings') -and $parsed.mappings) {
            foreach ($entry in $parsed.mappings.GetEnumerator()) {
                $entries.Add([pscustomobject]@{
                    MigTdHash = ([string]$entry.Key).ToLowerInvariant()
                    MigTdHcsId = [string]$entry.Value
                })
            }
        }
        return [pscustomobject]@{
            Available = $true
            RawJson = $raw
            Entries = @($entries)
            Error = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Available = $false
            RawJson = $null
            Entries = @()
            Error = $_.Exception.Message
        }
    }
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

function Get-HcsSystemProvenance {
    param([Parameter(Mandatory)] [string]$Id)

    $system = $null
    try {
        Import-HcsTestModule
        $system = Get-HcsSystem -Id $Id -ErrorAction Stop
        $rawProperties = Get-HcsSystemProperties -System $system -RawJson
        $properties = $rawProperties | ConvertFrom-Json
        return [pscustomobject]@{
            Id = $Id
            Available = $true
            State = [string]$properties.State
            RuntimeId = [string]$properties.RuntimeId
            IsClosed = [bool]$system.IsClosed
            Error = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Id = $Id
            Available = $false
            State = $null
            RuntimeId = $null
            IsClosed = $null
            Error = $_.Exception.Message
        }
    }
    finally {
        if ($system -and -not $system.IsClosed) {
            $system.Close()
        }
    }
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $OutputDir) {
    $OutputDir = Join-Path `
        (Get-Location) `
        "migtd-provenance-$($env:COMPUTERNAME)-$timestamp"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

$osRegistry = Get-ItemProperty `
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$hostInfo = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    CapturedAt = [datetimeoffset]::Now.ToString('o')
    ProductName = [string]$osRegistry.ProductName
    DisplayVersion = [string]$osRegistry.DisplayVersion
    CurrentBuild = [string]$osRegistry.CurrentBuildNumber
    Ubr = [string]$osRegistry.UBR
    BuildLabEx = [string]$osRegistry.BuildLabEx
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    PowerShellEdition = $PSVersionTable.PSEdition
}

$repositories = @(
    Get-GitProvenance -Name MigTD -Path $MigTdRepoPath
    Get-GitProvenance -Name WindowsOS -Path $OsRepoPath
    Get-GitProvenance -Name IgvmAgent -Path $IgvmAgentRepoPath
)

$files = [System.Collections.Generic.List[object]]::new()
foreach ($path in @($IgvmFilePath | Where-Object { $_ })) {
    $files.Add((Get-FileProvenance -Kind Igvm -Path $path))
}
foreach ($path in @($HashFilePath | Where-Object { $_ })) {
    $files.Add((Get-FileProvenance -Kind HashFile -Path $path))
}

$serialLogs = @($SerialLogPath | Where-Object { $_ } |
    ForEach-Object { Get-SerialHashProvenance -Path $_ })
$mappings = if ($SkipHostMappings) {
    [pscustomobject]@{
        Available = $false
        RawJson = $null
        Entries = @()
        Error = 'Skipped by caller.'
    }
} else {
    Get-MappingProvenance
}
$hcsSystems = if ($SkipHcsSystems) {
    @()
} else {
    @($MigTdHcsId | Where-Object { $_ } |
        ForEach-Object { Get-HcsSystemProvenance -Id $_ })
}

$tools = @('wpr.exe', 'tracerpt.exe', 'logman.exe', 'wevtutil.exe', 'git') |
    ForEach-Object {
        $command = Get-Command $_ -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Name = $_
            Available = [bool]$command
            Path = if ($command) { $command.Source } else { $null }
            Version = if ($command -and $command.Version) {
                $command.Version.ToString()
            } else {
                $null
            }
        }
    }

$provenance = [ordered]@{
    Host = $hostInfo
    Repositories = $repositories
    Files = @($files)
    SerialLogs = $serialLogs
    HostMappings = $mappings
    HcsSystems = @($hcsSystems)
    Tools = @($tools)
}

$jsonPath = Join-Path $OutputDir 'migtd-deployment-provenance.json'
$clixmlPath = Join-Path $OutputDir 'migtd-deployment-provenance.clixml'
$textPath = Join-Path $OutputDir 'migtd-deployment-provenance.txt'
$provenance | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath
$provenance | Export-Clixml -LiteralPath $clixmlPath
@(
    '=== Host ==='
    ($hostInfo | Format-List | Out-String).TrimEnd()
    ''
    '=== Repositories ==='
    ($repositories | Format-Table -AutoSize | Out-String).TrimEnd()
    ''
    '=== Files ==='
    (@($files) | Format-Table -AutoSize | Out-String).TrimEnd()
    ''
    '=== Serial hashes ==='
    ($serialLogs | Format-List | Out-String).TrimEnd()
    ''
    '=== Host mappings ==='
    ($mappings | Format-List | Out-String).TrimEnd()
    ($mappings.Entries | Format-Table -AutoSize | Out-String).TrimEnd()
    ''
    '=== HCS systems ==='
    ($hcsSystems | Format-Table -AutoSize | Out-String).TrimEnd()
    ''
    '=== Tools ==='
    (@($tools) | Format-Table -AutoSize | Out-String).TrimEnd()
) | Set-Content -LiteralPath $textPath

Write-Host "MigTD deployment provenance: $OutputDir"
