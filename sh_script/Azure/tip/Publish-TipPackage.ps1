#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PackageDir,

    [Parameter(Mandatory)]
    [string]$WinBuildRoot,

    [Parameter(Mandatory)]
    [string]$Destination,

    [string]$ArchFlavor = "amd64fre",

    [string]$SecFwFile,

    [switch]$SkipSecFw,

    [switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-ExistingDirectory {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Description not found: $Path"
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function Resolve-TestAutomationBins {
    param(
        [Parameter(Mandatory)]
        [string]$BuildRoot,

        [Parameter(Mandatory)]
        [string]$Flavor
    )

    $candidates = @(
        $BuildRoot
        (Join-Path $BuildRoot "test_automation_bins")
        (Join-Path $BuildRoot "$Flavor\test_automation_bins")
    )

    foreach ($candidate in $candidates) {
        if ((Split-Path $candidate -Leaf) -ieq "test_automation_bins" -and
            (Test-Path -LiteralPath (Join-Path $candidate "vm") -PathType Container)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw "test_automation_bins was not found under '$BuildRoot' for architecture flavor '$Flavor'."
}

function Resolve-FirstFile {
    param(
        [Parameter(Mandatory)]
        [string[]]$Candidates,

        [Parameter(Mandatory)]
        [string]$Description
    )

    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw "$Description was not found. Checked:`n  $($Candidates -join "`n  ")"
}

function Resolve-SecureFirmware {
    param(
        [Parameter(Mandatory)]
        [string]$AutomationBins,

        [Parameter(Mandatory)]
        [string]$BuildRoot,

        [Parameter(Mandatory)]
        [string]$Flavor
    )

    $candidates = @(
        (Join-Path $AutomationBins "vm\test\migration\tdx\secfw_test_GenuineIntel.dll")
        (Join-Path $AutomationBins "vm\test\securefirmware\secfw_test_GenuineIntel.dll")
        (Join-Path $BuildRoot "$Flavor\secfw_test_GenuineIntel.dll")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    $matches = @(
        Get-ChildItem -LiteralPath $AutomationBins `
            -Filter "secfw_test_GenuineIntel.dll" `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
            Select-Object -First 2
    )
    if ($matches.Count -eq 1) {
        return $matches[0].FullName
    }
    if ($matches.Count -gt 1) {
        throw "Multiple Secure Firmware DLLs were found under $AutomationBins. Pass -SecFwFile with the intended file."
    }

    throw "Secure Firmware test DLL was not found under the selected winbuild. Pass -SecFwFile with the matching file or -SkipSecFw when it is already installed."
}

function Copy-DirectoryContent {
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$DestinationPath
    )

    New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
    Get-ChildItem -LiteralPath $Source -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $DestinationPath -Recurse -Force
    }
}

function Get-NormalizedPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($fullPath)
    if ($fullPath.Length -gt $root.Length) {
        return $fullPath.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar)
    }
    return $fullPath
}

function Get-CanonicalPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $normalizedPath = Get-NormalizedPath $Path
    $root = [System.IO.Path]::GetPathRoot($normalizedPath)
    $relativePath = $normalizedPath.Substring($root.Length)
    $segments = $relativePath -split '[\\/]'
    $currentPath = $root

    foreach ($segment in $segments) {
        if (-not $segment) {
            continue
        }
        $candidate = Join-Path $currentPath $segment
        if (Test-Path -LiteralPath $candidate) {
            $item = Get-Item -LiteralPath $candidate -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $target = $item.ResolveLinkTarget($true)
                if ($target) {
                    $currentPath = $target.FullName
                    continue
                }
            }
            $currentPath = $item.FullName
        }
        else {
            $currentPath = $candidate
        }
    }

    return Get-NormalizedPath $currentPath
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Parent
    )

    if ([string]::Equals($Path, $Parent, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $parentPrefix = $Parent
    if (-not $parentPrefix.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $parentPrefix += [System.IO.Path]::DirectorySeparatorChar
    }
    return $Path.StartsWith($parentPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

$resolvedPackageDir = Resolve-ExistingDirectory -Path $PackageDir -Description "TiP package"
$resolvedBuildRoot = Resolve-ExistingDirectory -Path $WinBuildRoot -Description "Winbuild build directory"
$testAutomationBins = Resolve-TestAutomationBins -BuildRoot $resolvedBuildRoot -Flavor $ArchFlavor

$hcsTestSource = Join-Path $testAutomationBins "vm\test\compute\HCSTest"
if (-not (Test-Path -LiteralPath $hcsTestSource -PathType Container)) {
    throw "Prebuilt HCSTest was not found: $hcsTestSource"
}
$hcsTestCoreClr = Join-Path $hcsTestSource "coreclr\Microsoft.HostCompute.Test.PowerShell.v2.dll"
if (-not (Test-Path -LiteralPath $hcsTestCoreClr -PathType Leaf)) {
    throw "HCSTest v2 coreclr binary was not found: $hcsTestCoreClr"
}

$vmgsToolSource = Resolve-FirstFile -Description "VmgsTool.exe" -Candidates @(
    (Join-Path $testAutomationBins "vm\tools\VmgsTool.exe")
    (Join-Path $testAutomationBins "vm\underhill\vmgstool.exe")
)

$resolvedSecFw = $null
if (-not $SkipSecFw) {
    if ($SecFwFile) {
        $resolvedSecFw = Resolve-FirstFile -Description "Secure Firmware test DLL" -Candidates @($SecFwFile)
    }
    else {
        $resolvedSecFw = Resolve-SecureFirmware `
            -AutomationBins $testAutomationBins `
            -BuildRoot $resolvedBuildRoot `
            -Flavor $ArchFlavor
    }
}

$normalizedPackageDir = Get-CanonicalPath $resolvedPackageDir
$normalizedBuildRoot = Get-CanonicalPath $resolvedBuildRoot
$resolvedDestination = Get-CanonicalPath $Destination
$inputPaths = @($normalizedPackageDir, $normalizedBuildRoot)
if ($resolvedSecFw) {
    $inputPaths += Get-CanonicalPath $resolvedSecFw
}
foreach ($inputPath in $inputPaths) {
    if ((Test-PathWithin -Path $resolvedDestination -Parent $inputPath) -or
        (Test-PathWithin -Path $inputPath -Parent $resolvedDestination)) {
        throw "Destination must not be the same as, contain, or be contained by an input path: $inputPath"
    }
}
if (Test-Path -LiteralPath $resolvedDestination) {
    if (-not $Force) {
        throw "Destination already exists: $resolvedDestination. Pass -Force to replace it."
    }
}

$destinationParent = Split-Path $resolvedDestination -Parent
if (-not $destinationParent) {
    throw "Destination must include a parent directory: $Destination"
}
New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null

$stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) "MigTdTipPublish-$([guid]::NewGuid())"
$publishTemp = "$resolvedDestination.publish-$([guid]::NewGuid())"
$destinationBackup = "$resolvedDestination.backup-$([guid]::NewGuid())"
try {
    Copy-DirectoryContent -Source $resolvedPackageDir -DestinationPath $stagingRoot

    $dependenciesDir = Join-Path $stagingRoot "dependencies"
    $hcsTestDestination = Join-Path $dependenciesDir "HCSTest"
    if (Test-Path -LiteralPath $hcsTestDestination) {
        Remove-Item -LiteralPath $hcsTestDestination -Recurse -Force
    }
    Copy-DirectoryContent -Source $hcsTestSource -DestinationPath $hcsTestDestination

    $toolsDir = Join-Path $dependenciesDir "Tools"
    New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    Copy-Item -LiteralPath $vmgsToolSource -Destination (Join-Path $toolsDir "VmgsTool.exe") -Force

    $secFwDir = Join-Path $dependenciesDir "SecFw"
    if ($SkipSecFw -and (Test-Path -LiteralPath $secFwDir)) {
        Remove-Item -LiteralPath $secFwDir -Recurse -Force
    }
    elseif ($resolvedSecFw) {
        New-Item -ItemType Directory -Path $secFwDir -Force | Out-Null
        Copy-Item -LiteralPath $resolvedSecFw -Destination (Join-Path $secFwDir "secfw_test_GenuineIntel.dll") -Force
    }

    $requiredFiles = @(
        (Join-Path $stagingRoot "Install-TipDependencies.ps1")
        (Join-Path $dependenciesDir "PowerTest\PowerTest.psd1")
        (Join-Path $dependenciesDir "PowerTest\TdxLiveMigrationUtilities.psm1")
        (Join-Path $dependenciesDir "PowerTest\HCSUtilities.psm1")
        (Join-Path $dependenciesDir "PowerTest\LiveMigrationUtilities.psm1")
        (Join-Path $dependenciesDir "PowerTest\LiveMigrationTestUtilities.psm1")
        (Join-Path $dependenciesDir "PowerTest\VmgsUtilities.psm1")
        (Join-Path $dependenciesDir "PowerTest\WmiUtilities.psm1")
        (Join-Path $dependenciesDir "PowerTest\IVMUtilities.psm1")
        (Join-Path $hcsTestDestination "HCSTest.psd1")
        (Join-Path $hcsTestDestination "coreclr\Microsoft.HostCompute.Test.PowerShell.v2.dll")
        (Join-Path $toolsDir "VmgsTool.exe")
    )
    if (-not $SkipSecFw) {
        $requiredFiles += Join-Path $dependenciesDir "SecFw\secfw_test_GenuineIntel.dll"
    }
    foreach ($requiredFile in $requiredFiles) {
        if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
            throw "Published package dependency is missing: $requiredFile"
        }
    }

    Copy-Item -LiteralPath $stagingRoot -Destination $publishTemp -Recurse

    $hadDestination = Test-Path -LiteralPath $resolvedDestination
    if ($hadDestination) {
        Move-Item -LiteralPath $resolvedDestination -Destination $destinationBackup
    }
    try {
        Move-Item -LiteralPath $publishTemp -Destination $resolvedDestination
    }
    catch {
        if ($hadDestination -and
            (Test-Path -LiteralPath $destinationBackup) -and
            -not (Test-Path -LiteralPath $resolvedDestination)) {
            Move-Item -LiteralPath $destinationBackup -Destination $resolvedDestination
        }
        throw
    }
    if ($hadDestination -and (Test-Path -LiteralPath $destinationBackup)) {
        Remove-Item -LiteralPath $destinationBackup -Recurse -Force
    }
}
finally {
    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $publishTemp) {
        Remove-Item -LiteralPath $publishTemp -Recurse -Force
    }
}

Write-Host "Published TiP package: $resolvedDestination" -ForegroundColor Green
Write-Host "Winbuild content: $testAutomationBins"
Write-Host "HCSTest: $hcsTestSource"
Write-Host "VmgsTool: $vmgsToolSource"
if ($resolvedSecFw) {
    Write-Host "Secure Firmware: $resolvedSecFw"
}
else {
    Write-Warning "Secure Firmware was intentionally omitted; the target host must already have the correct firmware configured."
}
