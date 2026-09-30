#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
  Install the dependencies bundled with a MigTD TiP package.

.DESCRIPTION
  Installs PowerTest and HCSTest v2 for PowerShell 7, installs the package's
  matching VmgsTool, and optionally installs test Secure Firmware. Host
  migration settings can also be configured and validated.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PackageDir = $PSScriptRoot,
    [string]$PowerTestInstallRoot = "$env:ProgramFiles\PowerShell\Modules",
    [string]$HcsTestInstallRoot = "$env:ProgramFiles\PowerShell\Modules",
    [string]$VmgsToolInstallPath = "$env:SystemRoot\System32\vmgstool.exe",
    [switch]$SkipSecureFirmware,
    [switch]$ConfigureHost,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function New-StagedModuleDirectory {
    param(
        [Parameter(Mandatory)] [string]$Source,
        [Parameter(Mandatory)] [string]$Destination,
        [Parameter(Mandatory)] [string]$Manifest
    )

    $manifestPath = Join-Path $Source $Manifest
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Bundled module manifest not found: $manifestPath"
    }
    $destinationParent = Split-Path $Destination -Parent
    New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
    $stagingPath = "$Destination.install-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null
    Get-ChildItem -LiteralPath $Source -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $stagingPath -Recurse -Force
    }
    Test-ModuleManifest -Path (Join-Path $stagingPath $Manifest) -ErrorAction Stop | Out-Null
    return $stagingPath
}

function Install-StagedModuleDirectories {
    param(
        [Parameter(Mandatory)]
        [object[]]$Modules
    )

    $installed = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($module in $Modules) {
            if (-not $PSCmdlet.ShouldProcess($module.Destination, "Install module from $($module.Source)")) {
                continue
            }
            $backup = "$($module.Destination).backup-$([guid]::NewGuid())"
            $hadDestination = Test-Path -LiteralPath $module.Destination
            if ($hadDestination) {
                Move-Item -LiteralPath $module.Destination -Destination $backup
            }
            try {
                Move-Item -LiteralPath $module.StagingPath -Destination $module.Destination
            }
            catch {
                if ($hadDestination -and
                    (Test-Path -LiteralPath $backup) -and
                    -not (Test-Path -LiteralPath $module.Destination)) {
                    Move-Item -LiteralPath $backup -Destination $module.Destination
                }
                throw
            }
            $installed.Add([pscustomobject]@{
                Destination = $module.Destination
                Backup = $backup
                HadDestination = $hadDestination
            })
        }
    }
    catch {
        for ($index = $installed.Count - 1; $index -ge 0; $index--) {
            $entry = $installed[$index]
            if (Test-Path -LiteralPath $entry.Destination) {
                Remove-Item -LiteralPath $entry.Destination -Recurse -Force
            }
            if ($entry.HadDestination -and (Test-Path -LiteralPath $entry.Backup)) {
                Move-Item -LiteralPath $entry.Backup -Destination $entry.Destination
            }
        }
        throw
    }

    foreach ($entry in $installed) {
        if ($entry.HadDestination -and (Test-Path -LiteralPath $entry.Backup)) {
            Remove-Item -LiteralPath $entry.Backup -Recurse -Force
        }
    }
}

function Install-BundledFile {
    param(
        [Parameter(Mandatory)] [string]$Source,
        [Parameter(Mandatory)] [string]$Destination,
        [Parameter(Mandatory)] [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Bundled $Description not found: $Source"
    }

    $changed = -not (Test-Path -LiteralPath $Destination -PathType Leaf)
    if (-not $changed) {
        $sourceHash = (Get-FileHash -LiteralPath $Source -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash
        $changed = $sourceHash -ne $destinationHash
    }
    if ($changed -and (Test-Path -LiteralPath $Destination) -and -not $Force) {
        throw "$Description differs from the installed file: $Destination. Re-run with -Force to replace it."
    }

    if ($changed -and $PSCmdlet.ShouldProcess($Destination, "Install $Description from $Source")) {
        New-Item -ItemType Directory -Path (Split-Path $Destination -Parent) -Force | Out-Null
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
    }
    return $changed
}

$dependencies = Join-Path $PackageDir 'dependencies'
$powerTestSource = Join-Path $dependencies 'PowerTest'
$hcsTestSource = Join-Path $dependencies 'HCSTest'
$vmgsToolSource = Join-Path $dependencies 'Tools\VmgsTool.exe'
$secFwSource = Join-Path $dependencies 'SecFw\secfw_test_GenuineIntel.dll'
$powerTestDestination = Join-Path $PowerTestInstallRoot 'PowerTest'
$hcsTestDestination = Join-Path $HcsTestInstallRoot 'HCSTest'

if (Get-Module HCSTest) {
    throw 'HCSTest is loaded. Close this process and run setup from a fresh elevated PowerShell 7 process.'
}

$requiredPowerTestFiles = @(
    'PowerTest.psd1'
    'TdxLiveMigrationUtilities.psm1'
    'HCSUtilities.psm1'
    'LiveMigrationUtilities.psm1'
    'LiveMigrationTestUtilities.psm1'
    'VmgsUtilities.psm1'
    'WmiUtilities.psm1'
    'IVMUtilities.psm1'
)
foreach ($requiredPowerTestFile in $requiredPowerTestFiles) {
    $requiredPath = Join-Path $powerTestSource $requiredPowerTestFile
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Bundled PowerTest file not found: $requiredPath"
    }
}
$hcsTestV2 = Join-Path $hcsTestSource 'coreclr\Microsoft.HostCompute.Test.PowerShell.v2.dll'
if (-not (Test-Path -LiteralPath $hcsTestV2 -PathType Leaf)) {
    throw "Bundled HCSTest PowerShell 7 binary not found: $hcsTestV2. Run Publish-TipPackage.ps1 with the matching winbuild first."
}
if (-not (Test-Path -LiteralPath $vmgsToolSource -PathType Leaf)) {
    throw "Bundled VmgsTool not found: $vmgsToolSource. Run Publish-TipPackage.ps1 with the matching winbuild first."
}

foreach ($destination in @($powerTestDestination, $hcsTestDestination)) {
    if ((Test-Path -LiteralPath $destination) -and -not $Force) {
        throw "Destination already exists: $destination. Re-run with -Force to replace it."
    }
}

Import-Module (Join-Path $hcsTestSource 'HCSTest.psd1') `
    -ArgumentList @{ UseVersion2 = $true } -Global -Force
$loadedHcsTest = Get-Module HCSTest
$nestedName = ($loadedHcsTest.NestedModules | Select-Object -First 1).Name
if ($nestedName -notlike '*.v2') {
    throw "HCSTest v2 validation failed; loaded nested module '$nestedName'."
}
foreach ($command in 'New-VMStateFile', 'New-HcsSystemDocument') {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Bundled HCSTest v2 did not export $command."
    }
}

$powerTestStaging = $null
$hcsTestStaging = $null
try {
    $powerTestStaging = New-StagedModuleDirectory `
        -Source $powerTestSource `
        -Destination $powerTestDestination `
        -Manifest 'PowerTest.psd1'
    $hcsTestStaging = New-StagedModuleDirectory `
        -Source $hcsTestSource `
        -Destination $hcsTestDestination `
        -Manifest 'HCSTest.psd1'
    Install-StagedModuleDirectories -Modules @(
        [pscustomobject]@{
            Source = $powerTestSource
            StagingPath = $powerTestStaging
            Destination = $powerTestDestination
        }
        [pscustomobject]@{
            Source = $hcsTestSource
            StagingPath = $hcsTestStaging
            Destination = $hcsTestDestination
        }
    )
}
finally {
    foreach ($stagingPath in @($powerTestStaging, $hcsTestStaging)) {
        if ($stagingPath -and (Test-Path -LiteralPath $stagingPath)) {
            Remove-Item -LiteralPath $stagingPath -Recurse -Force
        }
    }
}

$null = Install-BundledFile -Source $vmgsToolSource -Destination $VmgsToolInstallPath -Description 'VmgsTool'

$rebootRequired = $false
$secFwDestination = Join-Path "$env:SystemRoot\System32" 'secfw_test_GenuineIntel.dll'
if ($SkipSecureFirmware) {
    Write-Warning 'Secure Firmware installation was skipped. The target host must already have the matching firmware configured.'
}
elseif (Test-Path -LiteralPath $secFwSource -PathType Leaf) {
    $secFwChanged = Install-BundledFile `
        -Source $secFwSource `
        -Destination $secFwDestination `
        -Description 'test Secure Firmware'
    if ($secFwChanged) {
        $rebootRequired = $true
    }

    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Hypervisor'
    $currentSecFw = Get-ItemPropertyValue $regPath -Name SecFwFile -ErrorAction SilentlyContinue
    if ($currentSecFw -ne 'secfw_test_GenuineIntel.dll') {
        if ($PSCmdlet.ShouldProcess($regPath, 'Set SecFwFile=secfw_test_GenuineIntel.dll')) {
            New-ItemProperty $regPath -Name SecFwFile -Value 'secfw_test_GenuineIntel.dll' `
                -PropertyType String -Force | Out-Null
            $rebootRequired = $true
        }
    }
}
elseif (-not (Test-Path -LiteralPath $secFwDestination -PathType Leaf)) {
    Write-Warning 'Test Secure Firmware is not bundled or installed. Republish with -SecFwFile before running TDX tests.'
}

if ($ConfigureHost) {
    $validator = Join-Path $PackageDir 'troubleshooting\Test-TdxLmLabBlade.ps1'
    if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) {
        throw "Host validation script not found: $validator"
    }
    $secFwBeforeConfigure = Get-ItemPropertyValue `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Hypervisor' `
        -Name SecFwFile -ErrorAction SilentlyContinue
    & $validator -PowerTestPath $powerTestDestination -Configure
    $secFwAfterConfigure = Get-ItemPropertyValue `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Hypervisor' `
        -Name SecFwFile -ErrorAction SilentlyContinue
    if ($secFwBeforeConfigure -ne $secFwAfterConfigure) {
        $rebootRequired = $true
    }
}

[pscustomobject]@{
    PowerTestPath = $powerTestDestination
    HcsTestPath = $hcsTestDestination
    HcsTestBinary = $nestedName
    VmgsToolPath = $VmgsToolInstallPath
    SecFwBundled = Test-Path -LiteralPath $secFwSource -PathType Leaf
    RebootRequired = $rebootRequired
}

if ($rebootRequired) {
    Write-Warning 'Reboot the host before running TiP tests so Hyper-V loads the selected test Secure Firmware.'
}
