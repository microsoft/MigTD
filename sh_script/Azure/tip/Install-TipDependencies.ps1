#Requires -RunAsAdministrator

<#
.SYNOPSIS
  Install the dependencies bundled with a MigTD TiP package.

.DESCRIPTION
  Installs PowerTest and HCSTest v2 into their standard Windows PowerShell
  module locations. If the package contains test Secure Firmware, installs it
  under System32 and selects it for Hyper-V. Host migration settings can also
  be configured and validated.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PackageDir = $PSScriptRoot,
    [string]$PowerTestInstallRoot = "$env:ProgramFiles\WindowsPowerShell\Modules",
    [string]$HcsTestInstallRoot = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules",
    [switch]$ConfigureHost,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Copy-ModuleDirectory {
    param(
        [Parameter(Mandatory)] [string]$Source,
        [Parameter(Mandatory)] [string]$Destination,
        [Parameter(Mandatory)] [string]$Manifest
    )

    if (-not (Test-Path (Join-Path $Source $Manifest))) {
        throw "Bundled module manifest not found: $(Join-Path $Source $Manifest)"
    }
    if ((Test-Path $Destination) -and -not $Force) {
        throw "Destination already exists: $Destination. Re-run with -Force to replace it."
    }
    if ($PSCmdlet.ShouldProcess($Destination, "Install module from $Source")) {
        if (Test-Path $Destination) {
            Remove-Item $Destination -Recurse -Force
        }
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        Copy-Item -Path (Join-Path $Source '*') -Destination $Destination -Recurse -Force
    }
}

$dependencies = Join-Path $PackageDir 'dependencies'
$powerTestSource = Join-Path $dependencies 'PowerTest'
$hcsTestSource = Join-Path $dependencies 'HCSTest'
$powerTestDestination = Join-Path $PowerTestInstallRoot 'PowerTest'
$hcsTestDestination = Join-Path $HcsTestInstallRoot 'HCSTest'

if (Get-Module HCSTest) {
    throw 'HCSTest is loaded in this PowerShell process. Close it and run setup from a fresh elevated Windows PowerShell process.'
}

$hcsTestV2 = Join-Path $hcsTestSource 'netfx\Microsoft.HostCompute.Test.PowerShell.v2.dll'
if (-not (Test-Path $hcsTestV2)) {
    throw "Bundled HCSTest v2 binary not found: $hcsTestV2"
}

Copy-ModuleDirectory -Source $powerTestSource -Destination $powerTestDestination -Manifest 'PowerTest.psd1'
Copy-ModuleDirectory -Source $hcsTestSource -Destination $hcsTestDestination -Manifest 'HCSTest.psd1'

Import-Module (Join-Path $hcsTestDestination 'HCSTest.psd1') `
    -ArgumentList @{ UseVersion2 = $true } -Global -Force
$loadedHcsTest = Get-Module HCSTest
$nestedName = ($loadedHcsTest.NestedModules | Select-Object -First 1).Name
if ($nestedName -notlike '*.v2') {
    throw "HCSTest v2 validation failed; loaded nested module '$nestedName'."
}

$rebootRequired = $false
$secFwSource = Join-Path $dependencies 'SecFw\secfw_test_GenuineIntel.dll'
if (Test-Path $secFwSource) {
    $secFwDestination = Join-Path "$env:SystemRoot\System32" 'secfw_test_GenuineIntel.dll'
    $secFwChanged = -not (Test-Path $secFwDestination)
    if (-not $secFwChanged) {
        $sourceHash = (Get-FileHash $secFwSource -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash $secFwDestination -Algorithm SHA256).Hash
        $secFwChanged = $sourceHash -ne $destinationHash
    }
    if ($PSCmdlet.ShouldProcess($secFwDestination, "Install test Secure Firmware from $secFwSource")) {
        Copy-Item $secFwSource $secFwDestination -Force
        if ($secFwChanged) {
            $rebootRequired = $true
        }
    }

    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Hypervisor'
    $currentSecFw = (Get-ItemProperty $regPath -Name SecFwFile -ErrorAction SilentlyContinue).SecFwFile
    if ($currentSecFw -ne 'secfw_test_GenuineIntel.dll') {
        if ($PSCmdlet.ShouldProcess($regPath, 'Set SecFwFile=secfw_test_GenuineIntel.dll')) {
            New-ItemProperty $regPath -Name SecFwFile -Value 'secfw_test_GenuineIntel.dll' `
                -PropertyType String -Force | Out-Null
            $rebootRequired = $true
        }
    }
} elseif (-not (Test-Path (Join-Path "$env:SystemRoot\System32" 'secfw_test_GenuineIntel.dll'))) {
    Write-Warning 'Test Secure Firmware is not bundled or installed. Install secfw_test_GenuineIntel.dll before running TDX tests.'
}

if ($ConfigureHost) {
    $validator = Join-Path $PackageDir 'troubleshooting\Test-TdxLmLabBlade.ps1'
    if (-not (Test-Path $validator)) {
        throw "Host validation script not found: $validator"
    }
    $secFwBeforeConfigure = (Get-ItemProperty `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Hypervisor' `
        -Name SecFwFile -ErrorAction SilentlyContinue).SecFwFile
    & $validator -PowerTestPath $powerTestDestination -Configure
    $secFwAfterConfigure = (Get-ItemProperty `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Hypervisor' `
        -Name SecFwFile -ErrorAction SilentlyContinue).SecFwFile
    if ($secFwBeforeConfigure -ne $secFwAfterConfigure) {
        $rebootRequired = $true
    }
}

$result = [pscustomobject]@{
    PowerTestPath = $powerTestDestination
    HcsTestPath = $hcsTestDestination
    HcsTestBinary = $nestedName
    SecFwBundled = Test-Path $secFwSource
    RebootRequired = $rebootRequired
}
$result

if ($rebootRequired) {
    Write-Warning 'Reboot the host before running TiP tests so Hyper-V loads the selected test Secure Firmware.'
}
