#Requires -Version 7.0

<#
.SYNOPSIS
  Validate or configure a TDX live-migration lab blade.

.EXAMPLE
  .\Test-TdxLmLabBlade.ps1 -PowerTestPath 'C:\Program Files\PowerShell\Modules\PowerTest'

.EXAMPLE
  .\Test-TdxLmLabBlade.ps1 -PowerTestPath C:\PowerTest -HcsTestSource \\share\HCSTest -Configure
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PowerTestPath = "$env:ProgramFiles\PowerShell\Modules\PowerTest",
    [string]$HcsTestSource,
    [string]$HcsTestInstallRoot = "$env:ProgramFiles\PowerShell\Modules",
    [string]$TestSecFwName = 'secfw_test_GenuineIntel.dll',
    [uint32]$FeatureId = 53058573,
    [string]$StagingToolPath,
    [switch]$Configure
)

$ErrorActionPreference = 'Stop'
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Check, [string]$Status, [string]$Detail)
    $results.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail })
}

function Import-ModuleFile {
    param([string]$Name)
    $path = Join-Path $PowerTestPath $Name
    if (-not (Test-Path $path)) {
        throw "PowerTest module file not found: $path"
    }
    Import-Module $path -Force -DisableNameChecking
}

if (-not (Test-Path $PowerTestPath)) {
    throw "PowerTest path not found: $PowerTestPath"
}

Import-ModuleFile 'TdxLiveMigrationUtilities.psm1'
Import-ModuleFile 'HCSUtilities.psm1'
Import-ModuleFile 'LiveMigrationUtilities.psm1'
Import-ModuleFile 'VmgsUtilities.psm1'

$hcsTest = Get-Module HCSTest
if ($hcsTest) {
    $loadedNestedName = ($hcsTest.NestedModules | Select-Object -First 1).Name
    if ($loadedNestedName -notlike '*.v2') {
        Add-Result 'HCSTest' 'FAIL' "Loaded non-v2 binary '$loadedNestedName'; close this PowerShell process and retry so the assembly can be replaced"
    }
} else {
    Import-Module HCSTest -ArgumentList @{ UseVersion2 = $true } -Global -Force -ErrorAction SilentlyContinue
}

if (-not (Get-Module HCSTest) -and $HcsTestSource) {
    if (-not (Test-Path $HcsTestSource)) {
        throw "HCSTest source not found: $HcsTestSource"
    }
    $destination = Join-Path $HcsTestInstallRoot 'HCSTest'
    if ($Configure -and $PSCmdlet.ShouldProcess($destination, "Install HCSTest from $HcsTestSource")) {
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Copy-Item -Recurse -Force (Join-Path $HcsTestSource '*') $destination
        Import-Module HCSTest -ArgumentList @{ UseVersion2 = $true } -Global -Force
    }
}

$hcsTest = Get-Module HCSTest
if ($hcsTest) {
    $nestedName = ($hcsTest.NestedModules | Select-Object -First 1).Name
    if ($nestedName -like '*.v2') {
        Add-Result 'HCSTest' 'PASS' "Loaded $nestedName"
    } elseif (-not ($results | Where-Object { $_.Check -eq 'HCSTest' -and $_.Status -eq 'FAIL' })) {
        Add-Result 'HCSTest' 'FAIL' "Loaded non-v2 binary: $nestedName"
    }
} elseif (-not ($results | Where-Object { $_.Check -eq 'HCSTest' -and $_.Status -eq 'FAIL' })) {
    Add-Result 'HCSTest' 'FAIL' 'Not installed or not importable; provide -HcsTestSource and -Configure'
}

foreach ($command in @(
    'New-TestHcsMigTd',
    'New-HcsSystemDocument',
    'Start-HcsSystem',
    'Add-VmHostMigrationTdMapping',
    'Set-VMHostMigrationPolicy',
    'Set-VmMigratablePolicy',
    'Get-VmMigratablePolicy',
    'Enable-LoopbackMigration'
)) {
    if (Get-Command $command -ErrorAction SilentlyContinue) {
        Add-Result $command 'PASS' 'Available'
    } else {
        Add-Result $command 'FAIL' 'Command unavailable'
    }
}

$vmStateCommand = Get-Command New-VmStateFile -ErrorAction SilentlyContinue
$vmgsTool = Get-Command vmgstool.exe -ErrorAction SilentlyContinue
if (-not $vmgsTool) {
    $systemVmgsTool = Join-Path $env:SystemRoot 'System32\vmgstool.exe'
    if (Test-Path $systemVmgsTool) {
        $vmgsTool = $systemVmgsTool
    }
}
if ($vmStateCommand) {
    Add-Result 'VM state file creation' 'PASS' "New-VmStateFile from $($vmStateCommand.Source)"
} elseif ($vmgsTool -or (Get-Command New-GuestStateFile -ErrorAction SilentlyContinue)) {
    Add-Result 'VM state file creation' 'WARN' 'New-VmStateFile absent; Invoke-TdxLmLoopback.ps1 will install its vmgstool/New-GuestStateFile shim'
} else {
    Add-Result 'VM state file creation' 'FAIL' 'Neither New-VmStateFile, vmgstool.exe, nor New-GuestStateFile is available'
}

$secFwPath = Join-Path "$env:SystemRoot\System32" $TestSecFwName
if (Test-Path $secFwPath) {
    Add-Result 'Test SecFw file' 'PASS' $secFwPath
} else {
    Add-Result 'Test SecFw file' 'FAIL' "$secFwPath not found"
}

$secFwRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Hypervisor'
$secFwValue = (Get-ItemProperty $secFwRegPath -Name SecFwFile -ErrorAction SilentlyContinue).SecFwFile
if ($secFwValue -eq $TestSecFwName) {
    Add-Result 'SecFwFile registry' 'PASS' $secFwValue
} elseif ($Configure -and $PSCmdlet.ShouldProcess($secFwRegPath, "Set SecFwFile=$TestSecFwName")) {
    Set-ItemProperty $secFwRegPath -Name SecFwFile -Value $TestSecFwName
    Add-Result 'SecFwFile registry' 'CHANGED' "$secFwValue -> $TestSecFwName; reboot required"
} else {
    Add-Result 'SecFwFile registry' 'FAIL' "Current='$secFwValue', expected='$TestSecFwName'"
}

Import-Module Hyper-V -Force
$vmHost = Get-VMHost
if ($Configure) {
    if (-not $vmHost.VirtualMachineMigrationEnabled -and $PSCmdlet.ShouldProcess('VMHost', 'Enable live migration')) {
        Enable-VMMigration
    }
    if ($PSCmdlet.ShouldProcess('VMHost', 'Set Kerberos/any-network/compression migration settings')) {
        Set-VMHost `
            -VirtualMachineMigrationAuthenticationType Kerberos `
            -UseAnyNetworkForMigration $true `
            -VirtualMachineMigrationPerformanceOption Compression
    }
    if ($PSCmdlet.ShouldProcess('VMHost', 'Enable loopback migration')) {
        Enable-LoopbackMigration
    }
    if ($PSCmdlet.ShouldProcess('VMHost', 'Apply loopback migration directory workaround')) {
        Enable-LoopbackMigrationDirectoryWorkaround
    }
    $vmHost = Get-VMHost
}

Add-Result 'Live migration' $(if ($vmHost.VirtualMachineMigrationEnabled) { 'PASS' } else { 'FAIL' }) `
    "Enabled=$($vmHost.VirtualMachineMigrationEnabled)"
Add-Result 'Migration authentication' $(if ($vmHost.VirtualMachineMigrationAuthenticationType -eq 'Kerberos') { 'PASS' } else { 'FAIL' }) `
    "$($vmHost.VirtualMachineMigrationAuthenticationType)"
Add-Result 'Migration network' $(if ($vmHost.UseAnyNetworkForMigration) { 'PASS' } else { 'FAIL' }) `
    "UseAnyNetwork=$($vmHost.UseAnyNetworkForMigration)"

$loopbackPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\Migration'
$loopbackValue = (Get-ItemProperty $loopbackPath -Name EnableLoopbackMigration -ErrorAction SilentlyContinue).EnableLoopbackMigration
Add-Result 'Loopback migration' $(if ($loopbackValue -eq 1) { 'PASS' } else { 'FAIL' }) "Registry=$loopbackValue"

$virtualizationSettingsPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization'
$requireIgvmAgent = (Get-ItemProperty $virtualizationSettingsPath -Name RequireIgvmAgent -ErrorAction SilentlyContinue).RequireIgvmAgent
if ($requireIgvmAgent -gt 0) {
    Add-Result 'RequireIgvmAgent' 'INFO' "Registry=$requireIgvmAgent; VM startup requires an available agent endpoint"
} else {
    Add-Result 'RequireIgvmAgent' 'PASS' 'Absent or zero; agent availability is not enforced at VM startup'
}

$testAttestationAgents = @(Get-Process -Name igvmagent -ErrorAction SilentlyContinue)
if ($testAttestationAgents.Count -eq 0) {
    Add-Result 'Test IGVM attestation agent' 'INFO' 'Not running; use a _mock_quote image plus -NoPersistentSecrets for a fully agent-free test'
} else {
    $agentDetails = ($testAttestationAgents | ForEach-Object {
        $path = try { $_.Path } catch { $null }
        "PID=$($_.Id)" + $(if ($path) { " Path=$path" } else { '' })
    }) -join '; '
    Add-Result 'Test IGVM attestation agent' 'INFO' "Running: $agentDetails. Regular igvm-attest images require a compatible agent for MigTD GetQuote"
}

if ($StagingToolPath) {
    if (-not (Test-Path $StagingToolPath)) {
        Add-Result "Velocity feature $FeatureId" 'FAIL' "StagingTool not found: $StagingToolPath"
    } else {
        $featureOutput = & $StagingToolPath /query $FeatureId 2>&1
        Add-Result "Velocity feature $FeatureId" 'INFO' ($featureOutput -join ' ')
    }
} else {
    Add-Result "Velocity feature $FeatureId" 'SKIP' 'Supply -StagingToolPath to query without PowerTest/BNS'
}

$results | Format-Table -AutoSize -Wrap
if ($results.Status -contains 'FAIL') {
    throw 'TDX live-migration lab-blade validation failed. Review the failed checks above.'
}
