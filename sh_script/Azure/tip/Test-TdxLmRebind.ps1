#Requires -RunAsAdministrator

<#
.SYNOPSIS
  Rebind a running TDX VM from one MigTD instance to another.

.DESCRIPTION
  Starts two MigTD instances from the supplied IGVM files, binds a TDX VM to
  the first, then invokes UpgradeMigrationPolicy to rebind it to the second.
  Runtime TD Info Hash values from the MigTD serial logs are authoritative.
  Before any MigTD load, the script verifies each IGVM sibling hash against
  its on-blade hash evidence file (<igvm>.hash.evidence.json). If both images
  have the same hash, the second mapping
  uses a synthetic lookup hash, matching the host OS rebind test; the VM's
  reported policy remains the real IGVM hash.

  The target VM uses NoPersistentSecrets by default so the test does not need
  target-VM IGVMAgent attestation.

.EXAMPLE
  .\Test-TdxLmRebind.ps1 `
      -OldIgvmFilePath .\test-migtd-accept-all_mock_quote.igvm `
      -NewIgvmFilePath .\test-migtd_mock_quote.igvm

.EXAMPLE
  .\Test-TdxLmRebind.ps1 `
      -OldIgvmFilePath .\test-migtd-accept-all_mock_quote.igvm `
      -NewIgvmFilePath .\test-migtd-accept-all_mock_quote.igvm
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$OldIgvmFilePath,
    [Parameter(Mandatory)] [string]$NewIgvmFilePath,
    [string]$OldHashFilePath = "$OldIgvmFilePath.hash",
    [string]$NewHashFilePath = "$NewIgvmFilePath.hash",
    [string]$OldMigTdId = 'tipmigtd-rebind-old',
    [string]$NewMigTdId = 'tipmigtd-rebind-new',
    [string]$VmName = 'tiptd-rebind',
    [string]$PowerTestPath = "$env:ProgramFiles\WindowsPowerShell\Modules\PowerTest",
    [switch]$UsePersistentSecrets,
    [switch]$CaptureSerial = $true,
    [ValidateRange(1, 120)] [int]$PolicyTimeoutSeconds = 15,
    [ValidateRange(0, 60)] [int]$SerialDrainTimeoutSeconds = 30,
    [switch]$SkipHashEvidenceValidation
)

$ErrorActionPreference = 'Stop'
$commonScript = Join-Path $PSScriptRoot 'TipHarness.Common.ps1'
if (-not (Test-Path $commonScript)) {
    throw "Harness helper not found: $commonScript"
}
. $commonScript
$script:serialCaptures = @{}
$script:runtimeHashes = @{}

function Import-PowerTestFile {
    param([Parameter(Mandatory)] [string]$Name)

    $path = Join-Path $PowerTestPath $Name
    if (-not (Test-Path $path)) {
        throw "PowerTest module file not found: $path"
    }
    Import-Module $path -Global -Force -DisableNameChecking
}

function Read-MigTdHash {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [switch]$Required
    )

    if (-not (Test-Path $Path)) {
        if ($Required) {
            throw "MigTD hash file not found: $Path"
        }
        return $null
    }
    $hash = (Get-Content $Path -Raw).Trim().ToLowerInvariant()
    if ($hash -notmatch '^[0-9a-f]{96}$') {
        throw "MigTD hash must be exactly 96 hexadecimal characters: $Path"
    }
    return $hash
}

function New-SyntheticHash {
    param([Parameter(Mandatory)] [string]$Hash)

    return -join ($Hash.ToCharArray() | ForEach-Object {
        '{0:x}' -f (([Convert]::ToInt32("$_", 16) + 1) % 16)
    })
}

function Start-MigTdInstance {
    param(
        [Parameter(Mandatory)] [string]$InstanceId,
        [Parameter(Mandatory)] [string]$IgvmPath,
        [string]$ExpectedHash
    )

    Write-Host "Starting MigTD '$InstanceId' from $IgvmPath"
    $instance = New-TestHcsMigTd `
        -Id $InstanceId `
        -IgvmFilePath (Resolve-Path $IgvmPath) `
        -GuestStateDirectory (Get-Location) `
        -EnableSerial:$CaptureSerial `
        -Force

    if ($CaptureSerial) {
        $logPath = Join-Path (Get-Location) "$InstanceId.serial.log"
        Remove-Item $logPath -ErrorAction SilentlyContinue
        $job = Start-Job -Name "$InstanceId-serial" -ScriptBlock {
            param($PipeName, $LogPath)
            try {
                $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
                    '.',
                    $PipeName,
                    [System.IO.Pipes.PipeDirection]::In)
                $pipe.Connect(15000)
                $reader = [System.IO.StreamReader]::new($pipe)
                while ($true) {
                    $line = $reader.ReadLine()
                    if ($null -eq $line) {
                        break
                    }
                    Add-Content -Path $LogPath -Value $line
                }
            } catch {
                Add-Content -Path $LogPath -Value "[serial-capture] $_"
            }
        } -ArgumentList "raw$InstanceId", $logPath
        $script:serialCaptures[$InstanceId] = [pscustomobject]@{
            Job = $job
            LogPath = $logPath
        }
    }

    try {
        $instance | Start-HcsSystem
        if ($CaptureSerial) {
            $script:runtimeHashes[$InstanceId] = Wait-MigTdRuntimeHash `
                -InstanceId $InstanceId `
                -ImagePath $IgvmPath `
                -ExpectedHash $ExpectedHash `
                -TimeoutSeconds $PolicyTimeoutSeconds
        }
        return $instance
    } catch {
        Stop-MigTdInstance $instance
        throw
    }
}

function Wait-MigTdRuntimeHash {
    param(
        [Parameter(Mandatory)] [string]$InstanceId,
        [Parameter(Mandatory)] [string]$ImagePath,
        [string]$ExpectedHash,
        [Parameter(Mandatory)] [int]$TimeoutSeconds
    )

    $capture = $script:serialCaptures[$InstanceId]
    if (-not $capture) {
        return
    }
    $actualHash = Wait-TipRuntimeHashFromSerialLog `
        -LogPath $capture.LogPath `
        -TimeoutSeconds $TimeoutSeconds `
        -ExpectedHash $ExpectedHash `
        -Context $InstanceId
    Write-Host "Runtime TD Info Hash verified for '$InstanceId': $actualHash"
    return $actualHash
}

function Stop-MigTdInstance {
    param([object]$Instance)

    $instanceId = if ($Instance) { $Instance.Id } else { $null }
    $localCleanupFailures = [System.Collections.Generic.List[string]]::new()
    try {
        if ($Instance -and -not $Instance.IsClosed) {
            try {
                Stop-HcsSystem $Instance -ErrorAction Stop
            } catch {
                $localCleanupFailures.Add("Stop-HcsSystem $instanceId failed: $($_.Exception.Message)")
            }
            try {
                $Instance.Close()
            } catch {
                $localCleanupFailures.Add("Close MigTD handle $instanceId failed: $($_.Exception.Message)")
            }
        }
    } finally {
        $capture = if ($instanceId) { $script:serialCaptures[$instanceId] } else { $null }
        if ($capture) {
            try {
                Wait-Job $capture.Job -Timeout 5 -ErrorAction Stop | Out-Null
            } catch {
                $localCleanupFailures.Add("Wait-Job $instanceId-serial failed: $($_.Exception.Message)")
            }
            if ($capture.Job.State -notin @('Completed', 'Failed')) {
                try {
                    Stop-Job $capture.Job -ErrorAction Stop | Out-Null
                } catch {
                    $localCleanupFailures.Add("Stop-Job $instanceId-serial failed: $($_.Exception.Message)")
                }
            }
            try {
                Remove-Job $capture.Job -Force -ErrorAction Stop
            } catch {
                $localCleanupFailures.Add("Remove-Job $instanceId-serial failed: $($_.Exception.Message)")
            }
            Write-Host "MigTD serial log: $($capture.LogPath)"
            $script:serialCaptures.Remove($instanceId)
        }
    }

    if ($localCleanupFailures.Count -gt 0) {
        throw ($localCleanupFailures -join '; ')
    }
}

function Assert-MigTdRunning {
    param(
        [Parameter(Mandatory)] [object]$Instance,
        [Parameter(Mandatory)] [string]$Role
    )

    if ($Instance.IsClosed) {
        throw "$Role MigTD HCS handle is closed."
    }

    $rawProperties = Get-HcsSystemProperties -System $Instance -RawJson
    $properties = $rawProperties | ConvertFrom-Json
    if ([string]$properties.State -ne 'Running') {
        throw "$Role MigTD is not running (HCS state=$($properties.State))."
    }
    if (-not $properties.RuntimeId) {
        throw "$Role MigTD has no HCS RuntimeId; its worker process is not ready."
    }

    Write-Host "$Role MigTD is alive: Id=$($Instance.Id) RuntimeId=$($properties.RuntimeId)"
}

function Wait-ForFinalRebindLogs {
    param(
        [string[]]$InstanceIds,
        [int]$TimeoutSeconds,
        [int]$RequestGraceSeconds = 5
    )

    if ($TimeoutSeconds -eq 0) {
        return
    }

    $captures = @($InstanceIds | ForEach-Object {
        $capture = $script:serialCaptures[$_]
        if ($capture) {
            [pscustomobject]@{
                InstanceId = $_
                LogPath = $capture.LogPath
            }
        }
    })
    if ($captures.Count -eq 0) {
        return
    }

    Write-Host "Waiting up to $TimeoutSeconds second(s) for final rebind log entries."
    $start = Get-Date
    $deadline = $start.AddSeconds($TimeoutSeconds)
    $started = @()
    $completed = @()
    $settledSince = $null
    $settledState = ''
    do {
        $started = @()
        $completed = @()
        foreach ($capture in $captures) {
            $text = if (Test-Path $capture.LogPath) {
                Get-Content $capture.LogPath -Raw -ErrorAction SilentlyContinue
            } else {
                ''
            }
            if ($text -match ('Processing StartRebinding request|' +
                'Pre-Session-Message Version|' +
                'finalize_spdm_session: body error|' +
                'Failure during rebinding status code')) {
                $started += $capture.InstanceId
                if ($text -match ('ReportStatus for rebinding completed|' +
                    'Failed to report status for StartRebinding|' +
                    'Failure during rebinding status code')) {
                    $completed += $capture.InstanceId
                }
            }
        }

        if ($started.Count -gt 0 -and $completed.Count -eq $started.Count) {
            $currentState = "$($started -join ',')|$($completed -join ',')"
            if ($currentState -ne $settledState) {
                $settledState = $currentState
                $settledSince = Get-Date
            } elseif ((Get-Date) -ge $settledSince.AddSeconds(2)) {
                Write-Host "Final rebind status captured for: $($completed -join ', ')"
                return
            }
        } else {
            $settledSince = $null
            $settledState = ''
        }
        if ($started.Count -eq 0 -and (Get-Date) -ge $start.AddSeconds($RequestGraceSeconds)) {
            Write-Warning 'No MigTD logged any rebinding activity; the host failed before delivering operation 2.'
            return
        }

        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    if ($started.Count -gt 0) {
        $missing = @($started | Where-Object { $_ -notin $completed })
        Write-Warning "Timed out waiting for terminal rebind logs from: $($missing -join ', ')"
    } else {
        Write-Warning 'Timed out without observing a MigTD StartRebinding request.'
    }
}

function Wait-VmMigrationPolicy {
    param(
        [Parameter(Mandatory)] [string]$TargetVmName,
        [Parameter(Mandatory)] [string]$ExpectedHash,
        [Parameter(Mandatory)] [int]$TimeoutSeconds
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $vm = Get-VM -Name $TargetVmName
        $actual = ([string](Get-VmMigrationPolicy -Vm $vm)).Trim().ToLowerInvariant()
        if ($actual -eq $ExpectedHash) {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    throw "VM migration policy did not become $ExpectedHash within $TimeoutSeconds seconds. Actual=$actual"
}

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw (New-TipHarnessException 'PRECONDITION' 'This test requires PowerShell 7 because the host migration mapping helpers use ConvertFrom-Json -AsHashtable.')
}
if ($OldMigTdId -eq $NewMigTdId) {
    throw (New-TipHarnessException 'PRECONDITION' 'OldMigTdId and NewMigTdId must be different.')
}
foreach ($path in @($OldIgvmFilePath, $NewIgvmFilePath)) {
    if (-not (Test-Path $path)) {
        throw (New-TipHarnessException 'PRECONDITION' "IGVM file not found: $path")
    }
}

Import-Module Hyper-V -Force
Import-PowerTestFile 'TdxLiveMigrationUtilities.psm1'
Import-PowerTestFile 'HCSUtilities.psm1'
Import-PowerTestFile 'LiveMigrationUtilities.psm1'
Import-PowerTestFile 'VmgsUtilities.psm1'
Import-PowerTestFile 'WmiUtilities.psm1'
Import-PowerTestFile 'IVMUtilities.psm1'

$hcsTest = Get-Module HCSTest
if ($hcsTest -and $hcsTest.NestedModules[0].Name -notlike '*.v2') {
    throw 'HCSTest v1 is already loaded. Close this PowerShell process and retry.'
}
if (-not $hcsTest) {
    Import-Module HCSTest -ArgumentList @{ UseVersion2 = $true } `
        -Global -Force -ErrorAction SilentlyContinue
    if (-not (Get-Module HCSTest)) {
        if (Get-Command Import-HcsTestModule -ErrorAction SilentlyContinue) {
            Import-HcsTestModule -UseVersion2
        } else {
            throw 'HCSTest is unavailable and HCSUtilities did not provide Import-HcsTestModule.'
        }
    }
}
if (-not (Get-Command New-HcsSystemDocument -ErrorAction SilentlyContinue)) {
    throw 'HCSTest v2 did not provide New-HcsSystemDocument.'
}

if (-not (Get-Command New-VmStateFile -ErrorAction SilentlyContinue)) {
    function global:New-VmStateFile {
        param(
            [Parameter(Mandatory)] [string]$GuestStateFilePath,
            [int]$FileSize = 16MB
        )

        $tool = Get-Command vmgstool.exe -ErrorAction SilentlyContinue
        if ($tool) {
            $tool = $tool.Source
        } elseif (Test-Path (Join-Path $env:SystemRoot 'System32\vmgstool.exe')) {
            $tool = Join-Path $env:SystemRoot 'System32\vmgstool.exe'
        }

        if ($tool) {
            & $tool -Create -FilePath $GuestStateFilePath "-FileSize=$FileSize" | Out-Null
        } elseif (Get-Command New-GuestStateFile -ErrorAction SilentlyContinue) {
            New-GuestStateFile -FilePath $GuestStateFilePath -FileSize $FileSize | Out-Null
        } else {
            throw 'Cannot create the MigTD guest state file: vmgstool.exe and New-GuestStateFile are unavailable.'
        }
    }
}

$oldHashEvidence = $null
$newHashEvidence = $null
if ($SkipHashEvidenceValidation) {
    $oldHashFileValue = Read-MigTdHash $OldHashFilePath -Required:(-not $CaptureSerial)
    $newHashFileValue = Read-MigTdHash $NewHashFilePath -Required:(-not $CaptureSerial)
} else {
    $oldHashEvidence = Resolve-TipMigTdHashFromFiles `
        -IgvmFilePath $OldIgvmFilePath `
        -HashFilePath $OldHashFilePath
    $newHashEvidence = Resolve-TipMigTdHashFromFiles `
        -IgvmFilePath $NewIgvmFilePath `
        -HashFilePath $NewHashFilePath
    $oldHashFileValue = $oldHashEvidence.MigTdHash
    $newHashFileValue = $newHashEvidence.MigTdHash
    Write-Host "Verified sibling hash evidence: $($oldHashEvidence.HashEvidencePath)"
    Write-Host "Verified sibling hash evidence: $($newHashEvidence.HashEvidencePath)"
}
$oldHash = $oldHashFileValue
$newHash = $newHashFileValue
$newMappingHash = $null

$oldMigTd = $null
$newMigTd = $null
$vm = $null
$scriptError = $null
$cleanupFailures = [System.Collections.Generic.List[string]]::new()
try {
    if ($oldHashFileValue) {
        Remove-VmHostMigrationTdMapping -MigTdHash $oldHashFileValue -ErrorAction SilentlyContinue
    }
    if ($newHashFileValue) {
        Remove-VmHostMigrationTdMapping -MigTdHash $newHashFileValue -ErrorAction SilentlyContinue
    }

    $oldMigTd = Start-MigTdInstance `
        -InstanceId $OldMigTdId `
        -IgvmPath $OldIgvmFilePath `
        -ExpectedHash $oldHashFileValue
    if ($CaptureSerial) {
        $oldHash = $script:runtimeHashes[$OldMigTdId]
    }
    Assert-MigTdRunning -Instance $oldMigTd -Role 'Old'
    Write-Host "Old MigTD hash used for binding: $oldHash"
    Remove-VmHostMigrationTdMapping -MigTdHash $oldHash -ErrorAction SilentlyContinue
    Add-VmHostMigrationTdMapping -MigTdHash $oldHash -VmId $oldMigTd.Id
    Set-VMHostMigrationPolicy DisabledByDefault $oldHash

    $vm = New-VM -Name $VmName -GuestStateIsolation TDX -Generation 2 -NoVHD
    if (-not $UsePersistentSecrets) {
        $vm | Set-GuestStateIsolationMode -IsolationMode NoPersistentSecrets
        Write-Host 'Configured target VM with NoPersistentSecrets.'
    }
    $vm | Set-VmMigratablePolicy -MigratablePolicy EnabledIfHostPermits | Out-Null
    $migratablePolicy = [string]($vm | Get-VmMigratablePolicy)
    if ($migratablePolicy -ne 'EnabledIfHostPermits') {
        throw "Failed to opt the TD into host-permitted migration. Actual policy=$migratablePolicy"
    }
    Write-Host 'Configured VM migratable policy: EnabledIfHostPermits.'
    $vm | Update-VmMigrationPolicy
    $vm | Start-VM

    $vm = Get-VM -Name $VmName
    if ($vm.State -ne 'Running') {
        throw "TD is not running after initial binding (state=$($vm.State))."
    }
    Wait-VmMigrationPolicy `
        -TargetVmName $VmName `
        -ExpectedHash $oldHash `
        -TimeoutSeconds $PolicyTimeoutSeconds
    Write-Host "Initial binding verified: $oldHash"

    $newMigTd = Start-MigTdInstance `
        -InstanceId $NewMigTdId `
        -IgvmPath $NewIgvmFilePath `
        -ExpectedHash $newHashFileValue
    if ($CaptureSerial) {
        $newHash = $script:runtimeHashes[$NewMigTdId]
    }
    Assert-MigTdRunning -Instance $newMigTd -Role 'New'
    Write-Host "New MigTD hash used for binding: $newHash"

    $newMappingHash = $newHash
    if ($oldHash -eq $newHash) {
        $newMappingHash = New-SyntheticHash $newHash
        Write-Host "Both MigTD images have hash $newHash"
        Write-Host "Using synthetic second mapping key $newMappingHash"
    }
    Remove-VmHostMigrationTdMapping -MigTdHash $newMappingHash -ErrorAction SilentlyContinue
    Add-VmHostMigrationTdMapping -MigTdHash $newMappingHash -VmId $newMigTd.Id
    Set-VMHostMigrationPolicy DisabledByDefault $newMappingHash

    Assert-MigTdRunning -Instance $oldMigTd -Role 'Old'
    Assert-MigTdRunning -Instance $newMigTd -Role 'New'
    Write-Host 'Triggering UpgradeMigrationPolicy rebind.'
    try {
        $vm | Update-VmMigrationPolicy
    } catch {
        $errorText = Convert-TipErrorRecordToString -ErrorRecord $_
        if ($errorText -match '0x800721CE|external policy') {
            throw (New-TipHarnessException 'TEST_FAILURE' "Rebind rejected with MIGPOLICY_UNSATISFIED_ERROR (0x800721CE). The old and new MigTD policies or enrolled identities do not mutually authorize this rebind. Inspect $OldMigTdId.serial.log and $NewMigTdId.serial.log for the failed policy check.")
        }
        throw (New-TipHarnessException 'TRANSPORT' "UpgradeMigrationPolicy rebind failed.`n$errorText`nInspect $OldMigTdId.serial.log and $NewMigTdId.serial.log.")
    }
    Wait-VmMigrationPolicy `
        -TargetVmName $VmName `
        -ExpectedHash $newHash `
        -TimeoutSeconds $PolicyTimeoutSeconds

    $vm = Get-VM -Name $VmName
    if ($vm.State -ne 'Running') {
        throw "TD stopped during rebind (state=$($vm.State))."
    }
    Write-Host "PASS: '$VmName' rebound to the new MigTD and remained running."
    Write-Host "Current migration policy: $newHash"
}
catch {
    $scriptError = $_
}
finally {
    if ($CaptureSerial -and ($oldMigTd -or $newMigTd)) {
        Wait-ForFinalRebindLogs `
            -InstanceIds @($OldMigTdId, $NewMigTdId) `
            -TimeoutSeconds $SerialDrainTimeoutSeconds
    }
    if ($vm) {
        try {
            $vm | Stop-VM -Force -ErrorAction Stop
        } catch {
            $cleanupFailures.Add("Stop-VM $VmName failed: $($_.Exception.Message)")
        }
        try {
            $vm | Remove-VM -Force -ErrorAction Stop
        } catch {
            $cleanupFailures.Add("Remove-VM $VmName failed: $($_.Exception.Message)")
        }
    }
    $finalPolicyHash = if ($newHash) { $newHash } else { $oldHash }
    if ($finalPolicyHash) {
        try {
            Set-VMHostMigrationPolicy DisabledByDefault $finalPolicyHash -ErrorAction Stop
        } catch {
            $cleanupFailures.Add("Set-VMHostMigrationPolicy DisabledByDefault failed: $($_.Exception.Message)")
        }
    }
    foreach ($hash in @(
        $newMappingHash,
        $oldHash,
        $newHashFileValue,
        $oldHashFileValue
    ) | Where-Object { $_ } | Select-Object -Unique) {
        try {
            Remove-VmHostMigrationTdMapping -MigTdHash $hash -ErrorAction Stop
        } catch {
            $cleanupFailures.Add("Remove-VmHostMigrationTdMapping $hash failed: $($_.Exception.Message)")
        }
    }
    try {
        Stop-MigTdInstance $newMigTd
    } catch {
        $cleanupFailures.Add("Stop-MigTdInstance $NewMigTdId failed: $($_.Exception.Message)")
    }
    try {
        Stop-MigTdInstance $oldMigTd
    } catch {
        $cleanupFailures.Add("Stop-MigTdInstance $OldMigTdId failed: $($_.Exception.Message)")
    }
}

if ($cleanupFailures.Count -gt 0) {
    $cleanupMessage = ($cleanupFailures -join '; ')
    if ($scriptError) {
        throw (New-TipHarnessException 'CLEANUP' "$cleanupMessage | PrimaryError=$($scriptError.Exception.Message)")
    }
    throw (New-TipHarnessException 'CLEANUP' $cleanupMessage)
}

if ($scriptError) {
    throw $scriptError
}

[pscustomobject]@{
    CaseType = 'Rebind'
    Outcome = 'RebindSuccess'
    VmName = $VmName
    OldMigTdId = $OldMigTdId
    NewMigTdId = $NewMigTdId
    OldMigTdHash = $oldHash
    NewMigTdHash = $newHash
    OldRuntimeMigTdHash = if ($CaptureSerial) { $script:runtimeHashes[$OldMigTdId] } else { $null }
    NewRuntimeMigTdHash = if ($CaptureSerial) { $script:runtimeHashes[$NewMigTdId] } else { $null }
    RuntimeMigTdHashSource = if ($CaptureSerial) { 'serial' } else { 'not-captured' }
    OldHashEvidencePath = if ($oldHashEvidence) { $oldHashEvidence.HashEvidencePath } else { Get-TipHashEvidencePath -HashFilePath $OldHashFilePath }
    NewHashEvidencePath = if ($newHashEvidence) { $newHashEvidence.HashEvidencePath } else { Get-TipHashEvidencePath -HashFilePath $NewHashFilePath }
    HashEvidenceVerified = [bool]($oldHashEvidence -and $newHashEvidence)
    SerialLogs = @(
        Join-Path (Get-Location) "$OldMigTdId.serial.log",
        Join-Path (Get-Location) "$NewMigTdId.serial.log"
    ) | Where-Object { Test-Path $_ }
}
