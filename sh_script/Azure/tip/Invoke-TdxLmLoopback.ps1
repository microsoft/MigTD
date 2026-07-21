<#
.SYNOPSIS
  Run one TDX MigTD loopback live-migration on a labblade.

.DESCRIPTION
  Starts the given MigTD IGVM, registers its hash, creates a TDX guest, migrates
  it to localhost (loopback), and asserts the outcome. Cleans up afterwards.
  Mirrors the Azure OS PR gate (Invoke-TdxLmE2ETest). Requires PowerTest's
  TdxLiveMigrationUtilities for New-TestHcsMigTd; pass -PowerTestPath to import it.

.EXAMPLE
  .\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-accept-all.igvm
  .\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-reject-all.igvm -ExpectReject
  .\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-accept-all.igvm -CaptureSerial
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$IgvmFilePath,
    [string]$HashFilePath = "$IgvmFilePath.hash",
    [string]$MigTdId = 'tipmigtd',
    [string]$VmName = 'tiptd',
    [switch]$ExpectReject,
    [string]$PowerTestPath = "$env:ProgramFiles\WindowsPowerShell\Modules\PowerTest",
    [ValidateRange(0, 300)]
    [int]$StartupDelaySeconds = 0,
    # Validate the target VM's 272-byte ServTdExt after prebind/start, then
    # clean up without issuing Move-VM.
    [switch]$ServTdExtOnly,
    # Sets GuestStateIsolationMode=NoPersistentSecrets before startup. OpenHCL
    # then suppresses target-VM host attestation. Regular MigTD images still use
    # IGVMAgent for GHCI GetQuote; pair this with a _mock_quote image to bypass
    # IGVMAgent completely. This changes the target VM security profile.
    [switch]$NoPersistentSecrets,
    [ValidateRange(0, 60)]
    [int]$SerialDrainTimeoutSeconds = 30,
    # Captures the MigTD's own serial console (built with --log-level info) to
    # <MigTdId>.serial.log via New-TestHcsMigTd -EnableSerial's named pipe.
    # Useful when migration fails with only a generic VMMS error and no detail
    # on why the MigTD itself rejected/aborted.
    [switch]$CaptureSerial
)
$ErrorActionPreference = 'Stop'

function Test-ServTdExtLayout {
    param(
        [Parameter(Mandatory)] [string]$TargetVmName,
        [Parameter(Mandatory)] [string]$ExpectedHash,
        [Parameter(Mandatory)] [string]$ModuleRoot,
        [ValidateRange(1, 120)] [int]$TimeoutSeconds = 15
    )

    if (-not (Get-Command Get-VmServTdExt -ErrorAction SilentlyContinue)) {
        $modulePath = Join-Path $ModuleRoot 'LiveMigrationTestUtilities.psm1'
        if (-not (Test-Path $modulePath)) {
            throw "PowerTest LiveMigrationTestUtilities.psm1 not found: $modulePath"
        }
        Import-Module $modulePath -Force
    }
    if (-not (Get-Command Get-VmServTdExt -ErrorAction SilentlyContinue)) {
        throw 'Get-VmServTdExt is unavailable after importing LiveMigrationTestUtilities.psm1.'
    }

    $expected = $ExpectedHash.Trim().ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{96}$') {
        throw 'Expected MigTD hash must be exactly 96 hexadecimal characters.'
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $raw = [string](Get-VmServTdExt -VmName $TargetVmName)
        $actual = ($raw -replace '[^0-9a-fA-F]', '').ToLowerInvariant()
        if ($actual) { break }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    if (-not $actual) {
        throw "Get-VmServTdExt returned no data for '$TargetVmName' within $TimeoutSeconds seconds."
    }
    if ($actual -notmatch '^[0-9a-f]+$') {
        throw "ServTdExt contains non-hexadecimal data: $raw"
    }
    if ($actual.Length -ne 544) {
        throw "ServTdExt must be 272 bytes (544 hex characters); received $($actual.Length / 2) bytes."
    }

    function Get-HexRange {
        param([int]$Offset, [int]$Length)
        return $actual.Substring($Offset * 2, $Length * 2)
    }
    function Assert-HexRange {
        param([string]$Name, [int]$Offset, [int]$Length, [string]$Expected)
        $value = Get-HexRange -Offset $Offset -Length $Length
        if ($value -ne $Expected) {
            throw "$Name mismatch at byte offset $Offset. Expected=$Expected Actual=$value"
        }
    }
    function Assert-ZeroRange {
        param([string]$Name, [int]$Offset, [int]$Length)
        Assert-HexRange -Name $Name -Offset $Offset -Length $Length -Expected ('00' * $Length)
    }

    # HV_TD_SERVICE_TD_EXT / MigTD ServtdExt is 272 bytes:
    #   0x000 init hash (48), 0x030 init attr/reserved (16),
    #   0x040 CPU/TCB/model metadata (44), 0x06c reserved (4),
    #   0x070 current hash (48), 0x0a0 current attr/reserved (112).
    Assert-HexRange -Name 'InitServTdInfoHash' -Offset 0 -Length 48 -Expected $expected
    Assert-ZeroRange -Name 'InitServTdAttrAndReserved' -Offset 48 -Length 16
    Assert-ZeroRange -Name 'InitMetadataReserved' -Offset 108 -Length 4
    Assert-HexRange -Name 'CurrentServTdInfoHash' -Offset 112 -Length 48 -Expected $expected
    Assert-ZeroRange -Name 'CurrentServTdAttrAndReserved' -Offset 160 -Length 112

    [pscustomobject]@{
        VmName = $TargetVmName
        LengthBytes = 272
        InitServTdInfoHash = Get-HexRange -Offset 0 -Length 48
        InitCpuSvn = Get-HexRange -Offset 64 -Length 16
        InitTeeTcbSvn = Get-HexRange -Offset 80 -Length 16
        InitTeeModel = Get-HexRange -Offset 96 -Length 12
        CurrentServTdInfoHash = Get-HexRange -Offset 112 -Length 48
        ReservedRangesZero = $true
        RawServTdExt = $actual
    } | Format-List
}

function Wait-ForFinalQuoteRetry {
    param(
        [string]$LogPath,
        [int]$TimeoutSeconds
    )

    if (-not $LogPath -or -not (Test-Path $LogPath) -or $TimeoutSeconds -eq 0) {
        return
    }

    $text = Get-Content $LogPath -Raw -ErrorAction SilentlyContinue
    if ($text -notmatch 'GetQuote returned Busy \(attempt 5/6\)' -or
        $text -match 'GetQuote failed after 6 attempts|get_quote_with_retry failed') {
        return
    }

    Write-Host "Waiting up to $TimeoutSeconds second(s) for the final GetQuote retry log."
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 250
        $text = Get-Content $LogPath -Raw -ErrorAction SilentlyContinue
        if ($text -match 'GetQuote failed after 6 attempts|get_quote_with_retry failed') {
            return
        }
    } while ((Get-Date) -lt $deadline)

    Write-Warning 'Timed out waiting for the final GetQuote retry log; stopping MigTD.'
}

if ($PowerTestPath) {
    Import-Module (Join-Path $PowerTestPath 'TdxLiveMigrationUtilities.psm1') -Force
    # New-TestHcsMigTd (and Start-HcsSystem/Stop-HcsSystem later in this script)
    # need the real HCSTest binary module for New-HcsSystemDocument/New-HcsSystem/
    # Start-HcsSystem/Modify-HcsSystem. HCSUtilities.psm1 defines these as plain
    # function calls but never imports HCSTest itself - only its own
    # Import-HcsTestModule helper does that, and nothing calls it automatically.
    $hcsUtilPath = Join-Path $PowerTestPath 'HCSUtilities.psm1'
    if (Test-Path $hcsUtilPath) { Import-Module $hcsUtilPath -Force }
    # Must load the V2 binary (Microsoft.HostCompute.Test.PowerShell.v2.dll):
    # V1's New-VmStateFile P/Invokes vmcompute.dll!CreateEmptyGuestStateFile, which
    # newer OS builds removed in favor of computestorage.dll (V2's HcsInterface).
    # Matches onecore/vm/test/migration/tdx/Loopback/Tdx.LiveMigration.Loopback.Tests.ps1
    # (Import-Module HCSTest -ArgumentList @{ UseVersion2 = $true }).
    $hcsTestModule = Get-Module HCSTest
    if ($hcsTestModule -and $hcsTestModule.NestedModules[0].Name -notlike '*.v2') {
        throw "HCSTest v1 is already loaded. Close this PowerShell process and retry; Remove-Module cannot unload its binary assembly."
    }
    if (-not $hcsTestModule) {
        # Import directly first: if HCSTest is already installed under
        # System32\WindowsPowerShell\v1.0\Modules (manually copied from winbuilds),
        # this succeeds with no network/BNS dependency. Only fall back to
        # PowerTest's Import-HcsTestModule if that direct import can't find it -
        # its $HcsTestModulePath parameter default unconditionally calls
        # Get-TestItem -Chunk TEST_AUTOMATION_BINS (BNS/winbuilds lookup) even when
        # unneeded, and our script's $ErrorActionPreference='Stop' turns that
        # internal failure into a hard error.
        Import-Module HCSTest -ArgumentList @{ UseVersion2 = $true } -Global -Force -ErrorAction SilentlyContinue
        if (-not (Get-Module HCSTest)) {
            if (Get-Command Import-HcsTestModule -ErrorAction SilentlyContinue) {
                Import-HcsTestModule -UseVersion2
            } else {
                throw "HCSTest module unavailable and Import-HcsTestModule not found (HCSUtilities.psm1 missing from -PowerTestPath?)."
            }
        }
    }
    if (-not (Get-Command New-HcsSystemDocument -ErrorAction SilentlyContinue)) {
        throw "New-HcsSystemDocument still unavailable after loading HCSTest (v2)."
    }
    # Some PowerTest builds' TdxLiveMigrationUtilities.psm1 (New-TestHcsMigTd) call
    # New-VmStateFile, which isn't defined anywhere in that module set (every other
    # module - IVMUtilities.psm1, VmgsUtilities.psm1 - creates guest state files via
    # New-GuestStateFile). Load VmgsUtilities.psm1 as a fallback and shim the gap
    # here rather than patching the vendored module.
    $vmgsUtilPath = Join-Path $PowerTestPath 'VmgsUtilities.psm1'
    if (Test-Path $vmgsUtilPath) { Import-Module $vmgsUtilPath -Force }
    if (-not (Get-Command New-VmStateFile -ErrorAction SilentlyContinue)) {
        function global:New-VmStateFile {
            param(
                [Parameter(Mandatory)] [string]$GuestStateFilePath,
                [int]$FileSize = 16MB
            )
            # Prefer the OS-shipped vmgstool.exe (present on TDX-capable hosts) so
            # this stays self-contained; fall back to PowerTest's New-GuestStateFile
            # (needs Copy-TestItem / internal test-content access) if unavailable.
            $tool = Get-Command vmgstool.exe -ErrorAction SilentlyContinue
            if ($tool) { $tool = $tool.Source }
            elseif (Test-Path (Join-Path $env:SystemRoot 'System32\vmgstool.exe')) {
                $tool = Join-Path $env:SystemRoot 'System32\vmgstool.exe'
            }
            if ($tool) {
                & $tool -Create -FilePath $GuestStateFilePath "-FileSize=$FileSize" | Out-Null
            } elseif (Get-Command New-GuestStateFile -ErrorAction SilentlyContinue) {
                New-GuestStateFile -FilePath $GuestStateFilePath -FileSize $FileSize | Out-Null
            } else {
                throw "Cannot create guest state file: vmgstool.exe not found (PATH or System32) and New-GuestStateFile (VmgsUtilities.psm1) is unavailable."
            }
        }
    }
    # The official aka.ms/tdxlm partner-facing loopback test
    # (Tdx.LiveMigration.Partner.Tests.ps1) calls this before enabling migration:
    # repoints Hyper-V's default VM/VHD storage paths to <SystemDrive>\HyperVData\...
    # instead of C:\ProgramData\Microsoft\Windows\Hyper-V. Per that test's own
    # comment, this (for undetermined reasons) is needed to make loopback
    # migration succeed on some lab systems - same generic "failed at migration
    # source" symptom this script can otherwise hit.
    $liveMigUtilPath = Join-Path $PowerTestPath 'LiveMigrationUtilities.psm1'
    if (Test-Path $liveMigUtilPath) { Import-Module $liveMigUtilPath -Force }
    if (Get-Command Enable-LoopbackMigrationDirectoryWorkaround -ErrorAction SilentlyContinue) {
        Enable-LoopbackMigrationDirectoryWorkaround
    }
}
if (-not (Test-Path $IgvmFilePath)) { throw "IGVM not found: $IgvmFilePath" }
if (-not (Test-Path $HashFilePath)) { throw "Hash file not found: $HashFilePath" }

$MigTdHash = (Get-Content $HashFilePath -Raw).Trim()
Write-Host "MigTD: $IgvmFilePath  hash=$MigTdHash"

$migTd = $null; $td = $null; $serialJob = $null; $serialLogPath = $null
try {
    $migTd = New-TestHcsMigTd -Id $MigTdId -IgvmFilePath (Resolve-Path $IgvmFilePath) -GuestStateDirectory . -EnableSerial:$CaptureSerial -Force

    if ($CaptureSerial) {
        $serialLogPath = Join-Path (Get-Location) "$MigTdId.serial.log"
        Remove-Item $serialLogPath -ErrorAction SilentlyContinue
        # New-TestHcsMigTd -EnableSerial wires the MigTD's COM port to named pipe
        # \\.\pipe\raw<Id>; connect a background reader so we can see the MigTD's
        # own log output (built with --log-level info) when migration fails with
        # only a generic VMMS error.
        $serialJob = Start-Job -Name "$MigTdId-serial" -ScriptBlock {
            param($PipeName, $LogPath)
            try {
                $pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', $PipeName, [System.IO.Pipes.PipeDirection]::In)
                $pipe.Connect(15000)
                $reader = [System.IO.StreamReader]::new($pipe)
                while ($true) {
                    $line = $reader.ReadLine()
                    if ($null -eq $line) { break }
                    Add-Content -Path $LogPath -Value $line
                }
            } catch {
                Add-Content -Path $LogPath -Value "[serial-capture] $_"
            }
        } -ArgumentList "raw$MigTdId", $serialLogPath
    }

    $migTd | Start-HcsSystem
    Add-VmHostMigrationTdMapping -MigTdHash $MigTdHash -VmId $migTd.Id
    Set-VMHostMigrationPolicy DisabledByDefault $MigTdHash

    $td = New-VM -Name $VmName -GuestStateIsolation TDX -Generation 2 -NoVHD
    if ($NoPersistentSecrets) {
        if (-not (Get-Command Set-GuestStateIsolationMode -ErrorAction SilentlyContinue)) {
            if (-not $PowerTestPath) {
                throw 'Set-GuestStateIsolationMode is required for -NoPersistentSecrets; provide -PowerTestPath.'
            }
            $wmiUtilitiesPath = Join-Path $PowerTestPath 'WmiUtilities.psm1'
            $ivmUtilitiesPath = Join-Path $PowerTestPath 'IVMUtilities.psm1'
            if (-not (Test-Path $wmiUtilitiesPath)) {
                throw "PowerTest WmiUtilities.psm1 not found: $wmiUtilitiesPath"
            }
            if (-not (Test-Path $ivmUtilitiesPath)) {
                throw "PowerTest IVMUtilities.psm1 not found: $ivmUtilitiesPath"
            }
            Import-Module $wmiUtilitiesPath -Force
            Import-Module $ivmUtilitiesPath -Force
        }
        $td | Set-GuestStateIsolationMode -IsolationMode NoPersistentSecrets
        Write-Host 'Configured NoPersistentSecrets; target-VM OpenHCL attestation is suppressed. MigTD GetQuote still uses IGVMAgent.'
    }
    $td | Set-VmMigratablePolicy -MigratablePolicy EnabledIfHostPermits | Out-Null
    $migratablePolicy = [string]($td | Get-VmMigratablePolicy)
    if ($migratablePolicy -ne 'EnabledIfHostPermits') {
        throw "Failed to opt the TD into host-permitted migration. Actual policy=$migratablePolicy"
    }
    Write-Host 'Configured VM migratable policy: EnabledIfHostPermits.'
    $td | Update-VmMigrationPolicy
    $td | Start-VM

    # The partner test migrates immediately. Keep timing configurable for
    # controlled experiments; both zero and five seconds have produced the same
    # generic VidTdxBind failure on the current blade.
    if ($StartupDelaySeconds -gt 0) {
        Write-Host "Waiting $StartupDelaySeconds second(s) before Move-VM"
        Start-Sleep -Seconds $StartupDelaySeconds
    }
    $td = Get-VM -Name $VmName
    if ($td.State -ne 'Running') {
        throw "TD is not running after Start-VM (state=$($td.State)); cannot begin TDX live migration"
    }

    if ($ServTdExtOnly) {
        if (-not $PowerTestPath) {
            throw '-PowerTestPath is required for -ServTdExtOnly.'
        }
        Test-ServTdExtLayout `
            -TargetVmName $VmName `
            -ExpectedHash $MigTdHash `
            -ModuleRoot $PowerTestPath
        Write-Host 'PASS: ServTdExt contains the prebound hash in both binding slots with expected zero padding.'
        return
    }

    $moveErr = $null
    Move-VM -Name $VmName -DestinationHost localhost -ErrorVariable moveErr -ErrorAction SilentlyContinue

    if ($ExpectReject) {
        if (-not $moveErr) { throw "FAIL: migration succeeded but rejection expected" }
        Write-Host "PASS: migration rejected as expected ($($moveErr[0]))"
    } else {
        if ($moveErr)     { throw "FAIL: migration failed: $($moveErr[0])" }
        Write-Host "PASS: migration succeeded"
    }
}
finally {
    if ($td)    { $td | Stop-VM -Force -ErrorAction SilentlyContinue; $td | Remove-VM -Force -ErrorAction SilentlyContinue }
    if ($MigTdHash) {
        Set-VMHostMigrationPolicy DisabledByDefault $MigTdHash -ErrorAction SilentlyContinue
    }
    if ($MigTdHash) { Remove-VmHostMigrationTdMapping -MigTdHash $MigTdHash -ErrorAction SilentlyContinue }
    if ($serialJob) {
        Wait-ForFinalQuoteRetry `
            -LogPath $serialLogPath `
            -TimeoutSeconds $SerialDrainTimeoutSeconds
    }
    if ($migTd)  { Stop-HcsSystem $migTd -ErrorAction SilentlyContinue; $migTd.Close() }
    if ($serialJob) {
        # Keep reading until MigTD is stopped and closes the named pipe. Stopping
        # this job before Stop-HcsSystem truncated logs while an outstanding
        # GetQuote retry was still running.
        Wait-Job $serialJob -Timeout 5 -ErrorAction SilentlyContinue | Out-Null
        if ($serialJob.State -notin @('Completed', 'Failed')) {
            Stop-Job $serialJob -ErrorAction SilentlyContinue | Out-Null
        }
        Remove-Job $serialJob -Force -ErrorAction SilentlyContinue
        if (Test-Path $serialLogPath) { Write-Host "MigTD serial log: $serialLogPath" }
    }
}
