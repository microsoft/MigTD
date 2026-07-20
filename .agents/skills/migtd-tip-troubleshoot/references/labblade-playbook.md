# MigTD TiP Lab-Blade Troubleshooting Playbook

This playbook records the troubleshooting sequence that took a TiP package from
module-load failures to a precise Hyper-V TDX bind failure. Paths outside MigTD
are examples only; pass them as parameters (`OS_ROOT`, `POWERTEST_PATH`,
`HCSTEST_SOURCE`) instead of committing machine-specific paths.

## 1. Package build and baseline

Build all variants on Linux:

```bash
./sh_script/Azure/tip/build_tip_package.sh \
    --out out/tip-package \
    --fetch-collaterals
```

Copy `out/tip-package` to the TDX host. The package contains accept-all,
reject-all, real-policy, and getquote-all IGVM/hash pairs.

## 2. PowerTest and HCSTest dependency chain

`New-TestHcsMigTd` is in `TdxLiveMigrationUtilities.psm1`, but it calls commands
from other modules:

- `New-HcsSystemDocument`, `New-HcsSystem`, `Start-HcsSystem`,
  `Stop-HcsSystem` and `New-VmStateFile` come from **HCSTest**.
- `Grant-VmGroupAccess` and `Add-HcsSystemDocumentIsolated` come from
  `HCSUtilities.psm1`.
- `Enable-LoopbackMigrationDirectoryWorkaround` and
  `Enable-LoopbackMigration` come from `LiveMigrationUtilities.psm1`.

Load HCSTest v2 explicitly:

```powershell
Import-Module HCSTest -ArgumentList @{ UseVersion2 = $true } -Global -Force
(Get-Module HCSTest).NestedModules | Select-Object Name, Path
```

The nested binary name must end in `.v2`.

### Why v2 matters

In the OS source tree:

```text
<OS_ROOT>\src\onecore\vm\compute\test\hcstest\powershell\New-VmStateFile.cs
<OS_ROOT>\src\onecore\vm\compute\test\hcstest\powershellV2\New-VmStateFile.cs
```

V1 reaches `vmcompute.dll!CreateEmptyGuestStateFile`; v2 uses the newer
`computestorage.dll` implementation. Loading v1 on a newer OS produces:

```text
Unable to find an entry point named 'CreateEmptyGuestStateFile' in DLL 'vmcompute.dll'
```

### Installing HCSTest without BNS at runtime

Copy a matching prebuilt HCSTest directory from winbuilds to:

```text
%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules\HCSTest
```

The source convention is:

```text
\\winbuilds\release\<branch>\<build>.<qfe>.<date-time>\<archflavor>\
test_automation_bins\vm\test\compute\HCSTest
```

Use `<OS_ROOT>\bin\<archflavor>\test_automation_bins\buildname.txt` to identify
the matching build. Copy from a fresh elevated PowerShell process: loaded .NET
assemblies remain locked even after `Remove-Module`.

PowerTest's `Import-HcsTestModule` has a default parameter that evaluates
`Get-TestItem -Chunk TEST_AUTOMATION_BINS` before it tries the installed module.
On a standalone blade that can fail while loading BNS dependencies:

```text
TestItem:HCSTest ... PathNotFound
Cannot find ... System.Private.ServiceModel.dll
```

Avoid that path by importing installed HCSTest directly first.

## 3. Host prerequisites

`Initialize-TdxLmMachine` performs:

```powershell
Enable-VMMigration
Set-VMHost `
    -VirtualMachineMigrationAuthenticationType Kerberos `
    -UseAnyNetworkForMigration $true `
    -VirtualMachineMigrationPerformanceOption Compression
Enable-LoopbackMigration
Update-SecFw
```

The test also follows the partner-reference workaround:

```powershell
Enable-LoopbackMigrationDirectoryWorkaround
```

Check:

- `%SystemRoot%\System32\secfw_test_GenuineIntel.dll` exists.
- `HKLM:\SYSTEM\CurrentControlSet\Control\Hypervisor\SecFwFile` selects it.
- Reboot only if the registry value changed.
- TDX-LM feature `53058573` is enabled. `Get-VelocityFeatureEnabled` requires
  `StagingTool.exe`; provide that tool explicitly on a standalone blade rather
  than triggering `Copy-TestItem`/BNS.

Use `scripts/Test-TdxLmLabBlade.ps1` for a repeatable report.

## 4. Serial logging and hash interpretation

Run:

```powershell
.\Invoke-TdxLmLoopback.ps1 ... -CaptureSerial
```

The observed serial sequence was:

```text
MigTD Version - 0.7.1
TDINFO policy binding verification failed: SvnMismatch
    (ignored: TEST MODE, continuing startup)
TD Info Hash: <96 hex chars>
enable_logarea: Logging has been enabled
```

Interpretation:

- The `SvnMismatch` was explicitly non-fatal in this test build.
- Reaching `EnableLogArea` proves MigTD booted and the host completed the first
  GHCI request.
- Silence after that means the host failed before sending later migration
  protocol requests.

Hyper-V's host `MigTdHash` is the value passed to `TDH.SERVTD.PREBIND`. It must
be the direct `SERVTD_INFO_HASH` printed as `TD Info Hash`:

```text
MigTdHash == TD Info Hash
```

The distinct composite value
`SHA384(SERVTD_INFO_HASH || SERVTD_TYPE || SERVTD_ATTR)` is the TDREPORT
`SERVTD_HASH`. It must not be written to the host `.hash` file. Use
`scripts/Test-MigTdHashBinding.ps1` to detect this specific mix-up.

## 5. Event and ETW ladder

Start with enabled channels:

```powershell
Get-WinEvent Microsoft-Windows-Hyper-V-VMMS-Admin
Get-WinEvent Microsoft-Windows-Hyper-V-VMMS-Operational
Get-WinEvent Microsoft-Windows-Hyper-V-Worker-Admin
Get-WinEvent Microsoft-Windows-Hyper-V-Worker-Operational
```

Important VMMS Admin events:

| Event | Meaning |
|---|---|
| 20413 | migration initiated |
| 20960 | TDX LM approval failed; includes reason/details |
| 20999 | TDX LM path reported not implemented |
| 21024 | generic migration failed summary |

If 20413 and 21024 occur at the same instant and 20960 is absent, the failure
occurred before MigTD approval.

Enable analytic channels only around one repro:

```powershell
wevtutil sl Microsoft-Windows-Hyper-V-VMMS-Analytic /e:true
wevtutil sl Microsoft-Windows-Hyper-V-Worker-Analytic /e:true
# reproduce
wevtutil sl Microsoft-Windows-Hyper-V-VMMS-Analytic /e:false
wevtutil sl Microsoft-Windows-Hyper-V-Worker-Analytic /e:false
```

Prefer `scripts/Invoke-TdxLmDiagnosticCapture.ps1`, which restores the original
channel state and writes a timestamp-bounded bundle. Add `-CaptureEtw` to
capture focused VMMS, Worker, VID, WinHv, and hypervisor providers into
`tdxlm.etl`.

## 6. Current failure boundary

Worker Operational event 1840 reported:

```text
onecore\vm\worker\migration\tdxprotocol.cpp(334)
0xC0350071
```

At the matching OS source:

```text
<OS_ROOT>\src\onecore\vm\worker\migration\TdxProtocol.cpp
```

line 334 throws the result returned by `VidTdxBind`. `0xC0350071` is
`ERROR_HV_OPERATION_FAILED`, a generic hypervisor status. It must not be
confused with `ERROR_HV_INVALID_SAVE_RESTORE_STATE`, which is `0xC0350017`.

The VID kernel path is:

```text
VID_IOCTL_TDX_BIND_OR_REBIND
  -> VidTdxIoctlPartitionBindOrRebind
  -> VidPartitionTableLookupAndReference(MigTdPartitionGuid)
  -> WinHvBindOrRebindMigrationTd(target partition, MigTD partition, ...)
```

The focused ETW capture exposed the lower-level SEAM status:

```text
EventName:            TDX Bind failed
PartitionId:          0x18
Status:               0x71
SeamStatus:           0xC0000D0300000000
MigrationPartitionId: 0x17
```

Intel's TDX module defines `0xC0000D0300000000` as
`TDX_SERVTD_INFO_HASH_MISMATCH`. `TDH.SERVTD.BIND` computes the service TD's
current `SERVTD_INFO_HASH` and compares it directly with the value stored by
`TDH.SERVTD.PREBIND`.

The package had incorrectly used:

```text
migtd-hash ... --calc-servtd-hash
```

That produced the outer composite hash `c9f787...`, while MigTD's direct TD
Info Hash was `5c2950...`. The correction is to omit `--calc-servtd-hash` when
generating the host `.hash` file.

The official partner test migrates immediately. The local test has reproduced
the same bind failure with both zero and five seconds of startup delay, so the
delay is not an established cause. Use this only for controlled comparison:

```powershell
.\Invoke-TdxLmLoopback.ps1 ... -StartupDelaySeconds 0
.\Invoke-TdxLmLoopback.ps1 ... -StartupDelaySeconds 15
```

Do not replace the reference `-NoVHD` topology unless intentionally testing a
different scenario.

## 7. Management-VTL startup timeout

After correcting the prebind hash, a later repro reached a different boundary:

```text
VidTdxIoctlPartitionPrebind ... success
StartVirtualProcessors ... success
StartVtl0 ... 0x800704C7 after 60 seconds
```

`WorkerTaskStarting` uses a 60-second default for `WaitVtl0Start`; the
`0x800704C7` record is the timeout cancellation, not proof that the operator
pressed Ctrl+C. No SEAM or hypercall failure accompanied this repro.

This is a management-firmware/HCL startup issue, not a prebind failure. The
focused WPR profile includes Hyper-V HCL, HCL kernel, Guest Emulation Device,
and GHCI virtual-device providers so a subsequent capture can identify why
`vmfirmwarecvm.dll` did not signal VTL0 readiness.

The expanded trace isolated this timeout to the host IGVM attestation RPC:

```text
Reading VM ID from VMGS
Retrieving key-encryption key
GuestEmulationDevice::OnAttestDelegate
```

The host implementation calls `RpcIGVmAttest` through the local
`IGVM_AGENT_RPC_SERVER` endpoint. Its binding has a 30-second call timeout.
For an unencrypted newly-created VMGS, OpenHCL tolerates failure and performs
both a wrapped-key request and a key-release request. If `igvmagent.exe` has
registered the endpoint but is stale, suspended, or otherwise not replying,
the two calls consume 30 seconds each and exactly exhaust the worker's
60-second `StartVtl0` budget.

Inspect the agent process before retrying:

```powershell
Get-Process igvmagent -ErrorAction SilentlyContinue |
    Select-Object Id, Path, StartTime, Responding
```

Process presence is not itself an error. Regular package images are built with
`igvm-attest`, and MigTD therefore needs a compatible IGVMAgent for GHCI
GetQuote during migration approval. A stale or incompatible agent must be
repaired or replaced, not simply removed when testing a regular image.

`RequireIgvmAgent` controls whether VM startup requires the endpoint:

```powershell
$path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization'
Get-ItemProperty $path -Name RequireIgvmAgent -ErrorAction SilentlyContinue
```

To suppress the target VM's OpenHCL attestation request, use:

```powershell
.\Invoke-TdxLmLoopback.ps1 ... -NoPersistentSecrets
```

This sets `GuestStateIsolationMode=NoPersistentSecrets`. Hyper-V advertises
`SuppressAttestation` to OpenHCL, which skips attestation before calling
`RpcIGVmAttest`. This is a valid smoke-test bypass, but it changes TPM/VMGS
persistence semantics and is not identical to the partner-reference test.

This only bypasses attestation for the target VM's OpenHCL startup. The packaged
MigTD is built with `igvm-attest`; its GHCI GetQuote operation still calls the
same IGVMAgent RPC interface during migration approval. A GetQuote failure with
`0x80072F78` is `WININET_E_INVALID_SERVER_RESPONSE`: the agent responded, but
its response did not satisfy the host's V2 header/size validation. Use an
IGVMAgent binary matching the host build and supporting GetQuote V2.

For a fully agent-independent smoke test, use a package image built with
`use-mock-quote` and suppress target-VM attestation:

```powershell
.\Invoke-TdxLmLoopback.ps1 `
    -IgvmFilePath .\test-migtd-accept-all_mock_quote.igvm `
    -PowerTestPath <POWERTEST_PATH> `
    -NoPersistentSecrets `
    -CaptureSerial
```

## 8. Validate ServTdExt after prebind

`Get-VmServTdExt` returns the runtime `HV_TD_SERVICE_TD_EXT` as 544 hexadecimal
characters (272 bytes). After first binding with `SERVTD_ATTR=0`, the relevant
layout is:

| Byte offset | Size | Expected value |
|---:|---:|---|
| 0 | 48 | initial bound `SERVTD_INFO_HASH` |
| 48 | 16 | zero initial attribute and reserved bytes |
| 64 | 44 | platform CPU SVN, TEE TCB SVN, and TEE model metadata |
| 108 | 4 | zero reserved bytes |
| 112 | 48 | current bound `SERVTD_INFO_HASH` |
| 160 | 112 | zero current attribute and reserved bytes |

Run the packaged validator:

```powershell
.\Test-TdxServTdExtPrebind.ps1 `
    -IgvmFilePath .\test-migtd-accept-all_mock_quote.igvm `
    -PowerTestPath <POWERTEST_PATH> `
    -NoPersistentSecrets
```

It starts MigTD, registers the prebind hash, starts the target VM, polls
`Get-VmServTdExt -VmName tiptd`, validates the exact layout above, and cleans
up without issuing `Move-VM`.

When serial capture observes `GetQuote returned Busy (attempt 5/6)`, cleanup
keeps MigTD alive for up to `-SerialDrainTimeoutSeconds` (default 30) so the
sixth-attempt terminal error is written before the named pipe closes.
