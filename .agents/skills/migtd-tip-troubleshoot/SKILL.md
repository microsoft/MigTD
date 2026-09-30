---
name: migtd-tip-troubleshoot
description: Troubleshoot Azure TiP / TDX lab-blade MigTD loopback migration failures, PowerTest and HCSTest setup, ServTD hash binding, MigTD serial logs, and Hyper-V VMMS/Worker ETW traces. Use when a lab-blade migration test fails, Move-VM reports a generic source/destination failure, New-TestHcsMigTd dependencies are missing, or TDX migration logs need diagnosis.
---

# MigTD TiP Lab-Blade Troubleshooting

Use this skill for real-hardware Azure TiP / TDX loopback migration failures.
The canonical test package is `sh_script/Azure/tip/`.

## Building the package (Linux)

To (re)build the TiP package from source on a fresh Debian/Ubuntu host, first
bootstrap the build environment once with the reusable setup script:

```bash
# System toolchain (single sudo apt install) + Rust + x86_64-unknown-none target
<REPO_ROOT>/sh_script/setup_build_env.sh
# print only the apt one-liner:  sh_script/setup_build_env.sh --print-apt
# apt step only / rust step only: --apt-only / --rust-only

source "$HOME/.cargo/env"
git submodule update --init --recursive deps/td-shim deps/spdm-rs deps/linux-sgx
./sh_script/preparation.sh
```

Then build:

```bash
export CC=clang AR=llvm-ar
./sh_script/Azure/tip/build_tip_package.sh \
    --os-root <OS_ROOT> --fetch-collaterals
```

On GCC >= 14 the vendored linux-sgx DCAP C code would fail to compile;
`src/attestation/build.rs` auto-demotes those errors to warnings, so no manual
`CFLAGS` override is needed.

`--os-root` bundles PowerTest, HCSTest PowerShell v2 source, and TDX
live-migration source scripts. The Linux build no longer requires winbuild
access. Use `Publish-TipPackage.ps1` on Windows to add HCSTest's `coreclr` v2
binary, VmgsTool, and Secure Firmware from the matching winbuild.

## Parameters

Never hardcode a developer's mount points or OS enlistment:

| Parameter | Meaning | Example |
|---|---|---|
| `REPO_ROOT` | MigTD repository root | `C:\src\MigTD` or `/home/user/MigTD` |
| `PACKAGE_DIR` | Published TiP package | `D:\migtd_igvm\tip-package` |
| `SOURCE_PACKAGE_DIR` | Linux-built source package copied to Windows | `C:\staging\tip-package` |
| `WINBUILD_ROOT` | Matching winbuild build directory | `\\winbuilds\release\<branch>\<build>` |
| `POWERTEST_PATH` | Installed PowerTest module directory | `C:\Program Files\PowerShell\Modules\PowerTest` |
| `OS_ROOT` | Optional Windows OS source enlistment | `Q:\src\os\os.2020` |
| `HCSTEST_SOURCE` | Optional prebuilt HCSTest folder from winbuilds | `\\winbuilds\...\test_automation_bins\vm\test\compute\HCSTest` |
| `SECFW_FILE` | Optional matching test Secure Firmware DLL | `\\winbuilds\...\secfw_test_GenuineIntel.dll` |
| `OUTPUT_DIR` | Diagnostic bundle destination | `D:\logs\tdxlm-20260719` |

If `OS_ROOT` is available, reference paths are:

```text
<OS_ROOT>\src\onecore\vm\test\migration\tdx\Loopback\Tdx.LiveMigration.Partner.Tests.ps1
<OS_ROOT>\src\onecore\vm\test\migration\tdx\Loopback\Tdx.LiveMigration.Loopback.Tests.ps1
<OS_ROOT>\src\onecore\vm\test\common\powershell\PowerTest
<OS_ROOT>\src\onecore\vm\worker\migration\TdxProtocol.cpp
<OS_ROOT>\src\onecore\vm\compute\test\hcstest\powershellV2
```

## Workflow

1. **Enrich and publish from a matching winbuild**

   ```powershell
   <SOURCE_PACKAGE_DIR>\Publish-TipPackage.ps1 `
       -PackageDir <SOURCE_PACKAGE_DIR> `
       -WinBuildRoot <WINBUILD_ROOT> `
       -ArchFlavor amd64fre `
       -SecFwFile <SECFW_FILE> `
       -Destination <PACKAGE_DIR> `
       -Force
   ```

   The publisher must add prebuilt HCSTest v2
   (`coreclr\Microsoft.HostCompute.Test.PowerShell.v2.dll`) and VmgsTool.
   Pass `-SkipSecFw` only when the blade already has the matching Secure
   Firmware configured.

2. **Install bundled dependencies and configure the host**

   ```powershell
   cd <PACKAGE_DIR>
   .\Run-TipTests.ps1 -InstallDependencies -ConfigureHost
   ```

   Run setup from a fresh elevated PowerShell 7 process. Reboot if it reports a
   Secure Firmware change, then run `.\Run-TipTests.ps1` for the default
   mock-quote/no-secrets migration and ServTdExt checks.

3. **Validate the host and modules**

   ```powershell
   <REPO_ROOT>\.agents\skills\migtd-tip-troubleshoot\scripts\Test-TdxLmLabBlade.ps1 `
       -PowerTestPath <POWERTEST_PATH>
   ```

   Add `-Configure` only when host settings should be changed. Supply
   `-HcsTestSource <HCSTEST_SOURCE>` if HCSTest v2 is not installed.
   In a built TiP package, the same helpers are under `troubleshooting\`.

4. **Run the package with serial capture**

   ```powershell
   cd <PACKAGE_DIR>
   .\Invoke-TdxLmLoopback.ps1 `
       -IgvmFilePath .\test-migtd-accept-all.igvm `
       -PowerTestPath <POWERTEST_PATH> `
       -CaptureSerial
   ```

   For a fully IGVMAgent-independent smoke test, use both the mock-quote image
   and the target-VM no-secrets mode:

   ```powershell
   .\Invoke-TdxLmLoopback.ps1 `
       -IgvmFilePath .\test-migtd-accept-all_mock_quote.igvm `
       -PowerTestPath <POWERTEST_PATH> `
       -NoPersistentSecrets `
       -CaptureSerial
   ```

   Validate startup request handling and a post-start external GetTDReport
   independently of migration/rebind:

   ```powershell
   .\Test-TdxMigTdStartupRequests.ps1 `
       -IgvmFilePath .\test-migtd-accept-all_mock_quote.igvm
   ```

   The Host OS `New-TestHcsMigTd` helper configures GHCI log level `Trace`, so
   startup issues `EnableLogArea` first and an internal `GetTDReport` second to
   cache TDINFO. The test treats that internal request as setup, then submits a
   separate HCS `MigTdReport` query with a random REPORTDATA nonce, matching the
   request path used by IGVMAgent health checks. It validates the nonce,
   TDREPORT hashes, image TD Info Hash, and external GHCI VDev events. With a
   working IGVMAgent, use
   `test-migtd-getquote-all.igvm -ExpectedGetQuoteResult Success` to match the
   Host OS GetQuote test (Worker Analytic event 18670).

   MigTD also accepts operation 5 (`GetMigtdData`), but the current Host OS
   `GhciRequestOperation` exposes only operations 1–4 and has no HCS/PowerShell
   trigger for operation 5. `Run-TipTests.ps1` reports it as `UNAVAILABLE`
   rather than claiming real-host coverage.

5. **Verify the host prebind hash**

   ```powershell
   <REPO_ROOT>\.agents\skills\migtd-tip-troubleshoot\scripts\Test-MigTdHashBinding.ps1 `
       -SerialLogPath .\tipmigtd.serial.log `
       -HashFilePath .\test-migtd-accept-all.igvm.hash
   ```

   Hyper-V passes host `MigTdHash` directly to `TDH.SERVTD.PREBIND`, so it must
   exactly equal the runtime `TD Info Hash` (`SERVTD_INFO_HASH`).

   ```text
   MigTdHash == TD Info Hash
   ```

   Do not use `migtd-hash --calc-servtd-hash` for the package `.hash`. That
   computes the outer TDREPORT `SERVTD_HASH`; using it for prebind causes
   `TDX_SERVTD_INFO_HASH_MISMATCH`.

6. **Validate the target ServTdExt after prebind**

   ```powershell
   .\Test-TdxServTdExtPrebind.ps1 `
       -IgvmFilePath .\test-migtd-accept-all_mock_quote.igvm `
       -PowerTestPath <POWERTEST_PATH> `
       -NoPersistentSecrets
   ```

   The 272-byte value returned by `Get-VmServTdExt` must contain the expected
   48-byte hash at offsets 0 and 112. Init/current attributes and all reserved
   ranges must be zero; CPU SVN, TEE TCB SVN, and TEE model metadata between
   the hashes are platform-specific.

7. **Test MigTD rebinding**

   ```powershell
   .\Test-TdxLmRebind.ps1 `
       -OldIgvmFilePath .\test-migtd_mock_quote.igvm `
       -NewIgvmFilePath .\test-migtd_mock_quote_rebind.igvm
   ```

   The inputs may be different files or the same file. For equal hashes, the
   script follows the host OS rebind test by assigning the second MigTD a
   synthetic mapping key while verifying the partition reports the real hash.
   It captures both MigTD serial logs by default. Rebind error `0x800721CE`
   maps to GHCI `MIGPOLICY_UNSATISFIED_ERROR`; inspect the old/new logs to
   identify which policy or identity check rejected the peer. For host-side
   boundaries, wrap the command with `Invoke-TdxLmDiagnosticCapture.ps1`,
   passing both serial paths and `-EnableAnalytic -CaptureEtw`; the WPR profile
   includes VMMS, Worker, VID, and GHCI VDev rebind events. The script verifies
   both HCS systems are `Running` with valid runtime IDs immediately before
   rebind and waits up to 30 seconds for terminal rebind logs before cleanup.
   Host policy is `DisabledByDefault`; the test VM is explicitly set to
   `EnabledIfHostPermits` before its migration-policy hash is assigned.

   Policy leaf-key rotation uses the same policy SVN, root CA, and leaf Subject
   Name with a different leaf key. Each peer authenticates the other peer's
   signed TCB mapping; the destination does not require future peer measurements
   in its local mapping. Test both directions:

   ```powershell
   .\Test-TdxLmRebind.ps1 `
       -OldIgvmFilePath .\test-migtd_mock_quote.igvm `
       -NewIgvmFilePath .\test-migtd_mock_quote_key_rotation.igvm
   .\Test-TdxLmRebind.ps1 `
       -OldIgvmFilePath .\test-migtd_mock_quote_key_rotation.igvm `
       -NewIgvmFilePath .\test-migtd_mock_quote.igvm
   ```

8. **Capture Hyper-V diagnostics around one clean repro**

   ```powershell
   <REPO_ROOT>\.agents\skills\migtd-tip-troubleshoot\scripts\Invoke-TdxLmDiagnosticCapture.ps1 `
       -OutputDir <OUTPUT_DIR> `
       -EnableAnalytic `
       -CaptureEtw `
       -SerialLogPath .\tipmigtd.serial.log `
       -ReproCommand {
           .\Invoke-TdxLmLoopback.ps1 `
               -IgvmFilePath .\test-migtd-accept-all.igvm `
               -PowerTestPath <POWERTEST_PATH> `
               -CaptureSerial
       }
   ```

   To isolate `Microsoft.Windows.HyperV.GhciVDev` events in a smaller ETL:

   ```powershell
   <REPO_ROOT>\.agents\skills\migtd-tip-troubleshoot\scripts\Invoke-GhciVDevDiagnosticCapture.ps1 `
       -OutputDir <OUTPUT_DIR> `
       -ReproCommand { <REPRO_COMMAND> }
   ```

   This uses provider GUID `AEFC8638-19A2-553A-06CB-C3984FFC7EE8` and exports
   raw `tracerpt` CSV/XML plus provider-filtered text/CLIXML when
   `Get-WinEvent` can decode the ETL. Use `Export-GhciVDevEvents.ps1` to process
   an existing trace.

9. **Classify the failure boundary**

   | Evidence | Boundary |
   |---|---|
   | MigTD does not boot | IGVM/SecFw/HCS launch |
   | Serial reaches `EnableLogArea`, then stops | Host failed before later MigTD protocol requests |
   | VMMS event 20960 | MigTD approval was requested and rejected/failed |
   | Worker `TdxProtocol.cpp:334` | `VidTdxBind` failed before approval |
   | `0xC0350071` | `ERROR_HV_OPERATION_FAILED`; generic hypervisor failure |
   | SEAM status `0xC0000D0300000000` | `TDX_SERVTD_INFO_HASH_MISMATCH` |
   | `StartVtl0` + `0x800704C7` after 60 seconds | management VTL readiness timeout; inspect HCL/GHCI ETW |
   | `StartVtl0` timeout after `OnAttestDelegate` | An unresponsive IGVMAgent can consume two 30-second RPC timeouts; verify agent health or use `-NoPersistentSecrets` |
   | VMMS says `Failed to receive compatibility info` | Destination/connection failure; inspect Worker event first |

## Load-bearing test behavior

- Load **HCSTest v2**:

  ```powershell
  Import-Module HCSTest -ArgumentList @{ UseVersion2 = $true } -Global
  ```

  V1 calls `vmcompute.dll!CreateEmptyGuestStateFile`; newer builds require the
  v2 path through `computestorage.dll`.
- Import installed HCSTest directly before using PowerTest's
  `Import-HcsTestModule`. Its default parameter calls
  `Get-TestItem -Chunk TEST_AUTOMATION_BINS` even when the module is already
  installed, which can fail through BNS (`System.Private.ServiceModel.dll`).
- Match `Tdx.LiveMigration.Partner.Tests.ps1`:
  - call `Enable-LoopbackMigrationDirectoryWorkaround`;
  - use `New-VM ... -GuestStateIsolation TDX -Generation 2 -NoVHD`;
  - call `Move-VM` immediately after `Start-VM`.
- Regular package images are built with `igvm-attest`; MigTD GHCI GetQuote
  therefore requires a compatible IGVMAgent even when the target VM uses
  `-NoPersistentSecrets`.
- `-NoPersistentSecrets` suppresses only the target VM's OpenHCL attestation
  call and changes TPM/VMGS persistence semantics.
- Pair `-NoPersistentSecrets` with an `_mock_quote` image for a fully
  IGVMAgent-independent smoke test.
- `RequireIgvmAgent` under
  `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization` controls
  whether VM startup requires an available agent endpoint; it is not needed
  for the fully mock-quote/no-secrets path.
- Use `-StartupDelaySeconds` only as a controlled experiment. Zero and five
  seconds producing the same bind failure rules out that timing difference;
  `0xC0350071` does not identify a timing or save/restore-state cause.
- `secfw_test_GenuineIntel.dll` must exist, the `SecFwFile` registry value must
  select it, and a reboot is required only when that registry value changes.

## Detailed reference

Read `references/labblade-playbook.md` for the investigation history, commands,
event channels, HRESULT interpretation, and parameterized OS-source lookup.
