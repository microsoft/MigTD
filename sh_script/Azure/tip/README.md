# MigTD TiP Loopback Test Package

Self-contained TDX live-migration test for a labblade. Build on Linux, copy the
package to the TDX host, run loopback migrations manually.

## 1. Build (Linux)

### 1.0 One-time build-environment setup (fresh host)

On a clean Debian/Ubuntu box, install the full toolchain (system packages via a
single `sudo apt-get install`, plus Rust + the `x86_64-unknown-none` target) with:

```bash
./sh_script/setup_build_env.sh          # sudo apt install + rustup/toolchain
# or just print the one-line apt command:  ./sh_script/setup_build_env.sh --print-apt
```

Then initialize submodules and apply patches (first time only):

```bash
source "$HOME/.cargo/env"
git submodule update --init --recursive deps/td-shim deps/spdm-rs deps/linux-sgx
./sh_script/preparation.sh
```

Set the C toolchain the MigTD/td-shim build expects:

```bash
export CC=clang AR=llvm-ar
```

On GCC >= 14 the vendored linux-sgx DCAP C code would otherwise fail to
compile; `src/attestation/build.rs` detects this and demotes those errors back
to warnings automatically, so no manual `CFLAGS` override is needed.

### 1.1 Build the package

```bash
./sh_script/Azure/tip/build_tip_package.sh \
    --out out/tip-package \
    --fetch-collaterals \
    --tcb-mapping /path/to/previous-release/tcb_mapping.json \
    --os-root /path/to/os.2020 \
    --hcstest-dir /path/to/prebuilt/HCSTest \
    --secfw-file /path/to/secfw_test_GenuineIntel.dll
```

This creates a source-complete package without requiring Linux access to
`\\winbuilds`. `--os-root` bundles PowerTest, HCSTest PowerShell v2 source, and
the OS TDX live-migration test sources. If matching prebuilts are mounted on
Linux, `--hcstest-dir`, `--vmgstool-file`, and `--secfw-file` can still create a
fully enriched package in one step.

Use `--skip-dependencies` for an image-and-test-script-only package when
PowerTest and HCSTest v2 are already installed on the TiP host.
Omit `--tcb-mapping` only for a first release; later releases must provide the
authority-maintained mapping whose historical real hashes remain supported.

Produces in `out/tip-package/`:

| File | Role |
|------|------|
| `test-migtd-accept-all.igvm` + `.hash` | allow-all policy → migration succeeds |
| `test-migtd-reject-all.igvm` + `.hash` | bad-FMSPC policy → migration rejected |
| `test-migtd.igvm` + `.hash` | `config/Azure/policy_data_raw.json` → succeeds if node FMSPC/TCB match |
| `test-migtd_rebind.igvm` + `.hash` | same real policy and signer with `policySvn` incremented by one |
| `test-migtd_key_rotation.igvm` + `.hash` | same real policy SVN/root/leaf Subject Name, signed by a new policy leaf key |
| `test-migtd-getquote-all.igvm` + `.hash` | GetQuote init image |
| `test-migtd-accept-all_mock_quote.igvm` + `.hash` | allow-all policy with built-in mock quote |
| `test-migtd-reject-all_mock_quote.igvm` + `.hash` | reject policy with built-in mock quote |
| `test-migtd_mock_quote.igvm` + `.hash` | policy generated from mock measurements with built-in mock quote |
| `test-migtd_mock_quote_rebind.igvm` + `.hash` | same mock-quote real policy and signer with `policySvn` incremented by one |
| `test-migtd_mock_quote_key_rotation.igvm` + `.hash` | mock-quote counterpart signed by the rotated policy leaf key |
| `test-migtd{,_rebind,_key_rotation,_mock_quote,_mock_quote_rebind,_mock_quote_key_rotation}.policy.json` | signed policy snapshot embedded in the corresponding image |
| `Invoke-TdxLmLoopback.ps1`, `Run-TipTests.ps1` | migration test scripts |
| `Test-TdxMigTdStartupRequests.ps1` | validate startup `EnableLogArea` plus an external post-start `GetTDReport` health-check query; optionally validate GetQuote |
| `Test-TdxServTdExtPrebind.ps1` | start a prebound TD and validate both ServTdExt hash slots and zero padding |
| `Test-TdxLmRebind.ps1` | rebind a running TD between two same- or different-image MigTD instances |
| `Publish-TipPackage.ps1` | enrich the source package with matching winbuild prebuilts and copy it to a destination |
| `Install-TipDependencies.ps1` | install bundled PowerTest, HCSTest v2, VmgsTool, and optional test SecFw |
| `troubleshooting/Export-MigTdMigrationTimeline.ps1` | normalize VMMS/Worker/VID/GHCI events from one ETL |
| `troubleshooting/Compare-MigTdNodeTraces.ps1` | align source and destination timelines around one migration request |
| `troubleshooting/Get-MigTdDeploymentProvenance.ps1` | capture host build, repository, image, hash, mapping, and HCS provenance |
| `troubleshooting/Test-CrossNodeMigTdBinding.ps1` | validate destination hash mapping and running MigTD before cross-node migration |
| `dependencies/Source` | OS-source snapshots of PowerTest, HCSTest v2, and TDX live-migration tests |
| `dependencies/PowerTest`, `dependencies/HCSTest` | installable host modules; HCSTest becomes complete after publishing |
| `dependencies/Tools/VmgsTool.exe` | build-matched VMGS creation tool added by the publisher |
| `dependencies/SecFw` | optional build-matched test Secure Firmware |

`.hash` is the direct `SERVTD_INFO_HASH` the host passes to
`TDH.SERVTD.PREBIND` as `MigTdHash`. Built with MigTD-native tooling only
(`cargo image`, `migtd-hash`, `build_azure_mock_test.sh`).

The `_mock_quote` variants use the `use-mock-quote` feature and do not use the
host IGVMAgent GetQuote path. Their sibling `.hash` files are still direct
`SERVTD_INFO_HASH` values calculated from each final emitted IGVM.

Each real-policy variant is emitted as an original/rebind pair. The rebind
policy increments `policySvn` with the same policy key, measures the resulting
image, then adds that image's hash to the same cumulative TCB mapping before
the final signing pass. The authenticated rebind-source policy therefore maps
both the original init hash and its current hash.
The real-quote pair uses a two-phase measure-then-bind build so its ServTD TCB
mapping contains the final image's real `tdinfo_hash`. The mock-quote pair
follows the same authority-history reset and adds the actual original/rebind
image hashes needed for ServTdExt lookup. Phase-1 synthetic mappings are never
promoted into the final signed mapping.
The builder calculates each image's final runtime TD Info Hash independently.
If a pair produces equal hashes, one shared mapping entry is sufficient.

The key-rotation variants keep `policySvn` unchanged so rebind is authorized
in both directions. Their outer policy certificate uses a new key, but chains
to the same root CA and carries the same leaf Subject Name. TD identity and TCB
mapping collateral remain signed by the original leaf, isolating the test to
rotation of the policy-signing leaf. Each image carries a signed TCB mapping for
its own measurements; after the peer mapping chain passes the same-root and
same-Subject-Name checks, the peer mapping supplies its MigTD SVN and identity.
The destination does not require the source/init measurements in its local TCB
mapping, so an older image does not need to predict a future rotation image.

For regular attestation, ServTdExt binds the supplied init TDINFO and the
authenticated source MROWNER/MROWNERCONFIG check enforces that the source policy
signer matches the init signer and that source policy SVN is greater than or
equal to init policy SVN. The local TCB-mapping lookup does not contribute to
that ordering and is intentionally omitted, allowing migration and rebinding
back and forth during a key-rotation rollout. The current `REVERT_ME` test mode
logs some MROWNER/MROWNERCONFIG failures instead of aborting; production must
restore those checks as hard failures.

## 2. Enrich and deploy to a TiP node (PowerShell 7 + FCShell)

The builder emits `out/migtd_package.zip` beside `out/tip-package`. Copy
`migtd_package.zip` to the SAW, then expand it directly under the SAW user's
home directory:

```powershell
$packageRoot = Join-Path $HOME 'migtd_package'
if (Test-Path -LiteralPath $packageRoot) {
    Remove-Item -LiteralPath $packageRoot -Recurse -Force
}
Expand-Archive C:\staging\migtd_package.zip -DestinationPath $HOME -Force
```

This creates:

```text
$HOME\migtd_package\Upload-TipPackage.ps1
$HOME\migtd_package\tip_package\...
```

First use PowerShell 7 on the SAW to add matching winbuild prebuilts:

```powershell
& "$HOME\migtd_package\tip_package\Publish-TipPackage.ps1" `
    -PackageDir "$HOME\migtd_package\tip_package" `
    -WinBuildRoot \\winbuilds\release\<branch>\<build> `
    -ArchFlavor amd64fre `
    -SecFwFile \\winbuilds\...\secfw_test_GenuineIntel.dll `
    -Destination "$HOME\migtd_package\tip_package_ready" `
    -Force
```

The publisher resolves
`<WinBuildRoot>\<ArchFlavor>\test_automation_bins`, replaces the source-only
HCSTest runtime directory with the matching prebuilt module, adds
`VmgsTool.exe` and Secure Firmware, validates the completed package, and leaves
the source package unchanged. Use `-SkipSecFw` only when the target host
already has the matching test Secure Firmware configured.

Then, from an FCShell session started via DCM Explorer, upload the enriched
package:

```powershell
& "$HOME\migtd_package\Upload-TipPackage.ps1" `
    -ClusterName CVL05PrdApp02 `
    -SessionId 11111111-2222-3333-4444-555555555555 `
    -PackagePath "$HOME\migtd_package\tip_package_ready"
```

The uploader requires the `acc_tip` and `TipNodeServiceAME` modules and an
already-created TiP session (allocate one with `tdx_lm_node_setup.ps1` or
`New-TipNodeSession`). It zips the package, publishes it to the fabric image
store as a `NodeExecutePackage`, and distributes it to every node in the
session. The fabric extracts it to `C:\NodeExecute\<PackageName>\` (default
`migtd-tip-package`) on each node, so the IGVMs and test scripts land at
`C:\NodeExecute\migtd-tip-package\`. Pass `-PackageName` to control the on-node
directory. Then run the tests on the node as in section 3.

## 3. Run (TDX labblade, elevated PowerShell 7)

Open a fresh elevated PowerShell 7 process in the published package, then:

```powershell
# One-time dependency install and host prep. Reboot if requested, then rerun
# without -InstallDependencies.
.\Run-TipTests.ps1 -InstallDependencies -ConfigureHost

# Default suite: startup request coverage, mock-quote migration, ServTdExt,
# and mock-quote rebind/key-rotation validation.
.\Run-TipTests.ps1

# Also run GetQuote initialization and regular IGVMAgent-dependent policy cases.
.\Run-TipTests.ps1 -IncludeAgentCases
```

The suite prints a `wait_for_requests coverage` matrix for all operations MigTD
accepts:

| Operation | Real-host trigger / coverage |
|------|------|
| `1 StartMigration` | `Move-VM` loopback |
| `2 StartRebinding` | `Update-VmMigrationPolicy` rebind |
| `3 GetTDReport` | explicit post-start HCS query matching IGVMAgent health checks; validates the nonce, TDREPORT hashes, image TD Info Hash, and external GHCI events |
| `4 EnableLogArea` | automatic first startup request; validated through GHCI VDev ETW |
| `5 GetMigtdData` | unavailable on the current Host OS GHCI VDev, whose `GhciRequestOperation` exposes only operations 1–4 |

The request test follows the Host OS GHCI test pattern and requires PowerShell
7 plus elevated WPR access. Startup's internal `GetTDReport` is verified only
as TDINFO-cache setup. Operation 3 coverage comes from a separate post-start
`Get-HcsSystemProperties` `MigTdReport` query using a random REPORTDATA nonce,
the same HCS path used by IGVMAgent health checks. With `-IncludeAgentCases`,
the test also starts `test-migtd-getquote-all.igvm` and requires Worker
Analytic event 18670, matching `Tdx.Ghci.GetQuote.TestMD.Tests.ps1`.

Each case: start MigTD → register hash with host policy `DisabledByDefault` →
create a TDX VM → set its migratable policy to `EnabledIfHostPermits` → assign
its MigTD hash → `Move-VM -DestinationHost localhost` → assert → cleanup while
leaving the host `DisabledByDefault`. This applies to migration, expected
rejection, ServTdExt prebind, and rebind tests. Requires PowerTest
`TdxLiveMigrationUtilities` for `New-TestHcsMigTd`. Rebinding uses
`Test-TdxLmRebind.ps1` with two same- or different-image inputs.

Some PowerTest builds' `New-TestHcsMigTd` call `New-VmStateFile`, which is not
defined in that module set. The publisher bundles the matching `VmgsTool.exe`,
and the installer places it in System32, so the compatibility shim does not
need PowerTest's internal `Copy-TestItem`/test-content path.

Similarly, `New-HcsSystemDocument`/`New-HcsSystem`/`Start-HcsSystem` come from
the real `HCSTest` binary module, which `HCSUtilities.psm1` only loads via its
own `Import-HcsTestModule` helper — nothing calls that automatically. `Invoke-
TdxLmLoopback.ps1` imports `HCSUtilities.psm1` and calls `Import-Module HCSTest
-ArgumentList @{ UseVersion2 = $true }` itself when `-PowerTestPath` is passed
(only falling back to PowerTest's `Import-HcsTestModule` if `HCSTest` isn't
already installed under `Program Files\PowerShell\Modules`). `UseVersion2`
matters: the V1 binary's `New-VmStateFile` P/Invokes
`vmcompute.dll!CreateEmptyGuestStateFile`, removed on newer OS builds in favor
of `computestorage.dll` (used by V2). This matches
`onecore/vm/test/migration/tdx/Loopback/Tdx.LiveMigration.Loopback.Tests.ps1`.

`Publish-TipPackage.ps1` takes HCSTest from the matching winbuilds share build
(see `bin\<archflavor>\test_automation_bins\buildname.txt` in the OS enlistment
for the exact build):
```
\\winbuilds\release\<branch>\<build>.<qfe>.<date-time>\<archflavor>\test_automation_bins\vm\test\compute\HCSTest
```
The package installer copies it to
`$env:ProgramFiles\PowerShell\Modules\HCSTest` and validates
`coreclr\Microsoft.HostCompute.Test.PowerShell.v2.dll`,
`New-VMStateFile`, and `New-HcsSystemDocument`. Run installation from a fresh
PowerShell 7 process because loaded HCSTest assemblies remain locked.

If migration fails with only a generic VMMS error (e.g. "migration operation
failed at migration source" with no further detail), pass `-CaptureSerial` to
`Invoke-TdxLmLoopback.ps1` to capture the MigTD's own log output (it's built
with `--log-level info`) to `<MigTdId>.serial.log` via `New-TestHcsMigTd
-EnableSerial`'s named pipe. If cleanup begins during GetQuote retry backoff,
the script waits up to 30 seconds for the sixth-attempt terminal log before
stopping MigTD; override this with `-SerialDrainTimeoutSeconds`.

`Invoke-TdxLmLoopback.ps1` also calls `Enable-LoopbackMigrationDirectoryWorkaround`
(from `LiveMigrationUtilities.psm1`) before attempting migration, matching the
official aka.ms/tdxlm partner-facing reference test
(`Tdx.LiveMigration.Partner.Tests.ps1`). It repoints Hyper-V's default VM/VHD
storage paths to `<SystemDrive>\HyperVData\...` — for undetermined reasons this
is needed on some lab systems to avoid the same generic "failed at migration
source" error with a bare `-NoVHD` loopback TD.

The script migrates the bare `-NoVHD` TD immediately after `Start-VM`, matching
the partner test. `-StartupDelaySeconds` permits controlled timing experiments;
do not infer a timing root cause from `0xC0350071`, which is the generic
`ERROR_HV_OPERATION_FAILED`. On the investigated blade, both zero and five
seconds reached the same `VidTdxBind` failure.

There are two attestation paths:

- Regular images use `igvm-attest`, so MigTD migration approval requires a
  compatible IGVMAgent for GHCI GetQuote.
- `-NoPersistentSecrets` suppresses only the target VM's OpenHCL attestation
  call. It changes TPM/VMGS persistence semantics.

For a fully IGVMAgent-independent smoke test, combine both bypasses:

```powershell
.\Invoke-TdxLmLoopback.ps1 `
    -IgvmFilePath .\test-migtd-accept-all_mock_quote.igvm `
    -PowerTestPath C:\path\to\PowerTest `
    -NoPersistentSecrets `
    -CaptureSerial
```

To validate prebind state without starting migration:

```powershell
.\Test-TdxServTdExtPrebind.ps1 `
    -IgvmFilePath .\test-migtd-accept-all_mock_quote.igvm `
    -PowerTestPath C:\path\to\PowerTest `
    -NoPersistentSecrets
```

The test reads `Get-VmServTdExt -VmName tiptd` after VM startup and validates
the 272-byte layout: the prebound hash at byte offsets 0 and 112, zero
SERVTD_ATTR/reserved ranges, and the variable CPU SVN/TEE TCB/model metadata
between the two hashes.

To rebind a running TD between two MigTD instances, provide any two packaged
IGVMs. They may be different files or the same file:

```powershell
.\Test-TdxLmRebind.ps1 `
    -OldIgvmFilePath .\test-migtd_mock_quote.igvm `
    -NewIgvmFilePath .\test-migtd_mock_quote_rebind.igvm
```

To exercise policy leaf-key rotation in both directions:

```powershell
.\Test-TdxLmRebind.ps1 `
    -OldIgvmFilePath .\test-migtd_mock_quote.igvm `
    -NewIgvmFilePath .\test-migtd_mock_quote_key_rotation.igvm
.\Test-TdxLmRebind.ps1 `
    -OldIgvmFilePath .\test-migtd_mock_quote_key_rotation.igvm `
    -NewIgvmFilePath .\test-migtd_mock_quote.igvm
```

`Run-TipTests.ps1` runs these two mock-quote rotation cases by default. With
`-IncludeAgentCases`, it also runs both directions between `test-migtd.igvm`
and `test-migtd_key_rotation.igvm`.

Runtime `TD Info Hash` values parsed from the two serial logs are authoritative,
so sibling `.hash` files may be stale or absent. Existing `.hash` files are
used only as cross-checks and as fallbacks when serial capture is disabled.
When the two runtime hashes are equal, the second host mapping uses a synthetic
key exactly as the host OS rebind test does; `Get-VmMigrationPolicy` must still
report the real IGVM hash. The target VM defaults to `NoPersistentSecrets`; pass
`-UsePersistentSecrets` only when target-VM attestation is intentionally part
of the test. Both MigTD serial logs are captured by default as
`tipmigtd-rebind-{old,new}.serial.log`; disable this with
`-CaptureSerial:$false`. The script warns when a sibling hash disagrees with
the runtime value and waits up to 30 seconds for
`ReportStatus for rebinding completed` before stopping either MigTD. If neither
side receives operation 2 within five seconds, it reports a pre-delivery host
failure instead. Override the timeout with `-SerialDrainTimeoutSeconds`.
Before `UpgradeMigrationPolicy`, the script queries both HCS systems and
requires each to be in `Running` state with a nonempty `RuntimeId`; the host
rebind implementation needs both MigTD worker processes and GHCI devices alive
at the same time. Host policy remains `DisabledByDefault`: the target TD is
explicitly marked `EnabledIfHostPermits` with `Set-VmMigratablePolicy`, and the
script verifies that setting before startup. Cleanup leaves the host
`DisabledByDefault` with the real final MigTD hash rather than enabling
migration for VMs that did not opt in.

During rebind, `0x800721CE` is the GHCI translation of
`MIGPOLICY_UNSATISFIED_ERROR`, despite Windows formatting it as “The account is
controlled by external policy.” It means the old and new MigTD policies or
enrolled identities do not mutually authorize the pair; inspect both serial
logs for the specific failed policy check.

Capture VMMS, Worker, VID, GHCI VDev, analytic-channel, and serial evidence
around one rebind attempt with:

```powershell
.\troubleshooting\Invoke-TdxLmDiagnosticCapture.ps1 `
    -OutputDir .\diag-rebind `
    -EnableAnalytic `
    -CaptureEtw `
    -SerialLogPath @(
        '.\tipmigtd-rebind-old.serial.log',
        '.\tipmigtd-rebind-new.serial.log'
    ) `
    -ReproCommand {
        .\Test-TdxLmRebind.ps1 `
            -OldIgvmFilePath .\old.igvm `
            -NewIgvmFilePath .\new.igvm
    }
```

In `tdxlm.etl`, inspect GHCI events
`CreateTdxPrepareRebindingRequest`, `SubmitRequest_Sent`, and
`RebindRequest_Failed`. The latter records `IsSource`, `PrimaryStatus`,
`DetailedError`, and `ResultHR`, distinguishing an old/source rejection from a
new/destination rejection. VMMS/Worker events show whether failure occurred
before request submission, in the data pump, or during `VidTdxRebind`.

For a smaller trace containing only provider
`Microsoft.Windows.HyperV.GhciVDev`
(`AEFC8638-19A2-553A-06CB-C3984FFC7EE8`), run:

```powershell
.\troubleshooting\Invoke-GhciVDevDiagnosticCapture.ps1 `
    -OutputDir .\diag-ghci `
    -ReproCommand {
        .\Test-TdxLmRebind.ps1 `
            -OldIgvmFilePath .\old.igvm `
            -NewIgvmFilePath .\new.igvm
    }
```

This writes `ghcivdev.etl`, raw `tracerpt` CSV/XML, provider metadata, and
provider-filtered text/CLIXML when `Get-WinEvent` can decode the ETL. To export
an existing trace separately:

```powershell
.\troubleshooting\Export-GhciVDevEvents.ps1 -EtlPath .\tdxlm.etl
```

For a cross-node SPDM transport failure, capture deployment provenance and
validate destination mapping before the repro:

```powershell
.\troubleshooting\Get-MigTdDeploymentProvenance.ps1 `
    -IgvmFilePath .\test-migtd-accept-all.igvm `
    -HashFilePath .\test-migtd-accept-all.igvm.hash `
    -SerialLogPath .\tipmigtd.serial.log `
    -MigTdHcsId <MIGTD_HCS_ID> `
    -PowerTestPath <POWERTEST_PATH> `
    -OutputDir .\provenance

.\troubleshooting\Test-CrossNodeMigTdBinding.ps1 `
    -SourceHashFilePath .\source-migtd.igvm.hash `
    -DestinationSerialLogPath .\destination-migtd.serial.log `
    -DestinationMigTdHcsId <DESTINATION_MIGTD_HCS_ID> `
    -PowerTestPath <POWERTEST_PATH> `
    -RequireRuntimeHash
```

Normalize the ETLs on a Windows machine, then align request events:

```powershell
.\troubleshooting\Export-MigTdMigrationTimeline.ps1 `
    -EtlPath .\td_source.etl -Node Source -OutputDir .\source-timeline
.\troubleshooting\Export-MigTdMigrationTimeline.ps1 `
    -EtlPath .\td_dest.etl -Node Destination -OutputDir .\destination-timeline

.\troubleshooting\Compare-MigTdNodeTraces.ps1 `
    -SourceTimelinePath .\source-timeline\migtd-migration-timeline.csv `
    -DestinationTimelinePath .\destination-timeline\migtd-migration-timeline.csv `
    -RequestId <REQUEST_ID> `
    -OutputDir .\cross-node-comparison
```

The comparison marks the first destination failure candidate and calculates
its delay to source cancellation. Confirm any file/line event against the
Windows OS source branch matching the tested host build.

An unresponsive agent can consume two 30-second target-VM attestation RPC
timeouts and exhaust the worker's 60-second `StartVtl0` budget. During regular
image migration, `0x80072F78` from GetQuote instead means the agent response
failed V2 header/size validation; use an agent binary matching the host build.

`RequireIgvmAgent` under
`HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization` only
controls whether VM startup requires an available endpoint. It is unnecessary
for the mock-quote/no-secrets path.

Design: `MigTD/doc/integration_test_azure_tip.md`.

Reusable host validation, hash verification, and ETW capture helpers are copied
into each built package:

```text
troubleshooting/
```

Their source and full agent playbook live in
`.agents/skills/migtd-tip-troubleshoot/` and
`.agents/skills/migtd-spdm-transport-debug/`.
