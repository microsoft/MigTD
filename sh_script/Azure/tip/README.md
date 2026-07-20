# MigTD TiP Loopback Test Package

Self-contained TDX live-migration test for a labblade. Build on Linux, copy the
package to the TDX host, run loopback migrations manually.

## 1. Build (Linux)

```bash
./sh_script/Azure/tip/build_tip_package.sh --out out/tip-package --fetch-collaterals
```

Produces in `out/tip-package/`:

| File | Role |
|------|------|
| `test-migtd-accept-all.igvm` + `.hash` | allow-all policy → migration succeeds |
| `test-migtd-reject-all.igvm` + `.hash` | bad-FMSPC policy → migration rejected |
| `test-migtd-real.igvm` + `.hash` | `config/Azure/policy_data_raw.json` → succeeds if node FMSPC/TCB match |
| `test-migtd-getquote-all.igvm` + `.hash` | GetQuote init image |
| `test-migtd-accept-all_mock_quote.igvm` + `.hash` | allow-all policy with built-in mock quote |
| `test-migtd-reject-all_mock_quote.igvm` + `.hash` | reject policy with built-in mock quote |
| `test-migtd-real_mock_quote.igvm` + `.hash` | policy generated from mock measurements with built-in mock quote |
| `Invoke-TdxLmLoopback.ps1`, `Run-TipTests.ps1` | migration test scripts |
| `Test-TdxServTdExtPrebind.ps1` | start a prebound TD and validate both ServTdExt hash slots and zero padding |

`.hash` is the direct `SERVTD_INFO_HASH` the host passes to
`TDH.SERVTD.PREBIND` as `MigTdHash`. Built with MigTD-native tooling only
(`cargo image`, `migtd-hash`, `build_azure_mock_test.sh`).

The `_mock_quote` variants are built through the corresponding targets in
`sh_script/Azure/Makefile` with the `use-mock-quote` feature. They do not use
the host IGVMAgent GetQuote path. Their sibling `.hash` files are still direct
`SERVTD_INFO_HASH` values calculated from each final emitted IGVM.

## 2. Run (TDX labblade, elevated PowerShell)

Copy `out/tip-package` to the host, then:

```powershell
# one-time host prep (loopback migration, test SecFw — may reboot)
.\Run-TipTests.ps1 -PackageDir . -PowerTestPath C:\path\to\PowerTest -InitializeHost

# single case
.\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-accept-all.igvm -PowerTestPath C:\path\to\PowerTest
.\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-reject-all.igvm -ExpectReject -PowerTestPath C:\path\to\PowerTest
```

Each case: start MigTD → register hash → create TDX VM → `Move-VM -DestinationHost
localhost` → assert → cleanup (`AlwaysDisabled`, remove mapping/VM). Requires
PowerTest `TdxLiveMigrationUtilities` for `New-TestHcsMigTd`. Rebind: re-run with a
second image (different hash) while a TD is bound.

Some PowerTest builds' `New-TestHcsMigTd` call `New-VmStateFile`, which isn't
defined anywhere in that module set (`New-VmStateFile no cmdlet`). `Invoke-
TdxLmLoopback.ps1` shims this itself when `-PowerTestPath` is passed — it uses
the OS-shipped `vmgstool.exe` if present, else falls back to PowerTest's
`New-GuestStateFile` (`VmgsUtilities.psm1`, which needs `Copy-TestItem`/internal
test-content access). No changes to the vendored PowerTest module are needed.

Similarly, `New-HcsSystemDocument`/`New-HcsSystem`/`Start-HcsSystem` come from
the real `HCSTest` binary module, which `HCSUtilities.psm1` only loads via its
own `Import-HcsTestModule` helper — nothing calls that automatically. `Invoke-
TdxLmLoopback.ps1` imports `HCSUtilities.psm1` and calls `Import-Module HCSTest
-ArgumentList @{ UseVersion2 = $true }` itself when `-PowerTestPath` is passed
(only falling back to PowerTest's `Import-HcsTestModule` if `HCSTest` isn't
already installed under `System32\WindowsPowerShell\v1.0\Modules`). `UseVersion2`
matters: the V1 binary's `New-VmStateFile` P/Invokes
`vmcompute.dll!CreateEmptyGuestStateFile`, removed on newer OS builds in favor
of `computestorage.dll` (used by V2). This matches
`onecore/vm/test/migration/tdx/Loopback/Tdx.LiveMigration.Loopback.Tests.ps1`.

If `HCSTest` isn't installed on your labblade yet, copy it from the matching
winbuilds share build (see `bin\<archflavor>\test_automation_bins\buildname.txt`
in your OS enlistment for the exact build) to
`$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\`:
```
\\winbuilds\release\<branch>\<build>.<qfe>.<date-time>\<archflavor>\test_automation_bins\vm\test\compute\HCSTest
```
Do this from a fresh PowerShell window (a previously-loaded `HCSTest` assembly
keeps its DLLs locked and blocks re-copying).

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
`.agents/skills/migtd-tip-troubleshoot/`.
