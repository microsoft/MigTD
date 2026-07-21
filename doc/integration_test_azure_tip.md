# Azure MigTD Integration Test (TiP) — Design

Status: Draft · Scope: per-PR validation of MigTD changes on real Azure TDX
hardware. Self-contained: built and tested with MigTD-native tooling only.

## 1. Goal

Gate every MigTD change with a real source⇄destination TD **live migration** on a
TDX host. Build the MigTD IGVM and its measurement hash with MigTD tooling, then
drive a loopback migration through the host's HCS/VMM interfaces and assert the
outcome (accept, reject, real-policy, rebind).

The images built here use the same names the **Azure OS PR gate** consumes
prebuilt from the `TDX_LM_IGVM_Binaries` vpack
(`test-migtd-{accept-all,reject-all,getquote-all}.igvm` + `.hash`), so a MigTD
change can be validated with source-built binaries before they ship as a vpack.
Production signing/release is out of scope — the test needs a functional image
and its hash, not a signed release.

## 2. Prerequisites

### 2.1 Build host (Linux, e.g. Ubuntu 22.04)

- Rust **1.88.0** with `rust-src` and the `x86_64-unknown-none` target.
- Authenticated cargo access to the private `ms-crates-io` feed (msrustup token);
  without it `cargo` fails with `Interactive operation required`.
- Build packages: `build-essential ocaml ocamlbuild wget pkg-config libtool unzip
  clang llvm nasm jq openssl libssl-dev git cmake perl python-is-python3`.
- Submodules initialized (handled by `./sh_script/preparation.sh`).
- Optional: outbound access to Azure THIM for `--fetch-collaterals` (fresh
  platform/QE collateral); otherwise the committed collateral is used.

### 2.2 TDX lab blade (Windows TDX host)

- TDX-capable Hyper-V host (e.g. `DC*es_v6`-class) with the **TDX module**
  installed and host OS/VMM exposing the required **GHCI** APIs.
- **Test Secure Firmware** (`secfw_test_GenuineIntel.dll`) in
  `C:\Windows\System32` with `HKLM\SYSTEM\CurrentControlSet\Control\Hypervisor\
  SecFwFile` set → **reboot** required (one-time).
- TDX-LM velocity feature **`53058573`** enabled.
- Live migration enabled: `Enable-VMMigration`, Kerberos auth,
  `Enable-LoopbackMigration` (one-time `Initialize-TdxLmMachine`).
- PowerShell modules available: **PowerTest** (`TdxLiveMigrationUtilities.psm1`),
  **Hyper-V**, **HCSTest** (v2).
- **Elevated** PowerShell; free disk for the TD's VMGS/VHD.

## 3. Build & policy (MigTD-native)

`sh_script/Azure/tip/build_tip_package.sh` performs, per variant:

1. `./sh_script/preparation.sh` — submodules + build prep.
2. For regular variants, generate the signed policy + issuer chain with
   `sh_script/Azure/build_azure_mock_test.sh --skip-test [--allow-all|--reject|
   <default real>] [--fetch-collaterals]` →
   `config/Azure/policy_v2_signed.json` + `config/Azure/policy_issuer_chain.pem`.
3. Build regular IGVMs with:
   `cargo image --policy-v2 --debug --image-format igvm --no-default-features
   --features vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,
   spdm_attestation,igvm-attest --policy-issuer-chain <chain> --policy <policy>
   --output <image>` (add `test-get-quote` for the getquote variant).
   Build `_mock_quote` variants through the matching targets in
   `sh_script/Azure/Makefile`; these replace `igvm-attest` with
   `use-mock-quote`.
4. Compute the host prebind hash:
   `migtd-hash --manifest config/Azure/servtd_info.json --image <image>
   --policy-v2`. The tool prints an `MRTD Hash: …` line first, then the 48-byte
   **SERVTD_INFO_HASH** as the last line. That final 96-char hex is written to
   `<image>.hash`; Hyper-V passes it directly to `TDH.SERVTD.PREBIND`.
   `--calc-servtd-hash` must not be used here because it produces the distinct
   outer TDREPORT `SERVTD_HASH`.
5. Bundle PowerTest from the matching OS enlistment, a prebuilt HCSTest v2
   package from that build's `test_automation_bins`, and the matching test
   Secure Firmware when available. The HCSTest source directory is not enough:
   the package must contain
   `netfx\Microsoft.HostCompute.Test.PowerShell.v2.dll`. Supply the prebuilt
   module explicitly with `--hcstest-dir`; the builder does not hardcode or
   infer a `\\winbuilds` location.

No dummy/base rebuild and no production signing are needed: the policy is built
from the `config/Azure/` templates (measurements via `azcvm-extract-report`) and
signed with a local test key by `build_azure_mock_test.sh`.

## 4. Package contents

`out/tip-package/` (≈7.4 MB per IGVM, debug build):

| File | Variant / role |
|------|----------------|
| `test-migtd-accept-all.igvm` + `.hash` | allow-all policy → migration **succeeds** |
| `test-migtd-reject-all.igvm` + `.hash` | bad-FMSPC (`DEADBEEF0000`) → migration **rejected** |
| `test-migtd.igvm` + `.hash` | real `config/Azure/policy_data_raw.json` (FMSPC `90C06F000000`) → succeeds iff node FMSPC/TCB match (MigTD-only extra) |
| `test-migtd_rebind.igvm` + `.hash` | same real policy/signing key with `policySvn` incremented by one |
| `test-migtd_key_rotation.igvm` + `.hash` | same real policy SVN/root/leaf Subject Name with a new policy leaf key |
| `test-migtd-getquote-all.igvm` + `.hash` | GetQuote initialization image |
| `test-migtd-accept-all_mock_quote.igvm` + `.hash` | allow-all policy with `use-mock-quote`; no host GetQuote agent required |
| `test-migtd-reject-all_mock_quote.igvm` + `.hash` | reject policy with `use-mock-quote` |
| `test-migtd_mock_quote.igvm` + `.hash` | policy generated from mock measurements with `use-mock-quote` |
| `test-migtd_mock_quote_rebind.igvm` + `.hash` | same mock-quote real policy/signing key with `policySvn` incremented by one |
| `test-migtd_mock_quote_key_rotation.igvm` + `.hash` | mock-quote counterpart with the rotated policy leaf key |
| `test-migtd{,_rebind,_key_rotation,_mock_quote,_mock_quote_rebind,_mock_quote_key_rotation}.policy.json` | signed policy snapshots embedded in the real-policy images |
| `Invoke-TdxLmLoopback.ps1`, `Run-TipTests.ps1`, `README.md` | migration test scripts |
| `Test-TdxServTdExtPrebind.ps1` | validates both prebound ServTdExt hash slots and reserved zero ranges after target startup |
| `Test-TdxLmRebind.ps1` | rebinds a running TD between two same- or different-image MigTD instances |
| `Install-TipDependencies.ps1` | installs bundled modules and optional test SecFw on the blade |
| `dependencies/PowerTest`, `dependencies/HCSTest` | build-matched host test modules |
| `dependencies/SecFw` | optional build-matched `secfw_test_GenuineIntel.dll` |

## 5. Manual lab-blade test

Build on the Linux host:

```bash
./sh_script/Azure/tip/build_tip_package.sh \
    --out out/tip-package \
    --os-root /path/to/os.2020 \
    --hcstest-dir /path/to/prebuilt/HCSTest \
    --secfw-file /path/to/secfw_test_GenuineIntel.dll
# add --fetch-collaterals to refresh Azure THIM collateral for the real variant
# add --skip-dependencies if PowerTest and HCSTest v2 are already installed
```

Copy `out/tip-package/` to the TDX lab blade, then in an **elevated** PowerShell:

```powershell
# one-time dependency install and host prep; reboot if requested
.\Run-TipTests.ps1 -InstallDependencies -ConfigureHost

# default agent-independent migration + ServTdExt tests
.\Run-TipTests.ps1

# optionally add regular IGVMAgent-dependent cases
.\Run-TipTests.ps1 -IncludeAgentCases

# or a single case
.\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-accept-all.igvm -PowerTestPath C:\path\to\PowerTest
.\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-reject-all.igvm -ExpectReject -PowerTestPath C:\path\to\PowerTest

# fully IGVMAgent-independent smoke test
.\Invoke-TdxLmLoopback.ps1 `
    -IgvmFilePath .\test-migtd-accept-all_mock_quote.igvm `
    -NoPersistentSecrets

# validate prebind ServTdExt without Move-VM
.\Test-TdxServTdExtPrebind.ps1 `
    -IgvmFilePath .\test-migtd-accept-all_mock_quote.igvm `
    -NoPersistentSecrets

# rebind between different or identical MigTD images
.\Test-TdxLmRebind.ps1 `
    -OldIgvmFilePath .\test-migtd_mock_quote.igvm `
    -NewIgvmFilePath .\test-migtd_mock_quote_rebind.igvm
```

Policy leaf-key rotation is tested in both directions at the same policy SVN:

```powershell
.\Test-TdxLmRebind.ps1 `
    -OldIgvmFilePath .\test-migtd_mock_quote.igvm `
    -NewIgvmFilePath .\test-migtd_mock_quote_key_rotation.igvm
.\Test-TdxLmRebind.ps1 `
    -OldIgvmFilePath .\test-migtd_mock_quote_key_rotation.igvm `
    -NewIgvmFilePath .\test-migtd_mock_quote.igvm
```

For both real-quote and mock-quote real-policy images, the builder creates an
original/rebind pair with a common policy signer. The rebind policy copies the
fully merged original `policyData` and changes only `policySvn`, incrementing
it by one. The real-quote pair maps the final image's measured
MRTD/RTMR0/RTMR1. The mock-quote pair retains the static mock measurements;
both migration and rebinding derive MigTD TCB metadata from the mock quote
instead of matching the live TDREPORT. The signed `.policy.json` snapshots
allow this relationship to be checked without extracting the IGVM firmware
volume. Each final image hash is calculated independently; equal hashes are
handled by the test's synthetic second mapping key.

The key-rotation images keep `policySvn` equal to the baseline so A→B and B→A
both satisfy policy SVN ordering. Only the outer policy-signing leaf changes:
the new leaf has a different key, the same Subject Name, and the identical root
CA. Embedded TD identity and TCB mapping collateral retain the original signer.
Each policy independently maps its own image measurements. Once the peer policy
and its embedded mapping/identity chains pass the same-root and same-leaf-
Subject-Name checks, the peer's signed TCB mapping supplies its MigTD SVN and
identity; the destination does not require those measurements in its local
mapping. This permits migration and rebinding back and forth while a new
policy-signing leaf is rolled out, without rebuilding the older image.

ServTdExt still binds init TDINFO, while the authenticated source
MROWNER/MROWNERCONFIG comparison enforces a matching policy signer and
`Source policySvn >= INIT policySvn`. The removed local TCB-mapping lookup only
tested whether the destination already knew the init measurements; its returned
engine SVN was unused. Current `REVERT_ME` test builds log some owner-binding
failures instead of aborting, so production must restore those checks as hard
failures for the SVN invariant to be strict.
The default `Run-TipTests.ps1` suite runs both mock-quote directions;
`-IncludeAgentCases` adds both regular-quote directions.

Each case performs: `New-TestHcsMigTd → Start-HcsSystem →
Add-VmHostMigrationTdMapping -MigTdHash <hash> -VmId →
Set-VMHostMigrationPolicy DisabledByDefault <hash> →
New-VM -GuestStateIsolation TDX →
Set-VmMigratablePolicy EnabledIfHostPermits →
Update-VmMigrationPolicy → Start-VM →
Move-VM -DestinationHost localhost`, asserts the result, then cleans up
while leaving the host policy `DisabledByDefault` before removing the mapping
and VM. This policy sequence is shared by migration, expected-rejection,
ServTdExt prebind, and rebind tests. Key VM settings: HCS schema 2.1, VM version
12.5, 1 vCPU, 512 MB.

## 6. Test cases

1. **accept-all** → migration succeeds.
2. **reject-all** → migration rejected.
3. **real policy** → succeeds when the node's FMSPC/TCB match `policy_data_raw.json`;
   `policy_reject_data_raw.json` is the negative twin.
4. **getquote-all** → exercises the initialization GetQuote path.
5. **mock-quote variants** → exercise migration without host GHCI GetQuote;
   combine with `-NoPersistentSecrets` to avoid all IGVMAgent calls.
6. **ServTdExt prebind** → after target startup, verify the 272-byte runtime
   extension contains the expected hash at offsets 0 and 112 with zero
   attributes/reserved ranges.
7. **rebind** → bind a running TD to the first MigTD, register a second MigTD,
   and invoke `UpgradeMigrationPolicy`. The two inputs may have different
   hashes or the same hash; same-hash tests use a synthetic second mapping key
   while verifying that the partition retains the real IGVM measurement.
8. **cycle** → repeat a case N times.

`TdxLiveMigrationUtilities.psm1` provides the host interfaces; reuse is optional —
any driver hitting the same HCS/VMM cmdlets works.

## 7. CI & open items

A self-hosted TDX agent can run the same build → register → migrate → assert →
cleanup flow per PR, publishing the IGVMs, `.hash` files, and migration logs;
the same artifacts can later promote into the `TDX_LM_IGVM_Binaries` vpack.

Open: provision the self-hosted TDX agent; collateral refresh cadence; optional
release-mode (non-debug) build. The QEMU/vsock/serial flow in
`doc/integration_test.md` stays out of scope (Azure uses the `vmcall-raw`
transport).
