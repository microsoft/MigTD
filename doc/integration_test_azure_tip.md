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
2. Generate the signed policy + issuer chain with
   `sh_script/Azure/build_azure_mock_test.sh --skip-test [--allow-all|--reject|
   <default real>] [--fetch-collaterals]` →
   `config/Azure/policy_v2_signed.json` + `config/Azure/policy_issuer_chain.pem`.
3. Build the IGVM:
   `cargo image --policy-v2 --debug --image-format igvm --no-default-features
   --features vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,
   spdm_attestation,igvm-attest --policy-issuer-chain <chain> --policy <policy>
   --output <image>` (add `test-get-quote` for the getquote variant).
4. Compute the host mapping hash:
   `migtd-hash --manifest config/Azure/servtd_info.json --image <image>
   --policy-v2 --calc-servtd-hash`. The tool prints an `MRTD Hash: …` line first,
   then the 48-byte **servtd hash** as the last line — that final 96-char hex is
   written to `<image>.hash` (the host reads it as `MigTdHash`).

No dummy/base rebuild and no production signing are needed: the policy is built
from the `config/Azure/` templates (measurements via `azcvm-extract-report`) and
signed with a local test key by `build_azure_mock_test.sh`.

## 4. Package contents

`out/tip-package/` (≈7.4 MB per IGVM, debug build):

| File | Variant / role |
|------|----------------|
| `test-migtd-accept-all.igvm` + `.hash` | allow-all policy → migration **succeeds** |
| `test-migtd-reject-all.igvm` + `.hash` | bad-FMSPC (`DEADBEEF0000`) → migration **rejected** |
| `test-migtd-real.igvm` + `.hash` | real `config/Azure/policy_data_raw.json` (FMSPC `90C06F000000`) → succeeds iff node FMSPC/TCB match (MigTD-only extra) |
| `test-migtd-getquote-all.igvm` + `.hash` | GetQuote initialization image |
| `Invoke-TdxLmLoopback.ps1`, `Run-TipTests.ps1`, `README.md` | host test scripts |

## 5. Manual lab-blade test

Build on the Linux host:

```bash
./sh_script/Azure/tip/build_tip_package.sh --out out/tip-package
# add --fetch-collaterals to refresh Azure THIM collateral for the real variant
```

Copy `out/tip-package/` to the TDX lab blade, then in an **elevated** PowerShell:

```powershell
# one-time host prep (loopback migration, test SecFw — may reboot)
.\Run-TipTests.ps1 -PackageDir . -PowerTestPath C:\path\to\PowerTest -InitializeHost

# or a single case
.\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-accept-all.igvm -PowerTestPath C:\path\to\PowerTest
.\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-reject-all.igvm -ExpectReject -PowerTestPath C:\path\to\PowerTest
```

Each case performs: `New-TestHcsMigTd → Start-HcsSystem →
Add-VmHostMigrationTdMapping -MigTdHash <hash> -VmId →
Set-VMHostMigrationPolicy EnabledByDefault <hash> →
New-VM -GuestStateIsolation TDX → Start-VM →
Move-VM -DestinationHost localhost`, asserts the result, then cleans up
(`Set-VMHostMigrationPolicy AlwaysDisabled`, remove mapping, remove VM). Key VM
settings: HCS schema 2.1, VM version 12.5, 1 vCPU, 512 MB.

## 6. Test cases

1. **accept-all** → migration succeeds.
2. **reject-all** → migration rejected.
3. **real policy** → succeeds when the node's FMSPC/TCB match `policy_data_raw.json`;
   `policy_reject_data_raw.json` is the negative twin.
4. **getquote-all** → exercises the initialization GetQuote path.
5. **rebind** → register a second image (different hash) while a TD is bound, then
   re-migrate (`Set-TestMigTdMeasurements` / new `.hash`).
6. **cycle** → repeat a case N times.

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
