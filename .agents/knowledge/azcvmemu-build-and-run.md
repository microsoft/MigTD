---
type: Reference
title: AzCVMEmu Build & Run — Agent Cheat Sheet
description: Feature-flag combinations, prerequisites, and migtdemu.sh invocations for building/running MigTD as a standard Rust app under Azure CVM Emulation.
tags: [azcvmemu, build, emu, tpm]
timestamp: 2026-07-13T22:37:00+00:00
---

# AzCVMEmu Build & Run — Agent Cheat Sheet

Canonical source: [doc/AzCVMEmu.md](../../doc/AzCVMEmu.md). Read that in full for
architecture rationale; this is the command/decision cheat sheet.

## Feature flag → mode

| Cargo features (with `--no-default-features`) | Attestation | Requires |
|---|---|---|
| `AzCVMEmu` | Real Azure IMDS attestation | Azure TDX CVM + TPM2-TSS |
| `AzCVMEmu,test_mock_report` | Mock TD reports/quotes, full attestation flow | Any Linux |
| `AzCVMEmu,igvm-attest` | `servtd_get_quote` path | Azure TDX CVM + TPM2-TSS |
| `AzCVMEmu,igvm-attest,test_mock_report` | IGVM attest + mock | Any Linux |
| `AzCVMEmu,test_disable_ra_and_accept_all` | Attestation bypassed entirely | Any Linux |

`AzCVMEmu` implies `main` + `vmcall-raw` (don't add them explicitly) and
**only** works with the `vmcall-raw` transport.

## Preferred invocation: `migtdemu.sh`

```bash
./migtdemu.sh --skip-ra --both --no-sudo --log-level info          # no attestation, any Linux
./migtdemu.sh --mock-report --both                                  # full attestation, mock data
./migtdemu.sh --igvm-attest --mock-report --both                    # servtd_get_quote path
./migtdemu.sh --policy-v2 --policy-file <f> --policy-issuer-chain-file <f> --both
./migtdemu.sh --features spdm_attestation --both
```

`--both` runs destination in the background then source in the foreground;
destination logs go to `dest.out.log`. See
[verification-and-checklist.md](verification-and-checklist.md) for the
**do-not-run-concurrently** rule (hardcoded port 8001, `taskset -c 0`, shared
`target/release/migtd`).

## TPM2-TSS gotcha

Runtime TPM2-TSS (`libtss2-esys`, `libtss2-tcti-device0`) is needed **unless**
you use `--skip-ra` (`test_disable_ra_and_accept_all`), which uses mock TD
reports/quotes and needs no TPM at all. The script auto-sets
`TSS2_TCTI=device:/dev/tpmrm0` and enables sudo automatically when
`/dev/tpmrm0` exists and permissions are insufficient (not needed for
`--mock-report` or `--skip-ra`).

## Manual run requires two env vars

```bash
export MIGTD_POLICY_FILE="/path/to/policy.json"
export MIGTD_ROOT_CA_FILE="/path/to/root_ca.cer"
```

Missing/nonexistent files → hard exit. See
`deps/td-shim-AzCVMEmu/README.md` for the emulation-layer implementation
details (RTMR extension as no-op, REPORTDATA bypass rationale — cross-check
against [Security Bypasses](security-bypasses.md)).
