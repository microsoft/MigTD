---
type: Reference
title: MigTD Security Bypasses — Feature Comparison
description: Catalogue of verification checks bypassed under AzCVMEmu/test_mock_report/use-mock-quote build features, and why each is bypassed.
tags: [security, build-features, attestation, spdm, tls]
timestamp: 2026-07-26T00:14:16+00:00
---

# MigTD Security Bypasses — Feature Comparison

This document catalogues the verification checks bypassed under the
development/test build features, and explains **why** each is bypassed.

> **None of these bypasses are acceptable in production.** They exist solely
> to enable development/testing on non-production environments.

> Locations are given by function (line numbers drift). The init-TDINFO
> verification is bypassed in EMU/mock by a **`cfg` feature gate**, not by any
> SERVTD_EXT opt-out — integration2 always sends a populated `ServtdExt`.

---

## Feature Semantics

| Feature | Environment | TDX HW | `tdcall_report` | Quote (QGS/IMDS) |
|---------|-------------|:---:|:---:|:---:|
| `AzCVMEmu` | Desktop emulator (no TDX) | ✗ | Emulated (REPORTDATA not bound) | Emulated |
| `test_mock_report` | Emulated (implies AzCVMEmu) | ✗ | Emulated | Emulated |
| `use-mock-quote` | **Real TDX hardware** | ✓ | **Real** (REPORTDATA correctly bound) | Static mock data |

- **`AzCVMEmu` / `test_mock_report`**: no hardware — `tdcall_report` is emulated
  and does **not** embed caller-supplied REPORTDATA, so every REPORTDATA-derived
  check must be bypassed.
- **`use-mock-quote`**: real TDX — `tdcall_report` binds REPORTDATA correctly,
  so quote-derived migration checks are bypassed while TDREPORT-derived rebind
  checks remain available. The temporary `REVERT_ME` continuity check is still
  logged rather than enforced in every feature configuration.

---

## SPDM Migration Path

| # | Check | `AzCVMEmu` | `use-mock-quote` | Location | Reason |
|---|-------|:---:|:---:|------|--------|
| 1 | REPORTDATA TH1 binding — v1 | **Bypassed** | **Bypassed** | `spdm_rsp::rsp_verify_peer_attestation_v1`, `spdm_req` (requester) | Migration verifies REPORTDATA from quote supplemental data; mock quote is static |
| 2 | REPORTDATA TH1 binding — v2 | **Bypassed** | **Bypassed** | `spdm_rsp::rsp_verify_peer_attestation_v2`, `spdm_req` (requester) | Same — quote supplemental data is mocked |
| 3 | init-TDINFO continuity cross-check + ServtdExt integrity | **Bypassed** | **Bypassed** | `mig_policy::authenticate_migration_source_with_init_tdinfo` (`#[cfg(not(any(AzCVMEmu, test_mock_report, use-mock-quote)))]`) | EMU/mock quote data does not carry production MROWNER/MROWNERCONFIG or TDINFO measurements |

> Gate note: the v1 REPORTDATA check is additionally disabled under
> `test_disable_ra_and_accept_all`.

---

## SPDM Rebinding Path (prepare-rebind)

| # | Check | `AzCVMEmu` | `use-mock-quote` | Location | Reason |
|---|-------|:---:|:---:|------|--------|
| 5 | REPORTDATA TH1 binding (responder) | **Bypassed** | **Enforced** | `spdm_rsp` rebind handler (`#[cfg(not(any(AzCVMEmu, test_mock_report)))]`) | Rebind uses only `tdcall_report` (no quotes); real HW binds REPORTDATA correctly |
| 6 | REPORTDATA TH1 binding (requester) | **Bypassed** | **Enforced** | `spdm_req::...rebind...` (`#[cfg(not(any(AzCVMEmu, test_mock_report)))]`, `verify_tdreport_data_binding`) | Same |
| 7 | Init/current MROWNER + policy-SVN continuity | **Logged only** | **Logged only** | `mig_policy::authenticate_rebinding_old` (`REVERT_ME` test mode) | Hosts do not yet consistently provision MROWNER/MROWNERCONFIG; failures are reported but temporarily non-fatal |

> Rebind init-TDINFO **integrity** (`verify_init_tdinfo` → `verify_servtd_info_hash`)
> is **enforced in all build modes** (the AzCVMEmu emulation populates the
> SERVTD_EXT fields so the hash matches). Only the cross-check is TEST MODE.

> **One-hash design status:** the intended ordering check does not need full
> Init_TDINFO. It resolves `ServtdExt.init_servtd_info_hash` and the
> authenticated source's current `tdinfo_hash` through the source's verified
> mapping and requires `init SVN <= current SVN`. That mapping-based init
> lookup is not implemented yet, so the table above describes only the
> transitional MROWNERCONFIG check currently present in code.

---

## TLS Path (non-SPDM)

| # | Check | `AzCVMEmu` | `use-mock-quote` | Location | Reason |
|---|-------|:---:|:---:|------|--------|
| 8 | Public-key hash in REPORTDATA (cert verification) | **Bypassed** | **Bypassed** | `ratls/server_client.rs` cert-verify callbacks (`cfg!(AzCVMEmu)` / `cfg!(use-mock-quote)`) | EMU: REPORTDATA not bound. Mock-quote: cert path uses quote-derived data which is mocked |

---

## What Remains Enforced

### Under `AzCVMEmu`
- Full SPDM / TLS handshake (key exchange, cipher negotiation)
- RTMR2 policyData integrity and event-log replay
- Inner JSON mapping/identity signatures or signed-CoRIM verification, with
  every signer bound to the RTMR1 root+EKU anchor
- Policy evaluation (`evaluate_policy_common` / `evaluate_policy_backward`)
- **Rebind init-TDINFO integrity** (`verify_servtd_info_hash`)
- **SERVTD_ATTR check** (`verify_servtd_attr`: `cur_servtd_attr == 0x0`)
- Rebind token creation/exchange and `tdcall_servtd_rebind_approve` (emulated)

### Under `use-mock-quote` (real HW)
All of the above, **plus**:
- **Rebind REPORTDATA TH1 binding** (real `tdcall_report`)
- **Rebind init-TDINFO integrity** against real `TDG.SERVTD.RD` data

`use-mock-quote` bypasses quote-derived migration REPORTDATA and migration
Init_TDINFO checks. There is no destination-local Init_TDINFO mapping
allowlist in the one-hash design. Both init and current SVNs should be
resolved through the authenticated source peer's verified JSON mapping or
CoRIM; today only the current peer lookup is wired.
