---
type: Reference
title: MigTD Security Bypasses — Feature Comparison
description: Catalogue of verification checks bypassed under AzCVMEmu/test_mock_report/use-mock-quote build features, and why each is bypassed.
tags: [security, build-features, attestation, spdm, tls]
timestamp: 2026-07-10T19:26:55+00:00
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
- **`use-mock-quote`**: real TDX — `tdcall_report` binds REPORTDATA correctly, so
  only *quote*-derived checks (migration path) need bypassing; *TDREPORT*-derived
  checks (rebind path) stay **enforced**.

---

## SPDM Migration Path

| # | Check | `AzCVMEmu` | `use-mock-quote` | Location | Reason |
|---|-------|:---:|:---:|------|--------|
| 1 | REPORTDATA TH1 binding — v1 | **Bypassed** | **Bypassed** | `spdm_rsp::rsp_verify_peer_attestation_v1`, `spdm_req` (requester) | Migration verifies REPORTDATA from quote supplemental data; mock quote is static |
| 2 | REPORTDATA TH1 binding — v2 | **Bypassed** | **Bypassed** | `spdm_rsp::rsp_verify_peer_attestation_v2`, `spdm_req` (requester) | Same — quote supplemental data is mocked |
| 3 | init-TDINFO cross-check + integrity + allowlist | **Bypassed** | **Bypassed** | `mig_policy::authenticate_migration_source_with_init_tdinfo` (`#[cfg(not(any(AzCVMEmu, test_mock_report, use-mock-quote)))]`) | EMU/mock TDINFO carries no real `mrowner`/measurements; the whole init-TDINFO block is `cfg`-gated to real HW |
| 4 | Engine-SVN allowlist (`get_engine_svn_by_measurements`) | Enforced | **Bypassed** | `mig_policy::authenticate_migration_source_with_init_tdinfo` (`#[cfg(not(use-mock-quote))]`) | Mock-quote MRTD belongs to a different (mock) binary, absent from `servtd_tcb_mapping` |

> Gate note: the v1 REPORTDATA check is additionally disabled under
> `test_disable_ra_and_accept_all`.

---

## SPDM Rebinding Path (prepare-rebind)

| # | Check | `AzCVMEmu` | `use-mock-quote` | Location | Reason |
|---|-------|:---:|:---:|------|--------|
| 5 | REPORTDATA TH1 binding (responder) | **Bypassed** | **Enforced** | `spdm_rsp` rebind handler (`#[cfg(not(any(AzCVMEmu, test_mock_report)))]`) | Rebind uses only `tdcall_report` (no quotes); real HW binds REPORTDATA correctly |
| 6 | REPORTDATA TH1 binding (requester) | **Bypassed** | **Enforced** | `spdm_req::...rebind...` (`#[cfg(not(any(AzCVMEmu, test_mock_report)))]`, `verify_tdreport_data_binding`) | Same |
| 7 | Engine-SVN allowlist (`authenticate_rebinding_old`) | Enforced | **Bypassed** | `mig_policy::authenticate_rebinding_old` (`#[cfg(not(use-mock-quote))]`) | Mock-quote MRTD differs from the production image |

> Rebind init-TDINFO **integrity** (`verify_init_tdinfo` → `verify_servtd_info_hash`)
> is **enforced in all build modes** (the AzCVMEmu emulation populates the
> SERVTD_EXT fields so the hash matches). Only the cross-check is TEST MODE.

---

## TLS Path (non-SPDM)

| # | Check | `AzCVMEmu` | `use-mock-quote` | Location | Reason |
|---|-------|:---:|:---:|------|--------|
| 8 | Public-key hash in REPORTDATA (cert verification) | **Bypassed** | **Bypassed** | `ratls/server_client.rs` cert-verify callbacks (`cfg!(AzCVMEmu)` / `cfg!(use-mock-quote)`) | EMU: REPORTDATA not bound. Mock-quote: cert path uses quote-derived data which is mocked |

---

## What Remains Enforced

### Under `AzCVMEmu`
- Full SPDM / TLS handshake (key exchange, cipher negotiation)
- Policy v2 JSON signature verification (ECDSA P-384) and certificate-chain validation
- Policy evaluation (`evaluate_policy_common` / `evaluate_policy_backward`)
- **Rebind init-TDINFO integrity** (`verify_servtd_info_hash`)
- **SERVTD_ATTR check** (`verify_servtd_attr`: `cur_servtd_attr == 0x0`)
- Rebind token creation/exchange and `tdcall_servtd_rebind_approve` (emulated)

### Under `use-mock-quote` (real HW)
All of the above, **plus**:
- **Rebind REPORTDATA TH1 binding** (real `tdcall_report`)
- **Migration init-TDINFO cross-check + integrity** (real `tdcall_report` / `TDG.SERVTD.RD`)

(`use-mock-quote` only bypasses the quote-derived migration REPORTDATA checks and
the `servtd_tcb_mapping` allowlist, since the mock quote carries static MRTD/RTMR.)
