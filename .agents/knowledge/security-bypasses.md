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

> Locations are given by function (line numbers drift). There is no local
> startup check comparing TDINFO.MROWNERCONFIG with policy SVN; peer
> init/current continuity is enforced through the authenticated one-hash
> mapping.

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
  checks remain available.

---

## SPDM Migration Path

| # | Check | `AzCVMEmu` | `use-mock-quote` | Location | Reason |
|---|-------|:---:|:---:|------|--------|
| 1 | REPORTDATA TH1 binding — v1 | **Bypassed** | **Bypassed** | `spdm_rsp::rsp_verify_peer_attestation_v1`, `spdm_req` (requester) | Migration verifies REPORTDATA from quote supplemental data; mock quote is static |
| 2 | REPORTDATA TH1 binding — v2 | **Bypassed** | **Bypassed** | `spdm_rsp::rsp_verify_peer_attestation_v2`, `spdm_req` (requester) | Same — quote supplemental data is mocked |

> Gate note: the v1 REPORTDATA check is additionally disabled under
> `test_disable_ra_and_accept_all`.

---

## SPDM Rebinding Path (prepare-rebind)

| # | Check | `AzCVMEmu` | `use-mock-quote` | Location | Reason |
|---|-------|:---:|:---:|------|--------|
| 5 | REPORTDATA TH1 binding (responder) | **Bypassed** | **Enforced** | `spdm_rsp` rebind handler (`#[cfg(not(any(AzCVMEmu, test_mock_report)))]`) | Rebind uses only `tdcall_report` (no quotes); real HW binds REPORTDATA correctly |
| 6 | REPORTDATA TH1 binding (requester) | **Bypassed** | **Enforced** | `spdm_req::...rebind...` (`#[cfg(not(any(AzCVMEmu, test_mock_report)))]`, `verify_tdreport_data_binding`) | Same |

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
- Init/current SVN ordering through the authenticated source's verified
  mapping; both mapping misses fail closed
- Policy evaluation (`evaluate_policy_common` / `evaluate_policy_backward`)
- **SERVTD_ATTR check** (`verify_servtd_attr`: `cur_servtd_attr == 0x0`)
- Rebind token creation/exchange and `tdcall_servtd_rebind_approve` (emulated)

### Under `use-mock-quote` (real HW)
All of the above, **plus**:
- **Rebind REPORTDATA TH1 binding** (real `tdcall_report`)

`use-mock-quote` bypasses quote-derived migration REPORTDATA checks. It does
not bypass mapped init/current SVN ordering. There is no destination-local
Init_TDINFO allowlist in the one-hash design.
