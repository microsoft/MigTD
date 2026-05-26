# MigTD Security Bypasses — Feature Comparison

This document catalogues verification checks bypassed under different
build features and explains **why** each feature requires (or does not
require) a given bypass.

> **None of these bypasses are acceptable in production.** They exist
> solely to enable development/testing on non-production environments.

---

## Feature Semantics

| Feature | Environment | TDX Hardware | `tdcall_report` | Quote (QGS/IMDS) | Purpose |
|---------|-------------|:---:|:---:|:---:|---------|
| `AzCVMEmu` | Desktop emulator (no TDX) | ✗ | Emulated (REPORTDATA not bound) | Emulated | Full protocol flow testing without hardware |
| `test_mock_report` | Emulated (implies AzCVMEmu) | ✗ | Emulated | Emulated | Unit/integration tests with mock TD reports |
| `use-mock-quote` | **Real TDX hardware** | ✓ | **Real** (REPORTDATA correctly bound) | Static mock data | Testing on TDX when QGS/IMDS unavailable |

### Key Difference

- **`AzCVMEmu` / `test_mock_report`**: No hardware — `tdcall_report` is
  emulated and **does not** embed caller-supplied REPORTDATA. All checks
  that depend on REPORTDATA content must be bypassed.

- **`use-mock-quote`**: Real TDX hardware — `tdcall_report` works
  correctly and **does** embed REPORTDATA (SHA384 of prefix ‖ TH1).
  Only quote-dependent checks need bypassing; TD-report-based checks
  (e.g., rebind REPORTDATA binding) remain **enforced**.

---

## Rebinding Flow (prepare-rebind)

### TLS Path (non-SPDM)

| # | Check | `AzCVMEmu` | `use-mock-quote` | File | Reason |
|---|-------|:---:|:---:|------|--------|
| 1 | mrowner match vs init TDINFO | **Bypassed** | Enforced | `ratls/server_client.rs:1001` | EMU returns zeroed mrowner; real HW has correct value |
| 2 | Public key hash in REPORTDATA | **Bypassed** | **Bypassed** | `ratls/server_client.rs:1156` | EMU: REPORTDATA not bound. Mock-quote: TLS path uses quote-derived supplemental data which is mocked |
| 3 | Public key hash (policy_v2 variant) | **Bypassed** | **Bypassed** | `ratls/server_client.rs:1193` | Same as #2 |

### SPDM Path

| # | Check | `AzCVMEmu` | `use-mock-quote` | File | Reason |
|---|-------|:---:|:---:|------|--------|
| 4 | init_tdinfo + servtd_ext hash | **Bypassed** (runtime) | Enforced | `mig_policy.rs:323` | EMU: `TDG.SERVTD.RD` returns ATTRIBUTES=0 → empty wire data. Real HW: populated correctly |
| 5 | REPORTDATA TH1 binding (responder) | **Bypassed** | **Enforced** | `spdm/spdm_rsp.rs:1208` | Rebind uses only `tdcall_report` (no quotes). Real HW binds REPORTDATA correctly |
| 6 | REPORTDATA TH1 binding (requester) | **Bypassed** | **Enforced** | `spdm/spdm_req.rs:1309` | Same — rebind path never invokes quote generation |
| 7 | ServtdExt parse from wire | **Bypassed** (runtime) | Enforced | `spdm/spdm_rsp.rs:1229` | EMU sends zero-length servtd_ext |
| 8 | Engine SVN allowlist (`authenticate_rebinding_old`) | Enforced | **Bypassed** | `mig_policy.rs:361` | Mock-quote MRTD differs from production image; EMU uses same binary |

---

## Migration Flow

| # | Check | `AzCVMEmu` | `use-mock-quote` | File | Reason |
|---|-------|:---:|:---:|------|--------|
| 9 | REPORTDATA TH1 binding (responder) | **Bypassed** | **Bypassed** | `spdm/spdm_rsp.rs:805` | Migration uses quote-embedded supplemental data which carries REPORTDATA; mock quote has static data |
| 10 | REPORTDATA TH1 binding (requester) | **Bypassed** | **Bypassed** | `spdm/spdm_req.rs:712` | Same |
| 11 | REPORTDATA binding v1 (responder) | **Bypassed** | **Bypassed** | `spdm/spdm_rsp.rs:703` | Same |
| 12 | REPORTDATA binding v1 (requester) | **Bypassed** | **Bypassed** | `spdm/spdm_req.rs:799` | Same |
| 13 | Supplemental data REPORTDATA verify | Enforced | **Bypassed** | `spdm/mod.rs:214` | `verify_peer_report` uses quote supplemental data; mock quote is static |
| 14 | Engine SVN allowlist (migration) | Enforced | **Bypassed** | `mig_policy.rs:1042` | Mock-quote MRTD not in tcb_mapping |

---

## Shared / General

| # | Check | `AzCVMEmu` | `use-mock-quote` | File | Reason |
|---|-------|:---:|:---:|------|--------|
| 15 | Event log RTMR verification | **Bypassed** | **Bypassed** | `event_log.rs:280` | EMU: no real RTMR. Mock-quote: RTMR in mock quote won't match event log from real platform |

---

## Summary: What Remains Enforced

### Under `AzCVMEmu`
- Full SPDM / TLS handshake (key exchange, cipher negotiation)
- Policy v2 JSON signature verification (ECDSA P-384)
- Certificate chain validation (root CA ↔ leaf)
- Policy evaluation: `evaluate_policy_common` + `evaluate_policy_backward`
- Rebind token creation and exchange
- `tdcall_servtd_rebind_approve` (emulated call)
- Cross-policy evaluation (`evaluate_against_policy`)
- Engine SVN allowlist (rebind path)

### Under `use-mock-quote`
All of the above, **plus**:
- **Rebind REPORTDATA TH1 binding** (real `tdcall_report` works)
- **mrowner verification** (real TDINFO)
- **init_tdinfo + servtd_ext hash** (real `TDG.SERVTD.RD` works)
- **ServtdExt parsing** (non-empty wire data from real hardware)

---

## Related Integration Branch Commits

The following commits on `origin/integration` provide a more comprehensive
fix by redesigning the wire protocol (always send 272-byte ServtdExt,
init_tdinfo length as sole opt-in signal):

- `90f97e2` — `fix(servtd_ext): unify wire-protocol contract for SERVTD_EXT opt-in`
- `6df3a03` — `refactor(mig_policy): drop init-reference policy evaluation from rebind/migration`

These should be cherry-picked or merged when ready to replace the local
bypasses in this document.
