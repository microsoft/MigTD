---
type: Reference
title: MigTD Architecture Overview (Azure Build)
description: Agent-oriented map of MigTD's main functional areas for the Azure IGVM build — flow, transport, attestation, policy v2, and error codes — with pointers into source.
tags: [architecture, azure, spdm, policy-v2, migration]
timestamp: 2026-07-13T22:37:00+00:00
---

# MigTD Architecture Overview (Azure Build)

Canonical source: [doc/MigTD_Functionality_Summary.md](../../doc/MigTD_Functionality_Summary.md)
(335 lines, kept up to date independently — read it in full before making
architectural changes). This file is a **navigation aid**: what exists where,
so you know which doc/source to open next.

## What MigTD is

A `no_std` Rust TDX **Service TD** (`SERVTD_TYPE = 0`) that mutually
remote-attests a migration source (MigTD-S) and destination (MigTD-D) over
**SPDM**, evaluates both against **policy v2**, and exchanges the **Migration
Session Key (MSK)** so the VMM can live-migrate a user TD. Entry point:
`src/migtd/src/lib.rs` (`_start`) → `main()` in
`src/migtd/src/bin/migtd/main.rs`.

## Where things live (map, not detail)

| Area | Source | Doc |
|---|---|---|
| End-to-end flow, MSK read/write, version negotiation | `src/migtd/src/bin/migtd/main.rs`, `migration/session.rs` | §2 |
| VMM interface (`vmcall-raw` GHCI, request dispatch) | `src/migtd/src/migration/{data,session,event}.rs` | §3 |
| Quote generation/verification (`igvm-attest`) | `src/attestation/src/{igvmattest,quote,attest}.rs` | §4 |
| Measurement / event log | `src/migtd/src/event_log.rs` | §4 |
| SPDM mutual attestation + secure session | `src/migtd/src/spdm/`, `migration/spdm_session.rs` | §5 |
| Policy v2 evaluation | `src/policy/`, `src/migtd/src/mig_policy.rs` | §6, [policy-v2-workflow.md](policy-v2-workflow.md) |
| TD binding / rebinding | `migration/servtd_ext.rs`, `migration/rebinding.rs` | §7, [init-tdinfo-servtd-ext.md](init-tdinfo-servtd-ext.md) |
| Crypto (ECDSA P-384, X.509, COSE_Sign1) | `src/crypto/` | §9 |
| Async runtime (no_std executor / tokio under emu) | `src/async/` | §10 |
| Build/hashing tools | `tools/migtd-hash`, `tools/migtd-policy-generator`, etc. | §11, §12 |
| AzCVMEmu emulation mode | `src/migtd/src/bin/migtd/cvmemu.rs` | §13, [azcvmemu-build-and-run.md](azcvmemu-build-and-run.md) |

## Migration error codes (host-visible) — quick lookup

| Code | Cause |
|:----:|-------|
| 1 | VMM-provided data not as expected |
| 3 | Out of memory |
| 4 | TDX module error (often mismatched `SERVTD_INFO_HASH`) |
| 5 | Failed to establish host communication channel |
| 6 | SPDM/secure-session error (remote quote verification or handshake aborted) |
| 7 | Unable to obtain the quote |
| 8 | Remote quote does not satisfy the migration policy |

## Explicitly out of scope of the Azure-focused doc

The one-hash TCB-mapping / CoRIM hash endorsement PoC (`servtd_corim`) and
non-Azure options (RA-TLS, virtio/vsock transports, `bin` image format) — see
[doc/MigTD_Functionality_Summary.md](../../doc/MigTD_Functionality_Summary.md) scope note.
