---
type: Reference
title: MigTD Build Features
description: Feature-gating map of which crates and code paths compile under which Cargo feature combinations.
tags: [build, cargo-features, feature-gating]
timestamp: 2026-07-10T19:26:55+00:00
---

# Build features — what compiles when

Source: `src/migtd/Cargo.toml`, `src/devices/Cargo.toml`, `Cargo.toml` workspace.

## Default in-scope feature set used in the audit

```
main, vmcall-raw, stack-guard, vmcall-interrupt, oneshot-apic,
spdm_attestation, igvm-attest, policy_v2
```

## Feature → enabled crates / modules

| Feature | Pulls in / enables |
|---|---|
| `main` | `bin/migtd` binary |
| `vmcall-raw` | `src/devices/vmcall_raw/` transport |
| `vmcall-interrupt` | Interrupt-driven completion in `vmcall_raw/transport/vmcall.rs` |
| `oneshot-apic` | One-shot APIC mode in `td_payload`/`devices/apic` |
| `spdm_attestation` | `src/migtd/src/spdm/` paths (requester + responder) |
| `igvm-attest` | `attestation/igvm-attest` integration in `attestation/` |
| `policy_v2` | `src/policy/src/v2/`, `attestation/attest-lib-ext` |
| `stack-guard` | Stack canary in `migtd` startup |

## Not in scope under that set

| Feature | Module |
|---|---|
| `virtio-vsock`, `vmcall-vsock` | `src/devices/vsock/` (entire crate path) |
| `virtio-serial` | `src/devices/virtio_serial/` |
| `AzCVMEmu` | `deps/td-shim-AzCVMEmu/`, `cvmemu` module |
| `fuzz` | `src/devices/*/fuzz/`, top-level `fuzz/` |
| `test_disable_ra_and_accept_all` | RA-bypass paths (skip-ra EMU tests only) |

## Always compiled

- `src/devices/virtio/` (not optional)
- `src/devices/pci/` (not optional, but in vmcall-raw builds it's effectively dead — still compiled)
- `src/crypto/` (rustls is default)
- `src/attestation/` (attest-lib backbone)

## How to decide if code is dead in your build

```bash
# Find feature gates on the offending function/module:
grep -rn '#\[cfg(' path/to/file.rs | head -20
# Then check Cargo.toml deps in the consuming crate.
```

If the function has `#[cfg(feature = "virtio-vsock")]` and your build doesn't enable that, the finding is wont-fix.
