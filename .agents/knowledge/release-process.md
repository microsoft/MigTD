---
type: Playbook
title: Release Process
description: Version semantics, release content checklist, and release steps for cutting a MigTD release branch.
tags: [release, semver, branching]
timestamp: 2026-07-13T22:37:00+00:00
---

# Release Process

Canonical source: [doc/release.md](../../doc/release.md).

## Versioning

`v<major>.<minor>.<patch>` per [semver.org](https://semver.org/).

## Release content checklist (per `v<major>.<minor>` branch)

- Release build image (no debug messages) + its `MigTD:TEE_INFO_HASH`.
- Debug build image (debug messages to virtual serial) + its
  `MigTD:TEE_INFO_HASH`.
- Release notes: tested features, critical fixes/known issues, and the exact
  configuration matrix (EMR SOC, IFWI/MCHECK, TDX-module, host
  hypervisor/QEMU, guest OS/kernel/initrd, attestation library/DCAP version),
  plus source/destination launch parameters.
- `Cargo.lock` (locks dependency versions — see
  [reproducible-build.md](reproducible-build.md) for why this matters for MRTD
  stability).

## Steps

1. Unit test on latest `main`.
2. Tag `v<major>.<minor>.<patch>-rc`.
3. Release test on the RC (validation engineer).
4. Fix issues found.
5. Create branch `v<major>.<minor>`.
6. Upload release content to that branch.

## Release test features

Migration flow, attestation flow.
