---
type: Reference
title: Security Test Areas — Static Analysis, Fuzzing, Secure Review
description: The MigTD security test surface — static analyzers, vulnerable-crate scanning, fuzz targets by area, and the secure-code-review checklist for external-input boundaries.
tags: [security, fuzzing, clippy, cargo-deny, review]
timestamp: 2026-07-13T22:37:00+00:00
---

# Security Test Areas

Canonical source: [doc/security_test.md](../../../../doc/security_test.md). Use this as
a checklist when reviewing changes that touch external-input boundaries (see
also the [migtd-review SKILL.md](../SKILL.md) trust model and
[triage-justifications.md](triage-justifications.md)).

## Static analysis

`cargo-clippy`, Prusti, MIRAI (see `td-shim`'s
[`static_analyzer.md`](https://github.com/confidential-containers/td-shim/blob/main/doc/static_analyzer.md)).

## Vulnerable crate scan

`cargo-deny` (see `td-shim`'s
[`cargo-deny.md`](https://github.com/confidential-containers/td-shim/blob/main/doc/cargo-deny.md))
— this is the `deny` stage of `run-ci-gauntlet.sh`.

## Fuzz targets by area

| Area | Fuzzer | Location |
|---|---|---|
| Virtio devices (VirtioPci, VirtioVsock) | AFL | `src/devices/virtio/fuzz/` |
| Migration policy | AFL & LibFuzzer | `src/policy/fuzz/` |
| X.509 certificate parsing | AFL & LibFuzzer | `src/crypto/fuzz/` |
| GHCI `VmcallServiceResponse` | AFL & LibFuzzer | `src/migtd/fuzz/` |

## Secure-code-review checklist (external-input boundaries)

These four areas take **untrusted external input** and must copy-to-private +
sanity-check before use — flag any code that reads from these sources
directly without validation as a candidate finding:

- **Virtio devices** — external input; copy to private memory before use.
- **GHCI `VmcallServiceResponse`** — VMM result is untrusted; copy to private
  memory + sanity-check before use.
- **Migration policy** — external input; must be measured (RTMR) and
  sanity-checked before use.
- **X.509 certificate** (peer MigTD's) — external input; must be measured and
  sanity-checked before use.

Cross-reference: [Domain Facts § Trust model](../../../knowledge/domain-facts.md)
— "VMM is untrusted but can DoS" already covers the DoS-vs-integrity
distinction for these same boundaries.
