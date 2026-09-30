---
type: Reference
title: Code Coverage Plan (Draft Status)
description: The proposed (not-yet-implemented) per-PR code coverage flow — decided aggregation backend, tooling, and phased plan — to avoid contradicting already-made decisions.
tags: [code-coverage, ci, codecov, grcov, draft]
timestamp: 2026-07-13T22:37:00+00:00
---

# Code Coverage Plan (Draft Status)

Canonical source: [doc/code_coverage.md](../../doc/code_coverage.md). **Status:
DRAFT for review — nothing here is implemented in CI yet.** If asked to "add
code coverage", read the full doc first; don't re-derive the plan from
scratch or contradict the decisions already made below.

## Decisions already made (don't re-litigate without new info)

- **Aggregation backend: Codecov** (flag-merge + carryforward), chosen over
  self-hosted merge, Coveralls, or ADO Cobertura.
- **Tooling: `grcov` → LCOV**, kept for uniformity across unit tests, AzCVMEmu
  integration, and (future) firmware coverage — all converge on `.profraw` →
  `grcov -t lcov`.
- **Firmware (real-hardware TDX) coverage approach: `minicov`** no_std
  runtime, phase 2 — capture counters and stream over an existing channel
  (serial/vsock) since the firmware is `no_std`, has no filesystem, and is a
  **measured** image (instrumentation changes MRTD, requiring policy/cert
  regeneration to match).

## Why AzCVMEmu integration coverage is "easy"

The AzCVMEmu binary is a **std host build**; `migtdemu.sh` launches it via
`env "${kv[@]}" … "$binary"` which inherits the parent environment, so
exporting `LLVM_PROFILE_FILE=…/%p-%m.profraw` instruments both source and
destination processes with **no script change**.

## Phased plan

1. **Phase 1 (now):** unit tests + a minimal AzCVMEmu subset (~4-6 of the 13
   legs) → Codecov flags `unittests` + `integration`, per-PR.
2. **Phase 2 (later):** firmware coverage via `minicov` on self-hosted TDX,
   uploaded under a **carryforward** `hardware` flag (so PRs without a
   hardware run still show the last-known production-path coverage).
3. **Phase 3:** lock in the covering subset, decide gating policy
   (informational vs. blocking threshold).

## Open questions still unresolved

Per-PR CI time budget for the instrumented subset; whether to invest in
firmware/minicov now vs. defer; gating policy; Codecov org onboarding
(`CODECOV_TOKEN` for fork PRs). Surface these to the user rather than
assuming an answer if picking this work up.
