---
type: Reference
title: Engineering Decisions Log
description: Concrete, non-obvious engineering decisions (feature/commit kept vs. dropped, and why) with commit SHAs and verification steps. Append-only; grows over time.
tags: [decisions-log, living-document]
timestamp: 2026-07-10T19:26:55+00:00
---

# Engineering Decisions Log

> Split from [AGENT_NOTES.md](/AGENT_NOTES.md) §11. This is a **decision
> log**, not a design doc — as opposed to [Domain Facts](domain-facts.md) and
> [Anti-patterns](anti-patterns.md), which record standing facts/rules, this
> file records one-off decisions. Keep entries to a sentence or two, cite the
> commit/SHA that acted on the decision. Append new entries at the bottom;
> see [AGENT_NOTES.md](/AGENT_NOTES.md) §"Reflect and update" for the update
> ritual that applies to this whole knowledge base.

- **Dropped the peer-leaf-certificate-expiration check**
  (`crypto::validate_peer_leaf_expiration`, previously enforced in
  `mig_policy.rs` for both the Policy and ServTDTCBMapping issuer chains on
  `integration2`). Reason: it rejects a destination whose signing cert
  expires before the source's, which blocks legitimate cert/key-rotation
  operations where a newly-issued destination cert intentionally has a
  shorter overlap/validity window than the cert it is rotating away from.
  Simplifies rotation operations. Dropped via
  `git rebase --onto <parent> <commit> integration2` (no later commit
  touched `src/crypto/src/lib.rs`, `src/crypto/src/x509.rs`, or
  `src/migtd/src/mig_policy.rs`, so the drop was conflict-free); verified
  by a tree-diff-equivalence check plus `cargo fmt --check` and
  `cargo xtask lib-test --crates migtd` (60 passed) before and after.

- **Dropped all `init_td_info` trace-logging and its dedup accessor**
  (`migration::trace_td_info()`/`trace_init_td_info_from_host()` full-buffer
  dumps, and the `MigtdMigrationInformation::init_td_info_or_local()`
  accessor that centralized the "VMM-provided vs. local fallback" pattern +
  its own minimal trace lines). Reason: the upcoming design removes
  `init_td_info` from the wire protocol entirely, so both the diagnostic
  logging and the accessor that exists purely to serve it become dead
  weight — no point carrying debugging aids and helper functions for data
  that won't exist. Dropped via two `git rebase --onto`/`--skip` steps
  (the accessor's own commit had to be skipped too, once identified as
  serving the same soon-to-be-removed field); 3 real conflicts arose where
  later commits built directly on the accessor/trace calls — resolved by
  keeping the surrounding functional code and stripping only the
  init_td_info-tracing lines. Verified: no `trace_td_info` /
  `init_td_info_or_local` references remain anywhere in `src/`; `cargo fmt
  --check` clean; `cargo xtask lib-test --crates migtd` (60 passed,
  unchanged); `fast-emu-check.sh` (skip-RA + SPDM skip-RA) both PASS.
