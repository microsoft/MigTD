---
type: Reference
title: Code Style Preferences
description: MigTD-specific Rust code style conventions — diff minimization, error handling, logging discipline, and refactoring guidance.
tags: [code-style, rust, logging, refactoring]
timestamp: 2026-07-10T19:26:55+00:00
---

# Code Style Preferences

> Condensed in the root [agent guide](../../AGENTS.md).

- **Minimize diff.** When refactoring or merging conflicts, **keep existing
  parameter and field names** instead of inventing new ones. Cosmetic
  renames during functional work get pushed back.
- **Don't churn unrelated formatting.** `cargo fmt` only on files you've
  modified.
- **No `expect()` / `unwrap()` in non-test code paths.** Return an error
  instead.
- **Prefer the `LogErr` / `LogError` helper trait** for `Result` → log + error
  patterns instead of hand-rolled `if let Err … { log!… }` blocks.
- **Refactor for reuse, not for novelty.** When asked for "polymorphism" /
  "template" / "common closure", deliver *real* deduplication. Don't add a
  trait/macro with only one implementation.
- **Don't add feature gates just to be safe.** If a feature is always
  desired, remove the gate.
- **Logging discipline:**
  - INFO level should be sparse.
  - **Never dump full quotes / certs / large blobs at INFO/DEBUG.** Log
    first 8 bytes + last 8 bytes + length. Excessive quote dump has caused
    multi-second stalls during real-hardware migration tests.
  - When adding diagnostic logs, gate behind explicit verbosity OR commit
    them as a clearly-named debug/diag commit that can be dropped later.
- **Don't fix code that "looks redundant" without proving it.** Canonical
  cautionary tale: `event_log::get_event_log()` returns `&raw[..size + 1]`;
  removing the `+1` (commit `bc99fa4`) passed unit tests but broke EMU
  integration. The `+1` is a load-bearing workaround for an upstream
  `cc_measurement` bug. See [migtd-review SKILL.md](/skills/migtd-review/SKILL.md) §1.
