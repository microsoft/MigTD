---
type: Reference
title: Anti-patterns — Things To NOT Do
description: Collected pushback items from past sessions — a checklist of mistakes to avoid repeating.
tags: [anti-patterns, checklist]
timestamp: 2026-07-10T19:26:55+00:00
---

# Anti-patterns — Things To NOT Do

> Condensed in the root [agent guide](../../AGENTS.md). See
> [Domain Facts](domain-facts.md) and [Code Style](code-style.md).

- ❌ Forget the DCO `Signed-off-by` trailer.
- ❌ Bundle unrelated changes into one commit.
- ❌ Use `expect()` / `unwrap()` in production paths.
- ❌ Rename parameters/fields gratuitously during a refactor.
- ❌ Add a feature gate when "always-on" is the obvious right answer.
- ❌ Dump full quotes or large buffers at log level INFO/DEBUG.
- ❌ Re-flag VMM DoS as a finding.
- ❌ Re-open the singleton-vector hypothesis for the cert_rot timeout.
- ❌ Increase a buffer size to *work around* a bug instead of fixing the bug.
- ❌ Run multiple `migtdemu.sh` invocations concurrently.
- ❌ Force-push without `--force-with-lease=<branch>:<sha>`.
- ❌ Force-push to `intel/*` or `ms/*` / `upstream/*` remotes.
- ❌ Run `cargo fmt` repo-wide; only touch files you modified.
- ❌ Add `.clawpatch/` or `.copilot-review-issues/` to source control
  (gitignored).
- ❌ Touch code in a sibling clone (e.g. `../MigTD2`) from the wrong checkout
  — another agent may be working there.
