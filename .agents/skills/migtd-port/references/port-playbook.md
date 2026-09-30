---
type: Playbook
title: MigTD Port Playbook — integration → intel/main
description: Durable heuristics and worked example for forward-porting Microsoft-fork MigTD changes onto an intel/main-based branch.
tags: [port, cherry-pick, integration, intel-main]
timestamp: 2026-07-10T19:26:55+00:00
---

# Port playbook — durable heuristics + worked example

Companion to `SKILL.md`. The first half is reusable for **any** `integration → intel/main`
port; the second half is the **worked integration → integration2 port (June 2026)** kept as
a concrete reference for the kinds of decisions that recur.

---

## Part A — durable heuristics

### Deciding keep vs skip for a CANDIDATE

For each commit the detector tags `CANDIDATE` (no strong subject match on target), read the
**actual diff** and ask, in order:

1. **Is the change already present in different form?** `git show <sha>` then grep the target
   tree for the introduced symbol/string. Subjects diverge more than code — the detector can
   miss a dupe whose subject was heavily reworded. If present and equivalent → skip-similar.
2. **Is it an always-skip category?** (CI bump, dep downgrade, `fuzzing.sh`, target-only file.) → skip.
3. **Does it depend on a commit you're skipping?** If so it's `skip-coupled` unless you also
   port the dependency. Re-express on the target's structure if the keeper part is wanted.
4. **Was it reverted later on `integration`?** Check `git log --oneline <sha>..integration --
   <files>` for a revert/supersede. If the net effect at `integration` tip is gone → skip.
   (Watch for `REVERT_ME:`-tagged temporary commits still live at the tip — keep only the
   surviving parts.)
5. **Otherwise → keep.** Cherry-pick, resolve onto the target's structure, verify.

### Detection method ranking (most → least reliable here)

1. **Subject similarity** vs the target's post-base subjects (`find-port-candidates.sh`). Best
   single signal because subjects survive upstreaming.
2. **`git cherry` patch-id** (`-`). Only catches byte-identical picks, but those are *certain*.
3. **Per-commit 3-way / `git merge-tree`** — unreliable when the branches diverged
   structurally (lots of false "conflicts"). Use only to sanity-check a specific pick.

### Convergence invariant

After the port, the target's **behaviour** should match `integration`'s tip for the ported
areas, while **keeping** the target's CI/dependency posture and any fix it already carries in
a better form. When in doubt, diff the specific module against `integration` tip and reconcile
deliberately — do not assume "more commits = closer".

---

## Part B — worked example: integration → integration2 (June 2026)

- **Topology:** merge-base `7829a8f9`. `integration2` = base + 86 (intel/main upstreamed work
  + CI/dep bumps). `integration` = base + 148. Baseline for the scan: `88f4ae7e`.
- **Candidate scan** (`88f4ae7e..integration`, 93 rows): triaged to
  **28 picked · 26 skip-similar · 9 skip-user · 1 skip-coupled** (the historical 64-row count
  was a tighter base window; the 93-row scan from `88f4ae7e` is what the current script prints).
- The tree was later **rebased/squashed** by the user, so the final commit count on
  `integration2` differs from "28 picks". Treat the numbers as illustrative of the *triage*,
  not the final history.

### Notable keep decisions

- **policy_v2 gating** (user-confirmed): gate init_td_info / servtd_ext code on `policy_v2`,
  **not** `all(vmcall-raw, policy_v2)` (the latter came from a skipped commit). Keep the
  target's `policy_v2` gate.
- **Truncating long logs**: several `integration` commits combined into one logical pick.
- **REVERT_ME #40/#42**: kept only the surviving parts (logging threshold doubling
  256/128/32; use-mock-quote allowlist gating); dropped the superseded soft-fails.
- **Partial pick of the REPORTDATA-bypass commit**: applied the bypass + script; dropped the
  unrelated ratls/mrowner and ServtdExt-optional hunks (pre-scope / out-of-scope).

### Notable skip decisions

- **SERVTD_EXT opt-out feature** (`f408a0c25`, `90f97e2bf`, `f9d966e18`, `0f4c2fd86`):
  **skipped by user constraint — assume SERVTD_EXT is always opt-in.** `read_servtd_ext()`
  returns `ServtdExt` (not `Option`). The opt-out series was entangled with a pre-scope
  refactor adding `init_policy_hash` to `client_rebinding` (5-arg vs target's 4-arg) and a
  `setup_evaluation_data_with_tdinfo` that doesn't exist on the target.
- **`fix(clippy): silence derivable_impls`** (`9912691ba`): `skip-coupled` — only needed
  because of the skipped init_td_info re-gating; the target doesn't have the offending impl.
- **User-requested skips**: UB-in-FFI-return-type fix, `unify init_td_info handling`, peak-heap
  logging, post-rebase fmt/cleanup, `enable jq for rebind-skip-ra` CI tweak.
- **Obsolete after squash** (`51efdbb1`, "port PR #825 cfg structure"): its `main.rs` import
  became net-zero and its `mig_policy` gating referenced `rebinding::InitData`, which the
  function no longer uses (signature changed to `&[u8; TD_INFO_SIZE]`). Dropped via
  `git rebase --onto 51efdbb1~1 51efdbb1`; re-verified clean (lib-test all configs, emu 8/8).

### Migration / rebinding facts confirmed during the port (target = integration2)

- `verify_servtd_info_hash` computes a **direct** `SHA384(masked_tdinfo)` (not the old
  composite `init_servtd_info_hash`). `verify_init_tdinfo` wraps it.
- Migration-dest `authenticate_migration_source_with_init_tdinfo` verifies init-TDINFO
  integrity + allowlist, gated `#[cfg(not(any(AzCVMEmu, test_mock_report, use-mock-quote)))]`
  (real-HW only). Both migration and rebinding use `get_local_tcb_evaluation_info()` (local
  TCB) as the policy reference — neither uses init as a relative reference.
- `verify_servtd_attr` only checks `cur == EXPECTED_SERVTD_ATTR` (0x0); the `cur == init_attr`
  check was removed.
- `finalize_spdm_session<Fut, T>` preserves `decode_spdm_session_err` error mapping.

### Validation commands used

```bash
cargo xtask lib-test --crates migtd          # migtd unit tests + targeted feature matrix
.agents/skills/migtd-port/scripts/fast-emu-check.sh    # per-pick smoke (skip-ra + spdm skip-ra)
.agents/skills/migtd-port/scripts/emu-milestone.sh     # 8-scenario checkpoint
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh # full CI parity before push
export SPDM_CONFIG="$(pwd)/config/spdm_config.json"     # required for any spdm build
```

Safety tags created (pattern to repeat): `integration2-backup-before-cherrypick`,
`integration2-before-drop-51efdbb1`.
