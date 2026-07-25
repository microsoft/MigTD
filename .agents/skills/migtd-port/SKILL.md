---
name: migtd-port
description: Port the Microsoft `integration` branch onto an intel/main-based branch in the MigTD repo by cherry-picking (or rebasing) only the not-yet-upstreamed commits, then validating each pick with cargo fmt + the AzCVMEmu integration tests. Use when asked to "port integration to intel/main", "cherry-pick the integration branch", "rebase integration onto intel/main", "bring integration changes to integration2", or to forward-port Microsoft MigTD changes upstream.
---

# MigTD Port (integration → intel/main)

Workflow + reusable scripts for moving the **remaining** Microsoft-fork changes from
the `integration` branch onto a branch based on `intel/main` (e.g. `integration2`,
or a fresh upstream PR branch). The hard part is **not** the mechanical cherry-pick —
it is figuring out which commits are *genuinely missing* versus already upstreamed in
reworded/squashed form, and never reverting the target branch's own improvements.

Pairs with the **migtd-review** skill (trust model, build features, full CI gauntlet).
Read that skill's §1 before reasoning about any behavioural conflict you resolve here.

---

## 1. The core problem (read FIRST)

- The **majority of `integration`'s work has already been upstreamed** to `intel/main`
  in *reworded and/or squashed* form. A naive `git cherry-pick base..integration`
  re-applies dozens of already-present commits and conflicts on ~80% of them.
- `git cherry` (patch-id) **under-detects** duplicates: upstreaming refines the patch,
  so the patch-id differs even though the change is present. `git cherry` only catches
  byte-identical cherry-picks (`-`).
- **Commit-message similarity is the reliable "already there" signal.** Subjects survive
  upstreaming mostly intact (often just gaining a `type(scope):` prefix). Matching each
  `integration` subject against the target branch's subjects finds the reworded dupes.
- Therefore: **detect → human-review → pick only the residue → verify each pick.**
  Never blind-pick. The end state must converge toward the `integration` *tip behaviour*,
  but must **keep** the target branch's CI/dependency improvements and any fix the target
  already carries in a better form.

### Topology & remotes

```
intel     https://github.com/intel/MigTD.git      # upstream target base (intel/main)
origin    https://github.com/<user alias>/MigTD.git # personal fork; carries origin/integration
upstream  https://github.com/microsoft/MigTD.git   # Microsoft fork (integration originates here)
```

- `integration` = Microsoft-fork dev branch (downstream of `intel/main` + lots of extra work).
- Target = an `intel/main`-based branch you are forward-porting onto.
- `merge-base integration <target>` is the common ancestor; everything after it on
  `integration` is a *candidate*, everything after it on the target is the
  *already-upstreamed corpus* you match against.

---

## 2. Always-skip categories

These are decided up front (the user's standing rules for this port). Mark them skip
without per-commit debate:

| Category | Rule |
|---|---|
| **CI workflow SHA / action bumps** | The target (intel/main) owns its CI. Do **not** port `integration`'s CI bumps. Keep the target's. |
| **Dependency *downgrades*** | Never move a dep backwards. If `integration` pins an older version than the target, keep the target's newer pin. |
| **`sh_script/fuzzing.sh`** | Skip — target keeps its own. |
| **Anything the target lacks a commit for** | If `integration` has no commit introducing a change (it's just an older state), that's not a change to port — keep the target's version. |
| **Commits with a high subject-similarity match on target** | Already upstreamed. Verify the diff is equivalent, then skip. |

Everything else is a **CANDIDATE** → review its actual diff → keep or skip with a reason.

---

## 3. The workflow

```
0. preparation     bash sh_script/preparation.sh         # once per fresh checkout / submodule update
1. safety tag      git tag <target>-backup-before-port   # so you can always get back
2. detect          scripts/find-port-candidates.sh ...   # table of keep/skip suggestions
3. triage          record decisions in the `picks` session table (see §5)
4. pick loop       per CANDIDATE:  git cherry-pick <sha>  ->  resolve  ->  scripts/port-verify.sh
5. milestone       scripts/emu-milestone.sh               # after each batch / after a squash/drop
6. full CI parity  migtd-review run-ci-gauntlet.sh        # before pushing (all 4 workflows)
7. push            --force-with-lease to a PERSONAL fork only; never a shared branch
```

### Step 2 — detect

```bash
.agents/skills/migtd-port/scripts/find-port-candidates.sh \
    --source origin/integration --target <target-branch> --base <baseline-sha>
```

Prints a numbered table; each row is tagged:
- `SKIP-patchid` — identical patch already on target (`git cherry` `-`). Safe skip.
- `SKIP-similar` — subject ≥ threshold% similar to a target commit → reworded duplicate.
  **Verify the diff, then skip.**
- `CANDIDATE` — no good match → likely genuinely missing. **Review the diff and decide.**

Add `--sql` to emit `INSERT INTO picks(...)` seed rows for the session DB, and `--full`
to see untruncated subjects. The suggestion is a *starting point* — you still read diffs.

### Step 4 — the per-pick gate (MANDATORY after every pick)

After each `git cherry-pick` and conflict resolution:

```bash
.agents/skills/migtd-port/scripts/port-verify.sh
```

It runs, fastest-first, stopping at the first failure:
1. `cargo fmt` (apply — picks frequently need reformatting; commit the reformat)
2. `cargo fmt --check`
3. `cargo xtask lib-test --crates migtd` (migtd unit tests + feature matrix)
4. `fast-emu-check.sh` (skip-RA + SPDM skip-RA emulation smoke)

Use `--no-emu` only for doc-only / non-boundary picks. Fix failures **before** the next
pick — do not pile commits on top of a broken one (use `git rebase -i` to fold/drop).

---

## 4. Verification ladder

Three tiers, cheap → expensive. Do **not** skip straight to push.

| Tier | Script | Scope | When |
|---|---|---|---|
| fast | `scripts/fast-emu-check.sh` | 2 emu scenarios (skip-RA, SPDM skip-RA) | after **every** pick (via `port-verify.sh`) |
| milestone | `scripts/emu-milestone.sh` | 8 curated emu scenarios | after a batch of picks / after a drop or squash |
| full CI | `.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh` | all 14 emu + 32 `cargo image` + format + deny | before pushing |

For just the full emu matrix or just the firmware builds:
```bash
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --only emu
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --only main
```

Why a fast gate per-pick and not the full 14 every time: the full emu matrix is ~20–40
min; the 2-scenario gate is a couple of minutes and catches the overwhelming majority of
broken picks (build break, fmt, obvious logic regressions). The milestone (8) and full
(14) tiers catch policy-v2 / rebind / key-rotation specific regressions.

> **migtdemu.sh is not parallel-safe** (hardcoded port 8001, `taskset -c 0`, fixed log
> names, shared `target/release/migtd`). Run emu scenarios **sequentially**. The scripts
> here already do.

---

## 5. Tracking decisions — the `picks` session table

Use the per-session SQLite DB (not a markdown file) to track every candidate. Schema used
in the worked example (`seq, hash, subject, status, note, pick_order`):

```sql
-- statuses: 'pick' | 'done' | 'skip-similar' | 'skip-user' | 'skip-coupled'
UPDATE picks SET status='done', pick_order=<n> WHERE seq=<k>;   -- after a successful pick
SELECT seq, hash, subject FROM picks WHERE status='pick' ORDER BY seq;  -- remaining work
```

Seed it from `find-port-candidates.sh --sql`, then correct statuses as you review diffs.
This survives context summarisation and lets you resume mid-port.

---

## 6. Conflict-resolution patterns & gotchas (learned)

- **Prefer the target's structure.** When a pick conflicts because the target refactored a
  function signature or moved code, re-express the *intent* of the `integration` commit on
  top of the target's structure — do not drag the old structure back.
- **Gate on what the target gates on.** Example from the integration2 port: init-TDINFO /
  servtd code is gated on `policy_v2` on the target, not `all(vmcall-raw, policy_v2)`.
  Keep the target's gate.
- **Split partial picks.** A single `integration` commit often bundles a keeper + a part
  that's already upstreamed or out-of-scope. Cherry-pick with `-n`, then `git reset`/`git
  checkout -p` to stage only the keeper hunks. Note the split in the `picks.note`.
- **Combine related picks** when several `integration` commits implement one logical change
  (e.g. all "truncate long logs" tweaks) — fold them into one commit. Ask the user before
  combining if it's non-obvious.
- **Watch `git rerere`.** It can replay a *wrong* prior resolution (seen: a duplicate
  `igvm-attest` key injected into `Cargo.toml`). If a resolution looks off, `git
  checkout --conflict=merge <file>` and redo by hand; disable rerere before a big rebase if
  it has a bad cached resolution.
- **Dropping an obsolete commit** mid-stack: `git rebase --onto <sha>~1 <sha> <branch>`.
  Re-run the milestone tier afterward — a "clean" drop can still change behaviour.
- **Feature-build footguns**: migtd default feature is `virtio-vsock` (no `vmcall-raw`); lib
  tests with the `main` feature need `--lib` (bin `main` symbol clash, E0428); SPDM builds
  need `export SPDM_CONFIG="$(pwd)/config/spdm_config.json"` (the scripts set this). For the
  broader feature-gating map (which crates compile under which feature), see migtd-review
  `references/build-features.md`.

---

## 7. Commit message conventions

- Brief, precise, conventional-commit style subject (`type(scope): summary`).
- Add a **`Signed-off-by:`** trailer (DCO — upstream PRs require it). `git commit -s`.
- For AI-assisted work, add **`Co-developed-by:`** for the AI contribution (user preference).
- Cherry-picks: keep `git cherry-pick -x` (adds `(cherry picked from commit …)`) when the
  provenance is useful for an upstream PR; drop it when squashing/reworking.
- Keep PR branches single-purpose (one logical change per upstream PR), e.g. `hash_fix`,
  `spdm-rebind-error-propagation` — cherry-pick the relevant commit(s) onto a fresh
  `intel/main`-based branch rather than pushing the whole port.

---

## 8. References

- `references/port-playbook.md` — durable heuristics + the worked integration→integration2
  example (categories, counts, the specific keep/skip decisions and why).
- `scripts/find-port-candidates.sh` — keep/skip detection (patch-id + subject similarity).
- `scripts/port-verify.sh` — the after-every-pick gate (fmt + lib-test + fast emu).
- `scripts/fast-emu-check.sh` — 2-scenario emu smoke.
- `scripts/emu-milestone.sh` — 8-scenario emu checkpoint.
- migtd-review skill — trust model (§1), build features, and `run-ci-gauntlet.sh` for full
  CI parity (format + deny + 32 image builds + 14 emu).
