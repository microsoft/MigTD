---
name: migtd-upstream
description: Upstream MigTD patches from Microsoft fork (origin/integration or origin/main) to Intel upstream (intel/main). Use when cherry-picking, grouping, rebasing, or filing PRs for upstream. Triggers on phrases like "upstream patches", "cherry-pick to intel", "create upstream PR", "upstream to intel/main".
---

# MigTD Upstream Workflow

Guidance for upstreaming production patches from the Microsoft MigTD fork
(`origin/integration`, `origin/main`) to Intel's upstream repository
(`intel/main`). Codifies the patch selection criteria, conflict resolution
strategies, PR grouping rules, and verification workflow.

---

## 1. Repository Layout

### Remotes

| Remote | URL | Purpose |
|--------|-----|---------|
| `intel` | `https://github.com/intel/MigTD.git` | Upstream target |
| `origin` | `https://github.com/haitaohuang/MigTD.git` | Personal fork (PRs filed from here) |
| `upstream` | `https://github.com/microsoft/MigTD.git` | Microsoft fork |

### Key branches

| Branch | Description |
|--------|-------------|
| `intel/main` | Upstream target — PRs merge here |
| `origin/main` | Microsoft fork main — production patches land here first |
| `origin/integration` | Microsoft integration branch — may contain REVERT_ME / debug patches |

### Upstream PR branches

Use the naming convention `upstream/pr<N>-<short-description>`:
```
upstream/pr1-trivial-fixes
upstream/pr2-quote-retry
upstream/pr2.5-misc-fixes
upstream/pr3-cert-chain-validation
```

---

## 2. Patch Selection Criteria

### INCLUDE (upstream these)

- **Bug fixes**: security, correctness, bounds checks, missing error handling
- **Refactoring**: code cleanup, deduplication, function extraction
- **Features merged to origin/main**: quote retry, cert chain validation, init-TDINFO verification
- **CI improvements**: test matrix additions, policy file generation
- **Build fixes**: compiler warnings, clippy fixes, feature-gate corrections

### EXCLUDE (do NOT upstream)

- **REVERT_ME commits**: debug scaffolding explicitly tagged for revert
- **`BC>` debug logging**: strip these lines when taking files from integration
- **`test-get-quote` feature**: test-only feature not for upstream
- **Microsoft-internal**: `.agents/`, `AGENT_NOTES.md`, fork-specific `.gitignore`
- **Reverted changes**: check `origin/main` history — if a patch was reverted, do NOT upstream it (e.g., interrupt flag loss fix `7245e53` was reverted by `3021675`)
- **Fork-specific cfg differences**: commits like "port PR #825 to Microsoft fork's cfg structure" that only exist because of fork divergence

### How to check if a change was reverted

```bash
git log --oneline origin/main --grep="revert" --grep="<keyword>" --all-match -i
```

---

## 3. Workflow Steps

### 3.1 Preparation

```bash
# Fetch all remotes
git fetch intel && git fetch origin && git fetch upstream

# Create upstream branch off intel/main
git checkout intel/main -b upstream/prN-description

# Identify commits to upstream
git log --oneline origin/integration --since="<date>" -- <path>
# Or compare two points:
git log --oneline <merge-base>..origin/integration
```

### 3.2 Cherry-Picking

Cherry-pick from the working branch (e.g., `upstream_intel_2`) where
conflicts have already been resolved, NOT from `origin/integration` directly
(which will re-trigger all conflicts):

```bash
# Pick in the order they appear on the resolved branch
git log --oneline --reverse upstream_intel_2 -- <path>
git cherry-pick <commit1> <commit2> ...
```

### 3.3 Conflict Resolution Strategy

When a commit has many conflict hunks (10+) and `origin/integration` already
contains all prior fixes, **take whole files from integration**:

```bash
git show origin/integration:<file> > <file>
sed -i '/BC>/d' <file>   # Strip debug logging
git add <file>
```

Then fix orphaned `log::info!()` / `log::error!()` calls left behind by
BC> removal. The pattern is a multi-line log macro whose format string was
the BC> line — after removal, only the argument list remains:

```rust
// BROKEN (format string was a BC> line, now deleted):
log::info!(
    some_var.len()
);

// FIX: delete the entire log::info!(...) block
```

Use this Python snippet to fix all at once:
```python
import re
pattern = r'    log::(info|error)!\(\n((?:        [^\"].*\n)*?)    \);\n'
content = re.sub(pattern, '', content)
```

### 3.4 Three-Way Verification

After cherry-picking, verify every changed file matches `origin/integration`
(minus expected exclusions like BC> lines):

```bash
for f in $(git diff --name-only intel/main..HEAD | grep "^src/"); do
  diff_out=$(diff <(git show HEAD:"$f") <(git show origin/integration:"$f") 2>&1)
  if [ -n "$diff_out" ]; then
    lines=$(echo "$diff_out" | wc -l)
    echo "DIFFERS ($lines lines): $f"
  else
    echo "MATCH: $f"
  fi
done
```

**Acceptable differences**: BC> debug lines, REVERT_ME blocks, `test-get-quote`
feature, debug threshold overrides (e.g., `LOG_TRUNCATE_THRESHOLD` doubled).

**Unacceptable differences**: any production logic not present on integration.

### 3.5 Build Verification

All three feature combinations must compile:

```bash
# Full features
cargo build -p migtd --target x86_64-unknown-none --no-default-features \
  --features main,vmcall-raw,policy_v2,spdm_attestation --profile release

# TLS only
cargo build -p migtd --target x86_64-unknown-none --no-default-features \
  --features main,vmcall-raw,policy_v2 --profile release

# Minimal
cargo build -p migtd --target x86_64-unknown-none --no-default-features \
  --features main,vmcall-raw --profile release
```

### 3.6 EMU Test Gauntlet

```bash
bash .agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --only emu
```

---

## 4. PR Grouping Strategy

### Principles

1. **Minimize cross-PR dependencies** — independent PRs can be reviewed/merged in parallel
2. **Group tightly-coupled changes** — if commit B doesn't compile without commit A, they go in the same PR
3. **Separate trivial from complex** — easy-to-review fixes go in an early PR to build reviewer trust
4. **Respect the merge order on origin/main** — if a series was merged as one PR on the fork, keep it together

### Dependency detection

Check if commits can stand alone by cherry-picking onto `intel/main` and building.
Common dependency signals:
- Shared files (especially `spdm_req.rs`, `spdm_rsp.rs`, `session.rs`, `rebinding.rs`)
- Import of symbols added by other commits (`TD_INFO_SIZE`, `local_peer_data()`, etc.)
- Refactoring that restructures function signatures used by later commits

### Stacking vs independent

- **Independent**: each PR branch is based on `intel/main` directly
- **Stacked**: PR branch is based on a prior PR branch

Prefer independent when possible. Use stacking only when code dependencies
make independence impossible. For stacked PRs, rebase the later PR when
the earlier one merges.

### PR ordering

Submit in dependency order. Example:
```
Wave 1 (parallel): PR1 (trivial), PR2 (quote retry)
Wave 2:            PR2.5 (misc fixes, on PR2)
Wave 3:            PR3 (cert chain, on PR2.5)
```

---

## 5. Commit Message Conventions

- Use conventional commit format: `type(scope): description`
  - Types: `fix`, `feat`, `refactor`, `security`, `test`, `chore`, `ci`
  - Scope: the crate or module (`vmcall_raw`, `spdm`, `attestation`, `ci`)
- Include `Signed-off-by:` trailer
- Include `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>` when appropriate
- Amend messages to match conventions: `GIT_SEQUENCE_EDITOR="sed -i 's/^pick <sha>/edit <sha>/'" git rebase -i <base>`

---

## 6. Common Pitfalls

### Cargo.lock conflicts

Cherry-picks often conflict on `Cargo.lock`. Resolution:
```bash
git checkout --theirs Cargo.lock && git add Cargo.lock
```
If that doesn't work, stash, continue, and amend.

### Empty cherry-picks

When taking whole files from integration, subsequent commits in the same
series may be empty (changes already present). Skip them:
```bash
git cherry-pick --skip
```

### Submodule / .agents staging

`.agents/` keeps getting staged. Exclude it:
```bash
echo ".agents/" >> .git/info/exclude
```

### Build errors after BC> removal

`sed -i '/BC>/d'` can break multi-line `log::info!()` calls. Always build
after stripping and fix orphaned log macros.

### Feature-gated code visibility

Some commits touch code behind `#[cfg(feature = "policy_v2")]` or
`#[cfg(all(feature = "vmcall-raw", feature = "policy_v2"))]`. A commit
may build with one feature set but fail with another. Always test all
three feature combinations.

---

## 7. Lessons Learned

1. **Don't upstream reverted patches** — always check `origin/main` for
   reverts before including a commit. The interrupt flag fix (`83aecba`)
   was included then had to be dropped after discovering the revert.

2. **Commits authored on a full integration branch can't easily be separated**
   — the SPDM refactoring, peer_data encoding, and init-TDINFO verification
   commits are deeply intertwined. Accept that some PRs will be large.

3. **Take whole files from integration for large conflicts** — when a commit
   has 30+ conflict hunks, manual resolution is error-prone. Taking the
   integration version and stripping debug lines is faster and more reliable.

4. **Three-way comparison is essential** — after every cherry-pick batch,
   diff against `origin/integration` to catch unintended changes.

5. **Don't include logging truncation changes** — the integration branch has
   doubled thresholds for debugging (REVERT_ME tagged). Keep production values.

6. **`origin/main` is the source of truth for what's been reverted** — not
   `origin/integration`, which may still contain pre-revert code.
