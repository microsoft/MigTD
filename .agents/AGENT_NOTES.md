# Agent Notes — MigTD

**Read this before doing anything in this repo.** These are facts and
conventions that have had to be repeated across many sessions by past
contributors. Adopting them up-front avoids rounds of correction.

The authoritative deep reference is `.agents/skills/migtd-review/SKILL.md`.
This file is the **cross-cutting TL;DR + workflow rules** that aren't
review-specific.

> **Living document.** This file is intended to accumulate institutional
> knowledge over time, contributed by both human collaborators and AI agents.
> See §12 ("Reflect and update") at the bottom — every agent should reread
> these notes at session start and propose updates at session end if something
> non-obvious was learned.

> **Concurrency note:** Multiple agents (and humans) may be working on this
> repository simultaneously, sometimes from sibling clones (e.g. a `MigTD2`
> directory next to `MigTD`). **Treat code changes as potentially racing.**
> This notes file, however, can be edited safely from any one agent at a time
> — it doesn't conflict with code work. If you're not the agent in charge of
> the current code task, restrict yourself to this notes file. Keep a backup
> of this file in your session-state folder to survive `git clean -fdx`.

---

## 1. Commit hygiene

- **Always commit with `git commit -s`** (or manually add the
  `Signed-off-by:` trailer using the current `git config user.name` and
  `user.email`). The project requires DCO sign-off on every committable
  change **except** debug-only or `REVERTME` test commits.
- Use the existing repo identity — do not invent a different author. If the
  Copilot `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`
  trailer is appropriate for your environment, include it **in addition to**
  the human Signed-off-by, not instead of it.
- **Commit message style: brief.** One short subject line stating the
  problem, then a short body describing the high-level solution. Skip filler
  like "no behavioural changes" boilerplate unless it materially helps a
  future reader.
- **Don't bundle unrelated changes** into one commit. Separate:
  - behaviour change vs refactor → two commits (or `fixup`/`squash` later);
  - pre-existing fmt/lint fix vs your fix → standalone commit with a
    "pre-existing; not caused by this series" note.
- **Fold/squash freely with `git rebase -i`** (`fixup` for "absorb and drop my
  message", `squash` for "absorb and keep my message"). This is requested
  often during cleanup.
- **Force-push** only to a personal fork remote (e.g. `origin`), and only
  with `--force-with-lease=<branch>:<known-sha>`. Never force-push to
  `intel/*` or `ms/*` / `upstream/*` remotes.

## 2. Remotes & branches

Typical remote layout in active checkouts:

```
intel    https://github.com/intel/MigTD.git        # Intel upstream
ms       https://github.com/microsoft/MigTD.git    # Microsoft fork
upstream https://github.com/microsoft/MigTD.git    # alias for ms
origin   https://github.com/<personal>/MigTD.git   # personal fork (push target)
```

- "Upstream" in conversation usually means **`intel/main`** when discussing
  Intel-bound patches, and **`microsoft/main`** (a.k.a. `ms/main` /
  `upstream/main`) when discussing the Microsoft fork. Confirm by context.
- **Microsoft-specific features kept out of Intel-bound patches** include
  `use-mock-quote`, AzCVMEmu emulation, and allow-all policy. Consult the
  upstream-merge skill (commonly under `.github/skills/migtd_upstream_patches`
  in a sibling clone) when rebasing toward Intel.

## 3. Mandatory setup after fresh checkout / submodule update / `git clean`

```bash
bash sh_script/preparation.sh
```

This applies the `spdm-rs` patches to `deps/td-shim/library/ring`
(`EphemeralPrivateKey::to_bytes`, `digest::serialize`). **Skipping it
produces build errors that look like a real baseline regression but
aren't.** CI runs it automatically; **locally you must run it manually**
after:

- a fresh clone,
- `git clean -fdx`,
- any `git submodule update`,
- switching to a branch with different submodule SHAs.

## 4. Verification — all four CI workflows MUST pass, no exceptions

The project standard is that **every test in every workflow passes** before a
change is considered done. Use the gauntlet script as the standard pre-push
verification:

```bash
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --list
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --from main   # resume
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --only emu    # one stage
```

Stages mirror the four workflows: **format → deny → main → emu** (after
`prep`). The script stops at the first failure. **Fix the root cause; don't
skip ahead.**

`cargo test` alone is **not sufficient** for changes to:

- `event_log` / RTMR replay
- policy parsing / verification (`policy/src/v2/`, `mig_policy.rs`)
- migration session / handshake / rebind paths
- SPDM transport (`src/spdm/`)
- crypto / cert / PEM parsing (`src/crypto/`)
- any vmcall transport

For those, **always** run the EMU integration tests (full or a relevant
subset via `./migtdemu.sh`).

### Common single-scenario EMU invocations

```bash
./migtdemu.sh --skip-ra --both --no-sudo --log-level info
./migtdemu.sh --features spdm_attestation --skip-ra --both --no-sudo --log-level info
./migtdemu.sh --operation rebind-prepare \
    --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
    --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
    --skip-ra --both --no-sudo --log-level info
./sh_script/build_AzCVMEmu_policy_and_test.sh --mock-report   # full matrix
```

**Do not run multiple `migtdemu.sh` invocations concurrently** — it hardcodes
TCP port 8001, pins to `taskset -c 0`, and writes a shared `target/release/migtd`
artefact.

## 5. Domain facts to internalise before flagging anything as a bug

### Trust model
- Single-core, single-threaded `no_std` Rust firmware. No `Sync`/`Send`
  races except via interrupts.
- **VMM is untrusted but can DoS.** DoS-via-VMM is *not* a finding.
- **Root of trust = `MRTD` + `RTMR0..3`** (attested). Cert chains are
  transport; the Root CA for `policy_v2` is itself measured into RTMR.
- After `mig_policy::init_policy()` succeeds, `VERIFIED_POLICY` is trusted.

### Rebind vs Migration attestation — DIFFERENT verifiers
- **Regular migration** → uses **quotes**. REPORTDATA at byte offset **520**.
  Helper: `verify_report_data_binding`.
- **Rebind** → uses **TDREPORT** (no quote). REPORTDATA at byte offset
  **128**. Helper: `verify_tdreport_data_binding`.
- **Mixing them = bug.** See commit `94975ec` (TH1 binding fix).

### TDINFO / MROwner / MROwnerConfig semantics
- **MROwner** = hash of the policy signer's public key.
- **MROwnerConfig** = MigTD policy SVN (a.k.a. "migtd svn").
- Each MigTD checks on startup that its **own** TDREPORT's `MROwner` matches
  the policy signer it has, and `MROwnerConfig` matches its policy SVN.
- For migration / rebind: destination verifies, using the report received
  from source, that source's `MROwner` == destination's (same signer) and
  source's `MROwnerConfig` >= destination's (i.e. dest SVN ≤ source SVN).
- The wire field carrying source's TDREPORT-derived init info is
  **`init_td_info`** (raw 512-byte `TdInfo`). It is the **only** thing the
  spec requires — there is **no separate** `init_migtd_data` /
  "init migtd hash" / `mig_policy_init_hash_src` blob. If you see one being
  added, push back. Past sessions removed those redundancies; merges from
  Intel occasionally re-introduce them.
- Under the **`AzCVMEmu`** feature, **skip the `verify_own_tdinfo()`
  MROwner/MROwnerConfig check** rather than emulating it via env vars. The
  env-var emulation approach was tried (commit `8ce39a3`) and abandoned as
  "too much to maintain". Current pattern: feature-gate-skip on `AzCVMEmu`.
- Existing `REVERTME` commits typically bypass MROwner/MROwnerConfig checks
  because the host isn't ready to plumb them through; these are test-only
  and must be reverted before upstreaming.

### vmcall / transport invariants
- `vmcall-raw` **never returns `Ok(0)` / EOF**. It blocks until data or
  error. "What if VMM returns 0 bytes?" is already defended at the transport
  layer.
- Each migration session has its own shared buffer with **`data_status` as
  ground truth**. Broadcast interrupt wakes are filtered by the per-buffer
  status check — correct by design.

### Heap allocator
- `ATTEST_HEAP_SIZE` is currently **2 MiB**. It was bumped from 512 KiB after
  commit `3c44ea9` removed the `LOCAL_TCB_INFO` cache, raising per-migration
  `verify_quote_integrity_ex` calls from 2 → 4 in TiP loopback; the 3rd call
  exhausted the old heap (#UD inside the C verifier).
- The C verifier (`verify_quote_integrity_ex` from Intel DCAP `servtd_attest`)
  uses **SgxSSL libcrypto** internally — host-glibc-libcrypto repro tools
  **under-report** heap pressure. Host repros must link the same allocator
  (tlibc dlmalloc/sbrk) and the same libcrypto (SgxSSL) as the in-image build.
- Single-thread heap **does** reuse freelists across calls; "leak across
  calls" was rejected as a hypothesis. The 2 MiB bump is the accepted answer.

### Rejected hypotheses — do not reopen without strong new evidence
- **Singleton GetQuote vector hijacking MigTD vector**: host VMM team
  definitively rejected this. `GhciRequestContext` omits
  `NotificationInterrupt` by spec; Send/Receive vectors are re-supplied each
  call. Don't propose fixes founded on this hypothesis.

## 6. Code style preferences

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
    multi-second stalls on TiP.
  - When adding diagnostic logs, gate behind explicit verbosity OR commit
    them as a clearly-named debug/diag commit that can be dropped later.
- **Don't fix code that "looks redundant" without proving it.** Canonical
  cautionary tale: `event_log::get_event_log()` returns `&raw[..size + 1]`;
  removing the `+1` (commit `bc99fa4`) passed unit tests but broke EMU
  integration. The `+1` is a load-bearing workaround for an upstream
  `cc_measurement` bug. See SKILL.md §1.

## 7. Common workflow patterns

- **Rebase onto upstream**: "rebase changes from `<SHA>` onto
  `origin/<branch>`. Discard changes already on that branch." Use
  `git rebase --onto`.
- **Cherry-pick from `intel/main` to simplify**: when bringing in fixes from
  Intel, prefer cherry-pick over re-implementation if the change is small.
- **Squash/fold during cleanup**: commits are often named by target SHA
  ("fold into `<sha>`", "fixup for `<sha>`"). Use `git rebase -i` with
  `fixup` / `squash`.
- **Reference-by-commit**: when a specific SHA is cited as a template, read
  that commit's diff before re-implementing.
- **Resume from a previous session checkpoint**: the session_store DB has
  `checkpoints` keyed by session title — search there.
- **TiP logs come from Windows**: paths like `C:\Users\<user>\Downloads\…`
  translate to `/mnt/c/Users/<user>/Downloads/…` under WSL.

## 8. Issue / PR filing

- GH issue title prefix: **`[Copilot Review]`** (not `[Security]` — not all
  findings are security).
- **Microsoft EMU (Enterprise Managed User) GH accounts cannot create
  issues on external repos.** Use a personal GH account via
  `gh auth login --hostname github.com --web`. Verify with `gh auth status`
  before running any issue-creation script.
- `gh issue close --reason "not planned"` (literal space, *not*
  `not_planned`).
- See `.agents/skills/migtd-review/scripts/create_review_issues.sh` for the
  template.

## 9. Things to NOT do (collected from past pushback)

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

## 10. Quick checklist before "I'm done"

1. `bash sh_script/preparation.sh` ran since last submodule change?
2. `cargo fmt --check` clean (only your touched files)?
3. `cargo clippy ... -- -D warnings` clean on in-scope features?
4. `cargo test` clean for crates you touched?
5. EMU tests run for boundary-code changes (event_log, policy, crypto, spdm,
   vmcall)?
6. All four CI workflows pass via `run-ci-gauntlet.sh`?
7. Every committable change is `-s` signed-off (excluding debug / `REVERTME`)?
8. Commit messages brief and accurate (problem + high-level solution)?
9. No unrelated changes piled into one commit?
10. Pushed only to a personal fork remote (`--force-with-lease` if rewriting)?

---

## 11. Decisions made

Record here concrete, non-obvious engineering *decisions* (feature/commit
kept vs. dropped, and why) — as opposed to sections 5/9 above, which are
domain facts and anti-patterns. This is a decision log, not a design doc:
keep entries to a sentence or two, cite the commit/SHA that acted on the
decision.

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

## 12. Reflect and update these notes

**Every agent must reread this file at session start, and reflect on it at
session end.** If during the session you:

- got corrected by a human collaborator on something that wasn't already
  written here,
- discovered a non-obvious architectural fact (especially one that
  contradicts a naive reading of the code),
- identified a rejected hypothesis worth recording,
- learned a workflow shortcut, repo-specific gotcha, or environment
  requirement,
- found that an entry here is now stale or wrong,

…then **update this file as part of your session output** (a separate small
commit, with sign-off, is fine — message it as `docs(agents): …`). Keep
edits lean:

- Add the smallest faithful note, not an essay.
- Cite a commit SHA, file:line, or test name when it helps a future reader
  verify the claim.
- If you remove an entry, briefly note why in the commit message — it
  protects against thrashing.
- Prefer editing existing sections over inflating new ones; the file should
  remain skimmable.
- If a fact is highly task-specific or temporary (e.g. "for the current PR,
  skip X"), it does **not** belong here — keep it in your session state.

If a backup mechanism is available in your environment (e.g. a session-state
folder outside the repo), keep a copy of this file there before any risky
operation like `git clean -fdx`.

The goal: a newcomer agent reading this file should be able to skip the
classes of mistakes their predecessors have made.
