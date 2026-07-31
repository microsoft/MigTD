# MigTD agent guide

Rules for every AI-assisted change.

## Start here

- Read [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Read the relevant [knowledge files](.agents/knowledge/index.md).
- Use the [review playbook](.agents/skills/migtd-review/SKILL.md).
- Inspect cited commits before copying a pattern.
- Confirm the target checkout and branch.
- Leave sibling checkouts untouched.

## Security model

- Firmware is single-core and single-threaded.
- Rust is `no_std`.
- Async execution is cooperative.
- Treat interrupt-shared state separately.
- Treat the VMM as untrusted.
- Ignore findings that only give the VMM more DoS.
- Trust `MRTD` and `RTMR0..3`.
- Treat certificate chains as transport.
- The policy root CA is measured into RTMR.
- Trust `VERIFIED_POLICY` only after `init_policy()`.
- Regular migration uses quotes.
- Quote REPORTDATA starts at byte 520.
- Use `verify_report_data_binding`.
- Rebind uses TDREPORT.
- TDREPORT REPORTDATA starts at byte 128.
- Use `verify_tdreport_data_binding`.
- Never mix the two paths.
- `MROwner` is the policy signer key hash.
- `MROwnerConfig` is the policy SVN.
- Check local TDINFO during startup.
- Require the same signer during migration.
- Require source SVN to meet destination SVN.
- Resolve both the initial and current MigTD hashes through the authenticated
  source's verified one-hash mapping.
- Require the mapped initial SVN to be no greater than the mapped current SVN.
- Ignore the legacy wire Init_TDINFO after validating request framing.
- Keep `init_td_info` as the sole wire TDINFO field.
- Do not add redundant MigTD hash fields.
- Under `AzCVMEmu`, skip the local TDINFO check.
- Never upstream test-only security bypasses.
- Size-check every VMM-controlled byte range.
- Check `u32` offset arithmetic for wraparound.
- Use `#[repr(C)]` or explicit serialization at boundaries.
- `vmcall-raw` never returns `Ok(0)` or EOF.
- Per-buffer `data_status` filters broadcast wakes.
- Read [security bypasses](.agents/knowledge/security-bypasses.md).
- Read [domain facts](.agents/knowledge/domain-facts.md).

## Code changes

- Keep diffs small.
- Preserve existing names during functional work.
- Avoid unrelated cleanup.
- Format only touched files.
- Avoid `expect()` and `unwrap()` outside tests.
- Return errors.
- Prefer `LogErr` or `LogError`.
- Deduplicate only when reuse is real.
- Avoid one-use traits and macros.
- Do not add precautionary feature gates.
- Keep INFO logs sparse.
- Never dump full quotes, certs, or large blobs.
- Log length and short edge slices instead.
- Gate temporary diagnostics.
- Prove odd code is redundant before changing it.
- Preserve load-bearing workarounds.
- Keep their explanatory comments.
- Never grow a buffer to mask a bug.

## Setup and build

- Run `bash sh_script/preparation.sh` after:
  - a fresh checkout;
  - `git clean -fdx`;
  - a submodule update;
  - a branch switch that changes submodules.
- The script applies required `spdm-rs` patches.
- Missing patches can mimic baseline failures.
- Use repository build scripts.
- Treat CI commands as the source of truth.

## Tests and validation

- Run the smallest relevant checks first.
- Run `cargo fmt --check`.
- Run Clippy for the in-scope features.
- Deny warnings where required.
- Run tests for every touched crate.
- Run EMU tests for boundary changes.
- Boundary areas include:
  - event log and RTMR replay;
  - policy parsing and verification;
  - migration, handshake, and rebind;
  - SPDM transport;
  - crypto, certificates, and PEM;
  - vmcall transport.
- `cargo test` alone is insufficient there.
- Never run `migtdemu.sh` concurrently.
- It shares port, CPU, and output state.
- Before pushing code, run:

  ```bash
  .agents/skills/migtd-review/scripts/run-ci-gauntlet.sh
  ```

- Require every stage to pass.
- Stages: `prep`, `format`, `deny`, `main`, `emu`.
- Stop on failure.
- Fix the root cause.
- Resume from the failed stage.
- Do not skip failing checks.
- Documentation-only changes need no build or test.

## Workflow

- Keep independent fixes on independent branches.
- Confirm remote meaning from context.
- Prefer cherry-picking an existing upstream fix.
- Use `git rebase --onto` for targeted rebases.
- Resolve conflicts with minimal churn.
- Do not touch unrelated worktree changes.
- Do not track `.clawpatch/`.
- Do not track `.copilot-review-issues/`.
- Use `[Copilot Review]` for review issue titles.
- Check account permissions before filing issues.
- Under WSL, use Git or `gh` through their normal GitHub authentication flow.
  A successful `git push` proves the cached Windows Git Credential Manager
  credential is usable; do not query GCM directly and mistake an API prompt
  without GitHub's authentication challenge for a missing cache.

## Contribution and commits

- Follow [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Use `<type>(<crate/module>): <subject>`.
- Use `migtd` for repository-wide changes.
- Add a short body.
- Explain what changed and why.
- Keep each commit to one logical change.
- Use the configured human identity.
- Add the human DCO sign-off to every commit.
- Never sign off for an AI.
- Never name an AI in `Signed-off-by`.
- Never name an AI in `Co-authored-by`.
- Declare AI help with:

  ```text
  Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]
  ```

- List only material specialist tools.
- Omit Git, compilers, formatters, editors, and test runners.
- Push to a personal fork.
- Never force-push shared remotes.
- If rewriting, use:

  ```text
  --force-with-lease=<branch>:<known-sha>
  ```

## Knowledge upkeep

- Recheck the knowledge index at session end.
- Record durable, non-obvious learnings.
- Record human corrections.
- Record rejected hypotheses worth preserving.
- Correct stale guidance.
- Update the smallest relevant topical file.
- Cite a SHA, file, or test when useful.
- Explain removed guidance in the commit body.
- Keep task-specific state out of the knowledge base.
- Keep the decisions log append-only.
- Add new topics only when no current file fits.
- Add OKF frontmatter to new knowledge files.
- Link new files from `.agents/knowledge/index.md`.
- Link new files from `.agents/index.md`.
- Preserve knowledge before risky cleanup.
