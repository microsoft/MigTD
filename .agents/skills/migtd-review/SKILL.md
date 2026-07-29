---
name: migtd-review
description: Security and correctness review of the Intel MigTD codebase (TDX migration TD firmware, Rust no_std). Use when reviewing MigTD source code, triaging clawpatch findings, filing GitHub issues for review findings, or running local EMU integration tests. Triggers on phrases like "review MigTD", "audit MigTD", "triage MigTD finding", "MigTD code review", "review code in intel/MigTD".
---

# MigTD Code Review

Domain-specific guidance for reviewing the Intel MigTD codebase. Codifies the trust model, build-feature scope, common false-positive patterns, lessons learned from previous reviews, and the verification workflow.

---

## 1. High-Level View (read this FIRST)

Most failed/regressed "fixes" in this codebase trace back to skipping this section. Internalize these properties before flagging anything.

### Execution model

- **Single-core, single-threaded `no_std` Rust firmware**. No `Sync`/`Send` races within one TD. There is no preemption between non-interrupt code paths.
  - Do **not** flag missing locks, atomics, or `Send` bounds unless an interrupt handler mutates shared state.
- **Heap is ~7 MiB**, bump-allocator behaviour for some paths. Out-of-memory is recoverable but rare.
- **Async runtime is cooperative** (`async_runtime` crate, single-threaded executor). Futures run to suspension; "races" between awaits are not races in the classical sense.

### Trust model

- **VMM is untrusted but has inherent DoS capability** — it can starve the TD, stall vmcalls, drop packets, withhold cycles, or kill the TD. **DoS-via-VMM is NOT a finding.** Do not file issues that boil down to "the VMM could refuse to make progress".
- **Root of trust = hardware attestation registers**: `MRTD` and `RTMR0..RTMR3`. The QE/PCK chain is a transport, not the root.
  - Policy-v2 signer identity is attested through the **RTMR1 signer anchor**
    (root-certificate fingerprint + enrolled signer-purpose EKU), not raw
    issuer-chain bytes or leaf Subject Name.
- **Trusted-after-init**: `mig_policy::init_policy()` verifies the RTMR2-bound
  policyData plus its inner JSON/CoRIM endorsements and freezes
  `VERIFIED_POLICY`. The legacy outer policy signature is ignored.
- **Two distinct attestation paths**:
  - *Regular migration* → uses **quotes**. REPORTDATA at byte offset **520**. Helper: `verify_report_data_binding`.
  - *Rebind* → uses **TDREPORT** (no quote). REPORTDATA at byte offset **128**. Helper: `verify_tdreport_data_binding`.
  - **Mixing the two = bug.** Always trace which helper is called from each rebind/migration code path. See commit `94975ec` for the TH1 binding fix.

### Boundary surfaces (where bugs actually live)

- The **vmcall transports** (`vmcall-raw`, `virtio-vsock`, etc.): every byte coming from VMM must be size-checked. Wrap-around arithmetic on `u32` offsets is a real risk; integer overflow on `u64` is generally not exploitable on 64-bit.
- **TLS-over-vmcall** in `crypto/`: certificate parsing, ASN.1, PEM. Look for slice indexing, `find()` ordering, and PEM block delimiters.
- **Policy parsing/verification** in `policy/src/v2/`: JSON/CoRIM decoding,
  RTMR1 anchor binding, PEM/x5chain handling, and one-hash lookups.
- **Event log / RTMR replay** in `migtd/src/event_log.rs` and upstream `cc-measurement`: bounds checks, off-by-ones, RTMR replay correctness.
- **FFI / over-the-wire structs**: anything sent between source and destination MigTDs or exchanged with td-shim must be `#[repr(C)]` (or explicitly serialised).

### What looks like a bug but isn't

- "VMM can supply OOB buffer offsets" → each migration ctx has its own shared buffer with `data_status` as ground truth.
- "`vmcall-raw` read returns 0 → infinite loop" → the transport blocks until data or error; it **never returns Ok(0)/EOF**.
- "Interrupt broadcast wakes all migrations" → per-buffer `data_status` check filters spurious wakes (correct by design).
- "TSC division by zero in calibration" → pre-conditioned by CPUID/feature detection on real hardware.
- "Unbounded heap allocation in peer-info parse" → bounded by mig session size limits and the 7 MiB heap. DoS only.
- "`ecdsa_sign` PKCS8 panic" → dead code; no callers in the production binary.
- "Missing `#[repr(C)]` on `ExchangeInformation`" → dead code behind `#[cfg(not(feature = "spdm_attestation"))]` in the in-scope build.
- "Misspelled identifier" → fix only if user-visible; do not churn internal names.

### Patterns that look like style fixes but are actually load-bearing

This is the most important class to internalise. **Do not "clean up" code that looks redundant without first proving it is redundant.**

- **`event_log::get_event_log()` returns `&raw[..size + 1]`**, not `&raw[..size]`. The `+1` looks like an off-by-one but is a deliberate workaround for a bug in upstream `cc_measurement::log::CcEvents::next()` (uses `<` instead of `<=`), which silently drops the last event when the slice ends exactly at the last event boundary. The runtime CCEL area is zero-padded so the extra byte is safe. **Removing the `+1` breaks AzCVMEmu integration tests** (lost policy tag → `Failed to initialize migration policy`). Upstream issue: <https://github.com/confidential-containers/td-shim/issues/848>. Regression test: `event_log::tests::last_event_visible_only_with_trailing_padding`.
- **Comments documenting workarounds are mandatory**. If you find code that does something odd without a comment, add the comment before considering changing the code.
- **CI history is the source of truth for "what broke when"**. If a regression appears, find the breaking commit via `git bisect` or by reading CI run history; do not guess from local symptoms (which may be masked by other environment issues — see §6).

### Why these matter

A previous review pass produced a "fix" (`bc99fa4`) that removed the `+1`, passed cargo fmt/clippy and the host-runnable unit tests, but silently broke the EMU integration tests. The breakage was not caught until CI history was inspected. The lesson: **passing `cargo test` is not sufficient evidence of correctness for changes that touch boundary code; always run the EMU integration tests after every behavioural change.**

---

## 2. Codebase essentials

- **MANDATORY first step after fresh checkout / submodule update**: run `bash sh_script/preparation.sh`. This:
  1. Invokes `deps/td-shim/sh_script/preparation.sh` (td-shim's own prep).
  2. Applies the spdm-rs ring patches (`0003-introduce-EphemeralPrivateKey-serialization.patch` and `0004-Introduce-digest-de-serialization.patch` from `deps/spdm-rs/external/patches/ring/`) to `deps/td-shim/library/ring`. MigTD's workspace-level `[patch.crates-io]` selects this ring copy, not spdm-rs's copy. The patches add `EphemeralPrivateKey::export_private_key_bytes`/`from_private_key_bytes` and `digest::Context::to_bytes`/`from_bytes`, which spdmlib needs to preserve intermediate SPDM context.
  3. Runs `deps/spdm-rs/sh_script/pre-build.sh`.
  CI does this automatically via `.github/actions/setup-build-environment` (default `run-preparation: true`). Locally you MUST run it manually after any `git clean -fdx`, `git submodule update`, or fresh clone. Failing to run it produces build errors that look like a real baseline regression but are not. See [`doc/dependency_preparation.md`](../../../doc/dependency_preparation.md) for the dependency-resolution rationale.
- **Build profiles vary**. Always confirm scope before flagging code as buggy. Default in-scope set used during the audit:
  - `vmcall-raw, stack-guard, main, vmcall-interrupt, oneshot-apic, spdm_attestation, igvm-attest, policy_v2`
  - `policy_v2` pulls in `policy/policy_v2` + `attestation/attest-lib-ext`.
  - **Out of scope in that profile**: `virtio-serial`, `virtio-vsock`, `vmcall-vsock`, `fuzz`, `AzCVMEmu` runtime (the host-side emu harness is separate from the in-firmware build).
- **Always in tree** (regardless of features): `virtio`, `pci`, `crypto` (rustls enabled by default).
- **Build (production image)**:
  ```bash
  cargo image --features main,vmcall-raw,stack-guard,vmcall-interrupt,oneshot-apic,spdm_attestation,igvm-attest,policy_v2
  ```
  - The xtask sets release/debug profile internally — do **not** pass `--release`.
- **Build (AzCVMEmu host harness)**: see §6.
- Bigger build cmd (matrix): `.github/workflows/main.yml`.
- Architectural facts:
  - `ring::pkcs8::Document` in **this fork** is stack-inlined `[u8; 185]` + `len`, NOT heap-allocated → `sensitive_data_cleanup` works as intended.
  - `verify_quote_integrity_ex` is a C-library built from source as a submodule.
  - Policy v2 supports a JSON servTD-collateral path (PEM chain derives the
    RTMR1 anchor) and a CoRIM-only path (direct 48-byte anchor + signed
    TCB-mapping CoRIM). The outer JSON policy signature is legacy/ignored;
    mapping/identity or CoRIM signatures must bind to the same root+EKU anchor.

---

## 3. Common false-positive patterns

| Pattern | Why it's usually NOT a bug |
|---|---|
| "VMM can supply OOB buffer offsets" | Each migration ctx has its own shared buffer; `data_status` is ground truth. Wrap arithmetic on `u32` offsets is checked. |
| "Shared log circular buffer overflow" | Wrapping logic keeps offsets in bounds; VMM is reader, not writer. |
| "vmcall-raw read returns 0 → infinite loop" | The `vmcall-raw` transport blocks until data or error; **never returns 0/EOF**. |
| "Interrupt broadcast wakes all migrations" | Spurious wakes are caught by per-buffer status check (correct by design). |
| "Cert chain weakness in attestation/SPDM verifier" | The root+signer-EKU anchor is measured into RTMR1; chain compromise alone is insufficient unless it can produce a chain under that anchor and evade revocation. |
| "TSC div-by-zero in calibration" | Pre-conditioned by CPUID/feature detection on real HW. |
| "Unbounded heap alloc in peer-info parse" | Bounded by mig session size limits + 7 MiB heap → just DoS. |
| "Misspelled identifier" | Fix only if user-visible; don't churn the codebase for internal names. |
| `ecdsa_sign` PKCS8 panic | Dead code — no callers in the production binary. |
| `ExchangeInformation` missing `#[repr(C)]` | Dead code behind `#[cfg(not(feature = "spdm_attestation"))]` in this build. |

---

## 4. Known real bug patterns

Fixes already merged that double as templates for what *real* bugs look like:

1. **Match-arm fallthrough** in `match … { _ => { … } }` blocks where caller expects early return → check every arm for explicit `return` (see `poll_vmcall_completion`, commit `ed80789`).
2. **Missing `#[repr(C)]`** on FFI / serialized-over-the-wire structs → see `HelloPacketPayload` (commit `a277723`).
3. **Wrong field used for crypto-algorithm lookup**: `cert.signature_algorithm` (the signer's algorithm) vs `cert.tbs_certificate.subject_public_key_info.algorithm` (the subject's algorithm used to verify the cert *under* the subject's pub key) → commit `70872c0`.
4. **PEM search order**: `find(END)` before `find(BEGIN)` allows END before BEGIN → search for END *after* BEGIN's end-index (commit `dfb449c`).
5. **Missing TH1 binding on SPDM rebind path**: rebind uses `TDREPORT` (REPORTDATA at offset **128**), regular migration uses quotes (REPORTDATA at offset **520**). They need distinct verification helpers (`verify_tdreport_data_binding` vs `verify_report_data_binding`). See commit `94975ec`.

---

## 5. The verification cycle (DO THIS AFTER EVERY FIX)

A fix is not done until **all of these pass — every test in every CI workflow, no exceptions**. The user explicitly requires this. The order matters — fastest feedback first.

### Local quick gate (must all be green before pushing)

```bash
# 0. Preparation (skip only if you've already run it since last submodule update)
bash sh_script/preparation.sh

# 1. Format check (instant)
cargo fmt --check

# 2. Clippy on the in-scope feature set
cargo clippy --workspace --all-targets \
    --features main,vmcall-raw,stack-guard,vmcall-interrupt,oneshot-apic,spdm_attestation,igvm-attest,policy_v2 \
    -- -D warnings

# 3. Host-runnable unit tests for the crates you touched (seconds)
cargo test -p migtd --lib <module_you_touched>
# e.g.: cargo test -p migtd --lib event_log
# e.g.: cargo test -p crypto

# 4. EMU integration tests (minutes) — REQUIRED for any change to:
#    - event_log / RTMR replay code
#    - policy parsing or verification
#    - migration session / handshake / rebind paths
#    - SPDM transport
#    - crypto / cert / PEM parsing
#    - any vmcall transport
./sh_script/build_AzCVMEmu_policy_and_test.sh --skip-test  # build first
./sh_script/build_AzCVMEmu_policy_and_test.sh              # then full test run
# OR run individual scenarios via ./migtdemu.sh (see §6).
```

### Full CI parity (all four workflows MUST pass — no exceptions)

The user has stated **every test in every workflow must pass**. The reusable gauntlet script automates this — use it as the standard pre-push verification:

```bash
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh
```

It runs the four CI workflows in the order `prep → format → deny → main → emu` and **stops at the first failure** with the failing command, the path of the captured log, and a resume hint (`--from <stage>`). Logs land under `target/ci-gauntlet/`. Total wall-clock is ~30 min cold, much less on warm caches.

```bash
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --list           # list stages
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --from main      # resume from main
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --only emu       # single stage
```

When the gauntlet fails, **fix the root cause first, then re-run from the failing stage** — do not skip ahead. The script intentionally bails so a review agent (or you) has time to read the log, propose a minimal fix, and re-verify before continuing.

What each stage covers (the commands the script runs are the source of truth):

| Workflow | Stage | What it runs |
|---|---|---|
| `.github/workflows/format.yml` | `format` | `cargo fmt -- --check`, `cargo check`, `cargo clippy --features stack-guard,virtio-vsock,virtio-serial,vmcall-interrupt` (no `-D warnings`) |
| `.github/workflows/deny.yml` | `deny` | `cargo deny check advisories`, `cargo deny check sources` (continue-on-error), `cargo deny check bans` |
| `.github/workflows/main.yml` | `main` | 32 `cargo image` builds = 4 devices × 2 policy_versions × 2 protocols × 2 build_types |
| `.github/workflows/integration-emu.yml` | `emu` | CoRIM-only policy build/tests plus 17 EMU scenarios mirroring the workflow matrix exactly, including both signed-CoRIM flows, explicit pre-builds, and the fail-closed revoked-signer policy test |

**Note**: the format.yml clippy step uses a *different* feature set than the in-scope set above (`stack-guard,virtio-vsock,virtio-serial,vmcall-interrupt`). Both must compile cleanly; the former is what runs in CI and gates merges.

**Why step 4 is mandatory**: passing `cargo test` is not sufficient evidence of correctness for boundary code. Unit tests in `migtd` exercise small, controlled inputs; many real bugs only surface when the full source ↔ destination migration handshake replays the event log, parses a real signed policy, or extends RTMRs. The bc99fa4/event_log regression is the canonical example — host unit tests passed; EMU integration tests failed loudly.

If `cargo image` succeeds (full TDX firmware build) that's a strong signal the change at least compiles for the no_std target, but it does not exercise runtime behaviour. The EMU harness does.

### EMU test failure debugging order

If an EMU test fails after a fix:

1. **First**: check the CI run history on GitHub to see whether the same test passes for an unrelated commit on `main`. If `main` is also failing the test in CI, the failure is pre-existing (environment, OpenSSL, runner image) — see §6.
2. **Then**: `git bisect` (or scan recent commits) to find the breaking commit. The narrative "my fix broke it" is often correct; the narrative "the failure is unrelated" is often wrong.
3. Only after you have a specific breaking commit, reason about *why* — typically by reading the diff in light of §1.

---

## 6. Running EMU integration tests locally

Prerequisites: Rust 1.88.0, nasm, clang, libtss2-dev, pkg-config, jq, and `bash sh_script/preparation.sh` has been run (see §2). On a fresh host, install the full toolchain in one shot with `./sh_script/setup_build_env.sh` (single `sudo apt-get install` + rustup/toolchain/`x86_64-unknown-none`; `--print-apt` shows just the apt one-liner).

Working tests on Ubuntu 24.04 (skip-RA paths):

```bash
./migtdemu.sh --skip-ra --both --no-sudo --log-level info
./migtdemu.sh --operation rebind-prepare \
    --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
    --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
    --skip-ra --both --no-sudo --log-level info
./migtdemu.sh --skip-ra --features spdm_attestation --both --no-sudo --log-level info
```

Full test matrix script (mirrors `.github/workflows/integration-emu.yml`):

```bash
./sh_script/build_AzCVMEmu_policy_and_test.sh --mock-report
```

### Policy file gotcha — `EXPLICIT_POLICY_FILE`

- `config/AzCVMEmu/policy_v2_signed.json`, `config/AzCVMEmu/policy_v2_raw.json`, and `config/AzCVMEmu/policy_issuer_chain.pem` are **tracked in git**. CI starts every job from a clean `actions/checkout`, so these are always present.
- `migtdemu.sh` only auto-generates policy files when `EXPLICIT_POLICY_FILE != true` *and* `SKIP_POLICY_GENERATION != true` (see `migtdemu.sh:452`). Passing `--policy-file` sets `EXPLICIT_POLICY_FILE=true`, which **disables** auto-generation. So if you `git clean -fdx` (or otherwise delete the tracked policy files), then run with `--policy-file`, you'll get `Error: Source Policy file not found: …`. Restore them with `git checkout config/AzCVMEmu/` and re-run.
- The key-rotation policy files (`policy_v2_signed_a/b/pm_b/pmi_b.json` + matching chains) are **not** tracked. The rotation scenarios in `integration-emu.yml` generate them on demand.

### Local CI matrix invocations (mirrors `integration-emu.yml`)

Single-instance scenarios (no `--mock-report` or `--policy-v2`):

```bash
./migtdemu.sh --skip-ra --both --no-sudo
./migtdemu.sh --features spdm_attestation --skip-ra --both --no-sudo
```

`policy_v2` + mock-report scenarios (require the tracked policy files):

```bash
./migtdemu.sh --policy-v2 --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
    --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
    --mock-report --both --no-sudo
```

Rebind scenarios use `--operation rebind-prepare`. SPDM scenarios add `--features spdm_attestation`. Key-rotation scenarios additionally pass `--policy-file`/`--policy-issuer-chain-file` pointing at the rotated artifacts (e.g., `policy_v2_signed_a.json`).

### No safe parallelism for `migtdemu.sh`

Do **not** run multiple `migtdemu.sh` invocations concurrently. The script:
- Hardcodes TCP port `8001` (no override flag).
- Uses `taskset -c 0` (all invocations contend on the same core).
- Writes log files at fixed names (`dest_*_out.log`, `migtd_<op>_<role>.log`).
- Builds into `target/release/migtd`, rebuilt per-scenario with different feature sets — concurrent runs will clobber each other's binary.

If you must speed up local CI parity, run scenarios sequentially in a single shell. CI parallelism is achieved per-job in GitHub Actions, where each runner has its own isolated filesystem.

### When CI passes but local fails (or vice versa)

CI failures can mask local regressions and vice versa. If `cargo image` or an EMU test fails locally but the same commit passes in CI on `main`, suspect: missing `preparation.sh`, missing system package, stale submodule, OpenSSL version skew, or deleted tracked policy files. Conversely, if a local change passes but CI fails, do **not** assume the CI is flaky — re-read the §1 trust-model rules first.

---

## 7. Workflow A — Triaging clawpatch findings

```bash
ls .clawpatch/findings/*.json | xargs -I{} jq -r '.findingId + " " + .status + " - " + .title' {}
# Open ones first:
ls .clawpatch/findings/*.json | xargs -I{} jq -r 'select(.status=="open") | .findingId + " - " + .title' {}
```

For each open finding:

1. Open the JSON; read `evidence`, `reasoning`, `reproduction` against the source.
2. Confirm the file/line is **actually compiled** in the in-scope build (check `Cargo.toml` features). Many findings are in vsock/virtio-serial dead code for vmcall-raw.
3. Decide and triage:
   ```bash
   clawpatch triage --finding <id> --status <false-positive|fixed|wont-fix> --note "<concise justification with file:line evidence>"
   ```
4. For *fixed* findings: make a minimal, surgical commit; reference the finding ID in the commit body. **Then run the §5 verification cycle, including EMU integration tests for any boundary-code change.**

Required JSON fields when manually creating a finding (clawpatch finding schema):
`schemaVersion, findingId, featureId, title, category, severity, confidence, triage, evidence, reasoning, reproduction (string not null), recommendation, whyTestsDoNotAlreadyCoverThis (string not null), suggestedRegressionTest (string not null), minimumFixScope, status, history, signature (string), linkedPatchAttemptIds (array), createdByRunId (string), createdAt, updatedAt`.

---

## 8. Workflow B — Manual deep review

Use parallel `explore` agents (Haiku) for breadth, then `view`/`grep` for verification. Suggested chunking:

- Agent 1: `src/devices/**`, `src/std-support/**`
- Agent 2: `src/spdm/**`, SPDM transport, attestation glue
- Agent 3: `src/migtd/src/main/*`, migration session, policy
- Agent 4: `src/crypto/**`, `src/attestation/**`, `src/policy/**`

Prompt each agent to read **only files compiled in the target build**, return findings as a structured list (file:line, severity, description, suggested fix). Then *you* verify each finding against the source before filing — agents will hallucinate; the trust model in §1 catches most hallucinations.

---

## 9. Workflow C — Filing GitHub issues for the audit

See `scripts/create_review_issues.sh` template. Important details:

- Use `[Copilot Review]` prefix in the title (not `[Security]`) — not every finding is a security concern.
- Microsoft org requires SSO; **EMU (Enterprise Managed User) accounts cannot create issues** — use a personal GitHub account with `gh auth login --hostname github.com --web` (device-flow login). Verify the active account with `gh auth status` before running create scripts.
- `gh issue close` uses `--reason "not planned"` (with a literal space), NOT `not_planned`.
- For each issue body file: include Title, Severity, File:line, Description, Triage Status (Fixed / False-positive / Wont-fix), and Triage Notes from the clawpatch finding.
- Before running the create script, scan all body files for duplicated triage-note sentences and empty triage-notes sections; cross-check empty ones against the original clawpatch JSON (the `triage.notes` array — multiple entries should be concatenated, deduplicated, and de-fluffed).

---

## 10. Workflow D — Filing upstream issues for cross-repo bugs

Some bugs surface in MigTD but live in submodules (`deps/td-shim`, `deps/spdm-rs`, etc.). When you confirm one:

1. Identify the upstream repo via `.gitmodules`.
2. Search existing issues + PRs (open and closed) for the symptom and the symbol names. Try at least 3–4 wordings.
3. Verify the bug still exists on upstream `origin/main` (the submodule SHA may be stale).
4. File an issue containing: a self-contained reproducer, the affected file:line, downstream impact, and a proposed fix. Offer to send a PR.
5. In the MigTD-side workaround, **add a code comment referencing the upstream issue URL** so the workaround is not removed later.
6. Add a **regression test** in MigTD that mirrors the upstream reproducer; phrase the assertion so it fails loudly when upstream fixes the bug, signaling that the workaround and test can be removed. Example: `event_log::tests::last_event_visible_only_with_trailing_padding`.

---

## 11. Things to avoid

- **Don't fix unrelated pre-existing issues** uncovered during review unless they are *directly coupled* to the change. If a pre-existing fmt/style issue blocks `cargo fmt --check` for your commit, fix it as a **separate** standalone commit with a clear "pre-existing; not caused by this series" note in the body — do not bundle it into a behavioural commit.
- **Don't churn formatting/lint across the codebase**. `cargo fmt` only touches files you've already modified; do not run it repo-wide.
- **Don't add `.clawpatch/` or `.copilot-review-issues/` to source control** — they are gitignored.
- **Don't "fix" code that looks redundant without proving it is redundant.** See §1's discussion of `event_log::get_event_log()`. The standard test is: revert your fix, run the EMU integration tests; if they break, the code was load-bearing.
- **Don't trust local symptoms when CI tells a different story.** A `SignatureVerificationFailed` locally on Ubuntu 24.04 can mask an entirely unrelated regression (or vice versa).
- **Don't pile new commits on top of an incorrect commit.** If a commit is wrong, use `git rebase -i` to drop or fold it (`fixup`/`squash`) before pushing. Force-push with `--force-with-lease=<branch>:<known-sha>` to a personal fork only; never to a shared branch.

---

## 12. References

- `references/build-features.md` — full feature gating + which crates compile when.
- `references/triage-justifications.md` — boilerplate justifications for the most common false-positives.
- `references/security-test-areas.md` — static analysis, fuzz targets by area, and the secure-review checklist for external-input boundaries.
- `scripts/list_open_findings.sh` — list open clawpatch findings.
- `scripts/create_review_issues.sh` — template to create GH issues from body files.
