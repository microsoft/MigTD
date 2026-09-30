# MigTD Code Coverage Proposal

Status: **DRAFT for review.** Aggregation backend decided: **Codecov**. No implementation yet.

This document proposes a per-PR code-coverage flow that combines unit tests and CI integration
tests into a single, line-by-line report, and outlines how to reach the production-only code paths
that only the real-hardware tests exercise.

## 1. Current state

Coverage exists only as **local, manual scripts** — nothing runs in CI, nothing is aggregated,
uploaded, or shown per-PR.

| Asset | What it does | Gaps |
|---|---|---|
| [`sh_script/unit_test_coverage.sh`](../sh_script/unit_test_coverage.sh) | `RUSTFLAGS=-Cinstrument-coverage` + `cargo test -p policy -p migtd -p crypto -p virtio -p vsock` → `grcov -t html`. Source-based LLVM coverage. | Local only; HTML only (no lcov); default features only (misses `policy_v2` / `vmcall-raw` / `spdm` legs that `xtask lib-test` builds); not in CI. |
| [`sh_script/fuzzing.sh`](../sh_script/fuzzing.sh) `-c` | Per-fuzz-target grcov HTML. | Local only; fuzz-only. |

CI test surfaces today (none produce coverage):

- **[`library.yml`](../.github/workflows/library.yml)** → `cargo xtask lib-test`: unit tests across
  crates and feature combos (migtd default / `policy_v2` / `main,policy_v2,vmcall-raw --lib`,
  policy v1+v2, etc.).
- **[`integration-emu.yml`](../.github/workflows/integration-emu.yml)** → 13-leg matrix driving
  [`migtdemu.sh`](../migtdemu.sh) (AzCVMEmu). Builds a **std host binary**
  (`x86_64-unknown-linux-gnu`, no `--target`) and runs source+destination as ordinary Linux
  processes with **mock quote / mock report**. Covers skip-RA, policy v2, IGVM-attest, SPDM,
  rebind, key-rotation, mapping-rotation, quote-retry.
- **[`integration-tdx.yml`](../.github/workflows/integration-tdx.yml)** → `[self-hosted, tdx]`
  runners; builds the **firmware image** (`cargo image`, no_std `x86_64-unknown-none`, `migtd.bin`)
  and runs `pytest` inside real TD guests with **real attestation**. Marked "Optional/Broken",
  `workflow_dispatch` only.

## 2. Goals

1. **Per-PR combined coverage** = unit tests ∪ CI integration tests, as one number + report.
2. Integration layer = the **AzCVMEmu** legs in `integration-emu.yml` — they run directly on the
   build runner with a mock quote, so they are directly instrumentable.
3. Reach toward **production-only code paths** that AzCVMEmu + mock_report does **not** exercise
   (real attestation / quote generation / TDX GHCI vmcalls / no_std firmware runtime) — these are
   only hit by the **real-hardware TDX** tests.
4. **Line-by-line** visibility: which source lines are covered, plus PR **diff** coverage.
5. Must run **per-PR**, but a **minimal covering subset** of legs is acceptable if it yields the
   same coverage (keep CI fast).
6. Prefer **GitHub-native** flow. **Decision: use Codecov** for aggregation/reporting.

## 3. Technical foundation (verified)

- Standardize on **source-based LLVM coverage** (`-Cinstrument-coverage`) — already the repo's
  approach via grcov.
- The AzCVMEmu binary is a **std host build** → directly instrumentable. `migtdemu.sh` launches it
  through `env "${kv[@]}" … "$binary"`, which **inherits** the parent environment, so exporting
  `LLVM_PROFILE_FILE=…/%p-%m.profraw` makes **both** the source and destination processes emit
  `.profraw` with **no script change**.
- Emit **LCOV** (`grcov … -t lcov`) as the interchange format → line-by-line in Codecov + local HTML.
- Merging reports from **different feature-variant builds** yields the **union** of covered lines —
  exactly the "covered by all CI tests combined" semantic. Lines `cfg`-gated out of a given build
  are simply absent from that report; a line counts as covered if **any** configuration hits it.
- The [`setup-build-environment`](../.github/actions/setup-build-environment/action.yml) action
  installs Rust 1.88.0 + `rust-src` but **not** `llvm-tools-preview`/grcov ([`fuzz.yml`](../.github/workflows/fuzz.yml)
  already adds `llvm-tools-preview`); coverage jobs must add both.

## 4. Coverage by test layer

### 4a. Unit tests — EASY
Enhance `unit_test_coverage.sh` to also emit `-t lcov`, and align its feature combos with
`xtask lib-test` (add `policy_v2` / `vmcall-raw` / `spdm` runs) so unit coverage reflects what CI
tests. Upload under flag **`unittests`**.

### 4b. AzCVMEmu integration — EASY/MODERATE
Per selected leg: add `llvm-tools-preview` + grcov; build with `RUSTFLAGS=-Cinstrument-coverage`;
`export LLVM_PROFILE_FILE=$PWD/emu-cov/<leg>-%p-%m.profraw`; run the existing `test-command`; then

```bash
grcov emu-cov --binary-path target/release/ -s . -t lcov \
    --ignore 'deps/*' --ignore 'target/*' -o emu-<leg>.lcov
```

Upload under flag **`integration`**. (Instrumentation forces a full instrumented rebuild of deps →
slower; see §6.)

### 4c. Real-hardware TDX firmware — HARD (production-only paths)
**Why it matters:** real attestation, quote generation, TDX GHCI vmcalls, and the no_std firmware
runtime are **only** exercised here; AzCVMEmu + mock cannot cover them.

**Why it's hard:** the firmware is `no_std`, `x86_64-unknown-none`, has **no filesystem** to write
`.profraw`, may never cleanly "exit", and is a **measured** image (instrumentation changes MRTD/RTMR).

**Feasible approach — [`minicov`](https://github.com/Amanieu/minicov)** (the standard no_std coverage runtime):
1. Build the firmware with `-Cinstrument-coverage` and link the `minicov` no_std runtime.
2. Reserve a memory region / linker section for the LLVM counters in the firmware memory map.
3. Under a **test-only feature**, call `minicov::capture_coverage()` at end-of-test and stream the
   buffer out-of-band over an existing channel (serial log / vsock), base64-encoded.
4. Host side: decode → reconstruct `.profraw` → grcov/llvm-cov → lcov.

**Risks / caveats to weigh:**
- Firmware **memory-layout & size budget**: counter sections may not fit the fixed firmware layout.
- **Measurement change:** instrumenting changes MRTD, so attestation policy / pre-production certs
  must be **regenerated to match the instrumented image** (the emu policy generator already does
  this by hashing the actual image; real-HW needs equivalent handling). Otherwise the very
  attestation path you want to cover will reject the image.
- **Cadence:** these run on self-hosted TDX and are currently optional/broken — they will not run on
  every PR.

**Recommended handling:** treat firmware coverage as a Codecov **carryforward flag** `hardware` —
when the hardware job doesn't run on a PR, Codecov carries the **last** hardware coverage forward so
the combined per-PR number still reflects production-path coverage without blocking the PR.

## 5. Line-by-line coverage

Yes, fully supported. `grcov -t lcov` (or `-t html`) gives per-line + branch data; **Codecov**
renders per-line covered/uncovered in the web UI **and** PR **diff coverage** (which changed lines
are covered). Locally, `grcov -t html` or `genhtml` produces a browsable line-by-line report.
With per-flag uploads (`unittests` / `integration` / `hardware`) you can also see which **layer**
covers a given line.

## 6. Per-PR cost control & "minimal covering subset"

Instrumented builds rebuild all deps (slower), and the emu matrix is 13 legs — instrumenting all of
them per-PR is heavy. Plan:

1. Run a **one-time full-matrix** instrumented pass; compute each leg's **marginal** line contribution.
2. The 13 legs vary along a few axes — attestation mode (skip-ra / mock-report / igvm-attest / spdm),
   policy (v1/v2), operation (migration / rebind / key-rotation / mapping-rotation), retry. A
   **representative subset (~4–6 legs)** whose union ≈ the full union is very likely.
3. Run the **subset per-PR**; run the **full matrix nightly/weekly** (or on label) to detect drift.
4. Optionally isolate everything in a **dedicated `coverage.yml`** so instrumented rebuilds never
   slow the existing fast PR matrix.

## 7. Alternatives considered

### Aggregation / reporting (decided: A — Codecov)
| Option | Pros | Cons |
|---|---|---|
| **A. Codecov flag-merge (+carryforward) — chosen** | GitHub-native; auto-merges matrix + unit + hardware uploads into one total with per-flag breakdown; per-line + PR diff coverage; carryforward solves "hardware not run every PR"; tokenless for public repo; historical trend UI | external service; fork PRs may need `CODECOV_TOKEN`; org must allow the Codecov app |
| B. Self-contained: artifacts + merge job + genhtml | no third party; data stays in GitHub; full control | must build/maintain merge, threshold, PR-comment, and carryforward-equivalent logic; no trend UI |
| C. Coveralls | similar to A; parallel/flag support | same external-service concerns; smaller feature set than Codecov flags/carryforward |
| D. ADO Cobertura + `PublishCodeCoverageResults@2` | native Coverage tab; merges multiple Cobertura; good if org mandates ADO | CI already lives in GitHub Actions → extra system; weaker per-PR GitHub annotations |

### Coverage tooling sub-choice
| Option | Pros | Cons |
|---|---|---|
| **grcov** (current) | already used by repo scripts; consumes raw profraw from externally-launched processes (fits `migtdemu.sh`); lcov/html/cobertura | external binary to install |
| cargo-llvm-cov | great for `cargo test`/`cargo run`; one command | awkward for binaries launched by a shell script out-of-band (the emu case) |
| raw llvm-tools (`llvm-profdata`+`llvm-cov`) | no extra deps beyond `llvm-tools-preview` | more manual; grcov already wraps this |

→ Keep **grcov** for uniformity (unit + emu + firmware-via-minicov all converge on profraw → lcov).

### Firmware coverage sub-choice
| Option | Pros | Cons |
|---|---|---|
| **minicov no_std runtime** | purpose-built for bare-metal; capture + dump over serial/vsock | code changes (dep, linker section, test hook); measurement regen; size budget |
| RAM-dump hack of profile runtime | no extra crate | very invasive/custom; fragile |
| Skip firmware coverage | zero effort | loses production-only path coverage (the main reason hardware tests exist) |

## 8. Recommendation (phased)

- **Phase 1 (now — high ROI, low effort):** unit + a minimal emu subset → grcov `-t lcov` →
  **Codecov** flags `unittests` + `integration`. Per-PR, line-by-line + diff coverage. Use a
  dedicated `coverage.yml` (or extend existing workflows) running the subset per-PR, full matrix
  nightly.
- **Phase 2 (later — high effort, high value):** firmware coverage on the self-hosted TDX runner via
  **minicov**, uploaded under a **carryforward `hardware`** flag so production-only paths enrich the
  combined number without running on every PR.
- **Phase 3 (tuning):** lock in the covering subset, set a coverage threshold / PR status, and decide
  gating policy (informational vs blocking).

Default tooling: **grcov → lcov → Codecov flag-merge**, reusing the repo's existing approach.

## 9. Open questions for reviewers

1. **Per-PR CI time budget** — is the instrumented subset acceptable inline, or should it live in a
   separate `coverage.yml` workflow?
2. **Invest in firmware/minicov now or defer** to Phase 2? (Requires firmware code + measurement-regen work.)
3. **Gating policy** — informational coverage report vs a blocking threshold / diff-coverage gate?
4. **Codecov onboarding** — confirm the Codecov GitHub app is enabled for the org, and whether a
   `CODECOV_TOKEN` secret is needed for fork PRs.
