---
type: Playbook
title: Setup, Verification Gauntlet & Pre-done Checklist
description: Mandatory post-checkout setup, the four-CI-workflow verification gauntlet, common EMU invocations, and the pre-done checklist.
tags: [ci, verification, emu, setup, checklist]
timestamp: 2026-07-10T19:26:55+00:00
---

# Setup, Verification Gauntlet & Pre-done Checklist

> Split from [AGENT_NOTES.md](/AGENT_NOTES.md) §3, §4, §10.

## Mandatory setup after fresh checkout / submodule update / `git clean`

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

## Verification — all four CI workflows MUST pass, no exceptions

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

See [AzCVMEmu build & run](azcvmemu-build-and-run.md) for feature-flag details
and [integration testing](integration-testing.md) for the QEMU/vsock and Azure
TiP test layers.

## Quick checklist before "I'm done"

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
