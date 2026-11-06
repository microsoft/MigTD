---
type: Playbook
title: Setup, Verification Gauntlet & Pre-done Checklist
description: Mandatory post-checkout setup, the five-CI-workflow verification gauntlet, common EMU invocations, and the pre-done checklist.
tags: [ci, verification, emu, setup, checklist]
timestamp: 2026-07-10T19:26:55+00:00
---

# Setup, Verification Gauntlet & Pre-done Checklist

> Condensed in the root [agent guide](../../AGENTS.md).

## Mandatory setup after fresh checkout / submodule update / `git clean`

```bash
bash sh_script/preparation.sh
```

This applies the `spdm-rs` patches to the ring source selected by MigTD's
workspace override, `deps/td-shim/library/ring`
(`EphemeralPrivateKey::export_private_key_bytes`/`from_private_key_bytes` and
`digest::Context::to_bytes`/`from_bytes`). See
[`doc/dependency_preparation.md`](../../doc/dependency_preparation.md) for why
spdm-rs's own ring copy is not selected. **Skipping preparation produces build
errors that look like a real baseline regression but aren't.** CI runs it
automatically; **locally you must run it manually** after:

- a fresh clone,
- `git clean -fdx`,
- any `git submodule update`,
- switching to a branch with different submodule SHAs.

If td-shim preparation cannot reset ring to its required commit in a shallow
checkout, fetch that exact commit into `deps/td-shim/library/ring` before
retrying. `deps/td-shim/sh_script/preparation.sh` does not stop at the failed
reset; subsequent cleanup/patch failures are not evidence of a source regression.

On a completely fresh checkout, `cargo fmt --check` can fail to resolve
`deps/spdm-rs/spdmlib/src/config.rs` before its build script has generated it.
After preparation, bootstrap it with:

```bash
SPDM_CONFIG="$PWD/config/spdm_config.json" cargo check -p spdmlib --features chunk-cap
```

The repository's SPDM configuration requires `chunk-cap`; without it,
`spdmlib/build.rs` rejects the configured transport buffer sizes.

## Verification — all five CI workflows MUST pass, no exceptions

The project standard is that **every test in every workflow passes** before a
change is considered done. Use the gauntlet script as the standard pre-push
verification:

```bash
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --list
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --from main   # resume
.agents/skills/migtd-review/scripts/run-ci-gauntlet.sh --only emu    # one stage
```

Stages mirror the five workflows: **format → deny → library → main → emu**
(after `prep`). The EMU stage includes artifact/verifier and CoRIM policy
checks, all 20 matrix scenarios, and an additional CoRIM rebind (21 total).
The script stops at the first failure. **Fix the root cause;
don't skip ahead.**

Generated JSON mappings use `svnMappings[].tdMeasurements.servtdInfoHash`.
The asymmetric CoRIM fixture generator must read that field, not the legacy
`tdinfo_hash` spelling (`sh_script/gen_asymmetric_servtd_corim_fixture.sh`).

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
./migtdemu.sh --skip-ra --debug --both --no-sudo --log-level info
./migtdemu.sh --features spdm_attestation --skip-ra --debug --both --no-sudo --log-level info
./migtdemu.sh --operation rebind --policy-v2 \
    --policy-file ./config/AzCVMEmu/policy_v2_signed.json \
    --policy-issuer-chain-file ./config/AzCVMEmu/policy_issuer_chain.pem \
    --servtd-tcb-mapping-file ./config/AzCVMEmu/tcb_mapping_signed.json \
    --skip-ra --debug --both --no-sudo --log-level info
./sh_script/build_AzCVMEmu_policy_and_test.sh --mock-report   # fixture generation and smoke tests
```

Intel commit `49683d20` replaced the two-phase EMU CLI operations with
`--operation rebind`. Keep local scripts and their runtime-log checks on this
single-phase spelling.

Policy-v2 rebinding also requires `--policy-v2`; naming a v2 policy file does
not select that mode. Keep separate v1 rebind cases without the flag.

**Do not run multiple `migtdemu.sh` invocations concurrently** — it hardcodes
TCP port 8001, pins to `taskset -c 0`, and writes a shared `target/release/migtd`
artefact.

See [AzCVMEmu build & run](azcvmemu-build-and-run.md) for feature-flag details
and [integration testing](integration-testing.md) for the QEMU/vsock test layer.

## Quick checklist before "I'm done"

1. `bash sh_script/preparation.sh` ran since last submodule change?
2. `cargo fmt --check` clean (only your touched files)?
3. `cargo clippy ... -- -D warnings` clean on in-scope features?
4. `cargo test` clean for crates you touched?
5. EMU tests run for boundary-code changes (event_log, policy, crypto, spdm,
   vmcall)?
6. All five mirrored CI workflows pass via `run-ci-gauntlet.sh`, plus other applicable checks?
7. Every commit is `-s` signed-off by the configured human, including debug / `REVERTME`?
8. Commit messages brief and accurate (problem + high-level solution)?
9. No unrelated changes piled into one commit?
10. Pushed only to a personal fork remote (`--force-with-lease` if rewriting)?
