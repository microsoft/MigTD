---
name: migtd-corim-release
description: Investigate and validate MigTD official CoRIM-only release builds, especially TiP loopback migration failures, UnqualifiedMigTdInfo, signer-anchor enrollment, TCB-mapping CoRIM lookup, and Azure production policy compatibility. Use when an official release passes pipeline hash checks but migration or rebinding fails, or when changing servtd_corim policy/build/release behavior.
---

# MigTD CoRIM-Only Release Validation

Use this skill when diagnosing an official release or changing the
`servtd_corim` path. The official build and release pipelines are the source
of truth; legacy JSON-policy EMU coverage is not a substitute.

## 1. Start from the exact release source

Do not investigate from whatever MigTD branch is currently checked out.

1. Obtain the parent repository SHA and MigTD gitlink from release build
   metadata when available.
2. Otherwise inspect the parent branch gitlink:

   ```bash
   git -C <ACC-MigTD> fetch origin
   git -C <ACC-MigTD> ls-tree origin/main MigTD
   ```

3. Preserve local changes, detach MigTD at that SHA, and recursively restore
   the pinned submodules. Only clean generated files after confirming they are
   disposable.
4. Run preparation after every fresh checkout or submodule change:

   ```bash
   git submodule update --init --recursive
   bash sh_script/preparation.sh
   ```

The preparation script intentionally dirties patched dependency worktrees.
That is expected and must not be mistaken for a source-version mismatch.

## 2. Follow the official pipeline

Read both pipeline files before drawing conclusions:

```text
<ACC-MigTD>/.pipelines/OneBranch-Official-Build.yaml
<ACC-MigTD>/.pipelines/OneBranch-Official-Release.yml
```

For the CoRIM-only release path, verify all of these facts:

- `migtd-policy-generator` is invoked without `--servtd-collateral`.
- The enrolled policy therefore has no `policyData.servtdCollateral`.
- A 48-byte signer anchor is enrolled and measured into RTMR1.
- Only the signed TCB-mapping CoRIM is enrolled under
  `7E5B9C11-2D4A-4F6E-9B3C-1A2B3C4D5E6F`.
- The TD-identity CoRIM is published as an endorsement artifact but is not
  enrolled or consumed by firmware.
- Pipeline hash/anchor checks prove artifact integrity, not that a migration
  policy can evaluate the runtime lookup result.

## 3. Enforce the runtime policy contract

`ServtdCorim::lookup_by_tdinfo_hash` returns:

```text
tdinfo_hash -> isvsvn
```

It deliberately returns no `tcb_date` or `tcb_status`. Consequently, a
CoRIM-only production policy may use `migtdIdentity.isvsvn`, but must not use
`migtdIdentity.tcbDate` or `migtdIdentity.tcbStatusAccepted` unless firmware
is extended to consume an authenticated TD-identity source.

The safe migration anti-downgrade rule is:

```json
{"isvsvn":{"operation":"greater-or-equal","reference":"self"}}
```

This accepts a peer at the local SVN or newer and rejects an older peer.

Run the reusable gate:

```bash
.agents/skills/migtd-corim-release/scripts/check-corim-only-policy.sh
```

## 4. Run CoRIM-only EMU flows

Legacy policy-v2 EMU scenarios call
`build_AzCVMEmu_policy_and_test.sh`, which generates a legacy JSON
`servtdCollateral` containing TD identity. Those tests:

- do not use `config/Azure/policy_data_raw.json`;
- do not enable `servtd_corim`;
- resolve MigTD date/status from JSON TD identity;
- therefore cannot detect an invalid date/status rule in a CoRIM-only release.

Generate the canonical mock-report CoRIM inputs explicitly:

```bash
./sh_script/build_AzCVMEmu_policy_and_test.sh \
  --mock-report --corim-only --skip-test
```

This emits:

- `policy_v2_corim.json`, with no `policyData.servtdCollateral`;
- `servtd_signer_anchor.bin`, exactly 48 bytes;
- `tcb_mapping_corim.cose`, signed and keyed to the canonical mock report's
  `tdinfo_hash`.

The builder fails if the mock report hash drifts from the committed fixture.
Run both required runtime paths:

```bash
./migtdemu.sh --policy-v2 \
  --policy-file config/AzCVMEmu/policy_v2_corim.json \
  --servtd-signer-anchor-file config/AzCVMEmu/servtd_signer_anchor.bin \
  --servtd-corim-file config/AzCVMEmu/tcb_mapping_corim.cose \
  --mock-report --features spdm_attestation --both --no-sudo

./migtdemu.sh --operation rebind-prepare \
  --policy-file config/AzCVMEmu/policy_v2_corim.json \
  --servtd-signer-anchor-file config/AzCVMEmu/servtd_signer_anchor.bin \
  --servtd-corim-file config/AzCVMEmu/tcb_mapping_corim.cose \
  --mock-report --features spdm_attestation --both --no-sudo
```

Require `Loaded signed ServTD CoRIM endorsement` in both source and
destination logs. That line, together with the absence of
`servtdCollateral`, proves the test did not fall back to legacy JSON.

Keep the dedicated policy contract job and both CoRIM-only runtime cases in
`.github/workflows/integration-emu.yml`. It builds the production feature
combination and runs policy tests against the production Azure policy plus a
real TCB-mapping CoRIM fixture; the runtime cases cover SPDM migration and
rebind-prepare with the actual CoRIM-only firmware-volume inputs.

## 5. Failure signature

When quote verification, policy/event-log verification, and evaluation-data
setup succeed, followed by:

```text
Policy v2 check failed
UnqualifiedMigTdInfo
```

inspect the `servtd.migtdIdentity` rule before debugging SPDM. Errors such as
`missing remote_information`, `ERROR_PEER`, and key-exchange failures afterward
are normally consequences of the responder rejecting policy evaluation.
