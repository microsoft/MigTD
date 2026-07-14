---
type: Playbook
title: Policy v2 Generation Workflow
description: End-to-end tool chain to produce and sign Policy v2 artifacts (collaterals, ServTD collateral, policy, issuer chain) and build/re-hash the image with them.
tags: [policy-v2, tools, signing, tcb-mapping]
timestamp: 2026-07-13T22:37:00+00:00
---

# Policy v2 Generation Workflow

Canonical source: [doc/policy_v2.md](../../doc/policy_v2.md). Use this when asked
to regenerate/re-sign a v2 policy, rotate the TCB mapping, or debug why a
built image has a mismatched `SERVTD_INFO_HASH`.

## Pipeline (each step feeds the next)

```text
1. migtd-collateral-generator     -> collateral_*.json            (platform TCB/QE collateral)
2. json-signer --sign tdIdentity  -> td_identity_signed.json
   json-signer --sign tdTcbMapping -> tcb_mapping_signed.json
   servtd-collateral-generator    -> servtd_collateral.json       (bundles both + issuer chains)
3. migtd-policy-generator v2      -> policy_v2.json
   json-signer --sign policyData -> policy_v2_signed.json
4. cargo image --policy-v2 --policy <signed> --policy-issuer-chain <chain>
```

Each tool has its own `readme.md` under `tools/<name>/`. At boot, MigTD
measures the issuer chain (RTMR1) and verifies+measures the canonical
`policyData` (RTMR2, `RawPolicyData::verify` in `src/policy/src/v2/policy.rs`)
— see [boot-measurements.md](boot-measurements.md) for the mechanics.

## Rotating the TCB mapping (update without re-signing everything)

```bash
bash sh_script/key_gen.sh                                   # new signing keypair
cargo image --policy-v2 --policy <old-signed> --policy-issuer-chain key/migtd_issuer_chain.pem
cd tools/migtd-hash && cargo build && popd
./target/debug/migtd-hash --manifest config/servtd_info.json --image target/release/migtd.bin \
    --policy-v2 --update-tcb-mapping config/templates/tcb_mapping.json
bash sh_script/build_policy_v2.sh [preprod/prod]             # re-sign policy with new keys
cargo image --policy-v2 --policy config/templates/policy_v2_signed.json \
    --policy-issuer-chain key/migtd_issuer_chain.pem
```

## Gotcha

Artifacts are expected under `config/templates/` by default
(`policy_v2_signed.json`, `policy_issuer_chain.pem`) — a mismatch between
where the tools write and where `cargo image --policy-v2` reads from is the
most common source of "policy verification failed at boot" confusion.
