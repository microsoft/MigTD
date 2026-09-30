---
type: Playbook
title: Policy v2 Generation Workflow
description: End-to-end tool chain for one-hash Policy v2 artifacts, JSON or CoRIM servTD endorsements, signer-anchor enrollment, and hash-stable updates.
tags: [policy-v2, tools, signing, tcb-mapping]
timestamp: 2026-08-25T22:12:55+00:00
---

# Policy v2 Generation Workflow

Design sources:
[tcb_mapping_design_proposal.md](../../doc/tcb_mapping_design_proposal.md) and
[rtmr1_signer_anchor_proposal.md](../../doc/rtmr1_signer_anchor_proposal.md).
The implementation source of truth is `src/policy/src/v2/measurement.rs` and
`src/policy/src/v2/policy.rs`. Use this playbook when regenerating a v2 policy,
rotating a mapping/signer leaf, or debugging a mismatched `SERVTD_INFO_HASH`.

## Supported packaging paths

```text
Shared:
  migtd-collateral-generator -> platform TCB/QE collaterals
  migtd-policy-generator v2  -> { "policyData": ... }

JSON compatibility path:
  sign tdTcbMapping (tdinfo_hash -> SVN)
  optionally sign tdIdentity (SVN -> date/status)
  servtd-collateral-generator -> JSON servtdCollateral + issuer chains
  cargo image --policy-v2 --policy <policy> --policy-issuer-chain <chain>

CoRIM-only path:
  omit --servtd-collateral when generating policyData
  produce signed TCB-mapping CoRIM (SERVTD_INFO_HASH -> SVN)
  enroll the precomputed 48-byte signer anchor and CoRIM:
  cargo image --policy-v2 --policy <policy> \
      --signer-anchor <anchor.bin> --servtd-corim <mapping.cose>
```

The legacy `{policyData, signature}` wrapper and `policy_v2_signed.json`
filenames remain accepted, but the **outer policy signature is ignored**.
PolicyData integrity comes from RTMR2. Authenticity of the re-issuable servTD
endorsement comes from either the inner JSON signatures or the CoRIM
`COSE_Sign1`, whose signer chain must resolve to the RTMR1 anchor.

At boot, MigTD:

1. Resolves the signer anchor
   `A = SHA384(tag || H(rootDER) || leafEkuOidDER)` from a PEM chain or the
   direct anchor slot and extends `SHA384(A)` into RTMR1.
2. Extends canonical `policyData` into RTMR2. JSON packaging redacts only the
   TCB mapping and mapping issuer chain; JSON TD Identity and its issuer chain
   remain measured. A CoRIM-only policy has no `servtdCollateral` and is
   measured as-is.
3. Verifies JSON/CoRIM signatures and binds their signer root+EKU to `A`.

## Updating mappings and rotating signer leaves

- `svnMappings[].tdMeasurements.tdinfo_hash` and CoRIM digest selectors use
  the complete 48-byte `SERVTD_INFO_HASH`, not individual MRTD/RTMR fields.
- A deployable mapping must cover both current MigTD releases and any initial
  MigTD hashes that can appear in target-TD `SERVTD_EXT` state. During
  migration/rebinding, the verifier uses the authenticated source's mapping
  to resolve both `init_servtd_info_hash` and the source's current report
  hash, then requires `init SVN <= current SVN`.
- That comparison is against the **source peer's verified mapping**, not the
  destination's local mapping. This preserves reverse migration because an
  older destination does not need to predict future source releases.
- Re-issuing a JSON mapping or CoRIM is measurement-neutral. Re-issuing JSON
  TD Identity or its issuer chain changes RTMR2 and requires a new
  `tdinfo_hash` endorsement.
- Images built with `use-mock-quote` need two current-release mapping entries:
  the synthetic mock-report `tdinfo_hash` used by peer policy evaluation and
  the final image `SERVTD_INFO_HASH` used by `SERVTD_EXT` continuity checks.
  Generate measured-image policy collateral with
  `build_azure_mock_test.sh --retain-mock-report-mapping`.
- Rotating leaf or intermediate keys is measurement neutral only when the root
  and signer-anchor EKU are unchanged; the new chain must still validate
  and pass signer revocation checks.
- When a CoRIM is enrolled it is the sole TCB lookup authority. Do not expect
  JSON fallback on a CoRIM miss.
- MigTD has no trusted clock or persistent mapping-generation state. Mapping
  publication order and rollback prevention remain release-authority and
  deployment responsibilities; do not describe signed mapping replacement as
  an independently enforced in-guest freshness guarantee.
- After enrollment, recompute the image hash with `migtd-hash` and require it
  to equal the pre-enrollment value. A mismatch means measured policy content,
  root, or signer EKU changed.

## Implementation status

The runtime enforces the completed design in both migration and rebinding:
it resolves `ServtdExt.init_servtd_info_hash` and the authenticated source's
current report hash through the source's verified mapping, fails closed on
either miss, and rejects `init SVN > current SVN`. The legacy wire
Init_TDINFO is ignored.

## Gotcha

Legacy scripts still use `config/templates/policy_v2_signed.json` and
`policy_issuer_chain.pem`. CoRIM-only builds instead need a policy without
`servtdCollateral`, the 48-byte anchor file, and the signed `.cose` mapping.
Do not mix the direct-anchor and PEM-chain inputs accidentally: the direct
anchor takes precedence when both CFV slots are populated.

GitHub `cargo image` matrix jobs are compile checks, not publishable release
artifacts. A deployable image must go through either the release CoRIM
generation/enrollment gates or a measured-image JSON mapping flow; never ship a
matrix image with the static template mapping.
