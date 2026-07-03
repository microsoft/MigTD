# One-Hash Implementation Notebook

Running log of engineering decisions while implementing the changes in
[`rtmr1_signer_anchor_proposal.md`](./rtmr1_signer_anchor_proposal.md) and
[`tcb_mapping_design_proposal.md`](./tcb_mapping_design_proposal.md).

Branch: `one_hash`. One commit per major decision.

## Scope (confirmed with author)

Four workstreams:

1. **RTMR1 signer anchor** — measure `A = SHA384("MIGTD-RTMR1-ANCHOR-V1" ‖ 0x00 ‖
   H(rootDER) ‖ 0x00 ‖ H(leafSubjectDER))` into RTMR1 instead of the raw issuer-chain
   bytes.
2. **Remove the outer policy-blob signature.**
3. **Redact `servtdTcbMappingIssuerChain` from RTMR2** (anchor it via RTMR1 instead).
4. **Signer-key revocation support** — full end-to-end (crypto core + policy schema +
   generator tooling + e2e CI test). Signer CRL delivered **inside the policy JSON
   `collaterals`** (like the existing `root_ca_crl` / `pck_crl`).

## Current-state findings (before I start)

The repo is already well ahead of the plain git-log titles. Verified by reading source:

| Item | State | Evidence |
|------|-------|----------|
| RTMR1 signer anchor | **Already implemented** | `policy::compute_signer_anchor` (`measurement.rs:247`), RTMR1 extend `main.rs:342`, offline reproduction `migtd-hash/src/lib.rs:199`, CoRIM binding `servtd_corim.rs:256` |
| `svnMappings` keyed on `tdinfo_hash` | Done | `servtd_collateral.rs` `Measurements.tdinfo_hash` |
| RTMR2 single redacted extend | Done, but redacts **only** `servtdTcbMapping` | `measurement.rs:234` (`coll.remove("servtdTcbMapping")`) |
| CoRIM support (`servtd_corim` feature) | Done | `servtd_corim.rs` |
| CRL parsing | `get_crl_number` only | `crypto/src/crl.rs:103` |
| Outer policy signature | **Still present** | `policy.rs` `RawPolicyData.signature`, `verify_policy_data_signature`, called from `verify()` |
| `servtdTcbMappingIssuerChain` in RTMR2 | **Still measured** | `measurement.rs` module doc + test `extract_...issuer_chain_flips` |
| Revocation (is_revoked / CRL sig verify / wiring / floor) | **Absent** | grep: only `get_crl_number` |

So the real remaining delta is: (2) outer-sig removal, (3) issuer-chain redaction +
RTMR1 binding, (4) revocation. (1) is present; I will verify completeness and parity
across runtime / offline tool / CoRIM.

## Key design decisions

### D1 — Signer anchor already implemented; verify, don't rewrite
The anchor formula, runtime extend, offline `migtd-hash` reproduction, and CoRIM
binding all already exist and agree on
`A = SHA384(tag ‖ 0x00 ‖ H(rootDER) ‖ 0x00 ‖ H(leafSubjectDER))`. Decision: keep it,
add/repair tests as needed, do not reimplement. (Commit references this notebook.)

### D2 — Outer signature removal keeps `policyData` integrity via RTMR2
Removing the outer `{policyData, signature}` signature is safe because `policyData`
(minus the redacted `servtdTcbMapping`) is measured into RTMR2 and re-checked by
`check_policy_integrity` against the event log. `servtdIdentity` and
`servtdTcbMapping` keep their own inner signatures. Implementation: make
`RawPolicyData.signature` optional and stop calling `verify_cert_chain_and_signature`
on the outer blob; parse `policyData` directly. Generator stops emitting the outer
signature. Not feature-gated (per proposal "replaces outright").

### D3 — RTMR2 redaction of `servtdTcbMappingIssuerChain` MUST be paired with an
### RTMR1 anchor binding (security-critical)
Once `servtdTcbMappingIssuerChain` is removed from the RTMR2 extend it is no longer
measured there, so an attacker could swap it (and re-sign a forged `servtdTcbMapping`)
without perturbing RTMR2. To keep it measured, bind it to RTMR1: after verifying the
mapping signature against the embedded chain, compute
`compute_signer_anchor(embedded_tcb_mapping_chain)` and require it to equal the RTMR1
anchor derived from the CFV `policy_issuer_chain`. This mirrors exactly what the CoRIM
path already does (`servtd_corim.rs:256`, `anchor != expected_signer_anchor`).
Verifying against the embedded chain (not the CFV chain directly) is required so leaf
rotation still works: the re-signed mapping's new leaf lives in the embedded chain
while RTMR1's anchor (root + subject) stays stable.

`servtdIdentityIssuerChain` is **not** redacted — it stays measured in RTMR2, so no
anchor binding is needed for the identity signer.

### D4 — Signer CRL lives in `collaterals.servtd_crl`; anti-rollback via
### `servtd_crl_num`
Mirror the existing `root_ca_crl` / `pck_crl` + `pck_crl_num` / `root_ca_crl_num`
machinery: add `servtd_crl` (PEM) to `Collaterals`, `servtd_crl_num` to
`PolicyEvaluationInfo` + `CrlPolicy`, compute the delivered CRL number with
`get_crl_number`, enforce a monotonic floor from the policy. Revocation itself: verify
the signer CRL's signature against the signer chain, then reject if any cert in the
`servtdTcbMapping` / identity signer chain is listed as revoked. Fail-closed. No
trusted in-guest clock, so `nextUpdate` is not enforced in-guest (monotonic number
only) — consistent with the proposal.

### D5 — e2e revocation test uses the mock-report AzCVMEmu flow
Add a CI matrix entry that generates a signer CRL revoking the mapping-signer leaf and
asserts migration fails closed with a revocation error, following the existing
mock-report e2e pattern in `integration-emu.yml`.

(Decisions appended as work proceeds.)
