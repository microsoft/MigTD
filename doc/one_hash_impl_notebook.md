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

## Progress log

### P1 — Outer policy signature removed (commit pending)
- `RawPolicyData.signature` → `Option<String>` (`#[serde(default,
  skip_serializing_if)]`); deserializes with or without the field.
- `RawPolicyData::verify()` no longer calls `verify_cert_chain_and_signature` on
  the outer blob; it parses `policyData` directly. `verify_policy_data_signature`
  deleted; `hex_string_to_bytes` import dropped.
- Tests added: `test_verify_policy_without_outer_signature`,
  `test_outer_signature_is_ignored` (both preserve exact `policyData` bytes so the
  inner servtd signatures stay valid). `cargo test -p policy --features policy_v2`:
  42 passed. `cargo build -p migtd --features policy_v2`: clean.
- **Deferred to P5 (tooling):** the generator (`build_AzCVMEmu_policy_and_test.sh`)
  still emits `{policyData, signature}`. The runtime now *ignores* the outer
  signature, so this is backward-compatible; the generator will stop emitting it
  when the CRL tooling lands.

### P2 — `servtdTcbMappingIssuerChain` redacted from RTMR2 + RTMR1 anchor binding
- `extract_canonical_policy_data_bytes` now also removes
  `servtdTcbMappingIssuerChain` (non-strict). Module/function docs updated.
- **Security binding (D3):** `RawPolicyData::verify()` now requires
  `compute_signer_anchor(servtdTcbMappingIssuerChain) ==
  compute_signer_anchor(cfv issuer_chain)`; mismatch → new
  `PolicyError::SignerAnchorMismatch`. This keeps the redacted chain measured
  (via RTMR1). Mirrors the CoRIM path.
- Tests: `extract_measures_identity_chain_but_redacts_mapping_chain`,
  `extract_redacts_servtd_tcb_mapping_issuer_chain`, updated
  `extract_sample_policy_canonical_bytes` + field-name-absence check, and
  `test_verify_policy_rejects_mapping_chain_anchor_mismatch` (new fixture
  `cert_chain/unrelated_issuer_chain.pem`). policy v2: 44 passed; migtd clean.
- **IMPORTANT for P5/P6 (e2e):** the anchor binding requires the CFV
  `policy_issuer_chain` slot (RTMR1) and the embedded `servtdTcbMappingIssuerChain`
  to share the same root + leaf subject. Today `build_AzCVMEmu_policy_and_test.sh`
  gives `policy_signing` (CFV) and `mapping_signing` (embedded) **different**
  CNs, which WOULD fail the binding. P5 must make the CFV
  `policy_issuer_chain*.pem` the **TCB-mapping** signer chain (per the design:
  "RTMR1 = TCBMapping issuer cert chain"). Unit-test fixtures already share one
  signer (CN=MigTD Info Issuer), so they pass.

### P3 — Revocation crypto core (`crypto/src/crl.rs`, `lib.rs`)
- `crl.rs`: `Crl.signature_algorithm` typed as `AlgorithmIdentifier` and
  `RevokedCertificate.user_certificate` as `UintRef` (for serial compare). New:
  `get_crl_issuer_der`, `verify_crl_signature(crl, issuer_pubkey)` (ECDSA-P384/
  SHA-384 only), `is_serial_revoked(crl, serial)`.
- `lib.rs`: `verify_signer_chain_not_revoked(chain_pem, crl_pem)` — locate the
  issuing CA in the chain (subject == CRL issuer), verify the CRL signature with
  its key, then fail closed if any cert serial is revoked. Freshness/anti-rollback
  is left to the policy layer (P4).
- Fixtures: `src/crypto/test/crl/` (root CA, leaf signer, empty CRL #0x1000,
  revoked CRL #0x1001). crypto suite: 18 passed (8 new).

### P4 — Revocation schema + wiring
- `collaterals.rs`: `Collaterals.servtd_crl: Option<String>` (PEM CRL, optional
  for back-compat; `serde(default, skip_serializing_if)`).
- `policy.rs`: `servtd_crl_num` added to `PolicyEvaluationInfo` and `CrlPolicy`
  (anti-rollback floor, mirrors `pck_crl_num`). `RawPolicyData::verify()` now
  enforces revocation: if `collaterals.servtd_crl` is present, both the mapping
  and identity signer chains are checked via
  `crypto::verify_signer_chain_not_revoked` → new `PolicyError::SignerRevoked`.
- `mig_policy.rs`: `servtd_crl_num_from_collaterals()` feeds the floor in all
  three `setup_evaluation_data*`; `verify_policy_and_event_log` adds a **peer
  revocation cross-check** (peer signer chains vs the LOCAL trusted CRL) so a
  malicious peer cannot hide a revoked signer by shipping a clean CRL.
- Tests: `crl_policy_enforces_servtd_crl_num_floor` (policy). policy: 45 passed;
  migtd: 42 passed; migtd builds clean.
- **Coverage:** `verify()`'s revocation enforcement is unit-tested by
  `verify_enforces_servtd_signer_revocation` (policy) — a self-contained signed
  policy under `test/policy_v2/revocation/` (one signer, matching empty/revoking
  CRLs): empty CRL → verifies, revoking CRL → `SignerRevoked`. The crypto layer
  and the P6 e2e cover the rest. The `mig_policy` peer cross-check is a
  defense-in-depth backstop over the same (unit-tested) crypto function and is
  reachable only via a full migration handshake, so it is exercised at the
  integration/e2e layer rather than by a dedicated unit test.
- **Not done (out of scope / follow-up):** CoRIM path (`servtd_corim` feature)
  revocation — the JSON `collaterals.servtd_crl` path is the delivered
  mechanism; CoRIM revocation would need the CRL threaded through the COSE flow.
  (`servtd_corim` also can't build here — the `corim` crate needs network.)

### P5 — e2e generator tooling (`build_AzCVMEmu_policy_and_test.sh`)
- **CFV = TCB-mapping signer chain (D3 e2e half):** `policy_issuer_chain*.pem`
  (the CFV `MIGTD_POLICY_ISSUER_CHAIN` slot, RTMR1) now copies the
  `mapping_issuer_chain*.pem`, so it shares root + leaf subject with the
  embedded `servtdTcbMappingIssuerChain` and the anchor binding holds. The old
  `policy_signing` family only signed the (now-ignored) outer signature.
- **Signer CRLs:** `generate_servtd_crls()` emits an empty CRL (#0x1000) and a
  CRL revoking the mapping-signer leaf (#0x1001), both signed by the shared root
  CA. `inject_servtd_crl()` embeds them as `collaterals.servtdCrl`.
- **Variants:** normal variants embed the empty CRL; a new `revoked` variant
  (`policy_v2_signed_revoked.json`) embeds the revoking CRL.
- **Outer signature:** the generator still runs `json-signer --name policyData`
  (kept because it preserves the canonical inner-signature byte passthrough that
  the runtime's inner `servtdIdentity`/`servtdTcbMapping` verification depends
  on). The runtime *ignores* the resulting outer signature, so "outer signing
  removed" holds at the trust layer.
- **Validated with `migtd-policy-verifier`** (runs the real `RawPolicyData::verify`,
  `policy_v2`): normal `a`/`pm_b`/`pmi_b` verify OK; `revoked` →
  `SignerRevoked`; normal + unrelated chain → `SignerAnchorMismatch`. (The full
  emulator binary can't build here — AzCVMEmu deps need the `msrustup` registry —
  so migration is validated in CI, but the `verify()` path is fully exercised
  locally by the verifier.)
- **Design note:** `servtdCrl` lives in `collaterals` and is therefore measured
  into RTMR2 (like `root_ca_crl`/`pck_crl`); updating it is a policy re-release,
  and `servtd_crl_num` is the policy-level anti-rollback floor — consistent with
  the existing platform-CRL pattern (the user chose "in collaterals").

### P6 — Revocation e2e CI test (`integration-emu.yml`)
- New matrix entry **"Policy v2 Signer Revocation (Mock Report)"**
  (`test-type: policy-v2-revoked`): runs `migtdemu.sh` with
  `policy_v2_signed_revoked.json` on both sides.
- Inverted assertion in "Run test": because `initialize_policy()` runs at boot
  (`runtime_main`), a revoked signer makes every MigTD log
  `SignerRevoked` and crash before migrating. The test **passes** iff a
  `SignerRevoked` line appears in the guest logs (definitive proof the control
  fired; the crash guarantees no migration). Debug dump added to "Check test
  outputs"; revoked policy added to the failure artifact set.
- **Note:** the emulator binary can't be built locally (msrustup), so this e2e
  step is validated in CI; the underlying `verify()` rejection is already proven
  locally by `migtd-policy-verifier` (P5) and the crypto/policy unit tests.

## Final validation (P7)

Unit suites (all green):
- `policy` v1: 26 passed · `policy` `policy_v2`: 45 passed
- `crypto`: 18 passed · `migtd` `policy_v2`: 42 passed
- `migtd` `test_disable_ra_and_accept_all`: compiles under `policy_v2`; the test
  build needs the `msrustup` registry here, so CI runs it.

e2e (local, via `migtd-policy-verifier` on generated policies — real
`RawPolicyData::verify`): normal `a`/`pm_b`/`pmi_b` → OK; `revoked` →
`SignerRevoked`; normal + unrelated chain → `SignerAnchorMismatch`.

## Coverage of the proposals (all items)

tcb_mapping_design_proposal.md: RTMR1 = TCBMapping issuer chain (CFV now that
chain; anchor pre-existing) ✓ · RTMR2 redacts `servtdTcbMapping` +
`servtdTcbMappingIssuerChain` ✓ · outer signature removed ✓ · `svnMappings`
keyed on `tdinfo_hash` (pre-existing) ✓.

rtmr1_signer_anchor_proposal.md: signer anchor (pre-existing, verified) ✓ ·
revocation — `is_revoked` ✓, CRL signature verify ✓, wired into local + peer
signer-chain checks ✓, CRL delivery + `servtd_crl_num` schema ✓, monotonic
anti-rollback ✓.

## Known limitations / follow-ups
- CoRIM (`servtd_corim` feature) revocation not wired (JSON `collaterals.servtd_crl`
  is the delivered path); `servtd_corim` needs the `corim` crate (network).
- The CFV slot GUID/event-tag are still named `*POLICY_ISSUER_CHAIN*`; their
  content is now the TCB-mapping signer chain (renaming is cosmetic and would
  churn enrollment tooling — left as-is, documented).
- Full emulator migration e2e runs only in CI (msrustup registry).

## Security review (code-review agent) — outcome

Verdict: **no exploitable issues** in the changed trust chain; all five reviewed
concerns (anchor binding, outer-sig removal, CRL revocation, revocation wiring,
anti-rollback) verified sound. Two low-severity hardening notes were raised:

- **B (fixed):** `verify_signer_chain_not_revoked` authenticated the CRL against
  *any* chain cert matching the CRL issuer subject, without requiring `cA=TRUE`.
  A non-CA end-entity leaf (whose key a peer may hold) could thus masquerade as a
  CRL issuer. **Fix:** require the matched issuer to be a CA (`is_ca_certificate`)
  before trusting it to sign the CRL. New regression test
  `signer_chain_not_revoked_rejects_non_ca_crl_issuer` (+ fixtures
  `nonca_leaf_chain.pem`, `crl_leaf_issued.pem`). This *also* closes note A's
  forgery vector: a peer cannot sign a CA/root-issued CRL without the root key.
- **A (documented):** the `servtd_crl_num` freshness floor reads `get_crl_number`
  from the delivered CRL. Its trust for a *peer's* CRL rests on (i) the CRL being
  authenticated by `verify_signer_chain_not_revoked` (now CA-issued only, fix B),
  and (ii) `validate_peer_cert_chain` binding the peer's root to the local root —
  so the peer's CRL must be signed by the shared root the peer does not control.
  Actual revocation is enforced by the **local** root-issued CRL in the peer
  cross-check; that backstop only runs when the **local** policy carries a
  `servtdCrl`, so production policies should always ship one (the e2e generator
  embeds an empty CRL in every variant). Unlike `pck_crl` (DCAP-authenticated),
  the servtd CRL has no external authenticator, so this local-CRL dependency is
  the intended trust root.

crypto suite after fix: 19 passed. Verifier re-check: normal → OK, revoked →
`SignerRevoked` (root-issued CRLs are CA-issued, unaffected by fix B).

## Post-review refinement — move `servtdCrl` into `servtdCollateral`

Reviewer/author feedback: the signer CRL belongs with the servTD signers it
revokes, not in the platform `collaterals` (SGX PCK / QE / platform CRLs — a
different PKI). Moved `servtd_crl` from `Collaterals` to `ServtdCollateral`
(`servtd_collateral.rs`). Measurement-neutral: `servtdCollateral` is measured into
RTMR2 except the redacted `servtdTcbMapping*` fields, so `servtdCrl` (a non-redacted
sibling) stays measured — same anti-rollback property.

- `policy.rs`: `verify()` reads `servtd_collateral.servtd_crl`; `VerifiedPolicy`
  gains a `servtd_crl` field so the peer cross-check and floor can read it.
- `mig_policy.rs`: `servtd_crl_num_from_collaterals` → `servtd_crl_num_from_policy`
  (reads `VerifiedPolicy.servtd_crl`); peer cross-check reads `local_policy.servtd_crl`.
- Tooling: `servtd-collateral-generator` gains `--servtd-crl` (RawValue-safe embed;
  no `jq` re-serialization that would break the inner signatures). The build script
  embeds the empty/revoking CRL per variant via that flag; `inject_servtd_crl` and
  the collaterals-CRL variants are removed.
- Empirical cross-check of Intel's PKI (repo CRLs + QVL `PckCrlVerifier`): the Root
  CA CRL is self-signed by the root key; the PCK CRL is signed by the issuing
  intermediate — confirming our same-root-CA-signs-the-CRL approach is standard.

Validation: policy v2 45, v1 26, migtd 42; verifier on regenerated policies —
normal/pm_b/pmi_b → OK, revoked → `SignerRevoked` (`servtdCollateral.servtdCrl`
present, `collaterals.servtdCrl` absent). Proposal doc updated to match.
