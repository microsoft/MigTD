servTD Signer-Key Revocation
================================================

> The scope of this proposal is **in-guest revocation of the servTD signer chain**
> (the TCB-mapping and identity issuers). It is the companion mitigation called out
> in [rtmr1_signer_anchor_proposal.md](./rtmr1_signer_anchor_proposal.md) under
> *"Security considerations — signing-key compromise"* and *"Implementation sketch —
> revocation support"*, promoted here to a standalone design and backed by a working
> proof-of-concept (see *Reference implementation* below).
>
> It does **not** change what MigTD measures (that is the RTMR1 anchor and RTMR2
> redesign proposals' domain); it adds an **authorization-layer** control on top of
> the existing trust model. For the concrete measurement values see
> [policy_v2_measurements.md](./policy_v2_measurements.md).

# Why revocation is needed

MigTD's runtime trust in a peer, and its own trust in the policy/identity signer,
rests on `verify_cert_chain_and_signature` (`src/crypto/src/lib.rs`) and
`validate_peer_cert_chain` (`src/crypto/src/lib.rs`). Those enforce **chain
integrity, root-CA match, leaf-Subject match, and the CA attribute** — but
**no revocation, no expiry, and (with the RTMR1 signer anchor) no leaf-key or
intermediate-CA pinning**. Two compromise cases follow from that, both invisible to
measurement:

1. **Stolen leaf private key, reused certificate.** No certificate bytes change, so
   RTMR1/`tdinfo_hash` are unchanged with *or* without the signer anchor. This risk
   pre-exists the anchor and must be handled the standard PKI way.

2. **Stolen intermediate CA.** With the RTMR1 signer anchor (which commits only to
   *root CA + leaf Subject*), a rogue leaf minted by a stolen intermediate under the
   same root and Subject is **measurement-indistinguishable** from the legitimate
   signer. This is the explicit price of the anchor's rotation/region agility.

```
   stolen intermediate CA key (same root + same leaf Subject)
             │  mints a new leaf, signs a forged servtdTcbMapping
             ▼
   forged mapping:  { tdinfo_hash(vulnerable_MigTD) → high SVN }
             │
             ▼   passes chain integrity + root + Subject + CA-attr (and the RTMR1 anchor)
             ▼
   vulnerable MigTD resolves to a high SVN → clears the baseline → accepted
```

Measurement answers *"what bytes are loaded"*, not *"is this signer still
authorized"*. The fix is therefore at the **authorization layer**: publish and
enforce a **Certificate Revocation List (CRL)** for the servTD signer chain, and
fail closed when a signer certificate is revoked.

# Current state

- **CRL parsing exists but only for platform TCB.** `src/crypto/src/crl.rs` decodes
  an X.509 CRL and exposes `get_crl_number()`; the platform flow stores per-CRL
  floors in the policy (`pck_crl_num`, `root_ca_crl_num`) and compares them against
  the delivered `pck_crl` / `root_ca_crl` in the collaterals. Actual
  platform-certificate revocation is delegated to the quote-verification path
  (`verify_quote_with_collaterals`, the `attestation` crate).
- **The servTD signer chain has no revocation at all.** Neither
  `verify_cert_chain_and_signature` nor `validate_peer_cert_chain` consults any CRL,
  and there is no delivery slot, no signature check on a CRL, and no serial lookup.

# Proposal

Deliver a **servTD signer CRL alongside the policy** and enforce it in-guest,
fail-closed, reusing the platform-CRL machinery wherever possible.

| Concern | Mechanism |
|---------|-----------|
| **Delivery** | `servtdCollateral.servtdCrl` — an optional PEM CRL inside the servTD collateral, co-located with the signers it revokes (`servtdIdentity`, `servtdTcbMapping`, and their issuer chains). |
| **Authentication** | The CRL's signature is verified against the issuing **CA** in the (RTMR1-anchored) signer chain before any of its contents are trusted. |
| **Enforcement** | Every certificate in the servTD TCB-mapping and identity signer chains is checked against the CRL; a revoked serial fails closed with `PolicyError::SignerRevoked`. Applied to both the local policy and (against the *local* CRL) the peer's chains. |
| **Anti-rollback** | A monotonic `servtd_crl_num` policy floor rejects a CRL older than the policy requires — mirroring `pck_crl_num` / `root_ca_crl_num`. |

```
 ┌──────────────────────── policyData.servtdCollateral ─────────────────────────┐
 │  servtdIdentity{,IssuerChain}  servtdTcbMapping{,IssuerChain}  (the signers)  │
 │  servtdCrl        ◄── NEW: PEM CRL for the servTD signer chain                │
 └──────────────────────────────────────────────────────────────────────────────┘
                                    │
        RawPolicyData::verify()     ▼        (local self-check, fail-closed)
   verify_signer_chain_not_revoked(mapping_chain,  servtdCrl)
   verify_signer_chain_not_revoked(identity_chain, servtdCrl)
                                    │
 verify_policy_and_event_log()      ▼        (peer cross-check vs LOCAL servtdCrl)
   verify_signer_chain_not_revoked(peer.mapping_chain,  local.servtdCrl)
   verify_signer_chain_not_revoked(peer.identity_chain, local.servtdCrl)
                                    │
   CrlPolicy: servtd_crl_num ≥ floor  ▼        (monotonic anti-rollback)
```

# Design details

## CRL delivery — `servtdCollateral.servtdCrl`

A new optional field on the servTD collateral object carries the signer CRL as PEM
(`ServtdCollateral.servtd_crl: Option<String>`). It belongs here — not in the
platform `collaterals` (the `pck_crl` / `root_ca_crl` / `qeIdentity` collaterals — a
different PKI) — because it
revokes the **servTD** signer chain, keeping `servtdCollateral` a self-contained
servTD trust bundle. Optional preserves backward compatibility: a policy without it
simply skips the revocation check. `servtdCollateral` is part of `policyData` and is
**measured into RTMR2** except the redacted `servtdTcbMapping` /
`servtdTcbMappingIssuerChain` fields; `servtdCrl` is *not* redacted, so it is
measured. Updating the CRL is therefore a policy re-release; see *Measurement
interaction* for the trade-off and an alternative.

## Crypto primitives (`src/crypto/src/crl.rs`, `lib.rs`)

Three parsing/verification helpers plus one orchestrator:

- **`is_serial_revoked(crl, serial) -> bool`** — returns whether a big-endian serial
  magnitude appears in the CRL's `revokedCertificates`. Performs **no** signature
  check itself; callers MUST authenticate the CRL first. Both the certificate serial
  and the CRL entry are decoded as `UintRef`, so `as_bytes()` strips DER sign-padding
  identically on both sides (no leading-zero mismatch).
- **`verify_crl_signature(crl, issuer_public_key) -> Result<()>`** — verifies the
  CRL's `signatureValue` over its `tbsCertList` with the issuing CA's public key.
  The algorithm is **hard-pinned to ECDSA-P384/SHA-384** (`ECDSA_WITH_SHA384_OID` +
  `ECDSA_P384_SHA384_ASN1`), matching the rest of the crate — no algorithm
  agility, no confusion.
- **`get_crl_issuer_der(crl) -> Vec<u8>`** — returns the CRL `issuer` Name DER, used
  to locate the issuing CA within the signer chain.
- **`verify_signer_chain_not_revoked(chain_pem, crl_pem) -> Result<()>`** (the
  orchestrator, `src/crypto/src/lib.rs`):
  1. **Authenticate before trust.** Locate the certificate in the chain whose
     `subject` DER equals the CRL `issuer` DER **and which is a CA**
     (`cA=TRUE`, RFC 5280 — see *Security analysis §B*), then verify the CRL
     signature with that CA's key. An issuer not present as a CA in the chain, or a
     bad signature, is a hard error (fail-closed).
  2. **Reject on revocation.** If the serial of **any** certificate in the chain is
     in the CRL, return an error.

  Freshness/anti-rollback (the monotonic CRL number) is intentionally **not** done
  here; it lives in the policy layer so it can be expressed as a policy rule.

## Enforcement points

- **Local self-check** — `RawPolicyData::verify()` (`src/policy/src/v2/policy.rs`):
  if `servtdCollateral.servtdCrl` is present, it runs `verify_signer_chain_not_revoked`
  against **both** the TCB-mapping and identity signer chains, mapping any failure to
  `PolicyError::SignerRevoked`. This runs at boot (`initialize_policy` →
  `init_policy`), so a MigTD whose own policy revokes its signer refuses to start.
- **Peer cross-check** — `verify_policy_and_event_log()`
  (`src/migtd/src/mig_policy.rs`): after the peer policy is verified and its chains
  are matched to the local root/Subject via `validate_peer_cert_chain`, the peer's
  mapping and identity signer chains are additionally checked against the **local**
  policy's `servtdCrl`. This is the backstop against a peer that ships a laundered
  (revocation-free) CRL of its own — the authoritative revocation list is the local
  one.

## Anti-rollback floor — `servtd_crl_num`

`PolicyEvaluationInfo` gains a `servtd_crl_num` field, populated by
`servtd_crl_num_from_policy()` (`src/migtd/src/mig_policy.rs`) via
`get_crl_number(servtdCollateral.servtdCrl)`. `CrlPolicy` gains an optional
`servtd_crl_num` property (`src/policy/src/v2/policy.rs`) evaluated exactly like
`pck_crl_num`: a `greater-or-equal` floor rejects a CRL number below the policy
minimum, and a missing number while a floor is set fails closed
(`PolicyError::CrlEvaluation`).

## Constraint — no trusted clock in-guest

Guest time is VMM-supplied and untrusted, so MigTD **cannot** enforce the CRL's
`nextUpdate` validity window. In-guest freshness relies entirely on the **monotonic
CRL number** (`servtd_crl_num`); wall-clock/`nextUpdate` freshness is enforced only
at the attestation service (out of scope here).

# Security analysis

## What it defends

- **Revoked leaf or intermediate.** Once the authority publishes a CRL listing the
  compromised certificate's serial, any policy carrying that CRL — and any peer whose
  signer chain includes that serial — fails closed. This is the mitigation for the
  stolen-intermediate exposure the RTMR1 anchor introduces, and for the stolen-leaf
  case that pre-exists it.

## Trust dependencies (what makes it sound)

- **§A — the CRL number is only as trustworthy as the CRL's authentication.**
  `servtd_crl_num` is read with `get_crl_number` (a plain parse). It is meaningful
  because the *same* CRL bytes are authenticated by `verify_signer_chain_not_revoked`
  during `verify()`, and — in the peer flow — because `validate_peer_cert_chain`
  binds the peer's chain root to the **local** root, so the peer's CRL must be signed
  by the shared root the peer does not control. Unlike `pck_crl` / `root_ca_crl`
  (authenticated on the quote-verification path, `verify_quote_with_collaterals`),
  the servTD CRL has **no external authenticator**; its trust root is the local,
  RTMR1-anchored signer chain. The practical consequence: **production policies
  should always ship a `servtdCrl`**
  (an empty one if nothing is revoked), because the peer cross-check only runs when
  the *local* policy carries one.
- **§B — only a CA may issue the CRL.** The CRL signer is required to carry
  `BasicConstraints cA=TRUE`. Without this, a non-CA end-entity leaf — whose private
  key a peer legitimately holds — could sign its own revocation-free CRL and satisfy
  both the revocation check and the freshness floor. Requiring a CA means a peer
  cannot forge a CRL without the (shared, uncompromised) root key.

## Residual / out of scope

- **Stolen key with a not-yet-revoked certificate** is invisible until the authority
  detects the compromise and publishes a revoking CRL — inherent to CRL-based
  revocation.
- **`nextUpdate` freshness** is not enforceable in-guest (no trusted clock).
- **The attestation-service side** (CRL/OCSP over the CoRIM `x5chain`) is standard
  PKI and not detailed here.

# Measurement interaction and an alternative

`servtdCrl` lives in `servtdCollateral`, which is part of `policyData`, so it is
**measured into RTMR2** and folded into `tdinfo_hash`. Consequences:

- **Rollback of the CRL is measurement-visible** as well as floor-gated
  (defense-in-depth).
- **Updating the CRL churns `tdinfo_hash`**, i.e. revoking a signer is a policy
  re-release + re-endorsement. Because revocation is a rare, deliberate event, this
  is acceptable and matches how the platform `root_ca_crl` / `pck_crl` (also inside
  the measured `policyData`) already behave.

# Reference implementation (proof-of-concept)

Implemented and validated on branch `one_hash` (see
[one_hash_impl_notebook.md](./one_hash_impl_notebook.md)). All symbols below exist
today.

| Concern | Location |
|---------|----------|
| Serial-revocation lookup | `src/crypto/src/crl.rs` — `is_serial_revoked` |
| CRL signature verification (ECDSA-P384/SHA-384) | `src/crypto/src/crl.rs` — `verify_crl_signature` |
| CRL issuer Name DER | `src/crypto/src/crl.rs` — `get_crl_issuer_der` |
| CRL number (reused) | `src/crypto/src/crl.rs` — `get_crl_number` |
| Chain-vs-CRL orchestrator (authenticate → reject; CA-issuer required) | `src/crypto/src/lib.rs` — `verify_signer_chain_not_revoked` |
| Delivery slot | `src/policy/src/v2/servtd_collateral.rs` — `ServtdCollateral.servtd_crl` |
| Local self-check + error | `src/policy/src/v2/policy.rs` — `RawPolicyData::verify`; `src/policy/src/lib.rs` — `PolicyError::SignerRevoked` |
| Anti-rollback floor | `src/policy/src/v2/policy.rs` — `CrlPolicy.servtd_crl_num`, `PolicyEvaluationInfo.servtd_crl_num` |
| Peer cross-check + floor input | `src/migtd/src/mig_policy.rs` — `verify_policy_and_event_log`, `servtd_crl_num_from_policy` |
| Generator (empty + revoking CRLs; `--servtd-crl` embed; revoked variant) | `sh_script/build_AzCVMEmu_policy_and_test.sh` — `generate_servtd_crls`; `tools/servtd-collateral-generator` — `--servtd-crl` |
| e2e negative test | `.github/workflows/integration-emu.yml` — *Policy v2 Signer Revocation (Mock Report)* |

## Tests

- **Unit (crypto):** `is_serial_revoked` true/false/empty; `verify_crl_signature`
  accepts the correct issuer key and rejects the wrong one; the orchestrator passes
  an empty CRL, fails closed on a revoked leaf, and rejects a non-CA CRL issuer.
- **Unit (policy):** `CrlPolicy` `servtd_crl_num` floor (at/above passes, below and
  missing fail closed).
- **Integration:** `migtd-policy-verifier` on generated policies — normal → OK,
  `revoked` → `SignerRevoked`, unrelated chain → `SignerAnchorMismatch`.
- **e2e (CI):** a `policy_v2_signed_revoked.json` variant (its `servtdCrl` revokes
  the TCB-mapping signer leaf) is loaded on both sides; every MigTD fails closed at
  `initialize_policy` with `SignerRevoked` and refuses to migrate. The workflow
  inverts the pass/fail sense for `test-type: policy-v2-revoked` and asserts the
  `SignerRevoked` evidence in the guest logs.

# Future work / open questions

1. **CoRIM path.** When the servTD collateral is delivered as a signed CoRIM
   (the in-repo `servtd_corim` feature), the signer is the COSE `x5chain`
   (RFC 9360). Revocation there should thread the CRL through the COSE flow (or
   run CRL/OCSP on the `x5chain`); this PoC wires only the JSON
   `servtdCollateral.servtdCrl` path.
2. **Key-usage check.** Optionally require the CRL issuer to assert the `cRLSign`
   KeyUsage bit in addition to `cA=TRUE`, for defence-in-depth against a mis-issued
   CA certificate.
3. **Redact-for-updateability.** Evaluate moving `servtdCrl` out of the RTMR2 extend
   (see *Measurement interaction*) if in-place CRL updates without re-endorsement
   become desirable.
4. **Multiple / per-issuer CRLs.** The current slot is a single CRL authenticated
   against the signer chain's CA. A chain with distinct mapping- and identity-issuer
   CAs under different sub-CAs would need either one CRL per issuing CA or a small
   list; today both share the root, so one root-issued CRL covers both.
5. **Service-side revocation** (CRL/OCSP over the CoRIM `x5chain`, `nextUpdate`
   time-window enforcement) — standard PKI, tracked separately.
