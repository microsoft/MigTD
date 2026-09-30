RTMR1 Signer-Anchor Measurement
================================================

> The scope of this proposal is limited to **what MigTD measures into RTMR1**. The
> RTMR2 / TCB-mapping circular-dependency work is covered separately in
> [tcb_mapping_design_proposal.md](./tcb_mapping_design_proposal.md); this proposal
> is the companion change called out there under *"RTMR1 signer anchor for key
> rotation"*.
> For the concrete current measurement values see
> [policy_v2_measurements.md](./policy_v2_measurements.md).

# Current design — RTMR1 measures the raw issuer cert chain

Today RTMR1 is, after the firmware boot separator, a **runtime extend over the raw
bytes of the policy/identity issuer certificate chain** (`policy_issuer_chain.pem`),
loaded from the CFV slot `MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID`. The MigTD core measures
it at boot into `mr_index = 2` → RTMR1 (`get_policy_issuer_chain_and_measure`,
`src/migtd/src/bin/migtd/main.rs`; tag `TAGGED_EVENT_ID_POLICY_ISSUER_CHAIN`). The
offline reference tool reproduces it as `rtmr1()` in `tools/migtd-hash/src/lib.rs`.

```
RTMR1_1     = SHA384( 0x00*48 || SHA384(separator 0x00000000) )   (td-shim)
RTMR1_final = SHA384( RTMR1_1 || SHA384(issuer_chain_bytes) )     (MigTD core)
                                          ▲
                                          └── the ENTIRE PEM chain, byte-for-byte
```

RTMR1 is part of `TDINFO`, so it folds into `tdinfo_hash = SHA384(TDINFO)` — the value
the TCB-mapping proposal uses as the `svnMappings` key and as the endorsed
`init/cur_servtd_info_hash`.

**What the chain is actually for.** The chain establishes the *trust anchor* for the
policy/identity signer. At runtime, MigTD-to-MigTD peer validation
(`validate_peer_cert_chain`, `src/crypto/src/lib.rs:290`) enforces only:

1. the peer chain's internal signatures are valid,
2. **the root CA matches by DER byte comparison**,
3. **the leaf certificate Subject Name matches**, and
4. every issuer in the chain is a CA (non-CA issuers rejected).

Note what the trust model does **not** require: an identical *leaf certificate* or an
identical *leaf public key*. Two MigTDs trust each other as long as they share the same
root CA and the same leaf Subject — the leaf key may differ.

The trust model also **does not pin intermediate-CA identity**: intermediate cert contents
are not compared against the local chain's intermediates, so either side may rotate its
intermediate CA(s) independently — as long as the shared root and the leaf Subject stay
stable and every issuer in the chain is itself a CA (check 4). Intermediates are still
validated *structurally* — signature integrity (check 1) and the CA attribute (check 4) —
just not by identity.

This rests on an **assumption about the leaf Subject**: the leaf cert's Subject Name
uniquely identifies the intended usage for the product/model — distinct usages must use
distinct Subject Names in their leaf certs. The RTMR1 anchor defined below inherits this
assumption, since it commits to that Subject (`S`).

```
   Runtime trust model (peer validation)      RTMR1 measurement (today)
   ───────────────────────────────────        ─────────────────────────
   cares about:  root DER  +  leaf Subject     hashes:  the WHOLE chain
   ignores:      leaf key, leaf cert bytes              (every byte, incl. leaf key)

                         ⇒ RTMR1 is far MORE sensitive than the trust model it encodes
```

# Problem 1: leaf-key rotation churns RTMR1

Issuers rotate the leaf signing key periodically (routine key rotation), issuing a new
leaf certificate under the *same root CA and same leaf Subject*.

**Peer-to-peer attestation already supports this.** As described above, peer validation
keys on the root CA and leaf Subject — not the leaf key — so old- and new-key builds
interoperate in a rolling deployment (commit `2d238cf3`).

**The attestation service does not.** Because RTMR1 hashes the *raw chain bytes*, the new
leaf changes RTMR1 → changes `tdinfo_hash`, so each rotation forces:

- a new MigTD **build** (the rotated chain is baked into the measured image), and
- a new **endorsement** entry keyed on the new `tdinfo_hash`, published to the attestation
  service so tenant TDs bound to the rotated MigTD still attest successfully.

So a rotation the runtime treats as a no-op becomes a build-and-endorsement update the
attestation service must track — deployment complexity for a change that does not touch the
trust anchor. RTMR1 is measuring the wrong granularity: the leaf key, not the trust anchor.

# Problem 2: regional leaf certificates fragment the RTMR1 measurement

Independently of the attestation format, the issuer may use a **different leaf certificate
per region** (regional keys / HSMs) while keeping the same root CA and same leaf Subject.
The runtime trust model treats all of these as the *same* anchor. But raw-chain RTMR1
hashes the exact chain bytes, so each region produces a *different* RTMR1 — and therefore a
different RTMR1 contribution to `tdinfo_hash` — for identical MigTD code and an identical
trust anchor:

```
   region A leaf ─┐
   region B leaf ─┼─ same root + same leaf Subject, different leaf cert/chain
   region C leaf ─┘
        raw chain in RTMR1:  3 different RTMR1  (chain bytes differ per region)
        signer anchor:       1 RTMR1 anchor     (root + leaf Subject identical)
```

So the trust-anchor measurement fragments by region for no trust-relevant reason — each
region needs its own `svnMappings` / endorsement entry even though the MigTD code and the
trust anchor are identical.

# Problem 3: CoRIM reuse for Azure attestation duplicates the cert chain

A goal of the TCB-mapping proposal is to make the signed `servtdTcbMapping` reusable
as-is by the tenant attestation service — instead of relying on separate out-of-band
endorsements. To realize that reuse in the **Microsoft Azure** environment, the mapping
must be reformatted as a **CoRIM** endorsement — the endorsement / reference-value format
consumed by the **Microsoft Azure Attestation (MAA)** service. A CoRIM endorsement
**embeds the signer's certificate chain** (the COSE `x5chain` parameter) so a verifier can
establish the signer trust anchor from the artifact itself.

If RTMR1 *also* folds the raw chain bytes into `tdinfo_hash`, the same chain is carried
twice — once inside the CoRIM, once inside the measurement — and the two copies must be
kept byte-consistent forever (two sources of truth for one signer).

```
   CoRIM endorsement (signed)              RTMR1 → tdinfo_hash
   ┌──────────────────────────────┐        ┌──────────────────────────────┐
   │ svnMappings / measurements    │        │ SHA384( … || SHA384(chain) )  │
   │ x5chain: [leaf, …, root]  ◄───┼── same │   full chain bytes again  ◄───┤
   └──────────────────────────────┘  chain  └──────────────────────────────┘
                         ▲                                   ▲
                         └──── duplicated, must stay in sync ┘
```

# Proposal — measure a stable signer anchor

Replace the raw-chain RTMR1 extend with an extend over a **signer anchor** `A` that
commits to *exactly the trust-anchor identity the runtime enforces* — the root CA and
the leaf Subject — and nothing else.

| | Today | Proposed |
|---|-------|----------|
| **RTMR1 extend input** | `SHA384(raw issuer chain PEM bytes)` | `SHA384(A)` where `A` is the signer anchor below |
| **CFV slot `MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID`** | full signing cert chain (unchanged) | full signing cert chain (**unchanged**) |
| **What RTMR1 is sensitive to** | every byte of the chain (incl. leaf key) | root CA DER + leaf Subject DER only |

The CFV still ships the **full** chain (peer validation and policy/identity signature
verification still need it); only **what is hashed into RTMR1** changes — a small,
stable anchor derived from the chain rather than the chain's raw bytes.

## RTMR1 signer-anchor formula

Define `H(x) = SHA384(x)`.

1. Root component:  `R = H(DER(root_certificate))`
2. Leaf-subject component:  `S = H(DER(leaf_certificate.tbsCertificate.subject))`
3. Domain-separated anchor:  `A = H("MIGTD-RTMR1-ANCHOR-V1" || 0x00 || R || 0x00 || S)`
4. RTMR extend chain:
   - `RTMR1_0 = 48-byte zero`
   - `RTMR1_1 = H( RTMR1_0 || H(separator_event_payload) )`   *(td-shim boot separator, unchanged)*
   - `RTMR1_final = H( RTMR1_1 || H(A) )`                     *(MigTD core, anchor event)*

`DER(...subject)` is the raw DER encoding of the leaf `tbsCertificate.subject`, used
(rather than a text rendering of the Distinguished Name) to avoid encoding ambiguity.
The `"MIGTD-RTMR1-ANCHOR-V1"` tag provides domain separation and a version hook for
future formula changes.

`A` deliberately commits to **only** the root CA and the leaf Subject — **not** the
intermediate CAs — matching peer validation, which likewise does not pin intermediate
identity. Intermediate-CA rotation under the same root + leaf Subject therefore leaves
RTMR1 unchanged, exactly as leaf-key rotation does.

# Benefits

- **No rotation churn** — `A` depends on the root CA and leaf Subject, not the leaf public
  key, so a leaf re-issue under the same root + Subject leaves RTMR1 **unchanged**. With
  the companion RTMR2 measuring policy without TCBMapping, the whole `tdinfo_hash` is then
  unchanged when nothing else changes — a key rotation needs no new endorsement /
  `svnMappings` entry.
- **Intermediate-CA rotation is free too** — `A` excludes intermediate CAs (matching peer
  validation, which does not pin intermediate identity), so rotating an intermediate CA
  under the same root + leaf Subject also leaves RTMR1 unchanged — no rebuild, no new
  endorsement.
- **Region-independent measurement** — regional leaf certificates that share the root +
  Subject produce the **same** RTMR1, and the same `tdinfo_hash` when nothing else differs,
  so one endorsement covers all such regions instead of one per region.
- **No CoRIM duplication** — RTMR1 commits to the *anchor identity* (root + Subject),
  not the chain bytes, so the CoRIM remains the single carrier of the full chain. No
  two-sources-of-truth synchronization burden.
- **Measurement matches the trust model** — RTMR1's sensitivity becomes exactly that of
  `validate_peer_cert_chain` (root DER + leaf Subject). The measured value answers the
  same question the runtime asks.
- **Trust-anchor changes stay visible** — changing the **root CA** DER changes `R` and
  therefore RTMR1 (intended); only leaf-key churn is decoupled.

# Design details

## Alignment with runtime peer validation

The anchor is the measured projection of the two equality checks already enforced by
`validate_peer_cert_chain` (`src/crypto/src/lib.rs:290`):

| Peer-validation check | Anchor component |
|-----------------------|------------------|
| Root CA must match (DER byte comparison) | `R = H(DER(root))` |
| Leaf Subject Name must match | `S = H(DER(leaf subject))` |
| Intermediate-CA identity **not** pinned (independent rotation allowed) | not folded into `A` — the anchor excludes intermediates, so intermediate rotation is measurement-stable |
| Chain internal signatures valid; non-CA issuers rejected | enforced at runtime; not folded into `A` (integrity, not identity) |

Contrast with `get_policy_signer_key_hash` (`src/crypto/src/lib.rs:105`), which hashes
the **leaf public key** and therefore *does* change on rotation. The anchor deliberately
avoids the leaf key so that rotation is measurement-stable.

## What changes when the leaf signing key rotates

Assumption: only the leaf signing key rotates — MigTD code, policy rules, root CA, and
leaf Subject are unchanged.

| Component | Changes? | Why |
|-----------|----------|-----|
| **MRTD** | No | Cert chain lives in the CFV (unmeasured content of the IGVM image) |
| **RTMR0** | No | MigTD binary code unchanged |
| **RTMR1** | **No** | `A` depends on root DER + leaf Subject DER, not the leaf key |
| **RTMR2** | No¹ | the companion RTMR2 (policy without TCBMapping) is unchanged here |
| **`tdinfo_hash` / endorsement** | No | no register changed, so the hash — and its existing endorsement — still apply |
| **IGVM rebuild** | No | only the CFV leaf cert is swapped (`td-shim-enroll`); the measurement is unchanged |

¹ RTMR2 is the companion [TCB-mapping proposal](./tcb_mapping_design_proposal.md)'s domain;
this proposal changes only RTMR1. RTMR2 redacts TCBMapping, so rotating the TCBMapping
signing leaf — the trust authority RTMR1 anchors — leaves RTMR2 (and the hash) unchanged.

## Regional leaf certificates

Regional leaf certificates are just the spatial version of rotation: every region whose
leaf shares the root + Subject produces the **same RTMR1**, and the **same `tdinfo_hash`** when
nothing else differs. Operators provision region-specific leaf certs into each region's
CFV slot (`MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID`); the authority then publishes **one**
`svnMappings` entry for all of them instead of one per region. Peer migration across
regions passes because the runtime check keys on root + Subject.

## Boot & offline measurement flow

- **Boot (MigTD core):** load the chain from CFV → parse the root certificate and the
  leaf `tbsCertificate.subject` → compute `R`, `S`, `A` → extend RTMR1 with `H(A)` and
  emit one event-log entry. The full chain remains available for signature verification
  and peer validation.
- **Offline (`migtd-hash` `rtmr1()`):** compute the identical `A` from the same CFV
  chain so the reproduced `tdinfo_hash` matches the running TD. This replaces the current
  "extend over raw chain bytes" path.

# Security considerations — signing-key compromise

The anchor lowers RTMR1's sensitivity from the exact issuer-chain bytes to **root CA + leaf
Subject**. That relaxation is the source of the proposal's rotation/region agility — and of one
new risk. This section states what the change introduces and what it leaves unchanged.

## Limitation introduced: stolen intermediate cert chain

Raw-chain RTMR1 (today) hashes the exact chain bytes, so **any** certificate change in the chain
alters RTMR1 — and therefore `tdinfo_hash` — including a leaf freshly minted by a **stolen
intermediate CA** under the same root and same leaf Subject. The signer anchor commits to root +
leaf Subject only, so that same stolen-intermediate-minted leaf becomes
**measurement-indistinguishable**: identical `A`, identical RTMR1, identical `tdinfo_hash`.

```
   stolen intermediate CA key (same root + same leaf Subject)
             │  mints a new leaf, signs
             ▼
   forged servtdTcbMapping:  { tdinfo_hash(vulnerable_MigTD) → high SVN }
             │
             ▼   passes validate_peer_cert_chain (root + Subject + CA-attr) and CoRIM x5chain
             ▼
   vulnerable MigTD resolves to high SVN → clears the baseline → accepted

   raw-chain RTMR1 :  new leaf ⇒ different tdinfo_hash  (measurement-visible)
   signer anchor   :  same root+Subject ⇒ SAME tdinfo_hash  (measurement-INvisible)  ← new risk
```

The anchor trades away RTMR1's ability to distinguish a different signing certificate under the
same root + Subject. A **stolen intermediate CA** — which can issue an arbitrary Subject-matching
leaf — is the concrete exposure this proposal introduces, and it must be mitigated at the
PKI/authorization layer (below).

## Not introduced here: stolen leaf key (reused certificate)

A stolen **leaf private key** used with the **existing leaf certificate** changes no certificate
bytes, so it is invisible to RTMR1 under **both** the raw-chain scheme and the anchor —
`tdinfo_hash` is unchanged either way. This risk therefore exists **with or without this
proposal** and must be mitigated independently; the anchor neither adds nor removes it.

In both cases the forgery clears every check the runtime performs today
(`verify_cert_chain_and_signature`, `src/crypto/src/lib.rs:123`; `validate_peer_cert_chain`,
`:290`) — those enforce only chain integrity, root match, leaf Subject, and the CA attribute,
with **no revocation, no expiry, and no leaf-key/intermediate pinning** — and the attestation
service accepts the mapping by CoRIM `x5chain` signature alone. Measurement answers *"what bytes
are loaded,"* not *"is this signer still authorized"*; the fix is authorization-layer, not
measurement.

## Mitigations

Neither attack is visible to measurement, so both are handled at the PKI layer — and only two
controls actually apply:

- **Strict key protection, especially for intermediate CA keys.** Because the anchor no longer
  distinguishes a rogue same-Subject leaf minted by a stolen intermediate, *preventing*
  intermediate-key compromise is the primary control: keep signing keys — above all the
  intermediate CAs — in an HSM, offline, rarely used, ideally under m-of-n quorum.
- **Certificate revocation — the mitigation for the stolen leaf key, and for intermediate keys
  once detected.** A stolen leaf key reusing its existing certificate is invisible to measurement
  with or without this proposal, so it is handled the standard PKI way: revoke the leaf (or
  intermediate) certificate and have consumers reject it. Today neither
  `verify_cert_chain_and_signature` nor `validate_peer_cert_chain` checks revocation
  (`src/crypto/src/lib.rs:123`, `:290`); add CRL/OCSP at the attestation service, and in-guest
  extend the existing CRL support (`src/crypto/src/crl.rs`, `get_crl_number`) to cover the signing
  chain, gated on a monotonic CRL number.

**Recommendation.** Treat the stolen-leaf-key case as pre-existing PKI hygiene (revocation), and
accept the stolen-intermediate case as the explicit price of the anchor's rotation/region
agility, offset by strict intermediate-key protection.

## Implementation sketch — revocation support (effort estimate)

Spelled out so the revocation mitigation can be scoped. The **attestation-service** side is
standard PKI — run CRL/OCSP on the CoRIM `x5chain` with an off-the-shelf verifier — and is not
detailed here. The **in-guest** side is where the work is; it breaks down as follows.

**Already present (reusable):**

- **CRL parsing** — `src/crypto/src/crl.rs` already decodes an X.509 CRL (`Crl` / `TbsCertList`),
  including the `revokedCertificates` list (`RevokedCertificate.user_certificate` serials),
  `thisUpdate` / `nextUpdate`, and the CRL Number extension via `get_crl_number()`.
- **Monotonic-CRL-number pattern** — the platform flow already stores per-CRL floors in the
  policy (`pck_crl_num`, `root_ca_crl_num`, `src/policy/src/v2/policy.rs:163-167`) and compares
  them against `get_crl_number()` of the delivered CRLs (`src/migtd/src/mig_policy.rs:581-583`).
  The signer-CRL anti-rollback check can copy this verbatim.
- **Signature primitives** — `verify_signature_with_algorithm` (`src/crypto/src/lib.rs`) already
  does the ECDSA/chain verification the CRL-signature check needs.

**New work required:**

1. **Revocation-by-serial check** (crypto, *small*) — `crl.rs` parses `revokedCertificates` but
   only exposes `get_crl_number`; add `is_revoked(crl, cert) -> bool` matching a cert's serial
   against the list. Data is already decoded.
2. **CRL signature verification** (crypto, *small–medium*) — `get_crl_number` only parses; it does
   not verify the CRL was signed by the issuing CA. Add verification of the CRL `signatureValue`
   against the issuer public key before trusting its contents.
3. **Wire revocation into the signer-chain checks** (crypto + migtd, *medium*) — have
   `verify_cert_chain_and_signature` (`lib.rs:123`) and/or `validate_peer_cert_chain` (`:290`)
   check each cert in the mapping/identity chain against the CRL and fail closed if revoked. This
   touches the hot verification path and both the local and peer flows.
4. **CRL delivery + schema** (policy, *medium*) — add a slot to carry the servtd signer CRL(s)
   (analogous to `root_ca_crl` / `pck_crl`, `src/policy/src/v2/collaterals.rs:88-89`) plus a policy
   floor `servtd_crl_num`. The CRL ships alongside the policy (CFV or collateral), and the policy
   generator/signing tooling must emit it.
5. **Anti-rollback enforcement** (migtd, *small*) — compare the delivered signer CRL's
   `get_crl_number()` against the `servtd_crl_num` floor and reject older; copy
   `mig_policy.rs:581-583`.

**Constraint — no trusted clock in-guest.** Time is VMM-supplied, so the guest cannot enforce the
CRL `nextUpdate` window; in-guest freshness relies on the monotonic CRL number (item 5), while
time-based freshness is enforced only at the service.

**Bottom line.** Items 1, 2, 5 are small; items 3 and 4 are the bulk (verification-path
integration and schema/delivery/tooling). No new crypto primitives are needed — CRL decoding,
hashing, and ECDSA verification all already exist.

# Notes

- **This proposal changes only RTMR1.** RTMR2 (the policy) is the companion
  [TCB-mapping proposal](./tcb_mapping_design_proposal.md)'s concern. Together the two keep
  `tdinfo_hash` the same across leaf rotation and across regions whenever the code, policy
  content, and trust anchor (root + Subject) are unchanged, while still binding the exact
  policy content. (A genuine content change — e.g. re-issuing `servtdIdentity` — does
  change RTMR2 and the hash, as intended.)
- **Orthogonal to the TCB-mapping proposal's RTMR2 changes.** That proposal's removal of the
  outer policy signature (now part of the proposal itself, not a future item) and its remaining
  *Future consideration* of dropping `servtdIdentity` both affect only **RTMR2** (the signed
  `policyData`), not RTMR1; this RTMR1-only change is orthogonal to either and can ship before,
  after, or without them.
- **Security trade-off — anchor binds identity, not the leaf key.** `A` commits to the
  root CA and the leaf Subject — **not** the leaf public key, and **not** the intermediate
  CAs. A leaf key (or an intermediate CA) compromised under the same root + Subject is
  therefore *not* distinguished by RTMR1 alone. This matches the existing runtime trust
  model and makes the root CA the unit of trust — the intended, explicit trade-off. Its
  consequences for a forged TCB mapping, and the mitigations, are detailed in
  *[Security considerations — signing-key compromise](#security-considerations--signing-key-compromise)* above.
- **Root rotation still visible.** Rotating or adding a *root* CA changes `R` and thus
  RTMR1 — intended, since that is a genuine trust-anchor change that should re-endorse.

# Current RTMR1 implementation (reference)

| Concern | Location |
|---------|----------|
| RTMR1 runtime extend (raw chain today) | `src/migtd/src/bin/migtd/main.rs` (`get_policy_issuer_chain_and_measure`) |
| `mr_index 2 → RTMR1`, tag id | `src/migtd/src/event_log.rs` (`MR_INDEX_POLICY_ISSUER_CHAIN`, `TAGGED_EVENT_ID_POLICY_ISSUER_CHAIN`) |
| Offline RTMR1 reproduction | `tools/migtd-hash/src/lib.rs` (`rtmr1`) |
| Peer trust model (root DER + leaf Subject) | `src/crypto/src/lib.rs:290` (`validate_peer_cert_chain`) |
| Leaf-public-key hash (changes on rotation; not used by anchor) | `src/crypto/src/lib.rs:105` (`get_policy_signer_key_hash`) |
| CFV slot holding the chain | `MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID` (`src/migtd/src/config.rs`) |
