RTMR1 Signer-Anchor Design and Signer Revocation
================================================

This document specifies the implemented Policy v2 signer identity measured in
RTMR1. RTMR2 and one-hash mapping behavior are defined in
[tcb_mapping_design_proposal.md](./tcb_mapping_design_proposal.md).

## Signer identity

MigTD identifies a policy/endorsement signer by:

- the SHA-384 fingerprint of its root certificate; and
- one dedicated signer-purpose leaf EKU OID.

Leaf public keys, leaf certificate bytes, subjects, and intermediate
certificate identities are not part of signer identity. This permits regional
leaf certificates and leaf/intermediate rotation under the same root+EKU.

## Anchor formula

Define `H(x) = SHA384(x)`:

```text
R = H(DER(root certificate))
A = H("MIGTD-RTMR1-ANCHOR-V1" || 0x00 || R || 0x00 || leaf_EKU_OID_DER)
```

After td-shim extends its separator event, MigTD extends `H(A)` into RTMR1
through the event-log helper:

```text
RTMR1_0     = zeros(48)
RTMR1_1     = H(RTMR1_0 || H(separator_event_payload))
RTMR1_final = H(RTMR1_1 || H(A))
```

Root or EKU changes alter RTMR1. Leaf-key and intermediate-CA rotation under
the same root+EKU do not.

## Enrollment forms

The CFV supports two mutually equivalent anchor sources.

### PEM-derived anchor

`MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID` carries a leaf-first PEM chain. MigTD
validates its anchor shape and derives `A` from the root DER and dedicated leaf
EKU. JSON collateral packaging uses this form because the same chain verifies
the inner JSON endorsements.

### Direct anchor

`MIGTD_SERVTD_SIGNER_ANCHOR_FFS_GUID` carries the precomputed 48-byte `A`.
CoRIM-only packaging uses this form because the signed CoRIM already carries
the full signer chain in its COSE `x5chain`; duplicating that chain in the CFV
is unnecessary.

`config::get_signer_anchor_source()` prefers the direct anchor slot if both
slots are populated. `policy::resolve_signer_anchor()` accepts either a
48-byte anchor or a PEM chain. `migtd-hash` follows the same precedence and
resolution rules.

The standard build CLI accepts either:

```text
--policy-issuer-chain <chain.pem>
--signer-anchor <anchor.bin>
```

At least one is required for Policy v2. The direct form is exactly 48 bytes.

## Runtime trust binding

The RTMR1 value and runtime verification enforce the same identity:

| Element | RTMR1 | Runtime verification |
|---|---|---|
| Root certificate | SHA-384 fingerprint in `A` | Peer/endorsement chain must have the same root |
| Signer purpose | Dedicated leaf EKU in `A` | Leaf must assert an EKU that reproduces `A` |
| Leaf key and certificate | Not included | Signature and chain validity checked, identity not pinned |
| Intermediate identity | Not included | Chain signatures and CA constraints checked |

JSON `servtdTcbMappingIssuerChain` bytes are redacted from RTMR2. The mapping
signature is accepted only when that chain resolves to the RTMR1 anchor.

CoRIM `x5chain` is similarly verified and bound to RTMR1 before any
`SERVTD_INFO_HASH -> SVN` lookup is trusted.

During pre-session exchange, a MigTD sends its anchor source: the direct
48-byte anchor when enrolled, otherwise its PEM issuer chain. The peer resolves
either representation to `A`, so the two packaging forms interoperate when
they share the same root+EKU.

## Rotation properties

| Change | RTMR1 changes? | Result |
|---|---:|---|
| Leaf key/certificate under same root+EKU | No | Rolling/regional rotation remains measurement-stable |
| Intermediate CA under same root+EKU | No | Intermediate rotation remains measurement-stable |
| Leaf subject | No | Subject is not signer identity |
| Root certificate | Yes | New trust anchor requires a new endorsement |
| Dedicated signer EKU | Yes | New signer purpose requires a new endorsement |

The JSON mapping issuer-chain bytes are unmeasured so leaf/intermediate
rotation can accompany the same image hash. JSON TD Identity and its issuer
chain remain measured in RTMR2; rotating or reissuing those bytes changes the
image hash by design.

## Security trade-off

The anchor identifies an authorization domain, not one signing key. A stolen
leaf key using its existing certificate is indistinguishable with or without
the anchor. A compromised intermediate can also mint a new leaf under the same
root+EKU without changing `A`.

Mitigations are:

- strong HSM and quorum protection for root/intermediate/signing keys;
- certificate-chain signature and CA-constraint validation;
- a measured servTD signer CRL; and
- authority-controlled signer EKU issuance.

## servTD signer CRL

Policy v2 accepts a top-level `servtdCrl` that applies to JSON signer chains
and CoRIM `x5chain`. The legacy `servtdCollateral.servtdCrl` location remains
accepted.

MigTD verifies the CRL signature against an issuing CA in the RTMR1-authorized
chain and rejects listed signer certificates. A configured
`servtd_crl_num` floor provides anti-rollback of the accepted CRL generation.
During peer authentication, the local policy's CRL is authoritative; a peer
cannot supply a different CRL to evade local revocation policy.

The guest has no trusted wall clock, so it does not treat `nextUpdate` as an
in-guest freshness guarantee. Updating measured `servtdCrl` changes RTMR2 and
`tdinfo_hash`, requiring a new image endorsement.

## Implementation references

| Concern | Location |
|---|---|
| Anchor formula and PEM derivation | `src/policy/src/v2/measurement.rs` |
| CFV slots and precedence | `src/migtd/src/config.rs` |
| Runtime RTMR1 extend | `src/migtd/src/bin/migtd/main.rs` |
| Offline reproduction | `tools/migtd-hash/src/lib.rs` |
| JSON/CoRIM anchor binding | `src/policy/src/v2/policy.rs` |
| Peer chain comparison | `src/crypto/src/lib.rs` |
| Signer CRL enforcement | `src/policy/src/v2/policy.rs`, `src/crypto/src/crl.rs` |

Anchor regression tests cover fixed inputs, root/EKU changes, leaf rotation,
direct-anchor resolution, JSON chain mismatch, CoRIM chain mismatch, and signer
revocation.
