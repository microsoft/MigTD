One-Hash TCB Mapping Design
===========================

This document specifies the implemented Policy v2 design for binding a MigTD
release to an SVN with one composite measurement:

```text
tdinfo_hash = SHA384(TDINFO)
```

For production MigTD, `SERVTD_ATTR == 0`, so this is also the value recorded by
the TDX module as `init_servtd_info_hash` and `cur_servtd_info_hash`. The signed
TCB mapping maps that complete 48-byte hash directly to MigTD SVN.

The implementation sources of truth are:

- `src/policy/src/v2/measurement.rs`
- `src/policy/src/v2/policy.rs`
- `src/policy/src/v2/servtd_collateral.rs`
- `src/policy/src/v2/servtd_corim.rs`
- `tools/migtd-hash/src/lib.rs`

## Security goals

The design provides these properties:

1. **Complete release identity.** The mapping key covers `MRTD`, `RTMR0..3`,
   and the other fields in `TDINFO`, rather than a subset of registers.
2. **No circular dependency.** The endorsement that contains `tdinfo_hash` is
   excluded from the RTMR2 input used to compute that hash.
3. **Measured policy.** Migration rules, platform collateral, policy SVN, and
   JSON TD Identity content are bound to RTMR2.
4. **Signer continuity with rotation.** Mapping and CoRIM signers must resolve
   to the RTMR1 root+EKU signer anchor. Leaf and intermediate certificates may
   rotate without changing the anchor.
5. **Direct init/current lookup.** Migration and rebinding resolve both hashes
   through the authenticated source's verified mapping and require
   `init SVN <= current SVN`.

## Measurement layout

| Register | Contents |
|---|---|
| `MRTD` | Measured td-shim BFV and MigTD payload pages, plus launch GPA layout |
| `RTMR0` | td-shim `EV_SEPARATOR` |
| `RTMR1` | td-shim `EV_SEPARATOR`, then the MigTD signer anchor |
| `RTMR2` | One extend over canonical Policy v2 `policyData` as defined below |
| `RTMR3` | Zero in production builds |

`TDINFO` includes these registers and the remaining hardware-defined identity
fields. `migtd-hash` reproduces the same values from the final image.

## RTMR1 signer anchor

Define `H(x) = SHA384(x)`:

```text
R = H(DER(root certificate))
A = H("MIGTD-RTMR1-ANCHOR-V1" || 0x00 || R || 0x00 || leaf_EKU_OID_DER)
```

MigTD extends `H(A)` into RTMR1 through the event-log helper. The CFV supplies
the anchor source in either of two forms:

- a PEM issuer chain, from which MigTD derives `A`; or
- a precomputed 48-byte `A`.

The direct 48-byte slot takes precedence when both slots are populated. The
standard JSON packaging uses the PEM form. CoRIM-only packaging uses the direct
anchor so the image need not duplicate the CoRIM `x5chain`.

Both forms produce the same RTMR1 when they represent the same root and signer
EKU. Root or EKU changes alter RTMR1; leaf-key and intermediate-CA rotation
under the same root+EKU do not.

## RTMR2 canonical policyData

RTMR2 receives exactly one extend over canonical JSON bytes. Canonicalization:

- sorts object keys lexicographically at every level;
- preserves array order;
- emits no insignificant whitespace; and
- accepts either a bare `policyData` object or the legacy
  `{ "policyData": ..., "signature": ... }` wrapper.

The outer wrapper signature is ignored. Integrity of measured policy content
comes from RTMR2.

### JSON collateral

When `policyData.servtdCollateral` is present, the canonicalizer removes only:

1. `servtdCollateral.servtdTcbMapping`
2. `servtdCollateral.servtdTcbMappingIssuerChain`

`servtdTcbMapping` contains the circular `tdinfo_hash` and must remain
replaceable as the authority adds or removes release entries. The mapping
issuer-chain bytes are also replaceable; `RawPolicyData::verify` instead
requires that chain to resolve to the RTMR1 signer anchor.

Every other `policyData` field is measured, including:

- `version`, `id`, and `policySvn`;
- `policy`, `forwardPolicy`, and `backwardPolicy`;
- platform `collaterals`;
- `servtdCollateral` version fields;
- `servtdIdentity`, including its signature;
- `servtdIdentityIssuerChain`; and
- top-level `servtdCrl`.

Measuring TD Identity prevents replacement with a different valid historical
identity without changing RTMR2 and therefore `tdinfo_hash`.

When `servtdCollateral` exists, `servtdTcbMapping` must be its direct child.
Missing or malformed mapping structure fails closed so schema drift cannot
silently place mapping bytes into RTMR2.

### CoRIM-only collateral

CoRIM-only `policyData` omits `servtdCollateral`. There are no JSON endorsement
bytes to redact, so the complete canonical `policyData` object is measured.

The separately enrolled `COSE_Sign1` CoRIM maps `SERVTD_INFO_HASH -> SVN`. Its
ES384 signature and embedded `x5chain` are verified, and the chain must resolve
to the same RTMR1 signer anchor. When a CoRIM is attached, it is the sole
servTD lookup authority; a missing hash does not fall back to JSON.

## Signed mapping formats

### JSON mapping

Each mapping entry contains the complete hash:

```text
svnMappings[].tdMeasurements.tdinfo_hash -> isvsvn
```

The JSON mapping signature is verified with
`servtdTcbMappingIssuerChain`, then that chain is bound to RTMR1 by its
root+EKU anchor.

An optional JSON `servtdIdentity` translates the resolved SVN to
`tcbDate`/`tcbStatus`. It is not the source of release identity; the one-hash
mapping is. If policy uses those status/date axes, the identity must be
present. SVN-only policy works without it.

### CoRIM mapping

The CoRIM uses digest-selecting conditional endorsement series records:

```text
SERVTD_INFO_HASH -> exact SVN
```

There is no CoRIM TD Identity document. CoRIM lookup supplies SVN only, so
CoRIM-compatible migration policy must not require JSON-only TD Identity
status/date values.

## Release construction

The release flow computes a stable hash without embedding that hash into its
own measurement:

1. Build or enroll the final measured policy content and signer anchor.
2. Place an empty JSON mapping sentinel, or omit `servtdCollateral` for
   CoRIM-only packaging.
3. Run `migtd-hash` on the resulting image to compute `tdinfo_hash`.
4. Add the hash-to-SVN entry to the authority-maintained cumulative JSON
   mapping or signed CoRIM.
5. Enroll the signed endorsement.
6. Re-run `migtd-hash` and require the hash to be unchanged.

The mapping must retain every supported historical initial hash. Removing a
hash revokes that image for future lookup and must be an explicit,
authority-reviewed operation.

Images built with `use-mock-quote` need both the synthetic report hash used by
peer evaluation and the final image hash used by `SERVTD_EXT` continuity.

## Runtime verification

After quote or TDREPORT authentication, MigTD:

1. verifies event-log replay and the RTMR2 canonical policy digest;
2. verifies JSON/CoRIM signatures and signer-anchor binding;
3. requires the authenticated peer's signer anchor to equal the local anchor;
4. resolves the authenticated source's current report `tdinfo_hash`;
5. resolves `ServtdExt.init_servtd_info_hash` through the same source mapping;
6. rejects either lookup miss; and
7. requires `init SVN <= current SVN` before policy evaluation succeeds.

The destination's local mapping is not used for the source's initial hash. An
older destination must not be required to predict future source releases.
The legacy wire `init_td_info` field is retained for framing compatibility but
is ignored.

## Replay and freshness model

The measurement and endorsement layers provide different guarantees:

- Changing measured `policyData`, including JSON TD Identity, changes RTMR2
  and `tdinfo_hash`; the changed image requires a matching endorsement.
- JSON mappings and CoRIMs are intentionally unmeasured and replaceable.
  Their authenticity comes from signatures bound to the RTMR1 anchor.
- A mapping lookup miss fails closed. Cumulative mappings preserve supported
  historical initial hashes; explicit removal revokes a hash.
- MigTD has no trusted wall clock or persistent mapping-generation state.
  Mapping publication order and rollback prevention are release-authority and
  deployment responsibilities. Policy SVN/status floors and signer CRL
  numbers enforce the configured acceptance baseline, but do not turn an
  unmeasured mapping into a time-fresh object.

## Regression tests

`src/policy/src/v2/measurement.rs` pins the byte-level contract:

- `extract_redacts_servtd_tcb_mapping`
- `extract_measures_servtd_identity`
- `extract_measures_identity_chain_but_redacts_mapping_chain`
- `extract_redacts_servtd_tcb_mapping_issuer_chain`
- `extract_allows_missing_servtd_collateral`
- `extract_sample_policy_canonical_bytes`
- `extract_canonical_bytes_do_not_contain_field_name`

Policy tests additionally cover signer-anchor mismatch, CoRIM-only policy,
fail-closed mapping misses, asymmetric source lookup, leaf rotation, and signer
revocation. The EMU matrix exercises JSON and CoRIM migration/rebinding paths.
