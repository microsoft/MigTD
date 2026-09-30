MigTD Policy v2 Measurements
============================

This document describes the implemented `MRTD` and `RTMR0..3` inputs for
Policy v2 images. The byte-level one-hash and endorsement contract is defined
in [tcb_mapping_design_proposal.md](./tcb_mapping_design_proposal.md).

The runtime and offline calculator share the same policy helpers:

- runtime: `src/migtd/src/bin/migtd/main.rs`
- canonical policy and signer anchor: `src/policy/src/v2/measurement.rs`
- offline reproduction: `tools/migtd-hash/src/lib.rs`

## Summary

| Register | Measured content | Measured by |
|---|---|---|
| `MRTD` | Initial td-shim BFV and MigTD payload pages, plus launch GPA layout | TDX module |
| `RTMR0` | One td-shim `EV_SEPARATOR` | td-shim |
| `RTMR1` | td-shim `EV_SEPARATOR`, then the Policy v2 signer anchor | td-shim, then MigTD |
| `RTMR2` | One extend over canonical Policy v2 `policyData` | MigTD |
| `RTMR3` | Nothing; remains zero in production | — |

All registers use SHA-384. One runtime extend is:

```text
RTMR_new = SHA384(RTMR_old || SHA384(measured_bytes))
```

## MRTD

The TDX module measures the initial private-page layout before the guest runs.
For every added page, `TDH.MEM.PAGE.ADD` records its GPA. Pages marked for
measurement also receive `TDH.MR.EXTEND` over their contents.

MigTD's metadata marks:

| Section | Content measured into MRTD? |
|---|---|
| td-shim BFV | Yes |
| MigTD payload | Yes |
| Configuration FV | No; GPA only |
| Temporary memory | No; GPA only |
| Permanent memory | Dynamically accepted, not initial content |

The CFV holds policy and signer material but its content is not in MRTD. MigTD
measures the trust-relevant CFV inputs into RTMR1 and RTMR2 after launch.

TDVF and IGVM package pages in different orders, so their MRTD values differ
even when their firmware and payload bytes match. Always calculate MRTD from
the exact image being deployed.

## RTMR0

td-shim extends the four-byte separator payload `0x00000000` into RTMR0 before
transferring control to MigTD:

```text
RTMR0 = SHA384(zeros(48) || SHA384(0x00000000))
```

MigTD adds no other production event to RTMR0.

## RTMR1 signer anchor

td-shim first extends the same separator into RTMR1. MigTD then resolves the
Policy v2 signer anchor:

```text
R = SHA384(DER(root certificate))
A = SHA384(
    "MIGTD-RTMR1-ANCHOR-V1" || 0x00 ||
    R || 0x00 ||
    leaf_EKU_OID_DER
)
RTMR1_final = extend(RTMR1_separator, A)
```

The event-log helper hashes `A` as part of the extend formula.

The CFV can carry:

- a PEM policy issuer chain, from which MigTD derives `A`; or
- a precomputed 48-byte `A`.

`config::get_signer_anchor_source()` prefers the direct anchor. JSON packaging
normally uses the PEM chain; CoRIM-only packaging normally uses the direct
anchor. The two forms are measurement-equivalent when they represent the same
root and signer-purpose EKU.

RTMR1 does **not** measure the complete issuer-chain bytes. Leaf-key and
intermediate-CA rotation under the same root+EKU leaves RTMR1 unchanged.

## RTMR2 canonical policyData

MigTD extends RTMR2 once with bytes returned by
`extract_canonical_policy_data_bytes`.

Canonicalization sorts object keys recursively, preserves array order, and
removes insignificant whitespace. The helper accepts both a bare `policyData`
object and the legacy `{policyData, signature}` envelope. The outer signature
is ignored; RTMR2 provides integrity for measured policy content.

### JSON collateral

If `servtdCollateral` is present, the helper removes:

```text
servtdCollateral.servtdTcbMapping
servtdCollateral.servtdTcbMappingIssuerChain
```

The mapping contains the circular `tdinfo_hash` and must be replaceable. Its
issuer-chain bytes are also replaceable, while policy verification requires
the chain's root+EKU identity to match the RTMR1 signer anchor.

All other fields remain measured, including JSON `servtdIdentity`, its
signature, and `servtdIdentityIssuerChain`. Reissuing any of those bytes
changes RTMR2 and `tdinfo_hash`.

### CoRIM-only collateral

A CoRIM-only policy omits `servtdCollateral`. The helper then redacts nothing
and measures the complete canonical `policyData` object. The separately
enrolled signed CoRIM is unmeasured and authenticated through its ES384
signature and RTMR1-bound `x5chain`.

### Event log

The digest records the full canonical bytes, while the tagged event payload is
the small policy version string. Peers recompute the canonical bytes with the
same helper and compare their hash with the event digest during replay.

## RTMR3

No production MigTD event targets RTMR3, so it remains all zero.

## Test-only measurement

`test_disable_ra_and_accept_all` replaces the normal Policy v2 measurements
with a test-feature event in RTMR2. Such images do not have production RTMR1
or RTMR2 values and must never be endorsed or released.

## Offline reproduction

Run `migtd-hash` against the final enrolled image:

```sh
cargo run -p migtd-hash -- \
  --image target/release/migtd.igvm \
  --manifest config/Azure/servtd_info.json \
  --policy-v2 \
  --verbose
```

For a TDVF image, pass the `.bin` image instead. `migtd-hash`:

1. derives MRTD using the selected image format;
2. seeds RTMR0 and RTMR1 with the td-shim separator;
3. resolves the PEM-derived or direct signer anchor and extends RTMR1; and
4. invokes the same canonical policy helper used at runtime and extends RTMR2.

Do not copy fixed RTMR1, RTMR2, or `tdinfo_hash` values from documentation.
They depend on the final image, measured policy content, and signer anchor.

## Release invariant

The release pipeline must prove:

```text
tdinfo_hash(before signed mapping enrollment)
    ==
tdinfo_hash(after signed mapping enrollment)
```

For JSON packaging, the pre-final policy contains an empty mapping sentinel.
For CoRIM-only packaging, `servtdCollateral` is absent. Enrolling the final
mapping or CoRIM must not change MRTD or any RTMR.

Changes to measured policy content, the signer root/EKU, firmware, payload, or
launch layout must change the resulting `tdinfo_hash`.

## Source and test index

| Concern | Source |
|---|---|
| Runtime measurement order | `src/migtd/src/bin/migtd/main.rs::do_measurements` |
| Event IDs and register indices | `src/migtd/src/event_log.rs` |
| Canonical RTMR2 bytes | `src/policy/src/v2/measurement.rs::extract_canonical_policy_data_bytes` |
| RTMR1 anchor formula | `src/policy/src/v2/measurement.rs::compute_signer_anchor` |
| CFV anchor precedence | `src/migtd/src/config.rs::get_signer_anchor_source` |
| Offline reproduction | `tools/migtd-hash/src/lib.rs` |
| Mapping/identity verification | `src/policy/src/v2/policy.rs` |

The measurement regression tests named in
[tcb_mapping_design_proposal.md](./tcb_mapping_design_proposal.md) pin the
redaction, canonicalization, CoRIM-only, and signer-anchor contracts.
