// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Policy v2 measurement primitives, per `docs/tcb_mapping_redesign.md`.
//!
//! These helpers are used by both the runtime (`migtd::bin::migtd::main`) and
//! the offline build tool (`migtd-hash`) so the two compute identical values
//! and the runtime `replay_event_log` cross-check stays consistent.
//!
//! ## RTMR2 measurement scheme
//!
//! Six independent extends into RTMR2 (`mr_index = 0x3`), in this fixed order:
//!
//! | # | Field | Helper | Tag ID | EventName |
//! |---|-------|--------|--------|-----------|
//! | 1 | `policyData.version`            | `extract_policy_version_bytes`      | `0x5` | `MigTdPolicyVersion` |
//! | 2 | `policyData.id`                 | `extract_policy_id_bytes`           | `0x6` | `MigTdPolicyId` |
//! | 3 | `policyData.policySvn`          | `extract_policy_svn_bytes`          | `0x7` | `MigTdPolicySvn` |
//! | 4 | `policyData.policy`             | `extract_policy_rules_bytes`        | `0x1` | `MigTdPolicy` |
//! | 5 | `policyData.collaterals`        | `extract_policy_collaterals_bytes`  | `0x8` | `MigTdPolicyCollaterals` |
//! | 6 | `policyData.servtdCollateral.servtdIdentity` | `extract_signed_servtd_identity_bytes` | `0x4` | `ServtdIdentity` |
//!
//! Each helper returns the **canonical** JSON bytes of its field value
//! including the field's natural delimiters (`"…"` for strings, `[…]` for
//! arrays, `{…}` for objects, digits only for numbers). Canonical means:
//! object keys sorted alphabetically, recursively, no whitespace.
//!
//! Canonicalization is implemented manually by [`canonical_value_bytes`] and
//! does **not** rely on `serde_json::to_vec`'s ordering, because other crates
//! in this workspace enable `serde_json/preserve_order`. If feature
//! unification ever turns that on in the policy crate's build, the helper
//! still emits sorted output.
//!
//! ## RTMR1 signer anchor
//!
//! `compute_signer_anchor` returns the 48-byte value `A` where
//! `A = SHA384("MIGTD-RTMR1-ANCHOR-V1" || 0x00 || R || 0x00 || S)`,
//! `R = SHA384(DER(root_cert))`, `S = SHA384(DER(leaf_cert.tbsCertificate.subject))`.
//! `A` is the value extended into RTMR1 (replacing the old "hash the full
//! policy issuer chain PEM bytes" scheme).
//!
//! Together they break the circular dependency that previously prevented
//! `svnMappings[].tdMeasurements` from being a stable, pre-signing-computable
//! function of the build inputs.

use alloc::{string::String, vec::Vec};
use crypto::{
    extract_leaf_subject_der_from_chain_pem, hash::digest_sha384,
    split_chain_pem_to_leaf_and_root_der, SHA384_DIGEST_SIZE,
};
use serde_json::Value;

use crate::PolicyError;

/// Domain-separation tag for the RTMR1 signer anchor (per redesign §RTMR1
/// signer-anchor formula). Bumped on any breaking change.
pub const SIGNER_ANCHOR_DOMAIN_TAG: &[u8] = b"MIGTD-RTMR1-ANCHOR-V1";

/// Single byte separator (`0x00`) between domain tag, R, and S.
const SIGNER_ANCHOR_SEPARATOR: u8 = 0x00;

/// `SERVTD_TYPE` for MigTD as used by TDX module (`servtd_type` is u16 LE).
const SERVTD_TYPE_MIGTD: u16 = 0;

/// "Outer" form of the canonical TDINFO hash used in svnMappings.
/// Equals `init_servtd_info_hash` in `SERVTD_EXT_STRUCT` when the bound MigTD
/// runs with `servtd_attr == 0` (production case).
///
/// `tdinfo_hash = SHA384( SHA384(unmasked_TDINFO) || SERVTD_TYPE(u16_LE=0)
///                                                 || servtd_attr(u64_LE=0) )`.
///
/// Callers MUST pass the SHA384 of the unmasked, fully-populated 512-byte
/// TDINFO_STRUCT (no IGNORE-mask bits applied). See `One_Hash_Endorsement.md`.
pub fn compute_tdinfo_hash(
    unmasked_tdinfo_sha384: &[u8],
) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    if unmasked_tdinfo_sha384.len() != SHA384_DIGEST_SIZE {
        return Err(PolicyError::InvalidParameter);
    }

    let mut buf = Vec::with_capacity(SHA384_DIGEST_SIZE + 2 + 8);
    buf.extend_from_slice(unmasked_tdinfo_sha384);
    buf.extend_from_slice(&SERVTD_TYPE_MIGTD.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());

    let digest = digest_sha384(&buf).map_err(|_| PolicyError::HashCalculation)?;
    let mut out = [0u8; SHA384_DIGEST_SIZE];
    out.copy_from_slice(&digest);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Canonicalization
// ---------------------------------------------------------------------------

/// Emit `v` as canonical JSON bytes into `out`:
///
/// * **Object keys are sorted alphabetically** at every nesting level. This is
///   the property the runtime / migtd-hash / verifier all rely on, and the one
///   `serde_json::to_vec(Value)` does NOT guarantee when any workspace member
///   enables `serde_json/preserve_order` (which `migtd-policy-generator`,
///   `json-signer`, and `servtd-collateral-generator` all do).
/// * **No whitespace** between tokens.
/// * **Array element order is preserved** (JSON arrays are ordered).
/// * **Scalars** (null, bool, number, string) are emitted by `serde_json` —
///   their representation does not depend on `preserve_order`.
fn canonical_value_bytes_into(v: &Value, out: &mut Vec<u8>) -> Result<(), PolicyError> {
    match v {
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                // A `Value::String` of the key serializes to a JSON-encoded
                // string literal (including the surrounding quotes and any
                // necessary escapes). Always safe regardless of feature flags.
                let key_bytes = serde_json::to_vec(&Value::String((*k).clone()))
                    .map_err(|_| PolicyError::InvalidPolicy)?;
                out.extend_from_slice(&key_bytes);
                out.push(b':');
                canonical_value_bytes_into(map.get(*k).ok_or(PolicyError::InvalidPolicy)?, out)?;
            }
            out.push(b'}');
        }
        Value::Array(arr) => {
            out.push(b'[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical_value_bytes_into(e, out)?;
            }
            out.push(b']');
        }
        other => {
            let scalar_bytes = serde_json::to_vec(other).map_err(|_| PolicyError::InvalidPolicy)?;
            out.extend_from_slice(&scalar_bytes);
        }
    }
    Ok(())
}

/// Canonical JSON bytes of `v` (sorted object keys at every level, no
/// whitespace). See [`canonical_value_bytes_into`] for details.
pub fn canonical_value_bytes(v: &Value) -> Result<Vec<u8>, PolicyError> {
    let mut out = Vec::new();
    canonical_value_bytes_into(v, &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// policyData field extraction
// ---------------------------------------------------------------------------

/// Parse `policy_input` and return the `policyData` value. Accepts both:
/// * the signed-wrapper form `{"policyData": {...}, "signature": "..."}`, and
/// * a bare `policyData` object (e.g. `policy_data_raw.json` content).
fn parse_policy_data(policy_input: &[u8]) -> Result<Value, PolicyError> {
    let top: Value =
        serde_json::from_slice(policy_input).map_err(|_| PolicyError::InvalidPolicy)?;

    let policy_data = match top.get("policyData") {
        Some(v) => v.clone(),
        None => top,
    };

    if !policy_data.is_object() {
        return Err(PolicyError::InvalidPolicy);
    }
    Ok(policy_data)
}

/// Canonical JSON bytes of `policyData.version` (a JSON string), INCLUDING
/// the surrounding quotes. Errors if missing, null, or wrong type. Used for
/// RTMR2 extend #1 (`TAGGED_EVENT_ID_POLICY_VERSION`).
pub fn extract_policy_version_bytes(policy_input: &[u8]) -> Result<Vec<u8>, PolicyError> {
    let pd = parse_policy_data(policy_input)?;
    let v = pd.get("version").ok_or(PolicyError::InvalidPolicy)?;
    if !v.is_string() {
        return Err(PolicyError::InvalidPolicy);
    }
    canonical_value_bytes(v)
}

/// Canonical JSON bytes of `policyData.id` (a JSON string), INCLUDING the
/// surrounding quotes. Errors if missing, null, or wrong type. Used for
/// RTMR2 extend #2 (`TAGGED_EVENT_ID_POLICY_ID`).
pub fn extract_policy_id_bytes(policy_input: &[u8]) -> Result<Vec<u8>, PolicyError> {
    let pd = parse_policy_data(policy_input)?;
    let v = pd.get("id").ok_or(PolicyError::InvalidPolicy)?;
    if !v.is_string() {
        return Err(PolicyError::InvalidPolicy);
    }
    canonical_value_bytes(v)
}

/// Canonical JSON bytes of `policyData.policySvn` (a JSON unsigned integer),
/// which is just the digit characters. Floats and negatives are rejected to
/// avoid representation ambiguity (`1` vs `1.0` vs `-0`). Errors if missing,
/// null, or wrong type. Used for RTMR2 extend #3 (`TAGGED_EVENT_ID_POLICY_SVN`).
pub fn extract_policy_svn_bytes(policy_input: &[u8]) -> Result<Vec<u8>, PolicyError> {
    let pd = parse_policy_data(policy_input)?;
    let v = pd.get("policySvn").ok_or(PolicyError::InvalidPolicy)?;
    match v {
        Value::Number(n) if n.is_u64() => canonical_value_bytes(v),
        _ => Err(PolicyError::InvalidPolicy),
    }
}

/// Canonical JSON bytes of `policyData.policy` (a JSON array), INCLUDING the
/// outer `[` / `]`. Errors if missing, null, or not an array. Used for RTMR2
/// extend #4 (`TAGGED_EVENT_ID_POLICY`).
///
/// Note: only the `policy` field is bound here. The `forwardPolicy` and
/// `backwardPolicy` fields, if present, are NOT measured by this helper.
pub fn extract_policy_rules_bytes(policy_input: &[u8]) -> Result<Vec<u8>, PolicyError> {
    let pd = parse_policy_data(policy_input)?;
    let v = pd.get("policy").ok_or(PolicyError::InvalidPolicy)?;
    if !v.is_array() {
        return Err(PolicyError::InvalidPolicy);
    }
    canonical_value_bytes(v)
}

/// Canonical JSON bytes of `policyData.collaterals` (a JSON object), INCLUDING
/// the outer `{` / `}`. Errors if missing, null, or not an object. Used for
/// RTMR2 extend #5 (`TAGGED_EVENT_ID_POLICY_COLLATERALS`).
pub fn extract_policy_collaterals_bytes(policy_input: &[u8]) -> Result<Vec<u8>, PolicyError> {
    let pd = parse_policy_data(policy_input)?;
    let v = pd.get("collaterals").ok_or(PolicyError::InvalidPolicy)?;
    if !v.is_object() {
        return Err(PolicyError::InvalidPolicy);
    }
    canonical_value_bytes(v)
}

/// Canonical JSON bytes of the signed `servtdIdentity` blob embedded at
/// `policyData.servtdCollateral.servtdIdentity`, INCLUDING the outer `{`/`}`.
/// Errors if missing, null, or the structural shape doesn't include both
/// `tdIdentity` and `signature` fields.
///
/// Used for RTMR2 extend #6 (`TAGGED_EVENT_ID_SERVTD_IDENTITY`). See
/// `docs/tcb_mapping_redesign.md` §"Servtd identity binding" for the threat
/// model (defeats playback / TCB-downgrade attacks via obsolete signed
/// identities).
///
/// The hash covers the full signed object including its `signature` field.
/// That means re-signing byte-identical inner content with a fresh signature
/// changes RTMR2 — intentional, so operators must rebuild the IGVM image
/// whenever the issuer re-signs `servtdIdentity`.
pub fn extract_signed_servtd_identity_bytes(policy_input: &[u8]) -> Result<Vec<u8>, PolicyError> {
    let pd = parse_policy_data(policy_input)?;

    let collateral = pd
        .get("servtdCollateral")
        .ok_or(PolicyError::InvalidPolicy)?;
    let identity = collateral
        .get("servtdIdentity")
        .ok_or(PolicyError::InvalidPolicy)?;

    let obj = identity.as_object().ok_or(PolicyError::InvalidPolicy)?;
    if !obj.contains_key("tdIdentity") || !obj.contains_key("signature") {
        return Err(PolicyError::InvalidPolicy);
    }

    canonical_value_bytes(identity)
}

/// Compute the RTMR1 signer anchor `A` from its component digests.
///
/// `A = SHA384(SIGNER_ANCHOR_DOMAIN_TAG || 0x00 || R || 0x00 || S)`
///
/// where `R = SHA384(DER(root_cert))` and `S = SHA384(DER(leaf_subject))`.
/// `0x00` is a single zero byte separator.
pub fn compute_signer_anchor(
    root_der: &[u8],
    leaf_subject_der: &[u8],
) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    let r = digest_sha384(root_der).map_err(|_| PolicyError::HashCalculation)?;
    let s = digest_sha384(leaf_subject_der).map_err(|_| PolicyError::HashCalculation)?;

    let mut buf = Vec::with_capacity(SIGNER_ANCHOR_DOMAIN_TAG.len() + 1 + r.len() + 1 + s.len());
    buf.extend_from_slice(SIGNER_ANCHOR_DOMAIN_TAG);
    buf.push(SIGNER_ANCHOR_SEPARATOR);
    buf.extend_from_slice(&r);
    buf.push(SIGNER_ANCHOR_SEPARATOR);
    buf.extend_from_slice(&s);

    let digest = digest_sha384(&buf).map_err(|_| PolicyError::HashCalculation)?;
    let mut out = [0u8; SHA384_DIGEST_SIZE];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Compute the RTMR1 signer anchor directly from a PEM cert chain (leaf-first).
///
/// Convenience wrapper combining the crypto crate's chain split + subject DER
/// extraction with `compute_signer_anchor`.
pub fn compute_signer_anchor_from_chain_pem(
    chain_pem: &[u8],
) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
    let (_leaf_der, root_der) =
        split_chain_pem_to_leaf_and_root_der(chain_pem).map_err(|_| PolicyError::InvalidPolicy)?;
    let leaf_subject = extract_leaf_subject_der_from_chain_pem(chain_pem)
        .map_err(|_| PolicyError::InvalidPolicy)?;
    compute_signer_anchor(&root_der, &leaf_subject)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_anchor_is_stable_for_fixed_inputs() {
        // Fixed test vectors so offline + runtime implementations cannot diverge.
        let root = b"the-root-DER-placeholder";
        let subject = b"CN=MigTD Info Issuer";
        let a = compute_signer_anchor(root, subject).unwrap();
        // Recompute and ensure deterministic.
        let a2 = compute_signer_anchor(root, subject).unwrap();
        assert_eq!(a, a2);

        // Verify the formula explicitly.
        let r = digest_sha384(root).unwrap();
        let s = digest_sha384(subject).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(SIGNER_ANCHOR_DOMAIN_TAG);
        buf.push(0u8);
        buf.extend_from_slice(&r);
        buf.push(0u8);
        buf.extend_from_slice(&s);
        let expected = digest_sha384(&buf).unwrap();
        assert_eq!(&a[..], expected.as_slice());
    }

    #[test]
    fn signer_anchor_changes_with_root_or_subject() {
        let a = compute_signer_anchor(b"root1", b"subj1").unwrap();
        let b = compute_signer_anchor(b"root2", b"subj1").unwrap();
        let c = compute_signer_anchor(b"root1", b"subj2").unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    // ------------------------------------------------------------------
    // canonical_value_bytes
    // ------------------------------------------------------------------

    #[test]
    fn canonical_value_sorts_keys_at_every_level() {
        let a: Value =
            serde_json::from_str(r#"{"b":{"y":2,"x":1},"a":[{"c":3,"b":2,"a":1}]}"#).unwrap();
        let b: Value =
            serde_json::from_str(r#"{"a":[{"a":1,"b":2,"c":3}],"b":{"x":1,"y":2}}"#).unwrap();
        let out_a = canonical_value_bytes(&a).unwrap();
        let out_b = canonical_value_bytes(&b).unwrap();
        assert_eq!(out_a, out_b);
        assert_eq!(&out_a, br#"{"a":[{"a":1,"b":2,"c":3}],"b":{"x":1,"y":2}}"#);
    }

    #[test]
    fn canonical_value_preserves_array_order() {
        let v: Value = serde_json::from_str(r#"[3,1,2]"#).unwrap();
        assert_eq!(canonical_value_bytes(&v).unwrap(), b"[3,1,2]");
    }

    #[test]
    fn canonical_value_emits_no_whitespace() {
        let v: Value = serde_json::from_str("{\n  \"a\" : 1 ,\n  \"b\" : [ 2 , 3 ]\n}").unwrap();
        assert_eq!(canonical_value_bytes(&v).unwrap(), br#"{"a":1,"b":[2,3]}"#);
    }

    // ------------------------------------------------------------------
    // extract_policy_*_bytes (typed)
    // ------------------------------------------------------------------

    /// Minimal bare-policyData with every field the 6-extend scheme uses.
    fn sample_bare_policy_data() -> &'static str {
        r#"{"id":"X-uuid","version":"2.0","policySvn":7,"policy":[{"global":{"tcb":{"tcbDate":{"reference":"2023","operation":"ge"}}}},{"servtd":{"x":1}}],"collaterals":{"majorVersion":1,"minorVersion":0,"teeType":129},"servtdCollateral":{"majorVersion":1,"minorVersion":0,"servtdIdentityIssuerChain":"chain","servtdIdentity":{"tdIdentity":{"id":"identity-1","version":1,"tcbLevels":[]},"signature":"deadbeef"},"servtdTcbMappingIssuerChain":"chain","servtdTcbMapping":{}}}"#
    }

    fn sample_wrapped_policy() -> alloc::string::String {
        format!(
            r#"{{"policyData":{},"signature":"sig"}}"#,
            sample_bare_policy_data()
        )
    }

    #[test]
    fn extract_version_returns_quoted_canonical_string() {
        let out = extract_policy_version_bytes(sample_bare_policy_data().as_bytes()).unwrap();
        assert_eq!(&out, br#""2.0""#);
    }

    #[test]
    fn extract_id_returns_quoted_canonical_string() {
        let out = extract_policy_id_bytes(sample_bare_policy_data().as_bytes()).unwrap();
        assert_eq!(&out, br#""X-uuid""#);
    }

    #[test]
    fn extract_svn_returns_digits_only() {
        let out = extract_policy_svn_bytes(sample_bare_policy_data().as_bytes()).unwrap();
        assert_eq!(&out, b"7");
    }

    #[test]
    fn extract_rules_returns_array_with_brackets() {
        let out = extract_policy_rules_bytes(sample_bare_policy_data().as_bytes()).unwrap();
        assert_eq!(out.first(), Some(&b'['));
        assert_eq!(out.last(), Some(&b']'));
        // Inner objects canonical: keys sorted at every level.
        let expected = br#"[{"global":{"tcb":{"tcbDate":{"operation":"ge","reference":"2023"}}}},{"servtd":{"x":1}}]"#;
        assert_eq!(&out, expected);
    }

    #[test]
    fn extract_collaterals_returns_object_with_braces() {
        let out = extract_policy_collaterals_bytes(sample_bare_policy_data().as_bytes()).unwrap();
        assert_eq!(out.first(), Some(&b'{'));
        assert_eq!(out.last(), Some(&b'}'));
        // Keys sorted: majorVersion, minorVersion, teeType.
        let expected = br#"{"majorVersion":1,"minorVersion":0,"teeType":129}"#;
        assert_eq!(&out, expected);
    }

    /// Every typed extractor accepts both the signed-wrapper form and the
    /// bare `policyData` form and produces identical bytes.
    #[test]
    fn extractors_accept_signed_wrapper_and_match_bare() {
        let bare = sample_bare_policy_data().as_bytes();
        let wrapped_owned = sample_wrapped_policy();
        let wrapped = wrapped_owned.as_bytes();

        for (name, bare_out, wrapped_out) in [
            (
                "version",
                extract_policy_version_bytes(bare).unwrap(),
                extract_policy_version_bytes(wrapped).unwrap(),
            ),
            (
                "id",
                extract_policy_id_bytes(bare).unwrap(),
                extract_policy_id_bytes(wrapped).unwrap(),
            ),
            (
                "svn",
                extract_policy_svn_bytes(bare).unwrap(),
                extract_policy_svn_bytes(wrapped).unwrap(),
            ),
            (
                "rules",
                extract_policy_rules_bytes(bare).unwrap(),
                extract_policy_rules_bytes(wrapped).unwrap(),
            ),
            (
                "collaterals",
                extract_policy_collaterals_bytes(bare).unwrap(),
                extract_policy_collaterals_bytes(wrapped).unwrap(),
            ),
            (
                "identity",
                extract_signed_servtd_identity_bytes(bare).unwrap(),
                extract_signed_servtd_identity_bytes(wrapped).unwrap(),
            ),
        ] {
            assert_eq!(bare_out, wrapped_out, "field {name} bare/wrapped mismatch");
        }
    }

    #[test]
    fn extractors_are_canonical_across_key_order() {
        let order_a = r#"{"version":"2.0","id":"X","policySvn":7,"policy":[{"b":2,"a":1}],"collaterals":{"teeType":129,"majorVersion":1,"minorVersion":0},"servtdCollateral":{"servtdIdentity":{"tdIdentity":{"version":1,"id":"i"},"signature":"aa"}}}"#;
        let order_b = r#"{"policy":[{"a":1,"b":2}],"id":"X","policySvn":7,"version":"2.0","servtdCollateral":{"servtdIdentity":{"signature":"aa","tdIdentity":{"id":"i","version":1}}},"collaterals":{"minorVersion":0,"majorVersion":1,"teeType":129}}"#;

        for (a, b) in [
            (
                extract_policy_version_bytes(order_a.as_bytes()).unwrap(),
                extract_policy_version_bytes(order_b.as_bytes()).unwrap(),
            ),
            (
                extract_policy_id_bytes(order_a.as_bytes()).unwrap(),
                extract_policy_id_bytes(order_b.as_bytes()).unwrap(),
            ),
            (
                extract_policy_svn_bytes(order_a.as_bytes()).unwrap(),
                extract_policy_svn_bytes(order_b.as_bytes()).unwrap(),
            ),
            (
                extract_policy_rules_bytes(order_a.as_bytes()).unwrap(),
                extract_policy_rules_bytes(order_b.as_bytes()).unwrap(),
            ),
            (
                extract_policy_collaterals_bytes(order_a.as_bytes()).unwrap(),
                extract_policy_collaterals_bytes(order_b.as_bytes()).unwrap(),
            ),
            (
                extract_signed_servtd_identity_bytes(order_a.as_bytes()).unwrap(),
                extract_signed_servtd_identity_bytes(order_b.as_bytes()).unwrap(),
            ),
        ] {
            assert_eq!(a, b);
        }
    }

    // ---------- type / presence rejections ----------

    #[test]
    fn extract_version_rejects_non_string_or_missing() {
        // missing
        assert!(extract_policy_version_bytes(
            br#"{"id":"x","policySvn":0,"policy":[],"collaterals":{}}"#
        )
        .is_err());
        // wrong type
        assert!(extract_policy_version_bytes(
            br#"{"version":2,"id":"x","policySvn":0,"policy":[],"collaterals":{}}"#
        )
        .is_err());
        // null
        assert!(extract_policy_version_bytes(
            br#"{"version":null,"id":"x","policySvn":0,"policy":[],"collaterals":{}}"#
        )
        .is_err());
    }

    #[test]
    fn extract_id_rejects_non_string_or_missing() {
        assert!(extract_policy_id_bytes(
            br#"{"version":"2.0","policySvn":0,"policy":[],"collaterals":{}}"#
        )
        .is_err());
        assert!(extract_policy_id_bytes(
            br#"{"version":"2.0","id":42,"policySvn":0,"policy":[],"collaterals":{}}"#
        )
        .is_err());
        assert!(extract_policy_id_bytes(
            br#"{"version":"2.0","id":null,"policySvn":0,"policy":[],"collaterals":{}}"#
        )
        .is_err());
    }

    #[test]
    fn extract_svn_rejects_non_unsigned_integer_or_missing() {
        // missing
        assert!(extract_policy_svn_bytes(
            br#"{"version":"2.0","id":"x","policy":[],"collaterals":{}}"#
        )
        .is_err());
        // negative (integer but not unsigned)
        assert!(extract_policy_svn_bytes(
            br#"{"version":"2.0","id":"x","policySvn":-1,"policy":[],"collaterals":{}}"#
        )
        .is_err());
        // float
        assert!(extract_policy_svn_bytes(
            br#"{"version":"2.0","id":"x","policySvn":1.0,"policy":[],"collaterals":{}}"#
        )
        .is_err());
        // string
        assert!(extract_policy_svn_bytes(
            br#"{"version":"2.0","id":"x","policySvn":"1","policy":[],"collaterals":{}}"#
        )
        .is_err());
        // null
        assert!(extract_policy_svn_bytes(
            br#"{"version":"2.0","id":"x","policySvn":null,"policy":[],"collaterals":{}}"#
        )
        .is_err());
    }

    #[test]
    fn extract_rules_rejects_non_array_or_missing() {
        assert!(extract_policy_rules_bytes(
            br#"{"version":"2.0","id":"x","policySvn":0,"collaterals":{}}"#
        )
        .is_err());
        assert!(extract_policy_rules_bytes(
            br#"{"version":"2.0","id":"x","policySvn":0,"policy":{"a":1},"collaterals":{}}"#
        )
        .is_err());
        assert!(extract_policy_rules_bytes(
            br#"{"version":"2.0","id":"x","policySvn":0,"policy":null,"collaterals":{}}"#
        )
        .is_err());
    }

    #[test]
    fn extract_rules_accepts_empty_array_with_brackets() {
        let input = br#"{"version":"2.0","id":"x","policySvn":0,"policy":[],"collaterals":{}}"#;
        let out = extract_policy_rules_bytes(input).unwrap();
        assert_eq!(&out, b"[]");
    }

    #[test]
    fn extract_collaterals_rejects_non_object_or_missing() {
        assert!(extract_policy_collaterals_bytes(
            br#"{"version":"2.0","id":"x","policySvn":0,"policy":[]}"#
        )
        .is_err());
        assert!(extract_policy_collaterals_bytes(
            br#"{"version":"2.0","id":"x","policySvn":0,"policy":[],"collaterals":[]}"#
        )
        .is_err());
        assert!(extract_policy_collaterals_bytes(
            br#"{"version":"2.0","id":"x","policySvn":0,"policy":[],"collaterals":null}"#
        )
        .is_err());
    }

    #[test]
    fn extract_collaterals_accepts_empty_object_with_braces() {
        let input = br#"{"version":"2.0","id":"x","policySvn":0,"policy":[],"collaterals":{}}"#;
        let out = extract_policy_collaterals_bytes(input).unwrap();
        assert_eq!(&out, b"{}");
    }

    // ------------------------------------------------------------------
    // extract_signed_servtd_identity_bytes
    // ------------------------------------------------------------------

    #[test]
    fn extract_servtd_identity_returns_canonical_object_with_braces() {
        let out =
            extract_signed_servtd_identity_bytes(sample_bare_policy_data().as_bytes()).unwrap();
        assert_eq!(out.first(), Some(&b'{'));
        assert_eq!(out.last(), Some(&b'}'));
        let expected = br#"{"signature":"deadbeef","tdIdentity":{"id":"identity-1","tcbLevels":[],"version":1}}"#;
        assert_eq!(&out, expected);
    }

    #[test]
    fn extract_servtd_identity_includes_signature_bytes() {
        let a = r#"{"servtdCollateral":{"servtdIdentity":{"tdIdentity":{"id":"i1"},"signature":"aa"}}}"#;
        let b = r#"{"servtdCollateral":{"servtdIdentity":{"tdIdentity":{"id":"i1"},"signature":"bb"}}}"#;
        let out_a = extract_signed_servtd_identity_bytes(a.as_bytes()).unwrap();
        let out_b = extract_signed_servtd_identity_bytes(b.as_bytes()).unwrap();
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn extract_servtd_identity_rejects_missing_collateral() {
        let input = r#"{"id":"x","version":"2.0","policySvn":0,"policy":[]}"#;
        assert!(extract_signed_servtd_identity_bytes(input.as_bytes()).is_err());
    }

    #[test]
    fn extract_servtd_identity_rejects_missing_identity_field() {
        let input = r#"{"policy":[],"servtdCollateral":{"servtdTcbMapping":{}}}"#;
        assert!(extract_signed_servtd_identity_bytes(input.as_bytes()).is_err());
    }

    #[test]
    fn extract_servtd_identity_rejects_missing_signature() {
        let input = r#"{"servtdCollateral":{"servtdIdentity":{"tdIdentity":{"id":"i1"}}}}"#;
        assert!(extract_signed_servtd_identity_bytes(input.as_bytes()).is_err());
    }

    #[test]
    fn extract_servtd_identity_rejects_missing_td_identity_body() {
        let input = r#"{"servtdCollateral":{"servtdIdentity":{"signature":"aa"}}}"#;
        assert!(extract_signed_servtd_identity_bytes(input.as_bytes()).is_err());
    }

    #[test]
    fn extract_servtd_identity_rejects_non_object_identity() {
        let input = r#"{"servtdCollateral":{"servtdIdentity":"not-an-object"}}"#;
        assert!(extract_signed_servtd_identity_bytes(input.as_bytes()).is_err());
    }

    // ------------------------------------------------------------------
    // tdinfo_hash (carried over unchanged)
    // ------------------------------------------------------------------

    #[test]
    fn compute_tdinfo_hash_formula_is_outer_with_attr_zero() {
        let inner = [0xAAu8; SHA384_DIGEST_SIZE];
        let got = compute_tdinfo_hash(&inner).unwrap();

        let mut expected_buf = Vec::new();
        expected_buf.extend_from_slice(&inner);
        expected_buf.extend_from_slice(&0u16.to_le_bytes());
        expected_buf.extend_from_slice(&0u64.to_le_bytes());
        let expected = digest_sha384(&expected_buf).unwrap();
        assert_eq!(&got[..], expected.as_slice());
    }

    #[test]
    fn compute_tdinfo_hash_rejects_wrong_length() {
        assert!(compute_tdinfo_hash(b"too-short").is_err());
        assert!(compute_tdinfo_hash(&[0u8; SHA384_DIGEST_SIZE + 1]).is_err());
    }
}
