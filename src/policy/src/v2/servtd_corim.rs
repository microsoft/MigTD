// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! CoRIM-based hash endorsement: decodes the wire format produced by the
//! host-side `mig-td-tools` signer and resolves a `tdinfo_hash` to a
//! [`ServtdLookup`]. This is the only alternative to the legacy JSON
//! collateral; the legacy path stays unchanged from the one-hash redesign.
//!
//! # Two documents
//!
//! The producer emits **two** independent signed CoRIMs, both of which MigTD
//! carries in its CFV:
//!
//! * **TCB Mapping CoRIM** — `SERVTD_INFO_HASH -> isvsvn`. Each authorized
//!   release contributes two triples in the `servtd-hash` environment:
//!   * a `reference-triple` whose single `MeasurementMap.mval.digests[0]` is
//!     the ServTD info hash (authenticity), and
//!   * a `conditional-endorsement-series` (CES) triple whose series record
//!     *selects* on that digest and *adds* `mval.svn = ExactValue(svn)`.
//!   The hash -> svn lookup is driven by the CES triples.
//!
//! * **TD Identity CoRIM** — `isvsvn -> (tcb_date, tcb_status)`. A single
//!   `reference-triple` in the `svn-tcb` environment carrying one
//!   `MeasurementMap` per SVN, keyed by `mkey = Uint(svn)`, with
//!   `mval.extra_entries[MVAL_TEE_TCBDATE]` (CBOR `#6.1(epoch-seconds)`) and
//!   `mval.extra_entries[MVAL_TEE_TCBSTATUS]` (text). Both keys are the
//!   Intel-profile extension keys exported by the `corim` crate
//!   (`tee.tcbdate` = -72, `tee.tcbstatus` = -88), not MigTD-local numbers.
//!
//! Both environments share one component
//! `class.class-id = Uuid(SERVTD_HASH_CLASS_UUID)` and are distinguished by
//! `environment.instance` (`"servtd-hash"` vs `"svn-tcb"`).
//!
//! # `no_std`
//!
//! Built `#![no_std]` in MigTD; decode uses
//! [`corim::validate::decode_and_validate_at`] (the `_at` variant) so no
//! `SystemTime` is touched.
//!
//! # Signature verification
//!
//! [`ServtdCorim::decode_signed`] verifies the surrounding `COSE_Sign1`
//! envelope: it checks the ES384 signature against the embedded RFC 9360
//! `x5chain` (via the `crypto` crate) and binds the chain's trust anchor to
//! the RTMR1-measured policy signer anchor ([`compute_signer_anchor`]), so a
//! CoRIM is only trusted when signed by the same root-of-trust the firmware
//! measured from the CFV policy issuer chain. [`ServtdCorim::decode`] takes
//! already-verified inner payload bytes and performs decode + match only.

use alloc::{
    format,
    string::String,
    vec::Vec,
};
use core::convert::TryFrom;

use corim::{
    profile::intel::{MVAL_TEE_TCBDATE, MVAL_TEE_TCBSTATUS},
    types::{
        comid::ComidTag,
        environment::EnvironmentMap,
        measurement::{MeasurementMap, SvnChoice},
        signed::{decode_signed_corim, CoseAlgorithm},
        triples::ConditionalEndorsementSeriesTriple,
    },
    validate::decode_and_validate_at,
};

use crypto::SHA384_DIGEST_SIZE;

use crate::{
    v2::{compute_signer_anchor, ServtdLookup},
    PolicyError,
};

// ---- Wire-format constants (must match `mig-td-tools::types::servtd`) ------

/// Component class UUID shared by both the `servtd-hash` and `svn-tcb`
/// environments (`mig-td-tools`: `SERVTD_HASH_CLASS_UUID`).
pub const SERVTD_HASH_CLASS_UUID: [u8; 16] = [
    0x7f, 0xb0, 0x0e, 0xe4, 0xa7, 0xff, 0x11, 0xed, 0x9e, 0x2f, 0x00, 0x15, 0x5d, 0x09, 0xde, 0x56,
];

/// Instance bytes selecting the TCB Mapping environment.
pub const SERVTD_HASH_INSTANCE_BYTES: &[u8] = b"servtd-hash";

/// Instance bytes selecting the TD Identity environment.
pub const SVN_TCB_INSTANCE_BYTES: &[u8] = b"svn-tcb";

// `tcb_date` and `tcb_status` are carried under the Intel-profile extension
// keys re-exported from `corim::profile::intel`:
//   MVAL_TEE_TCBDATE   = -72  (`tee.tcbdate`,   CBOR #6.1(epoch-seconds))
//   MVAL_TEE_TCBSTATUS = -88  (`tee.tcbstatus`, text)
// No MigTD-local key numbers are defined here.

/// Decoded CoRIM servtd collateral: the TCB Mapping document (hash -> svn)
/// and the TD Identity document (svn -> tcb level).
pub struct ServtdCorim {
    /// CoMID tags from the TCB Mapping CoRIM (`servtd-hash` environment).
    tcb_mapping: Vec<ComidTag>,
    /// CoMID tags from the TD Identity CoRIM (`svn-tcb` environment).
    td_identity: Vec<ComidTag>,
}

impl ServtdCorim {
    /// Decode the two CoRIM blobs (CBOR, `#6.501` unsigned wrapper) and
    /// validate them structurally per draft-ietf-rats-corim-10.
    /// `now_epoch_secs` evaluates any embedded validity windows.
    ///
    /// Signature verification of the surrounding `COSE_Sign1` envelope is the
    /// caller's responsibility; these inputs are the inner payload bytes.
    pub fn decode(
        tcb_mapping_cbor: &[u8],
        td_identity_cbor: &[u8],
        now_epoch_secs: i64,
    ) -> Result<Self, PolicyError> {
        let (_c1, tcb_mapping) = decode_and_validate_at(tcb_mapping_cbor, now_epoch_secs)
            .map_err(|_| PolicyError::InvalidServtdTcbMapping)?;
        let (_c2, td_identity) = decode_and_validate_at(td_identity_cbor, now_epoch_secs)
            .map_err(|_| PolicyError::InvalidServtdIdentity)?;
        Ok(Self {
            tcb_mapping,
            td_identity,
        })
    }

    /// Decode from two **signed** CoRIM documents (`COSE_Sign1-corim`,
    /// `#6.18`), as produced by the `mig-td-tools` signer and shipped in the
    /// `.cose` files, verifying each signature before any payload byte is
    /// trusted.
    ///
    /// For each document the COSE envelope is parsed, its embedded RFC 9360
    /// `x5chain` and ES384 signature are verified, and the chain's trust
    /// anchor is bound to `expected_signer_anchor` — the RTMR1-measured
    /// policy signer anchor derived from the CFV policy issuer chain (see
    /// [`compute_signer_anchor`]). This ties the CoRIM signer to the exact
    /// root-of-trust the firmware measured at boot, mirroring how the legacy
    /// JSON collateral is rooted in the measured policy issuer chain. Only
    /// after the anchor matches is the inner CoRIM payload
    /// (`bstr .cbor #6.501(corim-map)`) extracted and decoded via
    /// [`decode`](Self::decode).
    pub fn decode_signed(
        tcb_mapping_cose: &[u8],
        td_identity_cose: &[u8],
        now_epoch_secs: i64,
        expected_signer_anchor: &[u8; SHA384_DIGEST_SIZE],
    ) -> Result<Self, PolicyError> {
        let tcb_payload = verify_and_extract_payload(tcb_mapping_cose, expected_signer_anchor)
            .map_err(|_| PolicyError::InvalidServtdTcbMapping)?;
        let id_payload = verify_and_extract_payload(td_identity_cose, expected_signer_anchor)
            .map_err(|_| PolicyError::InvalidServtdIdentity)?;
        Self::decode(&tcb_payload, &id_payload, now_epoch_secs)
    }

    /// Resolve `SERVTD_INFO_HASH -> isvsvn` via the TCB Mapping CES triples.
    ///
    /// The digest is matched by **value** only; the producer currently labels
    /// the 48-byte SHA-384 ServTD info hash with the SHA-256 algorithm id
    /// (see the design-review gap note), so the algorithm field is not
    /// enforced here.
    fn svn_for_hash(&self, hash: &[u8]) -> Option<u16> {
        for comid in &self.tcb_mapping {
            let Some(ces_list) = comid.triples.conditional_endorsement_series.as_ref() else {
                continue;
            };
            for ces in ces_list {
                if let Some(svn) = ces_svn_for_hash(ces, hash) {
                    return Some(svn);
                }
            }
        }
        None
    }

    /// Resolve `isvsvn -> (tcb_date, tcb_status)` via the TD Identity table.
    fn level_for_svn(&self, svn: u16) -> Option<(String, String)> {
        for comid in &self.td_identity {
            let Some(ces_list) = comid.triples.conditional_endorsement_series.as_ref() else {
                continue;
            };
            for ces in ces_list {
                if let Some(level) = ces_level_for_svn(ces, svn) {
                    return Some(level);
                }
            }
        }
        None
    }

    /// Number of CoMID tags in each document. Exposed for diagnostics.
    pub fn comid_counts(&self) -> (usize, usize) {
        (self.tcb_mapping.len(), self.td_identity.len())
    }

    /// Resolve `(isvsvn, tcb_date, tcb_status)` for the MigTD whose masked
    /// `TDINFO_STRUCT` hashes to `tdinfo_hash` (the 48-byte
    /// `init/cur_servtd_info_hash`). Returns `None` if the hash is not
    /// endorsed by this CoRIM.
    pub fn lookup_by_tdinfo_hash(&self, tdinfo_hash: &[u8]) -> Option<ServtdLookup> {
        let isvsvn = self.svn_for_hash(tdinfo_hash)?;
        let (tcb_date, tcb_status) = self.level_for_svn(isvsvn)?;
        Some(ServtdLookup {
            isvsvn,
            tcb_date,
            tcb_status,
        })
    }
}

// ---- COSE_Sign1 envelope + signature verification --------------------------

/// Verify a signed `COSE_Sign1-corim` (`#6.18`) and return its attached CoRIM
/// payload bytes (`bstr .cbor #6.501(corim-map)`).
///
/// The full trust check is performed before any byte is returned:
/// 1. Parse the COSE envelope; require an **attached** payload.
/// 2. Require the protected `alg` to be ES384/ESP384 (ECDSA-P384/SHA-384) and
///    an RFC 9360 `x5chain` to be present.
/// 3. Verify the x5chain integrity and the COSE signature over the
///    `Sig_structure1` TBS (delegated to the `crypto` crate).
/// 4. Bind the chain's `(root, leaf-subject)` to `expected_signer_anchor` —
///    the RTMR1-measured policy signer anchor — so the CoRIM signer is the
///    same root-of-trust the firmware measured from the CFV. A mismatch is
///    fatal (fail-closed).
fn verify_and_extract_payload(
    cose: &[u8],
    expected_signer_anchor: &[u8; SHA384_DIGEST_SIZE],
) -> Result<Vec<u8>, PolicyError> {
    let envelope =
        decode_signed_corim(cose).map_err(|_| PolicyError::SignatureVerificationFailed)?;

    // Only ECDSA-P384/SHA-384 is supported by the crypto crate. Accept both
    // the deprecated polymorphic ES384 (-35, what the producer emits today)
    // and its fully-specified RFC 9864 replacement ESP384 (-51).
    match envelope.protected.alg {
        CoseAlgorithm::Es384 | CoseAlgorithm::Esp384 => {}
        _ => return Err(PolicyError::SignatureVerificationFailed),
    }

    let x5chain = envelope
        .protected
        .x5chain
        .as_ref()
        .ok_or(PolicyError::SignatureVerificationFailed)?;
    let certs = x5chain.certs();

    let tbs = envelope
        .to_be_signed(&[])
        .map_err(|_| PolicyError::SignatureVerificationFailed)?;

    let (root_der, leaf_subject_der) =
        crypto::verify_cose_sign1_es384_x5chain(&certs, &tbs, &envelope.signature)
            .map_err(|_| PolicyError::SignatureVerificationFailed)?;

    let anchor = compute_signer_anchor(&root_der, &leaf_subject_der)?;
    if anchor != *expected_signer_anchor {
        return Err(PolicyError::SignatureVerificationFailed);
    }

    envelope
        .payload
        .ok_or(PolicyError::SignatureVerificationFailed)
}

// ---- Environment matching --------------------------------------------------

fn is_servtd_hash_environment(env: &EnvironmentMap) -> bool {
    env_matches(env, SERVTD_HASH_INSTANCE_BYTES)
}

fn is_svn_tcb_environment(env: &EnvironmentMap) -> bool {
    env_matches(env, SVN_TCB_INSTANCE_BYTES)
}

fn env_matches(env: &EnvironmentMap, instance: &[u8]) -> bool {
    use corim::types::common::{ClassIdChoice, InstanceIdChoice};

    let class_ok = env
        .class
        .as_ref()
        .and_then(|c| c.class_id.as_ref())
        .map(|id| matches!(id, ClassIdChoice::Uuid(u) if *u == SERVTD_HASH_CLASS_UUID))
        .unwrap_or(false);

    let instance_ok = matches!(
        env.instance.as_ref(),
        Some(InstanceIdChoice::Bytes(b)) if b.as_slice() == instance
    );

    class_ok && instance_ok
}

// ---- TCB Mapping (CES) helpers --------------------------------------------

/// If this CES triple is in the `servtd-hash` environment and its first
/// series record selects on `hash`, return the SVN it adds.
fn ces_svn_for_hash(ces: &ConditionalEndorsementSeriesTriple, hash: &[u8]) -> Option<u16> {
    if !is_servtd_hash_environment(&ces.condition().environment) {
        return None;
    }
    for record in ces.series() {
        let selected = record
            .selection()
            .first()
            .and_then(digest_value)
            .map(|d| d == hash)
            .unwrap_or(false);
        if !selected {
            continue;
        }
        if let Some(svn) = record.addition().first().and_then(svn_exact) {
            return u16::try_from(svn).ok();
        }
    }
    None
}

/// First digest value of a measurement (the ServTD info hash).
fn digest_value(m: &MeasurementMap) -> Option<&[u8]> {
    Some(m.mval.digests.as_ref()?.first()?.value())
}

/// The exact SVN carried by a measurement's `mval.svn`, if present.
fn svn_exact(m: &MeasurementMap) -> Option<u64> {
    match m.mval.svn {
        Some(SvnChoice::ExactValue(n)) => Some(n),
        _ => None,
    }
}

// ---- TD Identity helpers ---------------------------------------------------

/// If this CES triple is in the `svn-tcb` environment and one of its series
/// records selects on `svn` (`selection.mval.svn == exact(svn)`), return the
/// `(tcb_date, tcb_status)` it adds. The producer encodes the TD-identity
/// table as one CES triple per SVN: select on the SVN, add the TCB level.
fn ces_level_for_svn(ces: &ConditionalEndorsementSeriesTriple, svn: u16) -> Option<(String, String)> {
    if !is_svn_tcb_environment(&ces.condition().environment) {
        return None;
    }
    for record in ces.series() {
        let selected = record
            .selection()
            .first()
            .and_then(svn_exact)
            .map(|s| s == svn as u64)
            .unwrap_or(false);
        if !selected {
            continue;
        }
        if let Some(level) = record.addition().first().and_then(measurement_level) {
            return Some(level);
        }
    }
    None
}

/// `(tcb_date, tcb_status)` from a measurement's extra entries (the CES
/// addition). `tcb_date` is rendered as an ISO-8601 `YYYY-MM-DDTHH:MM:SSZ`
/// string so it is directly comparable with the legacy collateral and the
/// policy engine's lexical ISO-8601 ordering.
fn measurement_level(m: &MeasurementMap) -> Option<(String, String)> {
    use corim::cbor::value::Value;

    let epoch = read_epoch(m.mval.extra_entries.get(&MVAL_TEE_TCBDATE)?)?;
    let status = match m.mval.extra_entries.get(&MVAL_TEE_TCBSTATUS)? {
        Value::Text(s) => s.clone(),
        _ => return None,
    };
    Some((epoch_to_iso8601(epoch), status))
}

/// Read an epoch-seconds value from a CBOR `#6.1(int)` tag or a bare integer.
fn read_epoch(v: &corim::cbor::value::Value) -> Option<i64> {
    use corim::cbor::value::Value;
    let inner = match v {
        Value::Tag(1, b) => b.as_ref(),
        other => other,
    };
    match inner {
        Value::Integer(n) => i64::try_from(*n).ok(),
        _ => None,
    }
}

/// Convert epoch seconds to `YYYY-MM-DDTHH:MM:SSZ` (UTC), `no_std`, no chrono.
fn epoch_to_iso8601(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Howard Hinnant's days-from-civil inverse: days since 1970-01-01 ->
/// `(year, month, day)`.
fn civil_from_days(z0: i64) -> (i64, u32, u32) {
    let z = z0 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{boxed::Box, vec, vec::Vec};
    use corim::{
        builder::{ComidBuilder, CorimBuilder},
        cbor::value::Value,
        types::{
            common::{ClassIdChoice, InstanceIdChoice, TagIdChoice},
            corim::CorimId,
            environment::{ClassMap, EnvironmentMap},
            measurement::{Digest, MeasurementValuesMap},
            triples::{
                CesCondition, ConditionalSeriesRecord, ReferenceTriple,
            },
        },
    };

    /// Producer's (mislabeled) digest alg id — see the SHA-256/SHA-384 gap.
    const SHA256_ALG: i64 = 1;

    fn class() -> ClassMap {
        ClassMap {
            class_id: Some(ClassIdChoice::Uuid(SERVTD_HASH_CLASS_UUID)),
            vendor: None,
            model: None,
            layer: None,
            index: None,
        }
    }

    fn servtd_hash_env() -> EnvironmentMap {
        EnvironmentMap {
            class: Some(class()),
            instance: Some(InstanceIdChoice::Bytes(SERVTD_HASH_INSTANCE_BYTES.to_vec())),
            group: None,
        }
    }

    fn svn_tcb_env() -> EnvironmentMap {
        EnvironmentMap {
            class: Some(class()),
            instance: Some(InstanceIdChoice::Bytes(SVN_TCB_INSTANCE_BYTES.to_vec())),
            group: None,
        }
    }

    fn ref_triple(hash: &[u8]) -> ReferenceTriple {
        ReferenceTriple::new(
            servtd_hash_env(),
            vec![MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    digests: Some(vec![Digest::new(SHA256_ALG, hash.to_vec())]),
                    ..MeasurementValuesMap::new()
                },
                authorized_by: None,
            }],
        )
    }

    fn ces_triple(hash: &[u8], svn: u16) -> ConditionalEndorsementSeriesTriple {
        let condition = CesCondition {
            environment: servtd_hash_env(),
            claims_list: Vec::new(),
            authorized_by: None,
        };
        let selection = MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![Digest::new(SHA256_ALG, hash.to_vec())]),
                ..MeasurementValuesMap::new()
            },
            authorized_by: None,
        };
        let addition = MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                svn: Some(SvnChoice::ExactValue(svn as u64)),
                ..MeasurementValuesMap::new()
            },
            authorized_by: None,
        };
        ConditionalEndorsementSeriesTriple::new(
            condition,
            vec![ConditionalSeriesRecord::new(vec![selection], vec![addition])],
        )
    }

    /// Build a TCB Mapping CoRIM mirroring `TcbMappingCorim::add_release`:
    /// a reference-triple plus a CES triple per `(hash, svn)`.
    fn build_tcb_mapping(entries: &[(Vec<u8>, u16)]) -> Vec<u8> {
        let mut comid = ComidBuilder::new(TagIdChoice::Text("migtd-tcb-mapping".into()));
        for (hash, svn) in entries {
            comid = comid.add_reference_triple(ref_triple(hash));
            comid = comid.add_conditional_endorsement_series(ces_triple(hash, *svn));
        }
        let comid = comid.build().expect("build tcb-mapping comid");
        CorimBuilder::new(CorimId::Text("migtd-tcb-mapping".into()))
            .add_comid_tag(comid)
            .expect("attach comid")
            .build_bytes()
            .expect("encode corim")
    }

    /// Build a TD Identity CoRIM mirroring `TdIdentityCorim::add_level`: one
    /// CES triple per SVN in the `svn-tcb` environment (select on `svn`, add
    /// `tcb_date` / `tcb_status`).
    fn build_td_identity(levels: &[(u16, i64, &str)]) -> Vec<u8> {
        let mut comid = ComidBuilder::new(TagIdChoice::Text("migtd-td-identity".into()));
        for (svn, date, status) in levels {
            let selection = MeasurementMap {
                mkey: None,
                mval: MeasurementValuesMap {
                    svn: Some(SvnChoice::ExactValue(*svn as u64)),
                    ..MeasurementValuesMap::new()
                },
                authorized_by: None,
            };
            let mut add_mval = MeasurementValuesMap::new();
            add_mval.extra_entries.insert(
                MVAL_TEE_TCBDATE,
                Value::Tag(1, Box::new(Value::Integer(*date as i128))),
            );
            add_mval
                .extra_entries
                .insert(MVAL_TEE_TCBSTATUS, Value::Text(status.to_string()));
            let addition = MeasurementMap {
                mkey: None,
                mval: add_mval,
                authorized_by: None,
            };
            let condition = CesCondition {
                environment: svn_tcb_env(),
                claims_list: Vec::new(),
                authorized_by: None,
            };
            comid = comid.add_conditional_endorsement_series(
                ConditionalEndorsementSeriesTriple::new(
                    condition,
                    vec![ConditionalSeriesRecord::new(vec![selection], vec![addition])],
                ),
            );
        }
        let comid = comid.build().expect("build td-identity comid");
        CorimBuilder::new(CorimId::Text("migtd-td-identity".into()))
            .add_comid_tag(comid)
            .expect("attach comid")
            .build_bytes()
            .expect("encode corim")
    }

    fn hash(byte: u8) -> Vec<u8> {
        vec![byte; 48]
    }

    #[test]
    fn hash_lookup_resolves_svn_then_level() {
        let tcb = build_tcb_mapping(&[(hash(0xAA), 5), (hash(0xBB), 7)]);
        // 2024-01-01T00:00:00Z = 1704067200 ; 2025-06-01T00:00:00Z = 1748736000
        let id = build_td_identity(&[
            (5, 1_704_067_200, "UpToDate"),
            (7, 1_748_736_000, "OutOfDate"),
        ]);
        let provider = ServtdCorim::decode(&tcb, &id, 0).expect("decode");
        assert_eq!(provider.comid_counts(), (1, 1));

        let hit = provider
            .lookup_by_tdinfo_hash(&hash(0xAA))
            .expect("match");
        assert_eq!(hit.isvsvn, 5);
        assert_eq!(hit.tcb_date, "2024-01-01T00:00:00Z");
        assert_eq!(hit.tcb_status, "UpToDate");

        let hit2 = provider
            .lookup_by_tdinfo_hash(&hash(0xBB))
            .expect("match");
        assert_eq!(hit2.isvsvn, 7);
        assert_eq!(hit2.tcb_date, "2025-06-01T00:00:00Z");
        assert_eq!(hit2.tcb_status, "OutOfDate");
    }

    #[test]
    fn unknown_hash_misses() {
        let tcb = build_tcb_mapping(&[(hash(0xAA), 5)]);
        let id = build_td_identity(&[(5, 1_704_067_200, "UpToDate")]);
        let provider = ServtdCorim::decode(&tcb, &id, 0).expect("decode");
        assert!(provider
            .lookup_by_tdinfo_hash(&hash(0xCC))
            .is_none());
    }

    #[test]
    fn known_hash_but_missing_level_misses() {
        // SVN 9 has a mapping but no TD Identity level.
        let tcb = build_tcb_mapping(&[(hash(0xAA), 9)]);
        let id = build_td_identity(&[(5, 1_704_067_200, "UpToDate")]);
        let provider = ServtdCorim::decode(&tcb, &id, 0).expect("decode");
        assert!(provider
            .lookup_by_tdinfo_hash(&hash(0xAA))
            .is_none());
    }

    #[test]
    fn wrong_length_hash_misses() {
        let tcb = build_tcb_mapping(&[(hash(0xAA), 5)]);
        let id = build_td_identity(&[(5, 1_704_067_200, "UpToDate")]);
        let provider = ServtdCorim::decode(&tcb, &id, 0).expect("decode");
        assert!(provider
            .lookup_by_tdinfo_hash(&[0xAA; 32])
            .is_none());
    }

    #[test]
    fn epoch_formatting() {
        assert_eq!(epoch_to_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_iso8601(1_704_067_200), "2024-01-01T00:00:00Z");
        assert_eq!(epoch_to_iso8601(1_748_736_000), "2025-06-01T00:00:00Z");
    }

    /// Interop regression: decode CBOR produced by the real host-side
    /// `mig-td-tools` signer (not our test reconstruction) and resolve a
    /// hash through both documents. The fixtures were generated with:
    ///   tcb-mapping-corim add-entry --servtd-hash <0xAA*48> --svn 5
    ///   tcb-mapping-corim add-entry --servtd-hash <0xBB*48> --svn 7
    ///   td-identity-corim add-level --svn 5 --tcb-date 2024-01-01 --tcb-status UpToDate
    ///   td-identity-corim add-level --svn 7 --tcb-date 2025-06-01 --tcb-status OutOfDate
    #[test]
    fn interop_with_mig_td_tools_producer() {
        let tcb = include_bytes!("../../test/policy_v2/corim/tcb_mapping.cbor");
        let id = include_bytes!("../../test/policy_v2/corim/td_identity.cbor");
        let provider = ServtdCorim::decode(tcb, id, 0).expect("decode producer CBOR");

        let hit = provider
            .lookup_by_tdinfo_hash(&hash(0xAA))
            .expect("hash 0xAA*48 -> svn 5");
        assert_eq!(hit.isvsvn, 5);
        assert_eq!(hit.tcb_date, "2024-01-01T00:00:00Z");
        assert_eq!(hit.tcb_status, "UpToDate");

        let hit2 = provider
            .lookup_by_tdinfo_hash(&hash(0xBB))
            .expect("hash 0xBB*48 -> svn 7");
        assert_eq!(hit2.isvsvn, 7);
        assert_eq!(hit2.tcb_date, "2025-06-01T00:00:00Z");
        assert_eq!(hit2.tcb_status, "OutOfDate");

        assert!(provider
            .lookup_by_tdinfo_hash(&hash(0xCC))
            .is_none());
    }

    /// End-to-end with the real signed `COSE_Sign1` samples emitted by
    /// `mig-td-tools`: verify each envelope's ES384 signature + `x5chain`,
    /// bind the signer to the RTMR1 signer anchor, then resolve a hash. The
    /// samples endorse a single release: `7c65bdfb…05b5554 -> svn 1`,
    /// `svn 1 -> (2023-08-09, UpToDate)`.
    #[test]
    fn interop_with_signed_cose_samples() {
        let tcb = include_bytes!("../../test/policy_v2/corim/tcb_mapping.cose");
        let id = include_bytes!("../../test/policy_v2/corim/td_identity.cose");

        // The anchor the firmware would measure into RTMR1 for this signer.
        // Deriving it exercises the real ES384 + chain verification path.
        let anchor = signer_anchor_from_sample(tcb);

        // 2025-01-01T00:00:00Z — inside the endorsement validity window.
        let provider = ServtdCorim::decode_signed(tcb, id, 1_735_689_600, &anchor)
            .expect("decode signed COSE");

        let mut hash = [0u8; 48];
        hex_decode(
            "7c65bdfb3f54799b1af25ce42de1bac6aa8359f8afa15eb18e6eddbe1ff14f0d\
             7788228e0463cb220a1176d0f05b5554",
            &mut hash,
        );
        let hit = provider
            .lookup_by_tdinfo_hash(&hash)
            .expect("signed-sample hash -> svn 1");
        assert_eq!(hit.isvsvn, 1);
        assert_eq!(hit.tcb_date, "2023-08-09T00:00:00Z");
        assert_eq!(hit.tcb_status, "UpToDate");
    }

    /// Fail-closed: a signer anchor that does not match the COSE x5chain's
    /// root-of-trust must be rejected, even though the signature itself is
    /// cryptographically valid. This is the RTMR1 binding that ties the CoRIM
    /// signer to the firmware-measured policy issuer.
    #[test]
    fn signed_cose_rejects_unmeasured_signer() {
        let tcb = include_bytes!("../../test/policy_v2/corim/tcb_mapping.cose");
        let id = include_bytes!("../../test/policy_v2/corim/td_identity.cose");

        let mut wrong = signer_anchor_from_sample(tcb);
        wrong[0] ^= 0xFF; // any anchor other than the signer's

        assert!(ServtdCorim::decode_signed(tcb, id, 1_735_689_600, &wrong).is_err());
    }

    /// Recover the signer anchor `A = compute_signer_anchor(root, leaf-subject)`
    /// from a sample's embedded x5chain, running the full signature + chain
    /// verification on the way (so a tampered sample would fail here).
    fn signer_anchor_from_sample(cose: &[u8]) -> [u8; SHA384_DIGEST_SIZE] {
        let env = decode_signed_corim(cose).expect("decode COSE");
        let tbs = env.to_be_signed(&[]).expect("tbs");
        let chain = env.protected.x5chain.as_ref().expect("x5chain");
        let certs = chain.certs();
        let (root_der, leaf_subject_der) =
            crypto::verify_cose_sign1_es384_x5chain(&certs, &tbs, &env.signature)
                .expect("verify signature");
        compute_signer_anchor(&root_der, &leaf_subject_der).expect("anchor")
    }

    fn hex_decode(s: &str, out: &mut [u8]) {
        let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert_eq!(bytes.len(), out.len() * 2);
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = (bytes[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            *byte = (hi << 4) | lo;
        }
    }
}
