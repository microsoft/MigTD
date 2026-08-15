// Copyright (c) 2025 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
};
use serde::{Deserialize, Serialize};
use serde_json::{self, value::RawValue};

use crate::{
    v2::{
        bytes_to_hex_string, compute_signer_anchor_from_chain_pem,
        measurement::extract_canonical_policy_data_bytes, policy, resolve_signer_anchor,
        verify_event_hash,
    },
    CcEvent, Collaterals, EventName, PolicyError, Report, ServtdCollateral, TdIdentity,
    TdTcbMapping,
};
use crypto::SHA384_DIGEST_SIZE;

#[cfg(feature = "servtd_corim")]
use crate::v2::ServtdCorim;

/// Result of a successful servtd lookup: the MigTD's ISV SVN, and — when the
/// optional TD Identity is present — the TCB level (`tcb_date`, `tcb_status`)
/// recorded for that SVN.
///
/// Produced by [`VerifiedPolicy::servtd_lookup_by_tdinfo_hash`] from either
/// the JSON collateral (one-hash `TdTcbMapping`, plus optional `TdIdentity`)
/// or, when attached, the CoRIM hash endorsement (`servtd_corim` feature).
/// Both resolve a `tdinfo_hash` to the endorsed `isvsvn`. `tcb_date` /
/// `tcb_status` are populated only from the optional JSON TD Identity; the
/// CoRIM path leaves them `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServtdLookup {
    pub isvsvn: u16,
    pub tcb_date: Option<String>,
    pub tcb_status: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum ServtdTcbStatus {
    UpToDate,
    OutOfDate,
    Revoked,
}

impl ServtdTcbStatus {
    pub fn as_str(&self) -> &str {
        match self {
            ServtdTcbStatus::UpToDate => "UpToDate",
            ServtdTcbStatus::OutOfDate => "OutOfDate",
            ServtdTcbStatus::Revoked => "Revoked",
        }
    }

    // "UpToDate" == "OutOfDate" > "Revoked"
    fn rank(&self) -> u8 {
        match self {
            ServtdTcbStatus::UpToDate | ServtdTcbStatus::OutOfDate => 2,
            ServtdTcbStatus::Revoked => 0,
        }
    }
}

impl TryFrom<&str> for ServtdTcbStatus {
    type Error = PolicyError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "UpToDate" => Ok(ServtdTcbStatus::UpToDate),
            "OutOfDate" => Ok(ServtdTcbStatus::OutOfDate),
            "Revoked" => Ok(ServtdTcbStatus::Revoked),
            _ => Err(PolicyError::InvalidParameter),
        }
    }
}

impl PartialOrd for ServtdTcbStatus {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.rank().cmp(&other.rank()))
    }
}

impl PartialEq for ServtdTcbStatus {
    fn eq(&self, other: &Self) -> bool {
        self.rank() == other.rank()
    }
}

impl Eq for ServtdTcbStatus {}

#[derive(Clone, Copy, Debug)]
pub enum TcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

impl TcbStatus {
    pub fn as_str(&self) -> &str {
        match self {
            TcbStatus::UpToDate => "UpToDate",
            TcbStatus::SWHardeningNeeded => "SWHardeningNeeded",
            TcbStatus::ConfigurationNeeded => "ConfigurationNeeded",
            TcbStatus::ConfigurationAndSWHardeningNeeded => "ConfigurationAndSWHardeningNeeded",
            TcbStatus::OutOfDate => "OutOfDate",
            TcbStatus::OutOfDateConfigurationNeeded => "OutOfDateConfigurationNeeded",
            TcbStatus::Revoked => "Revoked",
        }
    }

    // "UpToDate" == "SWHardeningNeeded" == "OutOfDate" >= "ConfigurationNeeded" ==
    // "ConfigurationAndSWHardeningNeeded" == "OutOfDateConfigurationNeeded” > "Revoked"
    fn rank(&self) -> u8 {
        match self {
            TcbStatus::UpToDate | TcbStatus::SWHardeningNeeded | TcbStatus::OutOfDate => 2,
            TcbStatus::ConfigurationNeeded
            | TcbStatus::ConfigurationAndSWHardeningNeeded
            | TcbStatus::OutOfDateConfigurationNeeded => 1,
            TcbStatus::Revoked => 0,
        }
    }
}

impl TryFrom<&str> for TcbStatus {
    type Error = PolicyError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "UpToDate" => Ok(TcbStatus::UpToDate),
            "SWHardeningNeeded" => Ok(TcbStatus::SWHardeningNeeded),
            "ConfigurationNeeded" => Ok(TcbStatus::ConfigurationNeeded),
            "ConfigurationAndSWHardeningNeeded" => Ok(TcbStatus::ConfigurationAndSWHardeningNeeded),
            "OutOfDate" => Ok(TcbStatus::OutOfDate),
            "OutOfDateConfigurationNeeded" => Ok(TcbStatus::OutOfDateConfigurationNeeded),
            "Revoked" => Ok(TcbStatus::Revoked),
            _ => Err(PolicyError::InvalidParameter),
        }
    }
}

impl PartialOrd for TcbStatus {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.rank().cmp(&other.rank()))
    }
}

impl PartialEq for TcbStatus {
    fn eq(&self, other: &Self) -> bool {
        self.rank() == other.rank()
    }
}

impl Eq for TcbStatus {}

/// Contains all required data to be evaluated against a rebinding policy
#[derive(Debug, Clone, Default)]
pub struct PolicyEvaluationInfo {
    /// The TEE_TCB_SVN of MigTD
    pub tee_tcb_svn: Option<[u8; 16]>,

    /// The date of the Trusted Computing Base (TCB) in ISO-8601 format, e.g. "2023-06-19T00:00:00Z"
    pub tcb_date: Option<String>,

    /// The status of the TCB
    pub tcb_status: Option<String>,

    /// The TCB evaluation data number used to track TCB revocations and updates
    pub tcb_evaluation_number: Option<u32>,

    /// The FMSPC of platform
    pub fmspc: Option<[u8; 6]>,

    /// The isvsvn of the MigTD TCB
    pub migtd_isvsvn: Option<u16>,

    /// The status of the MigTD TCB (from the optional TD Identity)
    pub migtd_tcb_status: Option<String>,

    /// The date of the MigTD TCB in ISO-8601 format (from the optional TD
    /// Identity), e.g. "2023-06-19T00:00:00Z"
    pub migtd_tcb_date: Option<String>,

    /// The minimal crl_num of pck_crl
    pub pck_crl_num: Option<u32>,

    /// The minimal crl_num of root_ca_crl
    pub root_ca_crl_num: Option<u32>,

    /// The CRL number of the servtd signer CRL (`servtdCrl`), used
    /// for monotonic anti-rollback of the signer revocation list. See
    /// `doc/rtmr1_signer_anchor_proposal.md` §revocation.
    pub servtd_crl_num: Option<u32>,
}

pub struct VerifiedPolicy<'a> {
    pub policy_data: policy::PolicyData<'a>,
    /// Verified one-hash TCB mapping from the JSON `servtdCollateral`. `None`
    /// for a CoRIM-only policy (no `servtdCollateral`); lookups then resolve
    /// through the attached CoRIM (fail-closed if none is attached).
    pub servtd_tcb_mapping: Option<TdTcbMapping>,
    /// Issuer chain (PEM) for the JSON mapping signer. `None` when the JSON
    /// `servtdCollateral` is absent (CoRIM-only).
    pub servtd_tcb_mapping_issuer_chain: Option<String>,
    /// Optional MigTD TD Identity (`isvsvn -> (tcb_date, tcb_status)`), present
    /// only when the JSON collateral ships a `servtdIdentity`. When absent,
    /// policy is driven by the ISV SVN alone.
    pub servtd_identity: Option<TdIdentity>,
    /// Optional TD Identity issuer chain (PEM), present iff `servtd_identity`
    /// is. Retained so the runtime can cross-check a peer's identity chain.
    pub servtd_identity_issuer_chain: Option<String>,
    /// Optional PEM CRL for the servTD signer chain, from
    /// top-level `servtdCrl` or the legacy
    /// `servtdCollateral.servtdCrl`. Retained so the runtime can cross-check a
    /// peer's signer chain against the local trusted CRL. The top-level form
    /// allows CoRIM-only policies to carry revocation state without restoring
    /// JSON TCB-mapping enrollment.
    pub servtd_crl: Option<String>,
    /// The RTMR1 signer anchor `A = SHA384(tag ‖ H(rootDER) ‖ leafEkuOidDER)`
    /// (hash of the root cert plus the leaf's dedicated signer-purpose EKU OID
    /// DER) this policy was bound to (resolved from the CFV signer-anchor slot
    /// or a PEM issuer chain). Used for the anchor-based peer cross-check.
    pub signer_anchor: [u8; SHA384_DIGEST_SIZE],
    /// Optional CoRIM-encoded servtd collateral. When attached it is the sole
    /// authority for servtd lookups (fail-closed: a CoRIM miss is a miss,
    /// with no fallback to the legacy JSON collateral). Only available with
    /// the `servtd_corim` feature.
    ///
    /// For a peer policy, this must be the peer's authenticated CoRIM.
    /// Using the local mapping breaks migration between independent releases.
    #[cfg(feature = "servtd_corim")]
    servtd_corim: Option<ServtdCorim>,
}

impl<'a> VerifiedPolicy<'a> {
    pub fn get_collaterals(&self) -> &Collaterals {
        &self.policy_data.collaterals
    }

    pub fn get_version(&self) -> &str {
        &self.policy_data.version
    }

    /// Attach decoded CoRIM servtd collateral. Once set, **all** servtd
    /// lookups resolve against the CoRIM and the legacy JSON collateral is no
    /// longer consulted.
    ///
    /// Callers attaching a CoRIM to a *peer's* `VerifiedPolicy` MUST have
    /// already verified `corim`'s COSE signature/x5chain against that same
    /// peer's own resolved `signer_anchor` (see `ServtdCorim::decode_signed`).
    /// Never attach a locally-sourced CoRIM to a peer's policy.
    #[cfg(feature = "servtd_corim")]
    pub fn set_servtd_corim(&mut self, corim: ServtdCorim) {
        self.servtd_corim = Some(corim);
    }

    /// Verify and attach the peer's signed TCB-mapping CoRIM using its signer
    /// anchor. Current and initial peer hash lookups then use this mapping.
    /// Callers must still apply the local authoritative servTD CRL.
    #[cfg(feature = "servtd_corim")]
    pub fn attach_verified_peer_servtd_corim(
        &mut self,
        peer_servtd_corim_cose: &[u8],
    ) -> Result<(), PolicyError> {
        let corim = ServtdCorim::decode_signed(peer_servtd_corim_cose, 0, &self.signer_anchor)?;
        self.servtd_corim = Some(corim);
        Ok(())
    }

    /// Check every retained servTD signer chain against an authoritative CRL.
    ///
    /// For local initialization, `authoritative_crl` is the CRL measured in
    /// this policy. For peer authentication, callers must pass the local
    /// policy's CRL rather than the peer's delivered CRL.
    pub fn verify_signer_chains_not_revoked(
        &self,
        authoritative_crl: &[u8],
    ) -> Result<(), PolicyError> {
        if let Some(mapping_chain) = self.servtd_tcb_mapping_issuer_chain.as_deref() {
            crypto::verify_signer_chain_not_revoked(
                crypto::SignerChain::Pem(mapping_chain.as_bytes()),
                authoritative_crl,
            )
            .map_err(|_| PolicyError::SignerRevoked)?;
        }
        if let Some(identity_chain) = self.servtd_identity_issuer_chain.as_deref() {
            crypto::verify_signer_chain_not_revoked(
                crypto::SignerChain::Pem(identity_chain.as_bytes()),
                authoritative_crl,
            )
            .map_err(|_| PolicyError::SignerRevoked)?;
        }
        #[cfg(feature = "servtd_corim")]
        if let Some(corim) = self.servtd_corim.as_ref() {
            corim.verify_signer_chain_not_revoked(authoritative_crl)?;
        }
        Ok(())
    }

    /// Resolve the MigTD ISV SVN (and, when the optional TD Identity is
    /// present, its `tcb_date` / `tcb_status`) from a 48-byte `tdinfo_hash`
    /// (= `init/cur_servtd_info_hash`).
    ///
    /// When the `servtd_corim` feature is enabled and a CoRIM is attached, it
    /// is the sole authority (**fail-closed**: a CoRIM miss returns `None`,
    /// the JSON collateral is not consulted) and returns SVN only (no TD
    /// Identity date/status). Otherwise the lookup uses the JSON collateral's
    /// `TdTcbMapping::get_engine_svn_by_tdinfo_hash`, then \u2014 if a `TdIdentity`
    /// is present \u2014 `TdIdentity::get_tcb_level_by_svn` for the date/status.
    pub fn servtd_lookup_by_tdinfo_hash(&self, tdinfo_hash: &[u8]) -> Option<ServtdLookup> {
        #[cfg(feature = "servtd_corim")]
        if let Some(corim) = &self.servtd_corim {
            return corim.lookup_by_tdinfo_hash(tdinfo_hash);
        }
        // JSON path — hash -> SVN via the one-hash TCB mapping, then optional
        // SVN -> (date, status) via the TD Identity when it is shipped.
        let isvsvn = self
            .servtd_tcb_mapping
            .as_ref()?
            .get_engine_svn_by_tdinfo_hash(tdinfo_hash)?;
        let (tcb_date, tcb_status) = match &self.servtd_identity {
            Some(identity) => {
                let level = identity.get_tcb_level_by_svn(isvsvn)?;
                (Some(level.tcb_date.clone()), Some(level.tcb_status.clone()))
            }
            None => (None, None),
        };
        Some(ServtdLookup {
            isvsvn,
            tcb_date,
            tcb_status,
        })
    }

    /// Convenience: compute the `tdinfo_hash` from a verified `Report` and
    /// resolve through [`servtd_lookup_by_tdinfo_hash`].
    ///
    /// [`servtd_lookup_by_tdinfo_hash`]: VerifiedPolicy::servtd_lookup_by_tdinfo_hash
    pub fn servtd_lookup_by_report(&self, report: &Report) -> Option<ServtdLookup> {
        let hash = crate::v2::compute_tdinfo_hash_from_report(report).ok()?;
        self.servtd_lookup_by_tdinfo_hash(&hash)
    }
}

pub fn check_policy_integrity(
    policy: &[u8],
    events: &BTreeMap<EventName, CcEvent>,
) -> Result<(), PolicyError> {
    // RTMR2 is extended once with the canonical bytes of `policyData` with
    // `servtdCollateral.servtdTcbMapping` removed. See
    // `doc/tcb_mapping_design_proposal.md` for the rationale. The verifier
    // recomputes those exact bytes via the same helper used by the runtime
    // extender (`get_policy_and_measure`) and `migtd-hash` (offline RTMR2
    // simulator), then asserts the event-log entry's recorded digest matches.
    let policy_data_bytes = extract_canonical_policy_data_bytes(policy)?;
    if !verify_event_hash(events, &EventName::MigTdPolicyData, &policy_data_bytes)? {
        return Err(PolicyError::PolicyHashMismatch);
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawPolicyData<'a> {
    #[serde(borrow)]
    pub policy_data: &'a RawValue,
    /// Legacy outer policy-blob signature.
    ///
    /// The outer signature has been **removed** from the trust model (per
    /// `doc/tcb_mapping_design_proposal.md`): `policyData` integrity is now
    /// established solely by the RTMR2 measurement (`check_policy_integrity`),
    /// not by an outer signature. This field is retained as an optional,
    /// **ignored** value only so that pre-existing signed policy blobs still
    /// deserialize. New policies omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl<'a> RawPolicyData<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<RawPolicyData>(slice).map_err(|_| PolicyError::InvalidPolicy)
    }

    pub fn get_collaterals(&self) -> Result<Collaterals, PolicyError> {
        let policy_data: PolicyData<'a> =
            serde_json::from_str(self.policy_data.get()).map_err(|_| PolicyError::InvalidPolicy)?;
        Ok(policy_data.collaterals)
    }

    /// Verify the servtd collateral using the given (RTMR1-anchored) issuer
    /// chain.
    ///
    /// The outer policy-blob signature has been **removed** from the trust
    /// model: `policyData` integrity is established by the RTMR2 measurement
    /// (`check_policy_integrity`), so this function no longer verifies an outer
    /// signature. It parses `policyData` directly and verifies the inner servtd
    /// collateral signatures against their embedded issuer chains.
    pub fn verify(&self, issuer_chain: &[u8]) -> Result<VerifiedPolicy<'a>, PolicyError> {
        let verified_policy = self.verify_signatures_and_anchors(issuer_chain)?;
        if let Some(servtd_crl) = verified_policy.servtd_crl.as_deref() {
            verified_policy.verify_signer_chains_not_revoked(servtd_crl.as_bytes())?;
        }
        Ok(verified_policy)
    }

    /// Verify a peer policy while applying only the caller-provided,
    /// locally-authoritative servTD CRL to its signer chains. The peer's own
    /// delivered CRL remains part of its measured policy data but is not
    /// trusted for revocation decisions.
    pub fn verify_with_authoritative_servtd_crl(
        &self,
        issuer_chain: &[u8],
        authoritative_crl: Option<&[u8]>,
    ) -> Result<VerifiedPolicy<'a>, PolicyError> {
        let verified_policy = self.verify_signatures_and_anchors(issuer_chain)?;
        if let Some(servtd_crl) = authoritative_crl {
            verified_policy.verify_signer_chains_not_revoked(servtd_crl)?;
        }
        Ok(verified_policy)
    }

    fn verify_signatures_and_anchors(
        &self,
        issuer_chain: &[u8],
    ) -> Result<VerifiedPolicy<'a>, PolicyError> {
        // `issuer_chain` is the RTMR1 signer-anchor source: either a
        // precomputed 48-byte anchor (CoRIM-only enrollment) or a PEM issuer
        // chain (legacy JSON enrollment). Both resolve to the same anchor.
        let cfv_anchor = resolve_signer_anchor(issuer_chain)?;

        // The outer policy-blob signature is no longer part of the trust model
        // (integrity comes from RTMR2). Parse policyData directly.
        let policy_data: PolicyData<'a> =
            serde_json::from_str(self.policy_data.get()).map_err(|_| PolicyError::InvalidPolicy)?;

        let servtd_crl = match (
            policy_data.servtd_crl.as_ref(),
            policy_data
                .servtd_collateral
                .as_ref()
                .and_then(|collateral| collateral.servtd_crl.as_ref()),
        ) {
            (Some(top_level), Some(legacy)) if top_level != legacy => {
                return Err(PolicyError::InvalidCollateral);
            }
            (Some(top_level), _) => Some(top_level.clone()),
            (None, legacy) => legacy.cloned(),
        };

        // Optional JSON servtd collateral. When absent (CoRIM-only), there is
        // no embedded chain to verify/bind here: the enrolled anchor is bound
        // to the CoRIM signer by `ServtdCorim::decode_signed`, and all servtd
        // lookups resolve through the CoRIM attached post-verify (fail-closed
        // when none is attached).
        let (
            servtd_tcb_mapping,
            servtd_tcb_mapping_issuer_chain,
            servtd_identity,
            servtd_identity_issuer_chain,
        ) = match &policy_data.servtd_collateral {
            Some(servtd_collateral) => {
                // Verify servtd collateral signature using its embedded chain
                let servtd_tcb_mapping = servtd_collateral.servtd_tcb_mapping.verify_signature(
                    servtd_collateral.servtd_tcb_mapping_issuer_chain.as_bytes(),
                )?;

                // Verify the optional TD Identity signature against its embedded
                // chain. `servtdIdentity` and `servtdIdentityIssuerChain` must
                // be present or absent together; a half-present pair fails closed.
                let servtd_identity = match (
                    servtd_collateral.servtd_identity.as_ref(),
                    servtd_collateral.servtd_identity_issuer_chain.as_deref(),
                ) {
                    (Some(raw_identity), Some(identity_chain)) => {
                        Some(raw_identity.verify_signature(identity_chain.as_bytes())?)
                    }
                    (None, None) => None,
                    _ => return Err(PolicyError::InvalidServtdIdentity),
                };

                // Bind the TCB-mapping signer chain to the RTMR1 signer anchor.
                // `servtdTcbMappingIssuerChain` is redacted from RTMR2 (measured
                // into RTMR1 instead), so require the chain that verified
                // `servtdTcbMapping` to hash to the same anchor RTMR1 commits to.
                // A swapped chain fails closed; leaf/intermediate rotation under
                // the same root + EKU keeps the anchor stable.
                let mapping_anchor = compute_signer_anchor_from_chain_pem(
                    servtd_collateral.servtd_tcb_mapping_issuer_chain.as_bytes(),
                )?;
                if cfv_anchor != mapping_anchor {
                    return Err(PolicyError::SignerAnchorMismatch);
                }

                // The optional TD Identity and issuer chain are measured into
                // RTMR2. Also require the chain to share the RTMR1 signer
                // anchor so mapping and identity stay in one trust domain.
                if let Some(identity_chain) =
                    servtd_collateral.servtd_identity_issuer_chain.as_deref()
                {
                    let identity_anchor =
                        compute_signer_anchor_from_chain_pem(identity_chain.as_bytes())?;
                    if cfv_anchor != identity_anchor {
                        return Err(PolicyError::SignerAnchorMismatch);
                    }
                }

                (
                    Some(servtd_tcb_mapping),
                    Some(servtd_collateral.servtd_tcb_mapping_issuer_chain.clone()),
                    servtd_identity,
                    servtd_collateral.servtd_identity_issuer_chain.clone(),
                )
            }
            None => (None, None, None, None),
        };

        // Sanity checks
        if !policy_data.validate() {
            return Err(PolicyError::InvalidParameter);
        }

        Ok(VerifiedPolicy {
            policy_data,
            servtd_tcb_mapping,
            servtd_tcb_mapping_issuer_chain,
            servtd_identity,
            servtd_identity_issuer_chain,
            servtd_crl,
            signer_anchor: cfv_anchor,
            #[cfg(feature = "servtd_corim")]
            servtd_corim: None,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyData<'a> {
    id: String,
    version: String,
    policy_svn: u32,
    policy: Option<Vec<PolicyTypes>>,
    forward_policy: Option<Vec<PolicyTypes>>,
    backward_policy: Option<Vec<PolicyTypes>>,
    pub collaterals: Collaterals,
    /// Optional locally-authoritative servTD signer CRL. This top-level form
    /// is used by CoRIM-only policies; the legacy copy nested under
    /// `servtdCollateral` remains accepted for backward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servtd_crl: Option<String>,
    /// Optional JSON servtd collateral. Absent for a CoRIM-only policy, whose
    /// servtd endorsement is delivered as a separately-enrolled CoRIM.
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    pub servtd_collateral: Option<ServtdCollateral<'a>>,
}

impl<'a> PolicyData<'a> {
    pub fn deserialize_from_json(slice: &'a [u8]) -> Result<Self, PolicyError> {
        serde_json::from_slice::<PolicyData>(slice).map_err(|_| PolicyError::InvalidPolicy)
    }

    pub fn validate(&self) -> bool {
        !self.id.is_empty() && self.version == "2.0"
    }

    pub fn get_policy_svn(&self) -> u32 {
        self.policy_svn
    }

    pub fn evaluate_policy_forward(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
        skip_global: bool,
    ) -> Result<(), PolicyError> {
        match self.forward_policy.as_ref() {
            Some(policy) => {
                Self::evaluate_policy_block(policy, value, relative_reference, skip_global)
            }
            None => Ok(()),
        }
    }

    pub fn evaluate_policy_backward(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
        skip_global: bool,
    ) -> Result<(), PolicyError> {
        match self.backward_policy.as_ref() {
            Some(policy) => {
                Self::evaluate_policy_block(policy, value, relative_reference, skip_global)
            }
            None => Ok(()),
        }
    }

    pub fn evaluate_policy_common(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
        skip_global: bool,
    ) -> Result<(), PolicyError> {
        match self.policy.as_ref() {
            Some(policy) => {
                Self::evaluate_policy_block(policy, value, relative_reference, skip_global)
            }
            None => Ok(()),
        }
    }

    fn evaluate_policy_block(
        block: &Vec<PolicyTypes>,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
        skip_global: bool,
    ) -> Result<(), PolicyError> {
        for policy_type in block {
            match policy_type {
                PolicyTypes::Global(global) if !skip_global => {
                    global.evaluate(value, relative_reference)?
                }
                PolicyTypes::Servtd(migtd) => migtd.evaluate(value, relative_reference)?,
                _ => {}
            }
        }
        Ok(())
    }

    pub fn evaluate_against_policy(&self, other_policy: &PolicyData) -> Result<(), PolicyError> {
        // Check if the SVN in this policy is qualified
        if self.policy_svn < other_policy.policy_svn {
            return Err(PolicyError::SvnMismatch);
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum PolicyTypes {
    Global(GlobalPolicy),
    Servtd(ServtdPolicy),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GlobalPolicy {
    tcb: Option<TcbPolicy>,
    platform: Option<PlatformPolicy>,
    crl: Option<CrlPolicy>,
}

impl GlobalPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(tcb_policy) = &self.tcb {
            tcb_policy.evaluate(value, relative_reference)?;
        }

        if let Some(platform_policy) = &self.platform {
            platform_policy.evaluate(value, relative_reference)?;
        }

        if let Some(crl_policy) = &self.crl {
            crl_policy.evaluate(value, relative_reference)?;
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbPolicy {
    tcb_date: Option<PolicyProperty>,
    tcb_status_accepted: Option<PolicyProperty>,
    tcb_evaluation_data_number: Option<PolicyProperty>,
}

impl TcbPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(property) = &self.tcb_evaluation_data_number {
            let tcb_evaluation_number = value
                .tcb_evaluation_number
                .ok_or(PolicyError::TcbEvaluation)?;
            if !property.evaluate_integer(
                tcb_evaluation_number,
                relative_reference.tcb_evaluation_number,
            )? {
                return Err(PolicyError::TcbEvaluation);
            }
        }

        if let Some(tcb_status_policy) = &self.tcb_status_accepted {
            if !tcb_status_policy.evaluate_tcb_status(
                value
                    .tcb_status
                    .as_deref()
                    .and_then(|s| s.try_into().ok())
                    .ok_or(PolicyError::TcbEvaluation)?,
                relative_reference
                    .tcb_status
                    .as_deref()
                    .and_then(|s| s.try_into().ok()),
            )? {
                return Err(PolicyError::TcbEvaluation);
            }
        }

        if let Some(tcb_date_policy) = &self.tcb_date {
            if !tcb_date_policy.evaluate_string(
                value
                    .tcb_date
                    .as_deref()
                    .ok_or(PolicyError::TcbEvaluation)?,
                relative_reference.tcb_date.as_deref(),
            )? {
                return Err(PolicyError::TcbEvaluation);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PlatformPolicy {
    fmspc: Option<PolicyProperty>,
}

impl PlatformPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(property) = &self.fmspc {
            let fmspc = value.fmspc.as_ref().ok_or(PolicyError::TcbEvaluation)?;
            let relative = relative_reference
                .fmspc
                .as_ref()
                .map(|s| bytes_to_hex_string(s));
            if !property.evaluate_string(&bytes_to_hex_string(fmspc), relative.as_deref())? {
                return Err(PolicyError::TcbEvaluation);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CrlPolicy {
    pck_crl_num: Option<PolicyProperty>,
    root_ca_crl_num: Option<PolicyProperty>,
    servtd_crl_num: Option<PolicyProperty>,
}

impl CrlPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(property) = &self.pck_crl_num {
            let pck_crl_num = value.pck_crl_num.ok_or(PolicyError::CrlEvaluation)?;
            if !property.evaluate_integer(pck_crl_num, relative_reference.pck_crl_num)? {
                return Err(PolicyError::CrlEvaluation);
            }
        }

        if let Some(property) = &self.root_ca_crl_num {
            let root_ca_crl_num = value.root_ca_crl_num.ok_or(PolicyError::CrlEvaluation)?;
            if !property.evaluate_integer(root_ca_crl_num, relative_reference.root_ca_crl_num)? {
                return Err(PolicyError::CrlEvaluation);
            }
        }

        if let Some(property) = &self.servtd_crl_num {
            let servtd_crl_num = value.servtd_crl_num.ok_or(PolicyError::CrlEvaluation)?;
            if !property.evaluate_integer(servtd_crl_num, relative_reference.servtd_crl_num)? {
                return Err(PolicyError::CrlEvaluation);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServtdPolicy {
    migtd_identity: MigTdIdentityPolicy,
}

impl ServtdPolicy {
    fn evaluate(
        &self,
        value: &PolicyEvaluationInfo,
        relative_reference: &PolicyEvaluationInfo,
    ) -> Result<(), PolicyError> {
        if let Some(property) = &self.migtd_identity.isvsvn {
            if !property.evaluate_integer(
                value
                    .migtd_isvsvn
                    .map(|v| v as u32)
                    .ok_or(PolicyError::UnqualifiedMigTdInfo)?,
                relative_reference.migtd_isvsvn.map(|v| v as u32),
            )? {
                return Err(PolicyError::SvnMismatch);
            }
        }

        // `tcbDate` / `tcbStatus` bars require the optional TD Identity to be
        // shipped. `migtd_tcb_date` / `migtd_tcb_status` are populated only when
        // the lookup resolved through a `TdIdentity`; a date/status bar with no
        // TD Identity present therefore fails closed here.
        if let Some(property) = &self.migtd_identity.tcb_date {
            if !property.evaluate_string(
                value
                    .migtd_tcb_date
                    .as_deref()
                    .ok_or(PolicyError::UnqualifiedMigTdInfo)?,
                relative_reference.migtd_tcb_date.as_deref(),
            )? {
                return Err(PolicyError::SvnMismatch);
            }
        }

        if let Some(property) = &self.migtd_identity.tcb_status_accepted {
            if !property.evaluate_servtd_tcb_status(
                value
                    .migtd_tcb_status
                    .as_deref()
                    .and_then(|s| s.try_into().ok())
                    .ok_or(PolicyError::UnqualifiedMigTdInfo)?,
                relative_reference
                    .migtd_tcb_status
                    .as_deref()
                    .and_then(|s| s.try_into().ok()),
            )? {
                return Err(PolicyError::SvnMismatch);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MigTdIdentityPolicy {
    pub isvsvn: Option<PolicyProperty>,
    pub tcb_date: Option<PolicyProperty>,
    pub tcb_status_accepted: Option<PolicyProperty>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum Reference {
    Integer(u32),
    String(String),
    IntegerList(Vec<u32>),
    StringList(Vec<String>),
}

#[derive(Serialize, Deserialize, Debug)]
struct PolicyField {
    operation: String,
    reference: Reference,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PolicyProperty {
    pub operation: String,
    pub reference: Reference,
}

impl PolicyProperty {
    pub fn evaluate_integer(
        &self,
        value: u32,
        relative_reference: Option<u32>,
    ) -> Result<bool, PolicyError> {
        let is_in_range = |value: &u32, range: &str| -> Result<bool, PolicyError> {
            let parts = range.split("..").collect::<Vec<&str>>();
            if parts.len() != 2 {
                return Err(PolicyError::InvalidOperation);
            }
            let start = parts[0]
                .parse::<u32>()
                .map_err(|_| PolicyError::InvalidReference)?;
            let end = parts[1]
                .parse::<u32>()
                .map_err(|_| PolicyError::InvalidReference)?;

            Ok(*value >= start && *value <= end)
        };

        match &self.reference {
            Reference::Integer(reference) => match self.operation.as_str() {
                "equal" => Ok(value == *reference),
                "greater-or-equal" => Ok(value >= *reference),
                _ => Err(PolicyError::InvalidOperation),
            },
            Reference::String(reference) => {
                if reference == "self" || reference == "init" {
                    let relative_reference =
                        relative_reference.ok_or(PolicyError::InvalidReference)?;
                    match self.operation.as_str() {
                        "equal" => Ok(value == relative_reference),
                        "greater-or-equal" => Ok(value >= relative_reference),
                        _ => Err(PolicyError::InvalidOperation),
                    }
                } else {
                    match self.operation.as_str() {
                        "in-range" | "in-time-range" => is_in_range(&value, reference),
                        _ => Err(PolicyError::InvalidOperation),
                    }
                }
            }
            Reference::IntegerList(items) => match self.operation.as_str() {
                "subset" => Ok(items.contains(&value)),
                _ => Err(PolicyError::InvalidOperation),
            },
            _ => Err(PolicyError::InvalidReference),
        }
    }

    #[allow(unused)]
    pub fn evaluate_integer_list(
        &self,
        values: &[u32],
        relative_reference: Option<&[u32]>,
    ) -> Result<bool, PolicyError> {
        let integer_list_op = |values: &[u32], reference: &[u32]| {
            if values.len() != reference.len() {
                return Ok(false);
            }
            match self.operation.as_str() {
                "array-equal" => {
                    for (i, val) in values.iter().enumerate() {
                        if *val != reference[i] {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                "array-greater-or-equal" => {
                    // Each value in input must be >= corresponding value in reference at same position
                    for (i, val) in values.iter().enumerate() {
                        if *val < reference[i] {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                _ => Err(PolicyError::InvalidOperation),
            }
        };

        match &self.reference {
            Reference::IntegerList(reference) => integer_list_op(values, reference),
            Reference::String(reference) => {
                if reference != "self" && reference != "init" {
                    return Err(PolicyError::InvalidReference);
                }
                let relative_reference = relative_reference.ok_or(PolicyError::InvalidReference)?;
                integer_list_op(values, relative_reference)
            }
            _ => Err(PolicyError::InvalidReference),
        }
    }

    /// Evaluate a String property against a reference value
    pub fn evaluate_string(
        &self,
        value: &str,
        relative_reference: Option<&str>,
    ) -> Result<bool, PolicyError> {
        match &self.reference {
            Reference::String(reference) => {
                let reference_value = match reference.as_str() {
                    "self" | "init" => relative_reference.ok_or(PolicyError::InvalidReference)?,
                    other => other,
                };
                match self.operation.as_str() {
                    "equal" => Ok(value == reference_value),
                    "greater-or-equal" => {
                        // Simple lexicographical comparison works for ISO-8601 format (e.g. "2025-01-01T00:00:00Z")
                        // This is because ISO-8601 is designed to be sortable as strings
                        Ok(value >= reference_value)
                    }
                    _ => Err(PolicyError::InvalidOperation),
                }
            }
            Reference::StringList(reference) => match self.operation.as_str() {
                "allow-list" => {
                    if reference.iter().any(|item| item == value) {
                        return Ok(true);
                    }
                    Ok(false)
                }
                "deny-list" => {
                    if reference.iter().any(|item| item == value) {
                        return Ok(false);
                    }
                    Ok(true)
                }
                _ => Err(PolicyError::InvalidOperation),
            },
            _ => Err(PolicyError::InvalidReference),
        }
    }

    /// Evaluate a TcbStatus property against a reference value
    fn evaluate_tcb_status(
        &self,
        value: TcbStatus,
        relative_reference: Option<TcbStatus>,
    ) -> Result<bool, PolicyError> {
        // "UpToDate" is always allowed.
        // "SWHardeningNeeded" is always allowed, because the information is missing when the state
        // is moved to "OutOfDate".
        // "OutOfDate" is always allowed, because time stamp is not trusted.
        const ALWAYS_ALLOW: &[TcbStatus] = &[
            TcbStatus::UpToDate,
            TcbStatus::OutOfDate,
            TcbStatus::SWHardeningNeeded,
        ];
        // "Revoked" is always denied.
        const ALWAYS_DENY: &[TcbStatus] = &[TcbStatus::Revoked];

        if ALWAYS_DENY.contains(&value) {
            return Ok(false);
        }

        if ALWAYS_ALLOW.contains(&value) {
            return Ok(true);
        }

        match &self.reference {
            Reference::String(reference) => {
                let reference_value = match reference.as_str() {
                    "self" | "init" => relative_reference.ok_or(PolicyError::InvalidReference)?,
                    other => TcbStatus::try_from(other)?,
                };
                match self.operation.as_str() {
                    "equal" => Ok(value == reference_value),
                    "greater-or-equal" => Ok(value >= reference_value),
                    _ => Err(PolicyError::InvalidOperation),
                }
            }
            Reference::StringList(reference) => {
                let mut policy_allow = Vec::new();
                match self.operation.as_str() {
                    "allow-list" => {
                        for item in reference {
                            // Check if this is a valid reference.
                            let _ = TcbStatus::try_from(item.as_str())?;
                            // Compare the raw string instead of the parsed TcbStatus because
                            // ConfigurationNeeded, ConfigurationAndSWHardeningNeeded, and
                            // OutOfDateConfigurationNeeded all rank-equal under PartialEq.
                            if item == TcbStatus::ConfigurationNeeded.as_str() {
                                policy_allow.push(TcbStatus::ConfigurationNeeded);
                                policy_allow.push(TcbStatus::ConfigurationAndSWHardeningNeeded);
                                policy_allow.push(TcbStatus::OutOfDateConfigurationNeeded);
                            }
                        }
                    }
                    "deny-list" => {
                        // Check if this is a valid reference.
                        let _ = reference
                            .iter()
                            .map(|item| TcbStatus::try_from(item.as_str()))
                            .collect::<Result<Vec<_>, _>>()?;
                        // All TCB statuses that are not in the `ALWAYS_ALLOW` list will be denied.
                    }
                    _ => return Err(PolicyError::InvalidOperation),
                }
                Ok(policy_allow.contains(&value))
            }
            _ => Err(PolicyError::InvalidReference),
        }
    }

    /// Evaluate a ServtdTcbStatus property against a reference value.
    fn evaluate_servtd_tcb_status(
        &self,
        value: ServtdTcbStatus,
        _relative_reference: Option<ServtdTcbStatus>,
    ) -> Result<bool, PolicyError> {
        // "UpToDate" is always allowed.
        // "OutOfDate" is always allowed, because the time stamp is not trusted.
        const ALWAYS_ALLOW: &[ServtdTcbStatus] =
            &[ServtdTcbStatus::UpToDate, ServtdTcbStatus::OutOfDate];
        // "Revoked" is always denied.
        const ALWAYS_DENY: &[ServtdTcbStatus] = &[ServtdTcbStatus::Revoked];

        if ALWAYS_DENY.contains(&value) {
            return Ok(false);
        }

        if ALWAYS_ALLOW.contains(&value) {
            return Ok(true);
        }

        // Every status already falls into either the always-allow or
        // always-deny set.
        Ok(false)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{format, string::ToString, vec};

    fn delivered_servtd_crl(policy: &RawPolicyData<'_>) -> String {
        let policy_data: serde_json::Value =
            serde_json::from_str(policy.policy_data.get()).unwrap();
        policy_data["servtdCollateral"]["servtdCrl"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn test_parse_policy_data() {
        let policy = include_str!("../../test/policy_v2/policy_data.json");
        assert!(serde_json::from_str::<PolicyData>(policy).is_ok());
    }

    #[test]
    fn test_verify_policy() {
        let policy_data = include_bytes!("../../test/policy_v2/policy_v2.json");
        let policy = RawPolicyData::deserialize_from_json(policy_data).unwrap();
        let issuer_chain =
            include_bytes!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem");
        policy.verify(issuer_chain).unwrap();
    }

    /// SVN-only deployment: a policy whose `servtdCollateral` ships **no**
    /// `servtdIdentity` (nor `servtdIdentityIssuerChain`) must still verify.
    /// The optional TD Identity is absent, so:
    ///   * `verify()` succeeds (the independent `servtdTcbMapping` signature
    ///     and its RTMR1 anchor binding are unaffected by the missing identity);
    ///   * `servtd_identity` / `servtd_identity_issuer_chain` are `None`;
    ///   * a servtd lookup resolves the SVN but leaves `tcb_date` / `tcb_status`
    ///     unset (there is no date/status source without TD Identity).
    ///
    /// The fixture is derived from `policy_v2.json` by dropping the two
    /// identity fields; the mapping signature signs only the `tdTcbMapping`
    /// bytes, so it remains valid.
    #[test]
    fn test_verify_policy_svn_only_no_identity() {
        use crate::v2::hex_string_to_bytes;

        let policy_data = include_bytes!("../../test/policy_v2/policy_v2_svn_only.json");
        let policy = RawPolicyData::deserialize_from_json(policy_data).unwrap();
        let issuer_chain =
            include_bytes!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem");
        let verified = policy.verify(issuer_chain).unwrap();

        assert!(verified.servtd_identity.is_none());
        assert!(verified.servtd_identity_issuer_chain.is_none());

        // The SVN resolves, but there is no date/status without TD Identity.
        let known_hash = hex_string_to_bytes(
            &verified.servtd_tcb_mapping.as_ref().unwrap().svn_mappings[0]
                .td_measurements
                .tdinfo_hash,
        )
        .unwrap();
        let lookup = verified
            .servtd_lookup_by_tdinfo_hash(&known_hash)
            .expect("known hash resolves");
        assert!(lookup.tcb_date.is_none());
        assert!(lookup.tcb_status.is_none());
    }

    /// SVN-only policy evaluation: with no TD Identity present, a `migtdIdentity`
    /// policy that uses only an `isvsvn` bar passes, while a `tcbStatus` /
    /// `tcbDate` bar fails closed because `migtd_tcb_status` / `migtd_tcb_date`
    /// are unpopulated (there is no date/status source without TD Identity).
    #[test]
    fn servtd_policy_svn_only_bars_and_fail_closed() {
        // SVN value present but no date/status (identity-absent lookup).
        let mut value = PolicyEvaluationInfo {
            migtd_isvsvn: Some(5),
            ..Default::default()
        };
        let relative = PolicyEvaluationInfo::default();

        // isvsvn-only bar: passes when the SVN qualifies.
        let svn_only: ServtdPolicy = serde_json::from_str(
            r#"{"migtdIdentity":{"isvsvn":{"operation":"greater-or-equal","reference":5}}}"#,
        )
        .unwrap();
        assert!(svn_only.evaluate(&value, &relative).is_ok());

        // A tcbStatus bar with no TD Identity present fails closed.
        let status_bar: ServtdPolicy = serde_json::from_str(
            r#"{"migtdIdentity":{"isvsvn":{"operation":"greater-or-equal","reference":5},"tcbStatusAccepted":{"operation":"string-equal","reference":"UpToDate"}}}"#,
        )
        .unwrap();
        assert!(status_bar.evaluate(&value, &relative).is_err());

        // A tcbDate bar with no TD Identity present also fails closed.
        let date_bar: ServtdPolicy = serde_json::from_str(
            r#"{"migtdIdentity":{"tcbDate":{"operation":"greater-or-equal","reference":"2024-01-01T00:00:00Z"}}}"#,
        )
        .unwrap();
        assert!(date_bar.evaluate(&value, &relative).is_err());

        // Once the (optional) TD Identity supplies date/status, the same bars
        // are satisfiable.
        value.migtd_tcb_status = Some("UpToDate".to_string());
        value.migtd_tcb_date = Some("2025-01-01T00:00:00Z".to_string());
        assert!(status_bar.evaluate(&value, &relative).is_ok());
        assert!(date_bar.evaluate(&value, &relative).is_ok());
    }

    #[cfg(feature = "servtd_corim")]
    #[test]
    fn azure_corim_policy_uses_svn_only_servtd_rule() {
        use crate::v2::hex_string_to_bytes;

        let policy: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../../config/Azure/policy_data_raw.json"
        ))
        .unwrap();
        let servtd = policy["policy"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|entry| entry.get("servtd"))
            .unwrap()
            .clone();
        let servtd: ServtdPolicy = serde_json::from_value(servtd).unwrap();

        let corim = ServtdCorim::decode(
            include_bytes!("../../test/policy_v2/corim/tcb_mapping.cbor"),
            0,
        )
        .unwrap();
        let endorsed_hash = hex_string_to_bytes(
            "347c6170a91341351937962e08a7695703e7b87984b1c69216372c380302ac420\
             d42381e4585007057b20b2579286384",
        )
        .unwrap();
        let lookup = corim.lookup_by_tdinfo_hash(&endorsed_hash).unwrap();
        assert!(lookup.tcb_date.is_none());
        assert!(lookup.tcb_status.is_none());

        let same_peer = PolicyEvaluationInfo {
            migtd_isvsvn: Some(lookup.isvsvn),
            migtd_tcb_date: lookup.tcb_date,
            migtd_tcb_status: lookup.tcb_status,
            ..Default::default()
        };
        let same = PolicyEvaluationInfo {
            migtd_isvsvn: Some(lookup.isvsvn),
            ..Default::default()
        };
        assert!(servtd.evaluate(&same_peer, &same).is_ok());

        let newer_peer = PolicyEvaluationInfo {
            migtd_isvsvn: Some(lookup.isvsvn + 1),
            ..Default::default()
        };
        assert!(servtd.evaluate(&newer_peer, &same).is_ok());

        let newer_local = PolicyEvaluationInfo {
            migtd_isvsvn: Some(lookup.isvsvn + 1),
            ..Default::default()
        };
        assert!(servtd.evaluate(&same_peer, &newer_local).is_err());
    }

    /// The outer policy-blob signature has been removed from the trust model.
    /// A policy with **no** outer `signature` field must still deserialize and
    /// verify — integrity is established by the RTMR2 measurement, checked
    /// separately in `check_policy_integrity`. The `policyData` bytes (and thus
    /// the inner servtd signatures) are preserved verbatim.
    #[test]
    fn test_verify_policy_without_outer_signature() {
        let policy_data = include_bytes!("../../test/policy_v2/policy_v2.json");
        let signed = RawPolicyData::deserialize_from_json(policy_data).unwrap();
        assert!(
            signed.signature.is_some(),
            "fixture is expected to carry a legacy outer signature"
        );

        // Re-wrap the exact same policyData bytes with NO outer signature.
        let no_sig = format!("{{\"policyData\":{}}}", signed.policy_data.get());
        let unsigned = RawPolicyData::deserialize_from_json(no_sig.as_bytes()).unwrap();
        assert!(unsigned.signature.is_none());

        let issuer_chain =
            include_bytes!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem");
        unsigned.verify(issuer_chain).unwrap();
    }

    /// A bogus outer signature must be **ignored** (never verified), because
    /// the outer signature is no longer part of the trust model. If it were
    /// still verified this garbage value would fail closed.
    #[test]
    fn test_outer_signature_is_ignored() {
        let policy_data = include_bytes!("../../test/policy_v2/policy_v2.json");
        let signed = RawPolicyData::deserialize_from_json(policy_data).unwrap();

        let tampered = format!(
            "{{\"policyData\":{},\"signature\":\"deadbeef\"}}",
            signed.policy_data.get()
        );
        let policy = RawPolicyData::deserialize_from_json(tampered.as_bytes()).unwrap();
        assert_eq!(policy.signature.as_deref(), Some("deadbeef"));

        // Verification succeeds despite the bogus outer signature.
        policy
            .verify(include_bytes!(
                "../../test/policy_v2/cert_chain/policy_issuer_chain.pem"
            ))
            .unwrap();
    }

    /// RTMR1 signer-anchor binding (security-critical): because
    /// `servtdTcbMappingIssuerChain` is redacted from the RTMR2 measurement, it
    /// is kept measured only by requiring it to hash to the RTMR1 signer anchor
    /// derived from the CFV issuer chain. Verifying against an unrelated CFV
    /// chain (different root + leaf signer EKU fingerprint) must fail closed with
    /// `SignerAnchorMismatch` — even though the embedded chains still validate
    /// the inner signatures.
    #[test]
    fn test_verify_policy_rejects_mapping_chain_anchor_mismatch() {
        let policy_data = include_bytes!("../../test/policy_v2/policy_v2.json");
        let policy = RawPolicyData::deserialize_from_json(policy_data).unwrap();
        let unrelated_chain =
            include_bytes!("../../test/policy_v2/cert_chain/unrelated_issuer_chain.pem");
        match policy.verify(unrelated_chain) {
            Err(PolicyError::SignerAnchorMismatch) => {}
            Err(other) => panic!("expected SignerAnchorMismatch, got {:?}", other),
            Ok(_) => panic!("expected SignerAnchorMismatch, but verify() succeeded"),
        }
    }

    /// End-to-end `verify()` revocation enforcement: a policy whose delivered
    /// servTD CRL revokes the signer leaf must fail closed
    /// with `SignerRevoked`, while the same policy carrying a revocation-free
    /// CRL verifies. The fixtures under `test/policy_v2/revocation/` are a
    /// self-contained PKI (one signer for both identity and mapping) with
    /// matching empty and revoking CRLs.
    #[test]
    fn verify_enforces_servtd_signer_revocation() {
        let chain = include_bytes!("../../test/policy_v2/revocation/signer_chain.pem");

        let ok = include_bytes!("../../test/policy_v2/revocation/policy_ok.json");
        RawPolicyData::deserialize_from_json(ok)
            .unwrap()
            .verify(chain)
            .expect("policy with an unrevoked signer should verify");

        let revoked = include_bytes!("../../test/policy_v2/revocation/policy_revoked.json");
        match RawPolicyData::deserialize_from_json(revoked)
            .unwrap()
            .verify(chain)
        {
            Err(PolicyError::SignerRevoked) => {}
            Err(other) => panic!("expected SignerRevoked, got {:?}", other),
            Ok(_) => panic!("expected SignerRevoked, but verify() succeeded"),
        }
    }

    /// Peer authentication must use the local CRL, never the CRL delivered in
    /// the peer's measured policy. A locally revoking CRL rejects a peer that
    /// advertises an empty CRL, while a local empty CRL accepts the same signer
    /// even if the peer advertises a revoking CRL.
    #[test]
    fn peer_verification_uses_authoritative_local_servtd_crl() {
        let chain = include_bytes!("../../test/policy_v2/revocation/signer_chain.pem");

        let peer_empty = RawPolicyData::deserialize_from_json(include_bytes!(
            "../../test/policy_v2/revocation/policy_ok.json"
        ))
        .unwrap();
        let empty_crl = delivered_servtd_crl(&peer_empty);
        let peer_revoking = RawPolicyData::deserialize_from_json(include_bytes!(
            "../../test/policy_v2/revocation/policy_revoked.json"
        ))
        .unwrap();
        let revoked_crl = delivered_servtd_crl(&peer_revoking);

        assert!(matches!(
            peer_empty.verify_with_authoritative_servtd_crl(chain, Some(revoked_crl.as_bytes())),
            Err(PolicyError::SignerRevoked)
        ));

        peer_revoking
            .verify_with_authoritative_servtd_crl(chain, Some(empty_crl.as_bytes()))
            .expect("the peer CRL must not override the local CRL");
    }

    /// CoRIM-only policies can carry the authoritative CRL without restoring
    /// the legacy JSON mapping. The CRL remains measured as part of policyData
    /// and is retained until the separately enrolled CoRIM chain is attached.
    #[test]
    fn corim_only_policy_retains_top_level_servtd_crl() {
        let raw = RawPolicyData::deserialize_from_json(include_bytes!(
            "../../test/policy_v2/revocation/policy_ok.json"
        ))
        .unwrap();
        let mut policy_data: serde_json::Value =
            serde_json::from_str(raw.policy_data.get()).unwrap();
        let servtd_crl = policy_data["servtdCollateral"]["servtdCrl"].take();
        let policy_data = policy_data.as_object_mut().unwrap();
        policy_data.remove("servtdCollateral");
        policy_data.insert("servtdCrl".to_string(), servtd_crl.clone());

        let wrapped = format!(
            r#"{{"policyData":{}}}"#,
            serde_json::Value::Object(policy_data.clone())
        );
        let policy = RawPolicyData::deserialize_from_json(wrapped.as_bytes()).unwrap();
        let verified = policy
            .verify(&[0xA5; SHA384_DIGEST_SIZE])
            .expect("CoRIM-only policy should retain its CRL");

        assert!(verified.servtd_tcb_mapping.is_none());
        assert_eq!(verified.servtd_crl.as_deref(), servtd_crl.as_str());
    }

    #[test]
    fn conflicting_servtd_crl_locations_fail_closed() {
        let raw = RawPolicyData::deserialize_from_json(include_bytes!(
            "../../test/policy_v2/revocation/policy_ok.json"
        ))
        .unwrap();
        let mut policy_data: serde_json::Value =
            serde_json::from_str(raw.policy_data.get()).unwrap();
        policy_data["servtdCrl"] = serde_json::Value::String("different CRL".to_string());

        let wrapped = format!(r#"{{"policyData":{policy_data}}}"#);
        let policy = RawPolicyData::deserialize_from_json(wrapped.as_bytes()).unwrap();
        assert!(matches!(
            policy.verify(include_bytes!(
                "../../test/policy_v2/revocation/signer_chain.pem"
            )),
            Err(PolicyError::InvalidCollateral)
        ));
    }

    /// Anti-rollback floor on the servtd signer CRL number: a policy `crl`
    /// block with `servtdCrlNum` rejects a delivered CRL whose number is below
    /// the floor (a rolled-back revocation list), and rejects a missing number
    /// when a floor is set. Fail-closed. Mirrors the pck/root_ca CRL floors.
    #[test]
    fn crl_policy_enforces_servtd_crl_num_floor() {
        let policy: CrlPolicy = serde_json::from_str(
            r#"{"servtdCrlNum":{"operation":"greater-or-equal","reference":4097}}"#,
        )
        .unwrap();
        let reference = PolicyEvaluationInfo::default();

        let mut value = PolicyEvaluationInfo::default();
        // At or above the floor passes.
        value.servtd_crl_num = Some(4097);
        assert!(policy.evaluate(&value, &reference).is_ok());
        value.servtd_crl_num = Some(5000);
        assert!(policy.evaluate(&value, &reference).is_ok());
        // Below the floor (rolled-back CRL) fails closed.
        value.servtd_crl_num = Some(4096);
        assert!(policy.evaluate(&value, &reference).is_err());
        // Missing CRL number while a floor is set fails closed.
        value.servtd_crl_num = None;
        assert!(policy.evaluate(&value, &reference).is_err());
    }

    /// Once a CoRIM is attached, `servtd_lookup_by_tdinfo_hash` is
    /// fail-closed: the legacy collateral is no longer consulted, so a hash
    /// the legacy table resolves misses (the CoRIM does not know it), while a
    /// hash the CoRIM knows resolves through it.
    #[cfg(feature = "servtd_corim")]
    #[test]
    fn servtd_lookup_is_fail_closed_when_corim_attached() {
        use crate::v2::{hex_string_to_bytes, ServtdCorim};

        let policy_data = include_bytes!("../../test/policy_v2/policy_v2.json");
        let policy = RawPolicyData::deserialize_from_json(policy_data).unwrap();
        let issuer_chain =
            include_bytes!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem");
        let mut verified = policy.verify(issuer_chain).unwrap();

        // A hash the *legacy* embedded tcb_mapping resolves.
        let legacy_hash = hex_string_to_bytes(
            &verified.servtd_tcb_mapping.as_ref().unwrap().svn_mappings[0]
                .td_measurements
                .tdinfo_hash,
        )
        .unwrap();
        assert!(verified
            .servtd_lookup_by_tdinfo_hash(&legacy_hash)
            .is_some());

        // Attach a CoRIM that only knows the pipeline sample's release
        // (hash 347c6170…79286384 -> svn 1).
        let tcb = include_bytes!("../../test/policy_v2/corim/tcb_mapping.cbor");
        verified.set_servtd_corim(ServtdCorim::decode(tcb, 0).unwrap());

        // Fail-closed: the legacy hash is no longer resolvable (no fallback).
        assert!(verified
            .servtd_lookup_by_tdinfo_hash(&legacy_hash)
            .is_none());

        // ...but a hash the CoRIM knows resolves through it.
        let corim_hash = hex_string_to_bytes(
            "347c6170a91341351937962e08a7695703e7b87984b1c69216372c380302ac420d42381e4585007057b20b2579286384",
        )
        .unwrap();
        let hit = verified.servtd_lookup_by_tdinfo_hash(&corim_hash);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().isvsvn, 1);
    }

    // Peer SVN must be resolved through the peer TCB-mapping CoRIM.
    #[cfg(feature = "servtd_corim")]
    const CORIM_KNOWN_HASH_HEX: &str = "347c6170a91341351937962e08a7695703e7b87984b1c69216372c380302ac420d42381e4585007057b20b2579286384";

    #[cfg(feature = "servtd_corim")]
    fn base_verified_policy() -> VerifiedPolicy<'static> {
        let policy_data = include_bytes!("../../test/policy_v2/policy_v2.json");
        let issuer_chain =
            include_bytes!("../../test/policy_v2/cert_chain/policy_issuer_chain.pem");
        let policy = RawPolicyData::deserialize_from_json(policy_data).unwrap();
        policy.verify(issuer_chain).unwrap()
    }

    /// Recover the RTMR1 signer anchor embedded in a signed COSE CoRIM
    /// sample's own `x5chain`, running the real ES384 signature + chain
    /// verification on the way. Mirrors the private
    /// `servtd_corim::test::signer_anchor_from_sample` helper, which is
    /// not reachable from this module.
    #[cfg(feature = "servtd_corim")]
    fn signer_anchor_from_cose_sample(cose: &[u8]) -> [u8; SHA384_DIGEST_SIZE] {
        use crate::v2::compute_signer_anchor;

        let env = corim::types::signed::decode_signed_corim(cose).expect("decode COSE");
        let tbs = env.to_be_signed(&[]).expect("tbs");
        let chain = env.protected.x5chain.as_ref().expect("x5chain");
        let certs = chain.certs();
        let (root_der, leaf_eku_oids_der) =
            crypto::verify_cose_sign1_es384_x5chain(&certs, &tbs, &env.signature)
                .expect("verify signature");
        let leaf_eku_oid_der = leaf_eku_oids_der.first().expect("leaf asserts >= 1 EKU");
        compute_signer_anchor(&root_der, leaf_eku_oid_der).expect("anchor")
    }

    /// Scenario 1: an older destination whose OWN local mapping does not
    /// know a newer source's `tdinfo_hash` still accepts the source once
    /// the source's own authenticated CoRIM (verified against the
    /// SOURCE's own resolved signer anchor) is attached to the source's
    /// `VerifiedPolicy`. The destination's local ignorance of the hash is
    /// irrelevant: only the peer's own mapping is consulted.
    #[cfg(feature = "servtd_corim")]
    #[test]
    fn peer_corim_resolves_hash_missing_from_destination_local_mapping() {
        use crate::v2::hex_string_to_bytes;

        let corim_hash = hex_string_to_bytes(CORIM_KNOWN_HASH_HEX).unwrap();

        // The destination's own local enrolled policy never saw this
        // source release, so its own (legacy JSON) mapping does not know
        // the hash.
        let verified_dest = base_verified_policy();
        assert!(verified_dest
            .servtd_lookup_by_tdinfo_hash(&corim_hash)
            .is_none());

        // The source's own `VerifiedPolicy`: attach the source's own
        // signed CoRIM after verifying it against the SOURCE's own
        // resolved signer anchor (never the destination's).
        let tcb = include_bytes!("../../test/policy_v2/corim/tcb_mapping.cose");
        let mut verified_peer = base_verified_policy();
        verified_peer.signer_anchor = signer_anchor_from_cose_sample(tcb);
        verified_peer
            .attach_verified_peer_servtd_corim(tcb)
            .expect("peer corim verifies against the peer's own anchor");

        let hit = verified_peer.servtd_lookup_by_tdinfo_hash(&corim_hash);
        assert_eq!(
            hit.expect("peer's own CoRIM resolves its own release")
                .isvsvn,
            1
        );
    }

    /// Scenario 2: once a peer's authenticated CoRIM is attached, a
    /// `tdinfo_hash` it does not endorse fails closed (`None`), never
    /// falling back to the destination's local mapping or any default
    /// acceptance. `servtd_lookup_by_tdinfo_hash` is the single lookup
    /// primitive shared by BOTH the current-release lookup
    /// (`setup_evaluation_data`/`setup_evaluation_data_with_tdreport`, via
    /// `servtd_lookup_by_report`) and the initial-release lookup
    /// (`mig_policy::verify_init_servtd_svn_order`), so exercising it
    /// here covers a missing hash at either call site.
    #[cfg(feature = "servtd_corim")]
    #[test]
    fn peer_corim_missing_hash_fails_closed() {
        let tcb = include_bytes!("../../test/policy_v2/corim/tcb_mapping.cose");
        let mut verified_peer = base_verified_policy();
        verified_peer.signer_anchor = signer_anchor_from_cose_sample(tcb);
        verified_peer
            .attach_verified_peer_servtd_corim(tcb)
            .unwrap();

        // Neither the peer's CoRIM (single endorsed release) nor any
        // fallback resolves an unrelated hash.
        let unknown_hash = [0xAAu8; SHA384_DIGEST_SIZE];
        assert!(verified_peer
            .servtd_lookup_by_tdinfo_hash(&unknown_hash)
            .is_none());
    }

    /// Scenario 3a: a peer CoRIM signed under a root/EKU anchor that does
    /// not match the peer's own resolved RTMR1 signer anchor is rejected
    /// outright and never attached.
    #[cfg(feature = "servtd_corim")]
    #[test]
    fn attach_peer_corim_rejects_wrong_signer_anchor() {
        let tcb = include_bytes!("../../test/policy_v2/corim/tcb_mapping.cose");
        let mut wrong_anchor = signer_anchor_from_cose_sample(tcb);
        wrong_anchor[0] ^= 0xFF;

        let mut verified_peer = base_verified_policy();
        verified_peer.signer_anchor = wrong_anchor;

        assert!(verified_peer
            .attach_verified_peer_servtd_corim(tcb)
            .is_err());
    }

    /// Scenario 3b: after attaching, the peer CoRIM's signer chain is
    /// still checked against the LOCAL authoritative servTD CRL (never a
    /// peer-supplied one), and a revoked signer is rejected.
    #[cfg(feature = "servtd_corim")]
    #[test]
    fn attach_peer_corim_then_local_crl_rejects_revoked_signer() {
        let tcb = include_bytes!("../../test/policy_v2/corim/revocation/tcb_mapping.cose");
        let mut verified_peer = base_verified_policy();
        verified_peer.signer_anchor = signer_anchor_from_cose_sample(tcb);
        verified_peer
            .attach_verified_peer_servtd_corim(tcb)
            .unwrap();

        let local_crl =
            include_bytes!("../../test/policy_v2/corim/revocation/crl_leaf_revoked.pem");
        assert!(matches!(
            verified_peer.verify_signer_chains_not_revoked(local_crl),
            Err(PolicyError::SignerRevoked)
        ));
    }

    /// Scenario 4 (best-effort proxy — see final report): bidirectional
    /// signer-leaf rotation. `signer_a.pem`/`signer_b.pem` are two
    /// independently rotated leaf keys under the SAME root + dedicated
    /// signer EKU and resolve to the identical RTMR1 signer anchor
    /// (`measurement::signer_anchor_from_chain_ignores_leaf_subject_and_key`).
    /// This proves the property `attach_verified_peer_servtd_corim`'s
    /// accept/reject decision depends on: anchor equality alone, not which
    /// specific leaf-key generation produced the peer's transported
    /// chain. A genuinely independent two-signer-key end-to-end CoRIM
    /// rotation could not be exercised locally: this repository ships
    /// only one signed CoRIM COSE sample key, and no tooling to mint a
    /// second one was available in this environment.
    #[cfg(feature = "servtd_corim")]
    #[test]
    fn rotated_leaf_keys_resolve_to_the_same_signer_anchor() {
        let anchor_old = compute_signer_anchor_from_chain_pem(include_bytes!(
            "../../../crypto/test/eku/signer_a.pem"
        ))
        .unwrap();
        let anchor_new = compute_signer_anchor_from_chain_pem(include_bytes!(
            "../../../crypto/test/eku/signer_b.pem"
        ))
        .unwrap();
        assert_eq!(
            anchor_old, anchor_new,
            "rotated leaf keys under the same root+EKU must resolve to the \
             same anchor, so attach_verified_peer_servtd_corim's decision \
             never depends on which generation produced the peer's chain"
        );

        // A rotated-generation anchor that happens NOT to match this
        // CoRIM sample's real signer (unrelated key material) still fails
        // closed: rotation alone never grants acceptance, the anchor must
        // genuinely match the CoRIM's own signer.
        let tcb = include_bytes!("../../test/policy_v2/corim/tcb_mapping.cose");
        let mut verified_after_rotation = base_verified_policy();
        verified_after_rotation.signer_anchor = anchor_new;
        assert!(verified_after_rotation
            .attach_verified_peer_servtd_corim(tcb)
            .is_err());
    }

    #[test]
    fn test_global_policy() {
        let global = include_str!("../../test/policy_v2/global.json");
        let global_policy = serde_json::from_str::<GlobalPolicy>(global).unwrap();
        let mut value = PolicyEvaluationInfo {
            tee_tcb_svn: None,
            tcb_date: Some("2025-09-01T00:00:00Z".to_string()),
            tcb_status: Some("UpToDate".to_string()),
            tcb_evaluation_number: Some(15),
            fmspc: Some([0x10, 0xC0, 0x6F, 0x00, 0x00, 0x00]),
            migtd_isvsvn: None,
            migtd_tcb_status: None,
            migtd_tcb_date: None,
            pck_crl_num: None,
            root_ca_crl_num: None,
            servtd_crl_num: None,
        };
        let relative_ref = PolicyEvaluationInfo::default();
        assert!(global_policy.evaluate(&value, &relative_ref).is_ok());

        // Unqualified TCB date
        value.tcb_date = Some("2024-09-01T00:00:00Z".to_string());
        assert!(global_policy.evaluate(&value, &relative_ref).is_err());
        value.tcb_date = Some("2025-09-01T00:00:00Z".to_string());

        // Unqualified TCB status
        value.tcb_status = Some("Revoked".to_string());
        assert!(global_policy.evaluate(&value, &relative_ref).is_err());
        value.tcb_status = Some("ConfigurationNeeded".to_string());

        // Unqualified TCB evaluation data number
        value.tcb_evaluation_number = Some(10);
        assert!(global_policy.evaluate(&value, &relative_ref).is_err());
        value.tcb_evaluation_number = Some(15);

        // Unqualified FMSPC

        value.fmspc = Some([0x10, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(global_policy.evaluate(&value, &relative_ref).is_err());
        value.fmspc = Some([0x10, 0xC0, 0x6F, 0x00, 0x00, 0x00]);

        assert!(global_policy.evaluate(&value, &relative_ref).is_ok());
    }

    #[test]
    fn test_policy_tcb_date() {
        // Test with a value reference
        let tcb_date_policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::String("2025-01-01T00:00:00Z".to_string()),
        };
        assert!(tcb_date_policy
            .evaluate_string("2025-06-15T12:00:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());
        assert!(!tcb_date_policy
            .evaluate_string("2024-01-01T00:00:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());

        // Test with "self" reference
        let tcb_date_policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::String("self".to_string()),
        };
        assert!(tcb_date_policy
            .evaluate_string("2025-06-15T12:01:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());
        assert!(!tcb_date_policy
            .evaluate_string("2025-06-15T11:00:00Z", Some("2025-06-15T12:00:00Z"),)
            .unwrap());
    }

    #[test]
    fn test_tcb_status_comparison() {
        assert!(TcbStatus::UpToDate == TcbStatus::OutOfDate);
        assert!(TcbStatus::UpToDate == TcbStatus::SWHardeningNeeded);
        assert!(TcbStatus::UpToDate > TcbStatus::ConfigurationNeeded);
        assert!(TcbStatus::UpToDate > TcbStatus::OutOfDateConfigurationNeeded);
        assert!(TcbStatus::UpToDate > TcbStatus::ConfigurationAndSWHardeningNeeded);
        assert!(TcbStatus::UpToDate > TcbStatus::Revoked);

        assert!(TcbStatus::ConfigurationNeeded < TcbStatus::SWHardeningNeeded);
        assert!(TcbStatus::ConfigurationNeeded < TcbStatus::OutOfDate);
        assert!(TcbStatus::ConfigurationNeeded == TcbStatus::ConfigurationAndSWHardeningNeeded);
        assert!(TcbStatus::ConfigurationNeeded == TcbStatus::OutOfDateConfigurationNeeded);
        assert!(TcbStatus::ConfigurationNeeded > TcbStatus::Revoked);
    }

    #[test]
    fn test_policy_tcb_status() {
        let assert_tcb_status_allowed =
            |policy: PolicyProperty,
             relative_reference: TcbStatus,
             allow_list: &[TcbStatus],
             deny_list: &[TcbStatus]| {
                for value in allow_list {
                    assert!(policy
                        .evaluate_tcb_status(*value, Some(relative_reference))
                        .unwrap());
                }
                for value in deny_list {
                    assert!(!policy
                        .evaluate_tcb_status(*value, Some(relative_reference))
                        .unwrap());
                }
            };

        let relative_reference = TcbStatus::UpToDate;
        // Test with an "allow-list" operation and "UpToDate" reference
        let tcb_status_policy = PolicyProperty {
            operation: "allow-list".to_string(),
            reference: Reference::StringList(vec!["UpToDate".to_string()]),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
            ],
            &[
                TcbStatus::Revoked,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
        );

        // Test with an "allow-list" operation and "ConfigurationNeeded" reference
        let tcb_status_policy = PolicyProperty {
            operation: "allow-list".to_string(),
            reference: Reference::StringList(vec!["ConfigurationNeeded".to_string()]),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
            &[TcbStatus::Revoked],
        );

        // Test with an empty "deny-list" reference
        let tcb_status_policy = PolicyProperty {
            operation: "deny-list".to_string(),
            reference: Reference::StringList(vec![]),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
            ],
            &[
                TcbStatus::Revoked,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
        );

        // Test with a "deny-list" reference that contains "OutOfDate"
        let tcb_status_policy = PolicyProperty {
            operation: "deny-list".to_string(),
            reference: Reference::StringList(vec!["OutOfDate".to_string()]),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
            ],
            &[
                TcbStatus::Revoked,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
        );

        // Test with "greater-or-equal" operation and "ConfigurationNeeded" reference
        let relative_reference = TcbStatus::ConfigurationNeeded;
        let tcb_status_policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::String("self".to_string()),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
            &[TcbStatus::Revoked],
        );

        // Test with "equal" operation and "UpToDate" reference
        let tcb_status_policy = PolicyProperty {
            operation: "equal".to_string(),
            reference: Reference::String("UpToDate".to_string()),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
            ],
            &[
                TcbStatus::Revoked,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
        );

        // Test with "equal" operation and "ConfigurationNeeded" reference
        let tcb_status_policy = PolicyProperty {
            operation: "equal".to_string(),
            reference: Reference::String("ConfigurationNeeded".to_string()),
        };
        assert_tcb_status_allowed(
            tcb_status_policy,
            relative_reference,
            &[
                TcbStatus::UpToDate,
                TcbStatus::SWHardeningNeeded,
                TcbStatus::OutOfDate,
                TcbStatus::ConfigurationNeeded,
                TcbStatus::OutOfDateConfigurationNeeded,
                TcbStatus::ConfigurationAndSWHardeningNeeded,
            ],
            &[TcbStatus::Revoked],
        );
    }

    #[test]
    fn test_policy_tcb_evaluation_number() {
        // Test with a value reference
        let tcb_evaluation_number_policy = PolicyProperty {
            operation: "greater-or-equal".to_string(),
            reference: Reference::Integer(5),
        };
        let relative_reference = u32::MAX;
        assert!(
            tcb_evaluation_number_policy
                .evaluate_integer(5, Some(relative_reference))
                .unwrap()
                && tcb_evaluation_number_policy
                    .evaluate_integer(10, Some(relative_reference))
                    .unwrap()
        );
        assert!(!tcb_evaluation_number_policy
            .evaluate_integer(4, Some(relative_reference))
            .unwrap());
    }
}
