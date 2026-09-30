// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use crypto::SHA384_DIGEST_SIZE;
pub use policy::{PolicyError, Report, REPORT_DATA_SIZE};

#[cfg(not(feature = "policy_v2"))]
pub use v1::*;

#[cfg(not(feature = "policy_v2"))]
mod v1 {
    use policy::verify_policy;

    use super::{get_rtmrs_from_suppl_data, PolicyError};
    use crate::{
        config::get_policy,
        event_log::{get_event_log, parse_events, verify_event_log},
    };

    pub fn authenticate_policy(
        is_src: bool,
        verified_report_local: &[u8],
        verified_report_peer: &[u8],
        event_log_peer: &[u8],
    ) -> Result<(), PolicyError> {
        let event_log = if let Some(event_log) = get_event_log() {
            event_log
        } else {
            return Err(PolicyError::InvalidEventLog);
        };

        let policy = if let Some(policy) = get_policy() {
            policy
        } else {
            return Err(PolicyError::InvalidParameter);
        };

        verify_event_log(
            event_log_peer,
            &get_rtmrs_from_suppl_data(verified_report_peer)?,
        )
        .map_err(|_| PolicyError::InvalidEventLog)?;
        let event_log = parse_events(event_log).ok_or(PolicyError::InvalidParameter)?;
        let event_log_peer = parse_events(event_log_peer).ok_or(PolicyError::InvalidParameter)?;

        verify_policy(
            is_src,
            policy,
            verified_report_local,
            &event_log,
            verified_report_peer,
            &event_log_peer,
        )
    }
}

#[cfg(feature = "policy_v2")]
pub use v2::*;

#[cfg(feature = "policy_v2")]
mod v2 {
    use alloc::ffi::CString;
    use alloc::{string::String, string::ToString, vec::Vec};
    use attestation::verify_quote_with_collaterals;
    use chrono::DateTime;
    use crypto::{crl::get_crl_number, hash::digest_sha384, pem_cert_to_der, SHA384_DIGEST_SIZE};
    use lazy_static::lazy_static;
    use policy::*;
    use spin::Once;
    use tdx_tdcall::tdreport::{tdcall_verify_report, TdInfo, TdxReport};

    use crate::event_log::{parse_events, verify_event_log};
    use crate::mig_policy::get_rtmrs_from_suppl_data;
    use crate::migration::pre_session_data::LogErr;
    use crate::migration::servtd_ext::ServtdExt;

    /// Compute the outer `tdinfo_hash` (attr=0) for the TD described by a
    /// `TdInfo` returned by `TDG.MR.REPORT`. This is the canonical lookup key
    /// for `servtd_tcb_mapping` after the TCB-mapping redesign.
    fn tdinfo_hash_from_td_info(td: &TdInfo) -> Result<[u8; SHA384_DIGEST_SIZE], PolicyError> {
        policy::compute_tdinfo_hash_from_fields(
            &td.attributes,
            &td.xfam,
            &td.mrtd,
            &td.mrconfig_id,
            &td.mrowner,
            &td.mrownerconfig,
            &td.rtmr0,
            &td.rtmr1,
            &td.rtmr2,
            &td.rtmr3,
        )
    }

    lazy_static! {
        pub static ref VERIFIED_POLICY: Once<VerifiedPolicy<'static>> = Once::new();
    }

    /// Initialize the global verified policy once
    pub fn init_policy(
        policy_json: &'static [u8],
        cert_chain: &[u8],
    ) -> Result<String, PolicyError> {
        let raw = RawPolicyData::deserialize_from_json(policy_json)?;

        // Get the root CA from collaterals and set it for quote verification
        #[cfg_attr(not(feature = "servtd_corim"), allow(unused_mut))]
        let mut verified_policy = raw.verify(cert_chain)?;

        // Attach the optional CoRIM hash endorsement enrolled in the CFV. Its
        // COSE signer chain is bound to the SAME RTMR1 signer anchor as the CFV
        // policy issuer chain, so a CoRIM signed under a different root cert or
        // leaf signer EKU fails closed. The CoRIM is NOT measured
        // (`config::get_servtd_corim` is never read by `do_measurements`), so
        // enrolling it does not change the ServTD/`tdinfo_hash`.
        // `now_epoch_secs = 0`: MigTD has no wall clock, so the producer must
        // not set CWT `nbf`/`exp` on the CoRIM.
        #[cfg(feature = "servtd_corim")]
        if let Some(cose) = crate::config::get_servtd_corim() {
            let anchor = resolve_signer_anchor(cert_chain)?;
            let corim = ServtdCorim::decode_signed(cose, 0, &anchor)?;
            verified_policy.set_servtd_corim(corim);
            if let Some(servtd_crl) = verified_policy.servtd_crl.as_deref() {
                verified_policy.verify_signer_chains_not_revoked(servtd_crl.as_bytes())?;
            }
        }

        let root_ca_der = pem_cert_to_der(verified_policy.get_collaterals().root_ca.as_bytes())
            .map_err(|_| PolicyError::InvalidCollateral)?;
        attestation::root_ca::set_ca(root_ca_der.as_ref())
            .map_err(|_| PolicyError::InvalidCollateral)?;

        let version = VERIFIED_POLICY
            .try_call_once(|| Ok(verified_policy))
            .map(|p| p.get_version().to_string())?;

        #[cfg(feature = "test-get-quote")]
        {
            log::info!("test-get-quote: testing quote generation during init\n");
            let _info = get_local_tcb_evaluation_info()?;
            log::info!("test-get-quote: quote generation and verification succeeded\n");
        }

        Ok(version)
    }

    /// Generate a fresh local TCB evaluation info on demand by creating a
    /// quote and verifying it against the policy collaterals.
    pub fn get_local_tcb_evaluation_info() -> Result<PolicyEvaluationInfo, PolicyError> {
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;
        let (quote, _report) =
            crate::quote::get_quote_with_retry(&[0u8; 64]).map_err(|err| match err {
                crate::quote::QuoteError::ReportGenerationFailed => PolicyError::GetTdxReport,
                _ => PolicyError::QuoteGeneration,
            })?;
        let (fmspc, suppl_data) = verify_quote(&quote, policy.get_collaterals())?;
        setup_evaluation_data(fmspc, &suppl_data, policy, policy, policy.get_collaterals())
    }

    /// Get reference to the global verified policy
    /// Returns None if the policy hasn't been initialized yet
    pub fn get_verified_policy() -> Option<&'static VerifiedPolicy<'static>> {
        VERIFIED_POLICY.get()
    }

    pub fn authenticate_remote(
        is_src: bool,
        quote_peer: &[u8],
        policy_peer: &[u8],
        event_log_peer: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        log::info!(
            "BC> POL-AR-01 authenticate_remote is_src={} quote.len={} policy.len={} event_log.len={}\n",
            is_src,
            quote_peer.len(),
            policy_peer.len(),
            event_log_peer.len()
        );
        let (policy_peer, peer_issuer_chain) =
            crate::migration::pre_session_data::decode_peer_data(policy_peer)
                .ok_or(PolicyError::InvalidParameter)?;
        log::info!(
            "BC> POL-AR-02 decode_peer_data ok policy.len={} issuer_chain.len={}\n",
            policy_peer.len(),
            peer_issuer_chain.len()
        );
        if is_src {
            log::info!("BC> POL-AR-03 -> authenticate_migration_dest\n");
            authenticate_migration_dest(quote_peer, event_log_peer, policy_peer, peer_issuer_chain)
        } else {
            log::info!("BC> POL-AR-03 -> authenticate_migration_source\n");
            authenticate_migration_source(
                quote_peer,
                event_log_peer,
                policy_peer,
                peer_issuer_chain,
            )
        }
    }

    fn authenticate_migration_dest(
        quote_dst: &[u8],
        event_log_dst: &[u8],
        mig_policy_dst: &[u8],
        policy_issuer_chain: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        log::info!("BC> POL-DST-01 authenticate_remote_common BEGIN\n");
        let (evaluation_data_dst, verified_policy_dst, suppl_data) = authenticate_remote_common(
            quote_dst,
            event_log_dst,
            mig_policy_dst,
            policy_issuer_chain,
        )?;
        log::info!(
            "BC> POL-DST-02 authenticate_remote_common ok suppl_data.len={}\n",
            suppl_data.len()
        );
        let relative_reference = get_local_tcb_evaluation_info()?;
        log::info!("BC> POL-DST-03 get_local_tcb_evaluation_info ok\n");
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        policy.policy_data.evaluate_policy_common(
            &evaluation_data_dst,
            &relative_reference,
            false,
        )?;
        log::info!("BC> POL-DST-04 evaluate_policy_common ok\n");
        policy.policy_data.evaluate_policy_forward(
            &evaluation_data_dst,
            &relative_reference,
            false,
        )?;
        log::info!("BC> POL-DST-05 evaluate_policy_forward ok\n");

        // Verify the destination's policy against local policy
        verified_policy_dst
            .policy_data
            .evaluate_against_policy(&policy.policy_data)?;
        log::info!("BC> POL-DST-06 evaluate_against_policy ok\n");

        Ok(suppl_data)
    }

    fn authenticate_migration_source(
        quote_src: &[u8],
        event_log_src: &[u8],
        mig_policy_src: &[u8],
        policy_issuer_chain: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        log::info!("BC> POL-SRC-01 authenticate_remote_common BEGIN\n");
        let (evaluation_data_src, _verified_policy_src, suppl_data) = authenticate_remote_common(
            quote_src,
            event_log_src,
            mig_policy_src,
            policy_issuer_chain,
        )?;
        log::info!(
            "BC> POL-SRC-02 authenticate_remote_common ok suppl_data.len={}\n",
            suppl_data.len()
        );
        let relative_reference = get_local_tcb_evaluation_info()?;
        log::info!("BC> POL-SRC-03 get_local_tcb_evaluation_info ok\n");
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        policy.policy_data.evaluate_policy_common(
            &evaluation_data_src,
            &relative_reference,
            false,
        )?;
        log::info!("BC> POL-SRC-04 evaluate_policy_common ok\n");
        policy.policy_data.evaluate_policy_backward(
            &evaluation_data_src,
            &relative_reference,
            false,
        )?;
        log::info!("BC> POL-SRC-05 evaluate_policy_backward ok\n");

        Ok(suppl_data)
    }

    // Authenticate the migtd-new from migtd-old side
    pub fn authenticate_rebinding_new(
        tdreport_dst: &[u8],
        event_log_dst: &[u8],
        mig_policy_dst: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        let (mig_policy_dst, peer_issuer_chain) =
            crate::migration::pre_session_data::decode_peer_data(mig_policy_dst)
                .ok_or(PolicyError::InvalidParameter)?;
        let (evaluation_data_dst, verified_policy_dst, tdx_report) = authenticate_rebinding_common(
            tdreport_dst,
            event_log_dst,
            mig_policy_dst,
            peer_issuer_chain,
        )?;
        let relative_reference = get_local_tcb_evaluation_info()?;
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        policy.policy_data.evaluate_policy_common(
            &evaluation_data_dst,
            &relative_reference,
            true,
        )?;
        policy.policy_data.evaluate_policy_forward(
            &evaluation_data_dst,
            &relative_reference,
            true,
        )?;

        // Verify the destination's policy against local policy
        verified_policy_dst
            .policy_data
            .evaluate_against_policy(&policy.policy_data)?;

        Ok(tdx_report.as_bytes().to_vec())
    }

    // Authenticate the migtd-old from migtd-new side
    // The legacy init-TDINFO argument remains in the wire/API shape but the
    // one-hash flow derives init identity from SERVTD_EXT.
    pub fn authenticate_rebinding_old(
        tdreport_src: &[u8],
        event_log_src: &[u8],
        mig_policy_src: &[u8],
        _init_tdinfo: &[u8],
        servtd_ext_src: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        let (mig_policy_src, peer_issuer_chain) =
            crate::migration::pre_session_data::decode_peer_data(mig_policy_src)
                .ok_or(PolicyError::InvalidParameter)?;
        // Verify quote src / event log src / policy src
        let (evaluation_data_src, verified_policy_src, tdx_report) = authenticate_rebinding_common(
            tdreport_src,
            event_log_src,
            mig_policy_src,
            peer_issuer_chain,
        )?;
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        let servtd_ext_src_obj =
            ServtdExt::read_from_bytes(servtd_ext_src).ok_or(PolicyError::InvalidParameter)?;
        verify_init_servtd_svn_order(
            &verified_policy_src,
            &evaluation_data_src,
            &servtd_ext_src_obj,
        )?;

        // If backward policy exists, evaluate the migration src based on it.
        let relative_reference = get_local_tcb_evaluation_info()?;
        policy.policy_data.evaluate_policy_backward(
            &evaluation_data_src,
            &relative_reference,
            true,
        )?;

        Ok(tdx_report.as_bytes().to_vec())
    }

    fn authenticate_remote_common<'p>(
        quote: &[u8],
        event_log: &[u8],
        mig_policy: &'p [u8],
        policy_issuer_chain: &[u8],
    ) -> Result<(PolicyEvaluationInfo, VerifiedPolicy<'p>, Vec<u8>), PolicyError> {
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        // 1. Verify quote & get supplemental data
        log::info!(
            "BC> POL-CMN-01 verify_quote begin quote.len={}\n",
            quote.len()
        );
        let (fmspc, suppl_data) = verify_quote(quote, policy.get_collaterals())
            .map_err(|_| PolicyError::QuoteVerification)?;
        log::info!(
            "BC> POL-CMN-02 verify_quote ok suppl_data.len={}\n",
            suppl_data.len()
        );

        // 2. Verify the signature of the provided policy and the integrity of the event log
        let verified_policy = verify_policy_and_event_log(
            event_log,
            mig_policy,
            policy_issuer_chain,
            &get_rtmrs_from_suppl_data(&suppl_data)?,
        )?;
        log::info!("BC> POL-CMN-03 verify_policy_and_event_log ok\n");

        // 3. Get TCB evaluation info from the collaterals
        let evaluation_data = setup_evaluation_data(
            fmspc,
            &suppl_data,
            &verified_policy,
            policy,
            policy.get_collaterals(),
        )?;
        log::info!("BC> POL-CMN-04 setup_evaluation_data ok\n");

        Ok((evaluation_data, verified_policy, suppl_data))
    }

    fn authenticate_rebinding_common<'p>(
        tdreport: &[u8],
        event_log: &[u8],
        mig_policy: &'p [u8],
        policy_issuer_chain: &[u8],
    ) -> Result<(PolicyEvaluationInfo, VerifiedPolicy<'p>, TdxReport), PolicyError> {
        // 1. Verify quote & get supplemental data
        let tdreport_verified = verify_tdreport(tdreport)?;

        // 2. Verify the signature of the provided policy and the integrity of the event log
        let verified_policy = verify_policy_and_event_log(
            event_log,
            mig_policy,
            policy_issuer_chain,
            &get_rtmrs_from_tdreport(&tdreport_verified)?,
        )?;

        // 3. Get TCB evaluation info from the collaterals
        let local_policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;
        let evaluation_data = setup_evaluation_data_with_tdreport(
            &tdreport_verified,
            &verified_policy,
            local_policy,
        )?;

        Ok((evaluation_data, verified_policy, tdreport_verified))
    }

    fn verify_svn_order(
        init_svn: Option<u16>,
        current_svn: Option<u16>,
    ) -> Result<(), PolicyError> {
        let init_svn = init_svn.ok_or(PolicyError::UnqualifiedMigTdInfo)?;
        let current_svn = current_svn.ok_or(PolicyError::UnqualifiedMigTdInfo)?;
        if init_svn > current_svn {
            return Err(PolicyError::SvnMismatch);
        }
        Ok(())
    }

    /// Resolve both releases through the authenticated source's one-hash
    /// mapping. The destination's local mapping is intentionally not used.
    fn verify_init_servtd_svn_order(
        source_policy: &VerifiedPolicy,
        source_evaluation: &PolicyEvaluationInfo,
        servtd_ext: &ServtdExt,
    ) -> Result<(), PolicyError> {
        let init_svn = source_policy
            .servtd_lookup_by_tdinfo_hash(&servtd_ext.init_servtd_info_hash)
            .map(|lookup| lookup.isvsvn);

        verify_svn_order(init_svn, source_evaluation.migtd_isvsvn)
    }

    fn get_rtmrs_from_tdreport(
        td_report: &TdxReport,
    ) -> Result<[[u8; SHA384_DIGEST_SIZE]; 4], PolicyError> {
        let mut rtmrs = [[0u8; SHA384_DIGEST_SIZE]; 4];
        rtmrs[0].copy_from_slice(&td_report.td_info.rtmr0);
        rtmrs[1].copy_from_slice(&td_report.td_info.rtmr1);
        rtmrs[2].copy_from_slice(&td_report.td_info.rtmr2);
        rtmrs[3].copy_from_slice(&td_report.td_info.rtmr3);

        Ok(rtmrs)
    }

    /// Verify a peer's migration policy and event log, then validate peer cert chains.
    fn verify_policy_and_event_log<'p>(
        event_log: &[u8],
        mig_policy: &'p [u8],
        policy_issuer_chain: &[u8],
        rtmrs: &[[u8; SHA384_DIGEST_SIZE]; 4],
    ) -> Result<VerifiedPolicy<'p>, PolicyError> {
        let unverified_policy = RawPolicyData::deserialize_from_json(mig_policy)?;

        // 1. Verify the event log integrity
        verify_event_log(event_log, rtmrs).map_err(|_| PolicyError::InvalidEventLog)?;

        // 2. Verify the peer policy using the peer's issuer chain
        let local_policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;
        let local_servtd_crl = local_policy.servtd_crl.as_deref().map(str::as_bytes);
        let mut verified_policy = unverified_policy
            .verify_with_authoritative_servtd_crl(policy_issuer_chain, local_servtd_crl)?;

        // 3. Validate that the peer's signer matches ours by comparing the
        //    RTMR1 signer anchor (root CA + leaf signer EKU) instead of the
        //    full policy issuer chain PEM. This supports the anchor-only (CoRIM)
        //    enrollment form, which carries no PEM. `verify()` has already
        //    bound the peer's embedded mapping chain to `signer_anchor`.
        if local_policy.signer_anchor != verified_policy.signer_anchor {
            return Err(PolicyError::PeerCertChainValidation);
        }

        // Cross-check the JSON mapping issuer chains when both sides ship one
        // (defense-in-depth; the signer_anchor equality above already binds the
        // signer). Absent on both sides (CoRIM-only) is fine; one-sided fails.
        match (
            local_policy.servtd_tcb_mapping_issuer_chain.as_deref(),
            verified_policy.servtd_tcb_mapping_issuer_chain.as_deref(),
        ) {
            (Some(local_mc), Some(peer_mc)) => {
                crypto::validate_peer_cert_chain(local_mc.as_bytes(), peer_mc.as_bytes())
                    .log_err("Peer tcb mapping cert chain validation")
                    .map_err(|_| PolicyError::PeerCertChainValidation)?;
            }
            (None, None) => {}
            _ => return Err(PolicyError::PeerCertChainValidation),
        }

        // Validate the peer's optional TD Identity issuer chain against ours
        // when both sides ship one. If exactly one side has it, the chains do
        // not match and it fails closed.
        match (
            local_policy.servtd_identity_issuer_chain.as_deref(),
            verified_policy.servtd_identity_issuer_chain.as_deref(),
        ) {
            (Some(local_identity_chain), Some(peer_identity_chain)) => {
                crypto::validate_peer_cert_chain(
                    local_identity_chain.as_bytes(),
                    peer_identity_chain.as_bytes(),
                )
                .log_err("Peer td identity cert chain validation")
                .map_err(|_| PolicyError::PeerCertChainValidation)?;
            }
            (None, None) => {}
            _ => return Err(PolicyError::PeerCertChainValidation),
        }

        // CoRIM is a local endorsement authority, not peer-supplied policy
        // data. Attach our verified CoRIM for peer TCB lookups, then apply our
        // measured CRL to every retained peer/local-authority signer chain.
        #[cfg(feature = "servtd_corim")]
        verified_policy.set_servtd_corim_from(local_policy);
        if let Some(servtd_crl) = local_servtd_crl {
            verified_policy
                .verify_signer_chains_not_revoked(servtd_crl)
                .log_err("Peer servtd signer revocation check")?;
        }

        // 4. Check the integrity of the policy with its event log
        let events = parse_events(event_log).ok_or(PolicyError::InvalidEventLog)?;
        check_policy_integrity(mig_policy, &events)?;

        Ok(verified_policy)
    }

    fn verify_quote(
        quote: &[u8],
        collaterals: &Collaterals,
    ) -> Result<([u8; 6], Vec<u8>), PolicyError> {
        let fmspc = get_fmspc_from_quote(quote)?;
        let collateral = get_collateral_with_fmspc(&fmspc, collaterals)?;
        let collateral_cstr = convert_collateral_to_cstring(&collateral)?;
        let suppl_data = verify_quote_with_collaterals(quote, collateral_cstr)
            .map_err(|_| PolicyError::QuoteVerification)?;

        Ok((fmspc, suppl_data))
    }

    fn verify_tdreport(tdreport: &[u8]) -> Result<TdxReport, PolicyError> {
        let tdx_report =
            TdxReport::read_from_bytes(tdreport).ok_or(PolicyError::InvalidTdReport)?;

        // Verify the REPORTMACSTRUCT
        tdcall_verify_report(tdx_report.report_mac.as_bytes())
            .map_err(|_| PolicyError::TdReportVerification)?;

        // Verify the TDINFO_STRUCT and TEE_TCB_INFO
        let tdinfo_hash = digest_sha384(tdx_report.td_info.as_bytes())
            .map_err(|_| PolicyError::HashCalculation)?;
        let tee_tcb_info_hash = digest_sha384(tdx_report.tee_tcb_info.as_bytes())
            .map_err(|_| PolicyError::HashCalculation)?;

        let mut validity = true;
        validity &= &tdx_report.report_mac.tee_tcb_info_hash == tee_tcb_info_hash.as_slice();
        validity &= tdx_report.report_mac.tee_info_hash != [0; 48];
        validity &= &tdx_report.report_mac.tee_info_hash == tdinfo_hash.as_slice();

        if !validity {
            return Err(PolicyError::InvalidTdReport);
        }
        Ok(tdx_report)
    }

    /// Compute the servtd signer CRL number from the authoritative local
    /// policy, if a signer CRL is present (`servtdCrl`, or its legacy nested
    /// location). Peer evaluation uses this local number rather than trusting
    /// the peer-delivered CRL. `None` when it is absent (backward
    /// compatibility); `Some(n)` feeds the `servtd_crl_num` anti-rollback
    /// floor.
    fn servtd_crl_num_from_policy(policy: &VerifiedPolicy) -> Result<Option<u32>, PolicyError> {
        policy
            .servtd_crl
            .as_deref()
            .map(|crl| get_crl_number(crl.as_bytes()))
            .transpose()
            .map_err(|_| PolicyError::InvalidCollateral)
    }

    fn setup_evaluation_data(
        fmspc: [u8; 6],
        suppl_data: &[u8],
        policy: &VerifiedPolicy,
        authoritative_crl_policy: &VerifiedPolicy,
        collaterals: &Collaterals,
    ) -> Result<PolicyEvaluationInfo, PolicyError> {
        let (tcb_date, tcb_status) = get_tcb_date_and_status_from_suppl_data(suppl_data)?;
        let collateral = get_collateral_with_fmspc(&fmspc, collaterals)?;
        let tcb_evaluation_number = get_tcb_evaluation_number_from_collateral(&collateral)?;
        let report_value = Report::new(suppl_data)?;

        let migtd = policy.servtd_lookup_by_report(&report_value);
        let pck_crl_num = get_crl_number(collaterals.pck_crl.as_bytes())
            .map_err(|_| PolicyError::InvalidCollateral)?;
        let root_ca_crl_num = get_crl_number(collaterals.root_ca_crl.as_bytes())
            .map_err(|_| PolicyError::InvalidCollateral)?;

        Ok(PolicyEvaluationInfo {
            tee_tcb_svn: None,
            tcb_date: Some(tcb_date.to_string()),
            tcb_status: Some(tcb_status.as_str().to_string()),
            tcb_evaluation_number: Some(tcb_evaluation_number),
            fmspc: Some(fmspc),
            migtd_isvsvn: migtd.as_ref().map(|m| m.isvsvn),
            migtd_tcb_status: migtd.as_ref().and_then(|m| m.tcb_status.clone()),
            migtd_tcb_date: migtd.as_ref().and_then(|m| m.tcb_date.clone()),
            pck_crl_num: Some(pck_crl_num),
            root_ca_crl_num: Some(root_ca_crl_num),
            servtd_crl_num: servtd_crl_num_from_policy(authoritative_crl_policy)?,
        })
    }

    fn setup_evaluation_data_with_tdreport(
        tdreport: &TdxReport,
        policy: &VerifiedPolicy,
        authoritative_crl_policy: &VerifiedPolicy,
    ) -> Result<PolicyEvaluationInfo, PolicyError> {
        #[cfg(feature = "use-mock-quote")]
        let mock_tdreport = attestation::tdreport::tdcall_report(
            &[0u8; attestation::tdreport::TD_REPORT_ADDITIONAL_DATA_SIZE],
        )
        .map_err(|_| PolicyError::GetTdxReport)?;
        #[cfg(feature = "use-mock-quote")]
        let mapping_tdreport = {
            log::warn!(
                "use-mock-quote: deriving rebinding MigTD TCB metadata from the mock quote report\n"
            );
            &mock_tdreport
        };
        #[cfg(not(feature = "use-mock-quote"))]
        let mapping_tdreport = tdreport;

        let tdinfo_hash = tdinfo_hash_from_td_info(&mapping_tdreport.td_info)?;
        let migtd = policy.servtd_lookup_by_tdinfo_hash(&tdinfo_hash);

        Ok(PolicyEvaluationInfo {
            tee_tcb_svn: Some(tdreport.tee_tcb_info.tee_tcb_svn),
            tcb_date: None,
            tcb_status: None,
            tcb_evaluation_number: None,
            fmspc: None,
            migtd_isvsvn: migtd.as_ref().map(|m| m.isvsvn),
            migtd_tcb_status: migtd.as_ref().and_then(|m| m.tcb_status.clone()),
            migtd_tcb_date: migtd.as_ref().and_then(|m| m.tcb_date.clone()),
            pck_crl_num: None,
            root_ca_crl_num: None,
            servtd_crl_num: servtd_crl_num_from_policy(authoritative_crl_policy)?,
        })
    }

    fn get_tcb_date_and_status_from_suppl_data(
        suppl_data: &[u8],
    ) -> Result<(String, String), PolicyError> {
        if suppl_data.len() < REPORT_DATA_SIZE {
            return Err(PolicyError::InvalidParameter);
        }

        let tcb_date_bytes = &suppl_data[Report::R_TCB_DATE];
        let tcb_status_bytes = &suppl_data[Report::R_TCB_STATUS];

        let tcb_date = u64::from_le_bytes(tcb_date_bytes.try_into().unwrap());
        let tcb_status = slice_to_string_null_terminated(tcb_status_bytes)?;

        Ok((unix_to_iso8601(tcb_date)?, tcb_status))
    }

    fn unix_to_iso8601(unix_timestamp: u64) -> Result<String, PolicyError> {
        DateTime::from_timestamp(unix_timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .ok_or(PolicyError::InvalidParameter)
    }

    fn slice_to_string_null_terminated(slice: &[u8]) -> Result<String, PolicyError> {
        // Find the null terminator or use the entire slice
        let end_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        let str_bytes = &slice[..end_pos];

        // Convert to String
        String::from_utf8(str_bytes.to_vec()).map_err(|_| PolicyError::InvalidParameter)
    }

    fn convert_collateral_to_cstring(
        collateral: &Collateral,
    ) -> Result<attestation::Collateral, PolicyError> {
        // Helper closure to convert &str to CString and map errors
        let cstring = |s: &str| -> Result<CString, PolicyError> {
            CString::new(s).map_err(|_| PolicyError::InvalidCollateral)
        };

        Ok(attestation::Collateral {
            major_version: collateral.major_version,
            minor_version: collateral.minor_version,
            tee_type: collateral.tee_type,
            pck_crl_issuer_chain: cstring(collateral.pck_crl_issuer_chain.as_str())?,
            root_ca_crl: cstring(collateral.root_ca_crl.as_str())?,
            pck_crl: cstring(collateral.pck_crl.as_str())?,
            tcb_info_issuer_chain: cstring(collateral.tcb_info_issuer_chain.as_str())?,
            tcb_info: cstring(collateral.tcb_info.as_str())?,
            qe_identity_issuer_chain: cstring(collateral.qe_identity_issuer_chain.as_str())?,
            qe_identity: cstring(collateral.qe_identity.as_str())?,
        })
    }

    /// Per GHCI 1.5: Verify that own TDINFO.MROWNERCONFIG matches policy SVN.
    ///
    /// NOTE: the `MROWNER == SHA384(policy-signer public key)` binding has been
    /// **deprecated** — the policy-signer trust root is now the RTMR1 signer
    /// anchor, and the CoRIM-only enrollment carries no signer public key in
    /// the image. Only the MROWNERCONFIG (policy SVN) binding is enforced.
    /// Must be called at MigTD startup to ensure VMM correctly provisioned the TD.
    pub fn verify_own_tdinfo() -> Result<(), PolicyError> {
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;
        let policy_svn = policy.policy_data.get_policy_svn();

        // Get own TDINFO from TDReport
        let tdx_report = tdx_tdcall::tdreport::tdcall_report(&[0u8; 64])
            .map_err(|_| PolicyError::GetTdxReport)?;
        let td_info = &tdx_report.td_info;

        // Verify MROWNERCONFIG == policy_svn (stored as little-endian u32 in first 4 bytes,
        // remaining 44 bytes must be zero)
        let mut expected_mrownerconfig = [0u8; SHA384_DIGEST_SIZE];
        expected_mrownerconfig[..4].copy_from_slice(&policy_svn.to_le_bytes());
        if td_info.mrownerconfig != expected_mrownerconfig {
            return Err(PolicyError::SvnMismatch);
        }

        Ok(())
    }

    /// Per GHCI 1.5: Verify initMigtdData.MROWNERCONFIG <= own policy SVN.
    ///
    /// NOTE: the `MROWNER == own policy-signer key hash` binding has been
    /// **deprecated** (see [`verify_own_tdinfo`]); only the MROWNERCONFIG
    /// (policy SVN floor) binding is enforced.
    pub fn verify_init_migtd_data_policy_binding(
        init_td_info: &[u8; crate::migration::TD_INFO_SIZE],
    ) -> Result<(), PolicyError> {
        use crate::migration::td_info_mrownerconfig;

        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;
        let my_policy_svn = policy.policy_data.get_policy_svn();

        // Check MROWNERCONFIG (init policy_svn) <= my policy_svn
        let init_mrownerconfig = td_info_mrownerconfig(init_td_info);
        let mut init_svn_bytes = [0u8; 4];
        init_svn_bytes.copy_from_slice(&init_mrownerconfig[..4]);
        let init_policy_svn = u32::from_le_bytes(init_svn_bytes);
        // Remaining 44 bytes should be zero
        if init_mrownerconfig[4..] != [0u8; SHA384_DIGEST_SIZE - 4] {
            return Err(PolicyError::InvalidParameter);
        }
        if init_policy_svn > my_policy_svn {
            return Err(PolicyError::SvnMismatch);
        }

        Ok(())
    }

    /// Destination-side migration helper: authenticate the source MigTD and
    /// require its initial mapped SVN to be no newer than its current mapped
    /// SVN. The legacy init-TDINFO argument is ignored for wire compatibility.
    ///
    /// Returns the verified supplemental data on success so the caller can
    /// reuse it for SPDM-level bindings (e.g., REPORTDATA / TH1).
    pub fn authenticate_migration_source_with_init_tdinfo(
        quote_src: &[u8],
        peer_data: &[u8],
        event_log_src: &[u8],
        _init_tdinfo: &[u8],
        servtd_ext_src: &[u8],
    ) -> Result<Vec<u8>, PolicyError> {
        let (mig_policy_src, peer_issuer_chain) =
            crate::migration::pre_session_data::decode_peer_data(peer_data)
                .ok_or(PolicyError::InvalidParameter)?;

        let (evaluation_data_src, verified_policy_src, suppl_data) = authenticate_remote_common(
            quote_src,
            event_log_src,
            mig_policy_src,
            peer_issuer_chain,
        )?;

        let relative_reference = get_local_tcb_evaluation_info()?;
        let policy = get_verified_policy().ok_or(PolicyError::InvalidParameter)?;

        // Existing migration-source policy checks (common + backward)
        policy.policy_data.evaluate_policy_common(
            &evaluation_data_src,
            &relative_reference,
            false,
        )?;
        policy.policy_data.evaluate_policy_backward(
            &evaluation_data_src,
            &relative_reference,
            false,
        )?;

        let servtd_ext =
            ServtdExt::read_from_bytes(servtd_ext_src).ok_or(PolicyError::InvalidParameter)?;
        verify_init_servtd_svn_order(&verified_policy_src, &evaluation_data_src, &servtd_ext)?;

        Ok(suppl_data)
    }

    #[test]
    fn test_verify_svn_order_init_lower() {
        assert!(verify_svn_order(Some(3), Some(5)).is_ok());
    }

    #[test]
    fn test_verify_svn_order_equal() {
        assert!(verify_svn_order(Some(5), Some(5)).is_ok());
    }

    #[test]
    fn test_verify_svn_order_init_higher() {
        assert!(matches!(
            verify_svn_order(Some(6), Some(5)),
            Err(PolicyError::SvnMismatch)
        ));
    }

    #[test]
    fn test_verify_svn_order_missing_init_mapping() {
        assert!(matches!(
            verify_svn_order(None, Some(5)),
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
    }

    #[test]
    fn test_verify_svn_order_missing_current_mapping() {
        assert!(matches!(
            verify_svn_order(Some(5), None),
            Err(PolicyError::UnqualifiedMigTdInfo)
        ));
    }

    #[test]
    fn test_unix_to_iso8601() {
        let timestamp = 1704067200; // Corresponds to 2024-01-01T00:00:00Z
        let iso_date = unix_to_iso8601(timestamp).unwrap();
        assert_eq!(iso_date, "2024-01-01T00:00:00Z");
    }
}

fn get_rtmrs_from_suppl_data(
    suppl_data: &[u8],
) -> Result<[[u8; SHA384_DIGEST_SIZE]; 4], PolicyError> {
    if suppl_data.len() < REPORT_DATA_SIZE {
        return Err(PolicyError::InvalidParameter);
    }

    let mut rtmrs = [[0u8; SHA384_DIGEST_SIZE]; 4];
    rtmrs[0].copy_from_slice(&suppl_data[Report::R_MIGTD_RTMR0]);
    rtmrs[1].copy_from_slice(&suppl_data[Report::R_MIGTD_RTMR1]);
    rtmrs[2].copy_from_slice(&suppl_data[Report::R_MIGTD_RTMR2]);
    rtmrs[3].copy_from_slice(&suppl_data[Report::R_MIGTD_RTMR3]);

    Ok(rtmrs)
}
