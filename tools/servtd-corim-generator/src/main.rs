// Copyright (c) Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use std::{fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::Parser;
use corim::{
    builder::{ComidBuilder, CorimBuilder},
    cbor::value::Value as CborValue,
    types::{
        common::{InstanceIdChoice, TagIdChoice},
        corim::CorimId,
        environment::{ClassMap, EnvironmentMap},
        measurement::{Digest, MeasurementMap, MeasurementValuesMap, SvnChoice},
        signed::{
            CoseAlgorithm, CwtClaims, SignedCorimBuilder, COSE_HEADER_KID, COSE_HEADER_X5CHAIN,
        },
        triples::{
            CesCondition, ConditionalEndorsementSeriesTriple, ConditionalSeriesRecord,
            ReferenceTriple,
        },
    },
};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING},
};
use sha2::{Digest as ShaDigest, Sha256};

const SHA384_ALG: i64 = 7;
const TCB_MAPPING_CORIM_ID: &str = "Microsoft/TDX/tcb-mapping";
const TCB_MAPPING_CORIM_TAG_ID: &str = "1F2E3D4C-5B6A-4798-8A9B-0C1D2E3F4A5B";
const MIGRATION_TD_INSTANCE: &[u8] = b"migration-td";
const DEFAULT_SIGNER_EKU_OID: &str = "1.3.6.1.4.1.32473.1.1";

#[derive(Debug, Parser)]
#[command(about = "Generate a signed MigTD TCB-mapping CoRIM")]
struct Cli {
    /// SHA-384 TDINFO hash to authorize, as 96 hexadecimal characters
    #[arg(long)]
    tdinfo_hash: String,

    /// MigTD SVN associated with the TDINFO hash
    #[arg(long)]
    svn: u16,

    /// Monotonic CoMID generation. This must meet the measured policySvn floor
    /// used by MigTD's anti-rollback policy.
    #[arg(long)]
    generation: u64,

    /// Leaf-first PEM certificate chain embedded into the COSE x5chain
    #[arg(long)]
    cert_chain: PathBuf,

    /// P-384 PKCS#8 PEM private key matching the leaf certificate
    #[arg(long)]
    private_key: PathBuf,

    /// Signer-purpose EKU represented in the did:x509 issuer claim
    #[arg(long, default_value = DEFAULT_SIGNER_EKU_OID)]
    signer_eku_oid: String,

    /// Signed TCB-mapping CoRIM output
    #[arg(long)]
    output: PathBuf,

    /// 48-byte signer-anchor output
    #[arg(long)]
    anchor_output: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let hash = hex::decode(&cli.tdinfo_hash).context("tdinfo hash is not valid hexadecimal")?;
    if hash.len() != 48 {
        bail!("tdinfo hash must be 48 bytes, got {}", hash.len());
    }

    let chain_pem = fs::read(&cli.cert_chain)
        .with_context(|| format!("read certificate chain {}", cli.cert_chain.display()))?;
    let certificates = load_pem_certificates(&chain_pem)?;
    if certificates.len() < 2 {
        bail!("certificate chain must contain at least a leaf and root certificate");
    }

    let payload = build_tcb_mapping(&hash, cli.svn, cli.generation)?;
    let issuer = did_x509_issuer(&certificates, &cli.signer_eku_oid)?;
    let kid = Sha256::digest(&certificates[0]).to_vec();
    let mut builder = signed_builder(payload, &certificates, kid, issuer);
    let tbs = builder
        .to_be_signed(b"")
        .map_err(|e| anyhow::anyhow!("build COSE to-be-signed bytes: {e}"))?;

    let private_key_pem = fs::read(&cli.private_key)
        .with_context(|| format!("read private key {}", cli.private_key.display()))?;
    let private_key = load_pem_block(&private_key_pem, "PRIVATE KEY")?;
    let rng = SystemRandom::new();
    let signing_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &private_key, &rng)
            .map_err(|_| anyhow::anyhow!("parse P-384 PKCS#8 private key"))?;
    let signature = signing_key
        .sign(&rng, &tbs)
        .map_err(|_| anyhow::anyhow!("sign CoRIM with P-384 private key"))?;
    let cose = builder
        .build_with_signature(signature.as_ref().to_vec())
        .map_err(|e| anyhow::anyhow!("build signed CoRIM: {e}"))?;

    let anchor = policy::compute_signer_anchor_from_chain_pem(&chain_pem)
        .map_err(|e| anyhow::anyhow!("compute signer anchor: {e:?}"))?;

    let verified = policy::ServtdCorim::decode_signed(&cose, 0, &anchor)
        .map_err(|e| anyhow::anyhow!("self-verify signed CoRIM: {e:?}"))?;
    let lookup = verified
        .lookup_by_tdinfo_hash(&hash)
        .context("self-verified CoRIM did not contain the requested TDINFO hash")?;
    if lookup.isvsvn != cli.svn {
        bail!(
            "self-verified CoRIM resolved SVN {}, expected {}",
            lookup.isvsvn,
            cli.svn
        );
    }

    fs::write(&cli.output, &cose)
        .with_context(|| format!("write signed CoRIM {}", cli.output.display()))?;
    fs::write(&cli.anchor_output, anchor)
        .with_context(|| format!("write signer anchor {}", cli.anchor_output.display()))?;

    println!(
        "Generated signed TCB-mapping CoRIM: {} ({} bytes)",
        cli.output.display(),
        cose.len()
    );
    println!(
        "Generated signer anchor: {} (48 bytes)",
        cli.anchor_output.display()
    );
    Ok(())
}

fn migration_td_environment() -> EnvironmentMap {
    EnvironmentMap {
        class: Some(ClassMap {
            class_id: None,
            vendor: Some("Intel".into()),
            model: Some("TDX".into()),
            layer: None,
            index: None,
        }),
        instance: Some(InstanceIdChoice::Bytes(MIGRATION_TD_INSTANCE.to_vec())),
        group: None,
    }
}

fn build_tcb_mapping(hash: &[u8], svn: u16, generation: u64) -> Result<Vec<u8>> {
    let digest = Digest::new(SHA384_ALG, hash.to_vec());
    let reference = ReferenceTriple::new(
        migration_td_environment(),
        vec![MeasurementMap {
            mkey: None,
            mval: MeasurementValuesMap {
                digests: Some(vec![digest.clone()]),
                ..MeasurementValuesMap::new()
            },
            authorized_by: None,
        }],
    );

    let condition = CesCondition {
        environment: migration_td_environment(),
        claims_list: Vec::new(),
        authorized_by: None,
    };
    let selection = MeasurementMap {
        mkey: None,
        mval: MeasurementValuesMap {
            digests: Some(vec![digest]),
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
    let ces = ConditionalEndorsementSeriesTriple::new(
        condition,
        vec![ConditionalSeriesRecord::new(
            vec![selection],
            vec![addition],
        )],
    );

    let comid = ComidBuilder::new(TagIdChoice::Text(TCB_MAPPING_CORIM_TAG_ID.into()))
        .set_tag_version(generation)
        .add_reference_triple(reference)
        .add_conditional_endorsement_series(ces)
        .build()
        .map_err(|e| anyhow::anyhow!("build TCB-mapping CoMID: {e}"))?;

    CorimBuilder::new(CorimId::Text(TCB_MAPPING_CORIM_ID.into()))
        .add_comid_tag(comid)
        .map_err(|e| anyhow::anyhow!("attach TCB-mapping CoMID: {e}"))?
        .build_bytes()
        .map_err(|e| anyhow::anyhow!("encode unsigned CoRIM: {e}"))
}

fn signed_builder(
    payload: Vec<u8>,
    certificates: &[Vec<u8>],
    kid: Vec<u8>,
    issuer: String,
) -> SignedCorimBuilder {
    let x5chain = certificates
        .iter()
        .map(|cert| CborValue::Bytes(cert.clone()))
        .collect();
    SignedCorimBuilder::new(CoseAlgorithm::Es384, payload)
        .set_cwt_claims(runtime_cwt_claims(issuer))
        .add_protected(COSE_HEADER_KID, CborValue::Bytes(kid))
        .add_protected(COSE_HEADER_X5CHAIN, CborValue::Array(x5chain))
}

fn runtime_cwt_claims(issuer: String) -> CwtClaims {
    // MigTD has no trusted wall clock. Freshness is enforced by the measured
    // policySvn floor and the CoMID tag generation, never CWT time claims.
    CwtClaims::new(issuer)
}

fn did_x509_issuer(certificates: &[Vec<u8>], signer_eku_oid: &str) -> Result<String> {
    let root = certificates
        .last()
        .context("certificate chain contains no root certificate")?;
    let root_hash = Sha256::digest(root);
    let root_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(root_hash.as_slice());
    Ok(format!(
        "did:x509:0:sha256:{root_hash}::eku:{signer_eku_oid}"
    ))
}

fn load_pem_certificates(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let pem = std::str::from_utf8(pem).context("certificate chain is not UTF-8 PEM")?;
    let mut certificates = Vec::new();
    let mut encoded = String::new();
    let mut in_certificate = false;

    for line in pem.lines() {
        match line {
            "-----BEGIN CERTIFICATE-----" => {
                if in_certificate {
                    bail!("nested PEM certificate header");
                }
                in_certificate = true;
                encoded.clear();
            }
            "-----END CERTIFICATE-----" => {
                if !in_certificate {
                    bail!("PEM certificate footer without header");
                }
                let der = base64::engine::general_purpose::STANDARD
                    .decode(&encoded)
                    .context("decode PEM certificate")?;
                certificates.push(der);
                in_certificate = false;
            }
            _ if in_certificate => encoded.push_str(line.trim()),
            _ => {}
        }
    }

    if in_certificate {
        bail!("unterminated PEM certificate");
    }
    if certificates.is_empty() {
        bail!("certificate chain contains no certificates");
    }
    Ok(certificates)
}

fn load_pem_block(pem: &[u8], label: &str) -> Result<Vec<u8>> {
    let pem = std::str::from_utf8(pem).context("private key is not UTF-8 PEM")?;
    let header = format!("-----BEGIN {label}-----");
    let footer = format!("-----END {label}-----");
    let encoded = pem
        .split_once(&header)
        .and_then(|(_, rest)| rest.split_once(&footer).map(|(body, _)| body))
        .context("private key does not contain a PKCS#8 PEM block")?
        .lines()
        .map(str::trim)
        .collect::<String>();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("decode PKCS#8 PEM private key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use corim::validate::decode_and_validate_at;

    #[test]
    fn runtime_claims_omit_unsupported_validity_windows() {
        let claims = runtime_cwt_claims("did:x509:test".into());
        assert!(claims.nbf.is_none());
        assert!(claims.exp.is_none());
    }

    #[test]
    fn mapping_carries_monotonic_generation() {
        let generation = 7;
        let payload = build_tcb_mapping(&[0xA5; 48], 3, generation).unwrap();
        let (_, comids) = decode_and_validate_at(&payload, 0).unwrap();
        assert_eq!(comids.len(), 1);
        assert_eq!(comids[0].tag_identity.tag_version_or_default(), generation);
    }
}
