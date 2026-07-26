TCB Mapping Design for One-Hash Endorsement
===================================================

# Problem Statement

Policy v2 bundles `{policy, collaterals, servtdCollateral (signed TCB mapping + signed identity)}` into one signed blob that is measured into RTMR2. This creates a **circular dependency**: binding RTMR2 into `svnMappings` requires RTMR2 to be known before the TCB mapping is generated, yet RTMR2 is computed over policy content that already contains that TCB mapping.

To avoid the cycle, today's `svnMappings` exclude RTMR2 and key only on `[MRTD, RTMR0, RTMR1]`. The signed TCB mapping therefore binds the MigTD code measurement and policy-signer anchor but **not** the policy content measured into RTMR2. Two complications follow:

- **Rebinding and migration** — the source MigTD cannot map `init_servtd_info_hash` (= `SHA384(TDINFO)`) to an SVN directly, so it must accept the full init TDINFO from the untrusted VMM on every request and re-derive the registers after verifying the init TDINFO.
- **Tenant TD attestation** — the attestation service holds only `init/cur_servtd_info_hash` (hashes over *all* registers) and cannot match them against the subset-keyed `svnMappings`, forcing reliance on separate hash-based endorsements.

See [Additional details](#additional-details) for the full data-flow diagrams and the `SERVTD_EXT_STRUCT` layout.

# Proposal

Change what is measured so the mapping key becomes a stable, pre-signing function of the build, breaking the cycle:

| Register | Today | Proposed |
|----------|-------|----------|
| **RTMR1** | Hash of the policy-issuer cert chain (PEM) | **Signer anchor** `A = SHA384(tag \|\| 0x00 \|\| SHA384(DER(root)) \|\| 0x00 \|\| DER(leaf signer EKU OID))` |
| **RTMR2** | Whole signed policy blob (includes the TCB mapping) | **Single canonical-bytes extend** of `policyData` with `servtdCollateral.servtdTcbMapping` redacted |
| **`svnMappings` key** | `[MRTD, RTMR0, RTMR1]` subset | Full `tdinfo_hash` (= `init_servtd_info_hash` = `SHA384(TDINFO)` for `attr=0`) |

`servtdTcbMapping` is the **only** field redacted from the RTMR2 extend, because it is the field that carries `tdinfo_hash`; excluding it removes the cycle while every other `policyData` field stays bound by construction. `svnMappings[].tdMeasurements.tdinfo_hash` is populated *after* measurement.

# Benefits

- **Breaks the circular dependency** — `tdinfo_hash` is computable from build inputs before the TCB mapping is signed.
- **Self-contained attestation lookup** — the service matches `init/cur_servtd_info_hash` directly against `svnMappings`, needing no out-of-band endorsements.
  - The same signed TCBMapping reusable by MigTD and Attestation services.
- **Simpler rebind/migration** — MigTD maps `init_servtd_info_hash` to an SVN locally; the VMM no longer supplies init TDINFO per request.
- **Low leaf-key-rotation churn** — the RTMR1 signer anchor depends only on the root CA and leaf signer EKU, so a leaf-key reissue does not change RTMR1.

# Extensions
- **Support CoRIM in MigTD:** Sign TCBMapping once, reuse for both tenant attestation and MigTD runtime peer/init TCB evaluation
- **Future Mig-NRX support:** SERVTD_EXT.{INIT,CUR}_INFO_HASH will measure the policy only so we redefine the hash key in svnMappings as the hash of the policy only.


# Additional details

## Diagrams and structures for current implementation

**Current TCBMapping without full measurement of MigTD and policy in svnMappings**

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Signed Policy Blob                           │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │ policyData                                                    │  │
│  │  ├── policy (migration rules)                                 │  │
│  │  ├── collaterals (platform TCB info)                          │  │
│  │  └── servtdCollateral                                         │  │
│  │       ├── servtdIdentity {tdIdentity, signature}              │  │
│  │       └── servtdTcbMapping                                    │  │
│  │            └── svnMappings[]:                                 │  │
│  │                 {[MRTD, RTMR0, RTMR1], isvsvn}                │  │
│  │                  ─────────────────────                        │  │
│  │                  RTMR2, RTMR3 excluded to avoid circularity   │  │
│  └─────────────────────┬─────────────────────────────────────────┘  │
│                        │                                            │
│  signature             │                                            │
└────────────────────────┼────────────────────────────────────────────┘
                         │ entire blob measured into
                         ▼
              ┌─────────────────────┐
              │       RTMR2         │  ← depends on svnMappings content
              └─────────────────────┘    (inside the measured blob)

   Result: svnMappings cannot include RTMR2 without creating a
   circular dependency, so RTMR2 is excluded — leaving the TCB
   mapping unable to fully bind MigTD identity to policy content.
```

*Note:* `SERVTD_EXT_STRUCT` is constructed by the TDX module at runtime using the tenant's TDCS and is not directly included in the TD report. Its hash, `SHA384(SERVTD_EXT_STRUCT)`, is included as `tdinfo.Servtd_hash`. The structure is read by the host OS and supplied to the Quoting service (QTD/QE), which verifies it against the hash and includes it in the TD Quote.

```rust
struct ServtdExt {
    init_servtd_info_hash: [u8; 48],
    init_servtd_attr: [u8; 8],
    reserved: [u8; 8],
    init_cpusvn: [u8; 16],
    init_tee_tcb_svn: [u8; 16],
    init_tee_model: [u8; 12],
    reserved1: [u8; 4],
    cur_servtd_info_hash: [u8; 48],
    cur_servtd_attr: [u8; 8],
    reserved2: [u8; 104],
}
```

** Init MigTD (rebinding/migration) TCB evaluation - current svnMappings require init TDINFO from VMM:**

```
   VMM / Host OS                          Current MigTD (source)
  ┌─────────────────────┐               ┌──────────────────────────────────┐
  │                     │               │                                  │
  │  TDX Module provides│               │  Needs to determine TCB level    │
  │  init_servtd_info_  │               │  of init MigTD bound to target   │
  │  hash to MigTD      │               │                                  │
  │                     │               │  svnMappings only has:           │
  │  But svnMappings    │               │    {[MRTD, RTMR0, RTMR1], isvsvn}│
  │  uses [MRTD,RTMR0,  │               │                                  │
  │  RTMR1] not full    │               │  Cannot derive [MRTD, RTMR0,     │
  │  tdinfo_hash        │               │  RTMR1] from init_servtd_info_   │
  │                     │               │  hash alone!                     │
  │                     │               │                                  │
  │  ┌───────────────┐  │   per-request │                                  │
  │  │ init TDINFO   │──┼──────────────►│  Verify:                         │
  │  │ (full struct) │  │   VMM carries │   SHA384(TDINFO) ==              │
  │  └───────────────┘  │   untrusted   │   init_servtd_info_hash? ✓       │
  │                     │   input       │                                  │
  │                     │               │  Extract [MRTD, RTMR0, RTMR1]    │
  │                     │               │  from verified TDINFO            │
  │                     │               │          │                       │
  │                     │               │          ▼                       │
  │                     │               │  Look up svnMappings →  isvsvn   │
  └─────────────────────┘               └──────────────────────────────────┘

   Problem: VMM must supply full init TDINFO struct on every migration
   request. MigTD verifies it against init_servtd_info_hash, then
   extracts individual registers to look up SVN. This adds:
   - VMM implementation complexity (carry and supply TDINFO per request)
   - Larger untrusted input surface per migration handshake
```

**Tenant TD attestation — current svnMappings not useful:**

```
  TD Quote (authenticated by QE signature)
  ┌──────────────────────────────────────────────────────────┐
  │  tdinfo                                                  │
  │   ├── MRTD, RTMR0, RTMR1, RTMR2, RTMR3, ...              │
  │   └── Servtd_hash = SHA384(SERVTD_EXT_STRUCT) ───────┐   │
  └──────────────────────────────────────────────────────┼───┘
                                                         │
   SERVTD_EXT_STRUCT (carried alongside quote)           │
  ┌──────────────────────────────────────────────────┐   │
  │  init_servtd_info_hash  (48 bytes)               │◄──┘ authenticated
  │  init_servtd_attr                                │      by Servtd_hash
  │  cur_servtd_info_hash   (48 bytes)               │
  │  cur_servtd_attr                                 │
  └──────────────┬──────────────────┬────────────────┘
                 │                  │
                 ▼                  ▼
   init_servtd_info_hash      cur_servtd_info_hash
   = SHA384(init TDINFO)      = SHA384(cur TDINFO)
                 │                  │
                 ▼                  ▼
  ┌──────────────────────────────────────────────────────────────┐
  │                    Attestation Service                       │
  │                                                              │
  │  Has: init_servtd_info_hash, cur_servtd_info_hash            │
  │       (single hashes of full TDINFO including ALL registers) │
  │                                                              │
  │  svnMappings provides:                                       │
  │    {[MRTD, RTMR0, RTMR1], isvsvn}                            │
  │     ─────────────────────────────                            │
  │     Incomplete! Missing RTMR2, RTMR3.                        │
  │                                                              │
  │  ✗ Cannot match init/cur_servtd_info_hash against            │
  │    svnMappings — the hash covers ALL registers but           │
  │    svnMappings only lists a subset.                          │
  │                                                              │
  │  ✗ Cannot reconstruct tdinfo_hash from partial registers     │
  │    without knowing RTMR2 (which svnMappings excludes).       │
  │                                                              │
  │  → Must rely on separate endorsements (CoRIM) that           │
  │    directly map tdinfo_hash → SVN, bypassing svnMappings.    │
  └──────────────────────────────────────────────────────────────┘
```

## Proposal details

Redesign what is measured into RTMR1/RTMR2 to break the circular dependency between measurement and policy construction. The endorsed `servtdHash` then captures both MigTD code and migration policy, while TCB mapping remains derivable without circular inputs.

### Redesigned measurement layout

Break policy content into independent measured components so RTMR2 no longer depends on TCB mapping content:

**Measurement register layout** (RTMR extends):

| Register | Before | Redesign |
|----------|--------|----------|
| **RTMR1** | Policy issuer cert chain anchor | **Signer anchor** derived from the root cert DER hash + leaf signer EKU OID (see below) |
| **RTMR2** | Signed policy blob (contains policy rules + collaterals + signed TCB mapping + signed identity) | **Single canonical-bytes extend** of `policyData` with `servtdCollateral.servtdTcbMapping` removed. By construction this binds every other top-level `policyData` field — `version`, `id`, `policySvn`, `policy`, `forwardPolicy`, `backwardPolicy`, `collaterals`, and the rest of `servtdCollateral` (including the issuer-signed `{tdIdentity, signature}` and both issuer chains). See "Servtd identity binding" below. |

**IGVM CFV file layout** (configuration firmware volume slots loaded at boot):

| CFV slot | Before | Redesign | Measured into |
|----------|--------|----------|---------------|
| `MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID` | Policy issuer cert chain | Signing cert chain; signer anchor measured at boot | **RTMR1** |
| `MIGTD_POLICY_FFS_GUID` | Signed policy with collaterals | Signed policy with collaterals, updated `svnMappings` semantics | **RTMR2** |

With this split:
- RTMR2 = single extend of canonical `policyData` with `servtdCollateral.servtdTcbMapping` redacted — every other field is automatically bound by being inside the canonical object. The redaction is the only escape hatch and permits `servtdTcbMapping` to be re-signed after the IGVM is shipped, preserving circularity-freedom.
- RTMR1 = hash(signer anchor) derived from root cert DER hash + leaf signer EKU OID (defined below).
- TCB mapping can bind `tdinfo_hash` (= `init_servtd_info_hash` = `SHA384(TDINFO)` for attr=0) to SVN without circularity.

**New design — full tdinfo hash in svnMappings but unmeasured, removing circular dependency:**

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Signed Policy Blob                              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ policyData                                                       │  │
│  │  ├── policy, version, id, policySvn, collaterals, ...            │  │
│  │  └── servtdCollateral                                            │  │
│  │       ├── servtdIdentity {tdIdentity, signature}  ──┐            │  │
│  │       ├── servtdIdentityIssuerChain                 │ measured   │  │
│  │       ├── servtdTcbMappingIssuerChain               │            │  │
│  │       └── servtdTcbMapping ◄────── NOT measured ──┐ │            │  │
│  │            └── svnMappings[]:                     │ │            │  │
│  │                 {tdinfo_hash, isvsvn}             │ │            │  │
│  └───────────────────────────────────────────────────┼─┼────────────┘  │
│  signature  ─────────────────────────────────────────┼─┤               │
└──────────────────────────────────────────────────────┼─┼───────────────┘
                                                       │ │
              RTMR2 = SHA384(canonical(policyData      │ │
                      minus servtdTcbMapping))  ◄──────┘ │
                         │                               │
              ┌──────────┼──────────────────┐            │
              │          ▼                  │            │
              │ tdinfo_hash = SHA384(TDINFO)│            │
              │   MRTD, RTMR0, RTMR1, RTMR2 │            │
              └──────────┬──────────────────┘            │
                         │                               │
                         ▼                               │
              svnMappings[].tdinfo_hash ─────────────────┘
                                          populated AFTER
                                          measurement
                                          (no circularity)

   RTMR1 = H(signer_anchor(root_CA, leaf_signer_EKU))
          ▲
          │
   CFV: signing cert chain (not measured as raw bytes)
```

#### RTMR1 signer-anchor formula

Define `H(x) = SHA384(x)`.

1. Root certificate component:
    - `R = H(DER(root_certificate))`
2. Leaf signer-purpose component:
    - `EKU_OID = DER(the leaf certificate's single dedicated signer EKU OID)`
3. Signer anchor payload (domain-separated):
    - `A = H("MIGTD-RTMR1-ANCHOR-V1" || 0x00 || R || 0x00 || EKU_OID)`
4. RTMR extend chain:
    - `RTMR1_0 = 48-byte zero`
    - `RTMR1_1 = H(RTMR1_0 || H(separator_event_payload))`
    - `RTMR1_final = H(RTMR1_1 || H(A))`

Where `separator_event_payload` is the measured boot separator event for RTMR1, and `A` is the signer anchor event payload.

#### Rationale

- Aligns with peer-cert policy semantics: peer validation enforces the same root certificate and the same single dedicated leaf signer EKU.
- Makes leaf key rotation under the same root and signer EKU low churn for RTMR1.
- Keeps trust-anchor sensitivity explicit: changing the root certificate DER changes `R`, therefore changes RTMR1.
- Uses the DER-encoded EKU OID to avoid text-format ambiguity.
- Makes the tradeoff explicit: this anchor binds root identity and signer purpose, not the leaf public key itself.

#### Servtd identity binding (RTMR2 single extend)

RTMR2 is extended **once** with the canonical bytes of `policyData` with
`servtdCollateral.servtdTcbMapping` removed. Every other `policyData` field
— including `version`, `id`, `policySvn`, `policy`, `forwardPolicy`,
`backwardPolicy`, `collaterals`, and the rest of `servtdCollateral`
(`majorVersion`, `minorVersion`, the issuer-signed
`{tdIdentity, signature}` object, `servtdIdentityIssuerChain`,
`servtdTcbMappingIssuerChain`) — is bound into RTMR2 by virtue of being
inside the canonical object bytes. The redaction is the only escape hatch
and is what makes `servtdTcbMapping` updateable after the IGVM is shipped.

This single extend folds together two security properties:
detecting drift between the bytes that were signed and the bytes loaded
into the running MigTD (covered by canonicalizing the whole `policyData`
sub-tree), and — whenever `servtdIdentity` is used for policy — defeating
its playback / TCB-downgrade attacks (covered by including
`servtdCollateral.servtdIdentity` in that sub-tree; see below).

**Role of `servtdIdentity` — a good-to-have enrichment, not the root of trust:**

- The core identity and anti-downgrade guarantee comes from the TCB mapping: the `tdinfo_hash → SVN` lookup plus the trust baseline (minimum acceptable SVN). This holds with or without `servtdIdentity`.
- `servtdIdentity` (its `tcbLevels`) is an **optional layer on top** of that SVN: each MigTD uses it to translate a peer's resolved SVN into a `tcbStatus` / `tcbDate` during the handshake, enabling richer TCB-recovery policy (status labels, date thresholds, non-monotonic per-SVN-level revocation) that pure SVN ordering cannot express.

**Initial implementation — retain `servtdIdentity` (minimal change):**

- Keep `servtdIdentity` in `policyData` exactly as today, so existing `tcbDate` / `tcbStatus` migration policies continue to work unchanged. It is measured into RTMR2 for free by the single redacted-`policyData` extend — no extra code, tag, or event-log entry.

**Why it MUST be measured whenever it is used:**

- Each MigTD consults its locally-loaded `servtdIdentity` to map a peer's `(isvProdId, isvSvn)` to a TCB status. The issuer periodically re-publishes `servtdIdentity` with updated `tcbLevels` to revoke or downgrade old SVNs.
- **Unmeasured**, an attacker could boot a peer with an obsolete-but-still-issuer-signed `servtdIdentity` (from before a revocation) and present old, vulnerable SVNs as `UpToDate`, then migrate to/from a healthy MigTD — a classic playback / downgrade attack.
- **Measured**, RTMR2 commits to the exact `servtdIdentity` bytes in use. A peer booting a different (e.g. obsolete) `servtdIdentity` gets a different `tdinfo_hash`; since the authority only publishes `svnMappings[]` entries for the current `servtdIdentity`, that peer falls outside the mapping and migration fails closed.

**Future option — drop `servtdIdentity` entirely:**

- If migration policy is expressed purely as SVN comparisons (e.g. peer SVN ≥ local, or ≥ a minimum), `servtdIdentity` can be removed: the peer's SVN is derived solely from the TCB mapping (`tdinfo_hash → SVN`), independent of `servtdIdentity`.
- Trade-off: this drops the `tcbStatus` / `tcbDate` policy axes and non-monotonic per-SVN-level revocation (mark SVN N `Revoked` while keeping N−1). Build-specific revocation is still possible by removing that build's `tdinfo_hash` entry from the mapping. Requires SVN monotonicity ("higher SVN ≥ as trustworthy") to hold.

**Why include the signature too:**

- Hash scope = **full canonical `policyData` minus `servtdTcbMapping`**, which includes the `{tdIdentity, signature}` object verbatim (canonical bytes, sorted keys, no whitespace).
- Including the signature means that **any** authority re-signing event (even of byte-identical content) changes RTMR2. This is intentional: operators must re-release the MigTD image whenever the issuer re-issues `servtdIdentity`, and `svnMappings[]` for the new image must be re-computed by the authority. This eliminates ambiguity over "which issuance is bound here".

**Why `servtdTcbMapping` is the only redacted field:**

- Measuring it would defeat the entire purpose of the redesign: `servtdTcbMapping` carries `svnMappings[].tdMeasurements.tdinfo_hash` (which is what `tdinfo_hash` itself derives from), and so binding it back into RTMR2 would re-introduce the circular dependency.
- The redaction is also what enables the authority to re-issue `servtdTcbMapping` (adding/removing `svnMappings[]` entries, bumping `nextUpdate`, etc.) without forcing a new IGVM release. Operators just swap the signed TCB mapping artifact alongside the existing IGVM.

**Why measure by construction:**

- The single redacted-`policyData` extend automatically binds every top-level `policyData` field, including any added in the future, without requiring an explicit whitelist update.
- Both issuer chains are covered for free: `servtdIdentityIssuerChain` and `servtdTcbMappingIssuerChain`. An attacker who could substitute either chain could weaponise it to validate an arbitrary identity or mapping; this scheme rules that out by construction.
- Optional blocks (`forwardPolicy` / `backwardPolicy`) are covered the same way — no separate extend, no separate tag, no separate event-log entry.

#### Alternatives considered

| Scheme | Result | Why chosen / rejected |
|--------|--------|-----------------------|
| **Single canonical extend over `policyData` with `servtdTcbMapping` redacted** *(chosen)* | One RTMR2 extend, one tag, one event-log entry. | Breaks the circular dependency by redacting exactly the field that contains `tdinfo_hash`; binds every other field by construction. |
| **Per-field extends** | N RTMR2 extends, each with own tag and event-log entry. | Requires discipline to add a new extend for every new `policyData` field — easy to forget, silently leaving fields unmeasured. Rejected. |
| **Single extend over raw (non-canonical) bytes** | One extend, no canonicalization. | Brittle: any whitespace or key-order difference between policy generator, CFV, and offline hash tool produces a different digest. Rejected. |
| **Single canonical extend over full `policyData` (no redaction)** | One extend covering `servtdTcbMapping` too. | Re-introduces the circular dependency. Rejected. |

**Layout invariant** (verifier-relevant):

```
RTMR2_extend_1: SHA384(canonical_bytes(policyData with servtdCollateral.servtdTcbMapping removed))
                tag 0x9 (TAGGED_EVENT_ID_POLICY_DATA)
                event name "MigTdPolicyData"
                helper extract_canonical_policy_data_bytes
```

Canonicalization is RFC-8785-style: object keys sorted lexicographically at every level, arrays preserve order, whitespace stripped, scalar encoding follows `serde_json` defaults.

#### Signing key rotation: impact and operational steps

MigTD supports leaf signing key rotation during live migration (commit `5f9a91e`). When two MigTDs with different leaf signing keys (but the same root CA and leaf signer EKU) migrate a tenant TD, the runtime peer validation succeeds because:

1. Each MigTD exchanges its signing cert chain alongside the policy during pre-session data exchange.
2. The peer validates the received chain: root CA and leaf signer EKU must match, internal signature integrity is verified, and non-CA issuers are rejected.
3. The peer's policy, TCB mapping chain, and TD identity chain are each validated against the local chains using the same rules.

This means **old and new MigTDs can coexist during a rolling deployment** — a MigTD built with the old leaf key can still migrate to/from one built with the new leaf key.
We will also add enforcement to allow MigTD with leaf cert expring earlier to migrate MigTD with leaf cert expiring later, reject the other way around.

##### What changes when the leaf signing key rotates

Assumption: **only the leaf signing key rotates** — the MigTD binary code, migration policy rules, root CA, and leaf signer EKU are unchanged.

| Component | Changes? | Why |
|-----------|----------|-----|
| **MRTD** | No | Cert chain is in CFV (unmeasured content in IGVM) |
| **RTMR0** | No | MigTD binary code is unchanged |
| **RTMR1** | **No** | Signer anchor `A` depends only on the root CA fingerprint and leaf signer EKU, not the leaf public key |
| **RTMR2** | **Yes** | `policyData` must be re-signed with the new key → signature bytes change → different canonical bytes |
| **TCB mapping** | Must add new entry | `svnMappings` keyed by `tdinfo_hash` which includes RTMR2 |
| **Endorsed tdinfo_hash** | **Yes** | RTMR2 contributes to `tdinfo_hash` |

The signer-anchor formula eliminates RTMR1 churn on leaf key rotation. However, **RTMR2 still changes** because the signed `policyData` envelope includes the signature bytes, and a new signing key produces a different signature even over identical policy content.

The remaining RTMR2 churn on key rotation is a consequence of the `servtdIdentity` anti-replay design (see "Why the `servtdIdentity` binding is necessary" above): RTMR2 measures the full signed `policyData` envelope so that the authority can revoke any specific issuance by removing its `tdinfo_hash` from `svnMappings[]`. A scheme that measured only unsigned policy rules would eliminate endorsement churn on key rotation but would also defeat this binding.

##### Key rotation impact summary

| Approach | RTMR1 changes? | RTMR2 changes? | TCB mapping update? | Endorsement update? | IGVM rebuild? |
|----------|----------------|----------------|---------------------|---------------------|---------------|
| **This redesign** (signer anchor + signed policyData) | No | Yes (signature) | Yes (new `tdinfo_hash`) | Yes | No (CFV swap only) |
| If RTMR2 measured **unsigned** policy rules only | No | **No** | **No** | **No** | No |
| Pre-redesign (full chain in RTMR1) | Yes | Yes | Yes | Yes | Yes |

### Build flow

The release artifact is produced in two stages: a build stage that compiles the MigTD binary into a *base IGVM* with a dummy CFV, and a release stage that signs the policy artifacts and enrolls the production bytes into the base IGVM's CFV via `td-shim-enroll` (a byte-level FFS slot replacement — no Rust rebuild).

1. **Build stage — base IGVM.** Compile MigTD and embed a dummy CFV containing the same canonical `policyData` content the final policy will carry, so the single redacted-`policyData` RTMR2 extend matches the final image byte-for-byte. The production signing chain is also enrolled into the `MIGTD_POLICY_ISSUER_CHAIN` CFV slot so RTMR1 already matches the final IGVM. The embedded `servtdIdentity` is signed by an ephemeral build-time key (the build environment has no access to production signing). This yields the base IGVM and a *preview* `tdinfo_hash`.

2. **Release stage — pre-final IGVM (CFV swap).** Re-sign `servtdIdentity` under production signing. Assemble a *pre-final* `policyData` with an empty `servtdTcbMapping` sentinel (the redacted RTMR2 extend ignores this field). Run `td-shim-enroll` to overwrite the CFV slots. Measure the re-enrolled binary to obtain the production `tdinfo_hash`.

3. **Release stage — TCB mapping.** Create `svnMappings: [{tdMeasurements: {tdinfo_hash}, isvsvn}]` using the production `tdinfo_hash`, then sign the TCB mapping.

4. **Release stage — final IGVM.** Assemble the final signed policy (now including the signed TCB mapping) and re-run `td-shim-enroll`. Verify its `tdinfo_hash` equals the pre-final value — a CI gate enforcing the "`tcbMapping` is not measured" invariant.

5. **Endorsements.** Compute endorsed `tdinfo_hash` (= `init_servtd_info_hash` = `SHA384(TDINFO)`) from the final image. This hash captures policy content (via the single RTMR2 extend) and signer trust anchor (via RTMR1).

### Attestation verification

The attestation service receives the Tenant TD Quote, which includes for each bound MigTD:

* `init_migtd_hash` ← `servtd_ext.init_servtd_info_hash` — the hash of the MigTD originally bound to the tenant TD.
* `cur_migtd_hash` ← `servtd_ext.cur_servtd_info_hash` — the hash of the currently bound MigTD.

Both values are authenticated by `tdinfo.Servtd_hash` (the `SHA384(SERVTD_EXT_STRUCT)` carried in the quote).

The service consults two signed endorsement artifacts:

1. **Authorization endorsement** (`servtd_info_hash → SVN`) — translates `init_migtd_hash` and `cur_migtd_hash` into `init_migtd_svn` and `cur_migtd_svn`. Cumulative across releases — must include historical entries so past `init_migtd_hash` values still resolve.

2. **Trust / baseline endorsement** — declares the minimum acceptable MigTD SVN. The service evaluates **both** initial and current bound MigTDs against this baseline (`init_migtd_svn >= min_migtd_svn` and `cur_migtd_svn >= min_migtd_svn`). A failure on either fails the attestation — catching both "originally bound to a now-revoked MigTD" and "currently bound to an out-of-date MigTD" cases.

**Post-redesign tenant TD attestation — self-contained reverse lookup:**

```
  TD Quote (authenticated by QE signature)
  ┌──────────────────────────────────────────────────────────┐
  │  tdinfo                                                  │
  │   └── Servtd_hash = SHA384(SERVTD_EXT_STRUCT) ───────┐   │
  └──────────────────────────────────────────────────────┼───┘
                                                         │
   SERVTD_EXT_STRUCT (carried alongside quote)           │
  ┌──────────────────────────────────────────────────┐   │
  │  init_servtd_info_hash  ─────────────────────┐   │◄──┘ authenticated
  │  cur_servtd_info_hash   ──────────────────┐  │   │      by Servtd_hash
  └───────────────────────────────────────────┼──┼───┘
                                              │  │
                                              ▼  ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │                     Attestation Service                           │
  │                                                                   │
  │  Step 1: Authorization endorsement (svnMappings in TCB mapping)   │
  │  ┌─────────────────────────────────────────────────────────────┐  │
  │  │  svnMappings[]:                                             │  │
  │  │    {tdinfo_hash: "abc123...", isvsvn: 3}                    │  │
  │  │    {tdinfo_hash: "def456...", isvsvn: 2}  ← historical      │  │
  │  │    {tdinfo_hash: "ghi789...", isvsvn: 1}  ← historical      │  │
  │  │                                                             │  │
  │  │  ✓ Direct lookup:                                           │  │
  │  │    init_servtd_info_hash == tdinfo_hash? → init_migtd_svn   │  │
  │  │    cur_servtd_info_hash  == tdinfo_hash? → cur_migtd_svn    │  │
  │  └─────────────────────────────────────────────────────────────┘  │
  │                          │                                        │
  │                          ▼                                        │
  │  Step 2: Trust baseline endorsement                               │
  │  ┌─────────────────────────────────────────────────────────────┐  │
  │  │  min_migtd_svn = 2                                          │  │
  │  │                                                             │  │
  │  │  init_migtd_svn >= min_migtd_svn?  (e.g. 3 >= 2 ✓)         │  │
  │  │  cur_migtd_svn  >= min_migtd_svn?  (e.g. 3 >= 2 ✓)         │  │
  │  │                                                             │  │
  │  │  Both pass → attestation succeeds                           │  │
  │  │  Either fails → attestation denied                          │  │
  │  └─────────────────────────────────────────────────────────────┘  │
  └───────────────────────────────────────────────────────────────────┘

   Key improvement: svnMappings now uses tdinfo_hash (= SHA384(full TDINFO))
   as the lookup key. The attestation service matches init/cur_servtd_info_hash
   directly against svnMappings — no out-of-band endorsements needed.
```

This design enables self-contained reverse lookup: the attestation service can derive MigTD identity and trustworthiness entirely from the `tdinfo_hash` → SVN mapping and the trust baseline, without requiring additional out-of-band endorsements.

Operationally, `svnMappings` is cumulative. A source MigTD policy must retain
the hash that initialized a tenant TD and the hash of the currently
authenticated source MigTD. Release generation therefore starts from the
previous authority-maintained mapping, adds or replaces the current release by
hash, and removes an older hash only through an explicit reviewed revocation.
Mappings are sorted before signing, and duplicate hashes with conflicting SVN
values are invalid.
