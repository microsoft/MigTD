TCB Mapping Design for One-Hash Endorsement
===================================================
# Current TCB Mapping inside Policy V2


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

Policy v2 bundles `{policy, collaterals, servtdCollateral (signed TCB mapping + signed identity)}` into one signed blob that is measured into RTMR2. This creates a **circular dependency**: binding RTMR2 into `svnMappings` requires RTMR2 to be known before the TCB mapping is generated, yet RTMR2 is computed over policy content that already contains that TCB mapping.

To avoid the cycle, today's `svnMappings` exclude RTMR2 and key only on `[MRTD, RTMR0, RTMR1]`. The signed TCB mapping therefore binds the MigTD code measurement and policy-signer anchor but **not** the policy content measured into RTMR2. This results in two problems described below.


# Problem 1: source MigTD cannot map the init hash to an SVN locally

The source MigTD cannot map `init_servtd_info_hash` (= `SHA384(TDINFO)`) to an SVN directly, so it must accept the full init TDINFO from the untrusted VMM on every request and re-derive the registers after verifying the init TDINFO.

**Init MigTD (rebinding/migration) TCB evaluation - current svnMappings require init TDINFO from VMM:**

```
   VMM / Host OS                          Current MigTD (source)
  ┌─────────────────────┐               ┌──────────────────────────────────┐
  │                     │               │                                  │
  │  TDX Module provides│               │  Needs to determine TCB level    │
  │  init_servtd_info_  │               │  of init MigTD bound to target   │
  │  hash to MigTD      │               │                                  │
  │  (from servtd_ext)  │               │  svnMappings only has:           │
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

# Problem 2: attestation service cannot match the info hash to svnMappings

The tenant TD attestation service holds only `init/cur_servtd_info_hash` (hashes over *all* registers) and cannot match them against the subset-keyed `svnMappings`, forcing reliance on separate hash-based endorsements.


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

*Note:* `SERVTD_EXT_STRUCT` is constructed by the TDX module at runtime using the tenant's TDCS and is not directly included in the TD report. Its hash, `SHA384(SERVTD_EXT_STRUCT)`, is included as `tdinfo.Servtd_hash`. The structure is read by the host OS and supplied to the Quoting service (QTD/QE), which verifies it against the hash and includes it in the TD Quote. MigTD can also read it from the bound target tenant TD's TDCS and use the hash to verify the tdinfo from VMM.

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

# Proposal


Break policy content into independent measured components so RTMR2 no longer depends on TCB mapping content:

**Measurement register layout** (RTMR extends):

| Register | Before | Proposed |
|----------|--------|----------|
| **RTMR1** | Policy issuer cert chain | Stable signer anchor derived from the root certificate and leaf signer-purpose EKU |
| **RTMR2** | Signed policy blob (contains policy rules + collaterals + signed TCB mapping + signed identity) | **Single canonical-bytes extend** of `policyData` with the signed TCB mapping, optional signed identity, and their issuer chains redacted. Every other field, including `policySvn`, remains measured. See "RTMR2 single redacted extend" below. |

**IGVM CFV file layout** (configuration firmware volume slots loaded at boot):

| CFV slot | Before | Proposed | Measured into |
|----------|--------|----------|---------------|
| `MIGTD_POLICY_ISSUER_CHAIN_FFS_GUID` | Policy issuer cert chain | Policy issuer chain or precomputed signer anchor | Derived signer anchor in **RTMR1** |
| `MIGTD_POLICY_FFS_GUID` | Signed policy with collaterals | Policy with collaterals (no outer signature), updated `svnMappings` semantics | **RTMR2** |

With this split:
- RTMR2 = measurement of canonical `policyData` with the independently signed TCB mapping and optional TD Identity, plus their issuer chains, redacted. This preserves circularity-freedom and lets those artifacts be re-issued without changing `tdinfo_hash`.
- TCB mapping can bind `tdinfo_hash` (= `init_servtd_info_hash` = `SHA384(TDINFO)` for attr=0) to SVN without circularity. (See "Schema note" at the end.)
- RTMR1 = stable signer anchor derived from the enrolled chain or supplied directly; the mapping and optional Identity issuer chains must resolve to that anchor.
- The outer policy-blob signature is removed.

**New design — full tdinfo hash in svnMappings but unmeasured, removing circular dependency:**

```
┌────────────────────────────────────────────────────────────────────────┐
│                    Policy Blob (no outer signature)                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ policyData                                                       │  │
│  │  ├── policy, version, id, policySvn, collaterals, ...  [measured]│  │
│  │  └── servtdCollateral                                            │  │
│  │       ├── servtdIdentity {tdIdentity, signature}   [NOT measured]│  │
│  │       ├── servtdIdentityIssuerChain                [NOT measured]│  │
│  │       ├── servtdTcbMappingIssuerChain              [NOT measured]│  │
│  │       └── servtdTcbMapping                         [NOT measured]│  │
│  │            └── svnMappings[]: {tdinfo_hash, isvsvn}              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘

   RTMR2 = SHA384(canonical( policyData minus {mapping, Identity, issuer chains} ))
                          │
                          ▼
   tdinfo_hash = SHA384(TDINFO)   over MRTD, RTMR0, RTMR1, RTMR2
                          │
                          ▼
   svnMappings[].tdinfo_hash  ← populated AFTER measurement (no circularity)
```


# Benefits

- **Breaks the circular dependency** — `tdinfo_hash` is computable from build inputs before the TCB mapping is signed.
- **Problem 1 solved with simpler rebind/migration** — MigTD maps `servtd_ext.init_servtd_info_hash` to an SVN locally; the VMM no longer supplies init TDINFO per request.
- **Problem 2 solved with TCB Mapping reused for attestation** — the service matches `init/cur_servtd_info_hash` directly against `svnMappings`, needing no out-of-band endorsements.

# Design details

## Implementation note

To minimize code branching, the proposed design **replaces** the current implementation outright — it is **not** feature-gated. No runtime or build-time toggle is kept between the old subset-keyed (`[MRTD, RTMR0, RTMR1]`) scheme and the new full-`tdinfo_hash` scheme; the new behavior is the only path.

## RTMR2 single redacted extend

RTMR2 is extended **once** with the canonical bytes of `policyData` after
redacting `servtdTcbMapping`, `servtdTcbMappingIssuerChain`, and the optional
`servtdIdentity` and `servtdIdentityIssuerChain`. Every other field —
including `version`, `id`, `policySvn`, policy rules, platform collaterals,
and `servtdCollateral` version fields — remains bound into RTMR2. The signed
artifacts can therefore be re-issued without perturbing `tdinfo_hash`; their
issuer chains must resolve to the signer anchor measured into RTMR1.

### No-clock anti-rollback for redacted collateral

Signature verification alone does not establish freshness: an older mapping or
TD Identity under the same signer anchor remains correctly signed. MigTD has no
trusted wall clock, so `issueDate` and `nextUpdate` are not security inputs.

The signed `version` in the JSON TCB mapping and TD Identity is therefore a
monotonic issuance generation. A CoRIM mapping uses the CoMID `tag-version`.
Each local artifact generation must be at least the measured `policySvn`.
During migration and rebinding, each peer JSON generation must also meet the
corresponding local JSON baseline. JSON and CoRIM generations are separate
namespaces and are never compared with each other.

`policySvn` is an anti-rollback floor, not a build or release number. A new
MigTD or collateral build does not inherently require a new `policySvn`.

### Operational release and rollback runbook

| Operation | Collateral action | `policySvn` / image action |
|-----------|-------------------|----------------------------|
| Routine release while older releases remain supported | Keep historical hashes in a cumulative mapping, add the new `tdinfo_hash` / `isvsvn`, advance the mapping generation, and sign and distribute the matching artifacts consistently. Advance the identity generation when re-issuing it; advance CoRIM `tag-version` only in its own namespace. | Retain the existing floor unless establishing a new security minimum. |
| Invalidate an old mapping or identity artifact | Reissue every required JSON and/or CoRIM artifact at or above a new floor. | Raise measured `policySvn` above every withdrawn generation, rebuild or repackage supported images with the new measured floor and `MROWNERCONFIG`, and retire old-floor images. |
| Revoke an old MigTD hash or release | Issue a replacement cumulative mapping that omits the hash but retains other supported historical hashes. | Raise the floor above the withdrawn mapping generation so it cannot be replayed, then retire the old image. |

Removing a historical hash has a sharp operational edge: the same mapping is
used to resolve `init_servtd_info_hash`. A tenant originally bound to a removed
hash can no longer resolve that value, so it cannot migrate or rebind. Preserve
historical hashes whenever tenant recoverability is required. Where the policy
path supports them, retain the hash-to-SVN entry and use JSON Identity status
or SVN acceptance policy to express trust restrictions; CoRIM provides SVN but
not Identity status. Do not assume a restrictive status or SVN rule preserves
a recovery flow without validating that flow.

CRL handling is separate. The `servtdCrl` CRL number is the monotonic freshness
value for that CRL; signer-certificate revocation is the authenticated CRL
content check against a signer chain. Incrementing a CRL number does not itself
revoke a certificate, and collateral `version`, CoRIM `tag-version`, and
`policySvn` do not replace certificate revocation.

The redactions do not weaken integrity of the measured policy fields.
Canonicalizing the remaining `policyData` binds them by construction, while
signatures, RTMR1 signer-anchor checks, and the generation floors protect the
independently re-issued mapping and Identity.

**Alternatives considered**

| Scheme | Result | Why chosen / rejected |
|--------|--------|-----------------------|
| **Single canonical extend over `policyData` with signed mapping / Identity fields redacted** *(chosen)* | One RTMR2 extend, one tag, one event-log entry. | Breaks the circular dependency and permits signed mapping / Identity re-issuance; binds all non-redacted fields by construction. |
| **Per-field extends** | N RTMR2 extends, each with own tag and event-log entry. | Requires discipline to add a new extend for every new `policyData` field — easy to forget, silently leaving fields unmeasured. Rejected. |
| **Single extend over raw (non-canonical) bytes** | One extend, no canonicalization. | Brittle: any whitespace or key-order difference between policy generator, CFV, and offline hash tool produces a different digest. Rejected. |
| **Single canonical extend over full `policyData` (no redaction)** | One extend covering `servtdTcbMapping` too. | Re-introduces the circular dependency. Rejected. |

## Build flow

The release artifact is produced in two stages: a build stage that compiles the MigTD binary into a *base IGVM* with a dummy CFV, and a release stage that signs the issuer collateral (`servtdIdentity` and `servtdTcbMapping`) and enrolls the production bytes into the base IGVM's CFV via `td-shim-enroll` (a byte-level FFS slot replacement — no Rust rebuild).

1. **Build stage — base IGVM.** Compile MigTD and embed a dummy CFV whose non-redacted canonical `policyData` fields match the final policy. The production signer anchor is enrolled so RTMR1 already matches the final IGVM. Redacted mapping and Identity fields may contain build-time placeholders. This yields the base IGVM and a *preview* `tdinfo_hash`.

2. **Release stage — pre-final IGVM (CFV swap).** Sign `servtdIdentity` when used and assemble a *pre-final* `policyData` with an empty `servtdTcbMapping` sentinel. The redacted fields do not affect RTMR2. Run `td-shim-enroll` to overwrite the CFV slots and measure the re-enrolled binary to obtain the production `tdinfo_hash`.

3. **Release stage — TCB mapping.** Add the production `{tdinfo_hash, isvsvn}` to the cumulative `svnMappings`, advance its generation, then sign the TCB mapping.

4. **Release stage — final IGVM.** Assemble the final policy (now including the signed TCB mapping) and re-run `td-shim-enroll`. Verify its `tdinfo_hash` equals the pre-final value — a CI gate enforcing the "`tcbMapping` is not measured" invariant.

5. **Endorsements.** Compute endorsed `tdinfo_hash` (= `init_servtd_info_hash` = `SHA384(TDINFO)`) from the final image. This hash captures policy content (via the single RTMR2 extend).

## Init_servTD verification - how problem 1 solved

With `svnMappings` keyed on the full `tdinfo_hash`, the source MigTD maps `servtd_ext.init_servtd_info_hash` to an SVN entirely from its locally-measured TCB mapping — the VMM no longer supplies the init TDINFO struct per request.

**Init MigTD (rebinding/migration) TCB evaluation — proposed svnMappings need no TDINFO from VMM:**

```
   VMM / Host OS                            Proposed MigTD (source)
  ┌─────────────────────┐               ┌──────────────────────────────────┐
  │                     │               │                                  │
  │  TDX Module provides│               │  Needs to determine TCB level    │
  │  init_servtd_info_  │               │  of init MigTD bound to target   │
  │  hash to MigTD      │               │                                  │
  │  (from servtd_ext)  │               │  svnMappings now keyed on full   │
  │                     │   no per-     │  tdinfo_hash:                    │
  │                     │   request     │    {tdinfo_hash, isvsvn}         │
  │  (no init TDINFO    │   TDINFO      │                                  │
  │   struct needed)    │──────────────►│  Direct lookup:                  │
  │                     │               │   init_servtd_info_hash ==       │
  │                     │               │   svnMappings[].tdinfo_hash?  ✓  │
  │                     │               │          │                       │
  │                     │               │          ▼                       │
  │                     │               │  → isvsvn                        │
  │                     │               │  (no VMM input, no register      │
  │                     │               │   re-derivation)                 │
  └─────────────────────┘               └──────────────────────────────────┘

   Result: MigTD maps init_servtd_info_hash → SVN from its locally-measured
   TCB mapping. The VMM supplies nothing per request, removing the
   untrusted-input surface and VMM implementation complexity.
```


## Attestation verification - how problem 2 solved

The attestation service receives the Tenant TD Quote, which includes for each bound MigTD:

* `init_migtd_hash` ← `servtd_ext.init_servtd_info_hash` — the hash of the MigTD originally bound to the tenant TD.
* `cur_migtd_hash` ← `servtd_ext.cur_servtd_info_hash` — the hash of the currently bound MigTD.

Both values are authenticated by `tdinfo.Servtd_hash` (the `SHA384(SERVTD_EXT_STRUCT)` carried in the quote).

The service consults two signed endorsement artifacts:

1. **Authorization endorsement** (`servtd_info_hash → SVN`) — translates `init_migtd_hash` and `cur_migtd_hash` into `init_migtd_svn` and `cur_migtd_svn`. Cumulative across releases — must include historical entries so past `init_migtd_hash` values still resolve.

2. **Trust / baseline endorsement** — declares the minimum acceptable MigTD SVN. The service evaluates **both** initial and current bound MigTDs against this baseline (`init_migtd_svn >= min_migtd_svn` and `cur_migtd_svn >= min_migtd_svn`). A failure on either fails the attestation — catching both "originally bound to a now-revoked MigTD" and "currently bound to an out-of-date MigTD" cases.

**Proposed tenant TD attestation — self-contained reverse lookup:**

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

# Additional considerations

These consequences and optional simplifications follow from the design above.

## Dropping `servtdIdentity` (pure-SVN policy)

If migration policy is expressed purely as SVN comparisons, `servtdIdentity` can be dropped: the peer's SVN is derived solely from the TCB mapping (`tdinfo_hash → SVN`), independent of `servtdIdentity`. Trade-off: loses the `tcbStatus` / `tcbDate` axes and non-monotonic per-SVN revocation (mark SVN N `Revoked` while keeping N−1), and requires SVN monotonicity ("higher SVN ≥ as trustworthy"). Removing a build's hash revokes lookup as well as authorization, with the tenant-recovery impact described above.

## RTMR1 signer anchor and key rotation

RTMR1 measures a stable signer anchor derived from the root certificate and the
leaf signer-purpose EKU. Leaf or intermediate rotation under the same anchor
does not change `tdinfo_hash`; changing the root or signer-purpose EKU does.

# Schema note — flat `tdinfo_hash` vs measurement registers (MRs)

Throughout this document `svnMappings[]` entries are written in the flattened form `{tdinfo_hash, isvsvn}` for readability. In the actual CoRIM/`policyData` schema the measurement is nested under `tdMeasurements` (e.g. `svnMappings[].tdMeasurements.tdinfo_hash`, see `src/policy/src/v2/servtd_collateral.rs`), and `tdMeasurements` is the place that can also carry the individual measurement registers / MRs (`MRTD`, `RTMR0`–`RTMR3`). This proposal keys the mapping on the single composite `tdinfo_hash` (= `SHA384(TDINFO)`, which already folds in all MRs) rather than the per-register subset used today; the implementation should populate `tdMeasurements.tdinfo_hash` accordingly.

# MRTD / RTMR measurements -current implementation

| Register | Measured content (Policy v2)                                              | Measured by        | Stage     |
| -------- | ------------------------------------------------------------------------ | ------------------ | --------- |
| `MRTD`   | Initial TD image: **td-shim BFV** + **MigTD core Payload** page contents, plus the GPAs of all added private pages. (CFV content **excluded**.) | TDX module (static) | TD build  |
| `RTMR0`  | One `EV_SEPARATOR` event (`u32` `0x0000_0000`). Nothing else.             | td-shim firmware   | Boot      |
| `RTMR1`  | `EV_SEPARATOR`, then the stable servTD signer anchor.                     | td-shim, then MigTD | Boot      |
| `RTMR2`  | Canonical `policyData` with signed mapping / Identity fields and their issuer chains redacted. | MigTD core | Boot |
| `RTMR3`  | *Nothing* — stays all-zero.                                              | —                  | —         |

See [policy_v2_measurements.md](./policy_v2_measurements.md) for details.