# PR 1038 and `ms/integration` Reconciliation

This document records the semantic rebase of `ms/integration` onto the
upstreaming stack for Intel/MigTD PR 1038.

## Result

- Intel base: `c9f39cc2253fdadd6bfb7041f94470d4157b5855`
- PR 1038 original head: `d71ef4b40c6eb856752b4b348615d98ffaec5cf3`
- PR 1038 rebased head before integration replay: `8f7cbc4b`
- Microsoft source head: `d3aae2bd8a943179120c63253c927c9ba2320fa8`
- Reconciled branch: `integration-pr1038-rebase`
- Integration accounting: 40 replayed or adapted, 24 superseded by PR 1038,
  and 1 omitted accidental validation-helper commit.

The 20 PR 1038 commits were kept intact and rebased onto current `intel/main`
before any Microsoft commit was considered. The 65 Microsoft commits were then
reviewed in chronological order. A commit was skipped only after comparing its
behavior with the final PR stack; partially overlapping commits were
re-expressed on the PR structure instead of restoring the older implementation.

## Authoritative design choices

### One-hash policy and signer identity

PR 1038 is authoritative for the one-hash endorsement format, CoRIM parsing,
dedicated-EKU signer anchors, RTMR1 enrollment, signer revocation, optional JSON
identity, and peer-data framing. Integration changes that implemented older
versions of those features were not replayed.

The resulting signer identity is the RTMR1 root-certificate plus dedicated-EKU
anchor. Legacy signer-key-hash and `MROwner`/`MROwnerConfig` interpretations were
not restored.

### Initial and current release continuity

The current MigTD SVN is resolved only from authenticated source evidence. The
initial hash is resolved from the authenticated source mapping and the
authenticated local mapping:

1. Matching source and local assignments are accepted.
2. A source assignment is accepted when the local mapping misses.
3. A local assignment is used only when the source mapping misses.
4. Conflicting assignments fail with `SvnMismatch`.
5. A miss from both mappings fails with `UnqualifiedMigTdInfo`.
6. The resolved initial SVN must not exceed the source-derived current SVN.

The legacy wire Init_TDINFO remains framing compatibility data and is ignored.
Both `ServtdExt` attributes must remain zero for the one-hash profile.

### Cumulative mappings

`migtd-hash` keeps mappings append-only:

- Existing hash-to-SVN assignments are immutable.
- A new release SVN cannot be lower than the historical maximum.
- Duplicate identical assignments are canonicalized.
- Conflicting assignments are rejected.
- Release revocation uses the authenticated servTD signer CRL; individual
  historical hashes are not deleted.

### Emulator-only rebind exception

AzCVMEmu cannot encode the live SPDM TH1 value in its mock TDREPORT. The
rebind REPORTDATA binding check is therefore bypassed only for `AzCVMEmu` or
`test_mock_report`. Production builds and real-hardware `use-mock-quote` builds
continue to call `verify_tdreport_data_binding`.

### Integration-only compatibility and diagnostics

The branch retains the explicitly marked legacy GetTDReport compatibility,
temporary migration tracing, and compile-time migration fault modes because
they are integration behavior. The fault modes short-circuit only
`StartMigration` handling and are blocked from release-profile builds.

The obsolete startup comparison between local TDINFO
`MROwner`/`MROwnerConfig` and policy signer/SVN was not restored.

### Azure policy

PR 1038's explicit Azure production FMSPC, servTD CRL floor, and MigTD SVN
floor were retained. The later integration change that replaced those values
with relative `self` references was skipped.

## Commit-by-commit disposition

`replayed` includes clean cherry-picks and semantic adaptations. Result SHAs
identify the corresponding commit on `integration-pr1038-rebase`.

| # | Source | Disposition | Result | Reconciliation |
|---:|---|---|---|---|
| 1 | `6342be84` | replayed | `7ca9c0d3` | Unique structured-log truncation. |
| 2 | `839020a5` | replayed | `8fac8e25` | Unique reproducible and portable build behavior. |
| 3 | `d3f5d321` | superseded | - | PR 1038 owns the complete one-hash implementation. |
| 4 | `4610f13a` | replayed | `c28760f0` | Added integration design documents; later documentation commits aligned them. |
| 5 | `cfc5b900` | superseded | - | PR 1038 has the newer CoRIM and revocation design. |
| 6 | `c76cb506` | superseded | - | PR 1038 dedicated-EKU anchor design is authoritative. |
| 7 | `a9e88524` | superseded | - | PR 1038 has direct-anchor CoRIM enrollment. |
| 8 | `8b5355a4` | superseded | - | PR 1038 has the newer authenticated continuity flow. |
| 9 | `f7de5b17` | replayed | `9b18dae8` | Unique Azure vmcall transport limits. |
| 10 | `62ba174b` | adapted | `2923e28d` | Kept PR policy scripts and peer semantics; retained unique Azure workflows, packaging, reproducibility, and quote diagnostics. |
| 11 | `e4499476` | replayed | `efb4a143` | Added TiP package, later removed by source commit 31. |
| 12 | `ddfe158c` | replayed | `2d46b143` | Added troubleshooting material, later removed by source commit 31. |
| 13 | `ff1a4896` | replayed | `514880a5` | Build, coverage, and functionality documentation. |
| 14 | `361856f1` | replayed | `51be1cd0` | Reusable agent guidance. |
| 15 | `50e43113` | replayed | `544f5f46` | Initial one-hash guidance, subsequently aligned. |
| 16 | `69aa5035` | superseded | - | PR 1038 already enforces mapped initial/current ordering. |
| 17 | `dded7cef` | superseded | - | Obsolete redesign references were already absent. |
| 18 | `be369acd` | adapted | `8dd4a502` | Retained tracing on PR peer framing; did not restore the obsolete startup bypass. |
| 19 | `086e9c43` | replayed | `f5069cf9` | Test confirms legacy rebinding Init_TDINFO is ignored. |
| 20 | `1020c604` | replayed | `a617d1a8` | Consolidated guidance into `AGENTS.md`. |
| 21 | `c6130fe6` | replayed | `42edfd7b` | Reproducible Azure build hardening. |
| 22 | `bc06ae7e` | superseded | - | PR 1038 already preserves cumulative mappings; commit 55 adds the remaining stricter rules. |
| 23 | `ef6644ab` | superseded | - | PR 1038 already applies authoritative servTD CRLs to CoRIM signers. |
| 24 | `34b70196` | superseded | - | PR 1038 already supports CoRIM-only releases and direct anchors. |
| 25 | `7805b25a` | superseded | - | The obsolete helper is already absent. |
| 26 | `73215b7d` | replayed | `9122679f` | Dependency preparation documentation. |
| 27 | `372fb459` | superseded | - | PR 1038 measures optional JSON servTD identity in RTMR2. |
| 28 | `cb27740b` | replayed | `18aadbc4` | JWT/SGX source pruning. |
| 29 | `5409757b` | superseded | - | PR 1038 already uses producer-neutral terminology and newer validation tests. |
| 30 | `eb52eed1` | superseded | - | PR 1038 rejects CoRIM time claims. |
| 31 | `0c3743fd` | adapted | `d56d3a41` | Removed downstream TiP assets while preserving PR-owned Azure policy tooling. |
| 32 | `d2b5c293` | replayed | `2bee809c` | Correct rebinding status reporting. |
| 33 | `74518e03` | superseded | - | PR 1038 uses authenticated peer CoRIM evidence. |
| 34 | `e5e7914a` | replayed | `00ceda08` | CoRIM CLI helper integration. |
| 35 | `39ca0a5f` | adapted | `9e72e10e` | Reworked asymmetric peer-CoRIM fixture and workflow for PR direct-anchor tooling. |
| 36 | `af884097` | superseded | - | PR 1038 preserves signer EKU during rotation. |
| 37 | `6415607f` | superseded | - | PR 1038 tooling already retains the required mock/runtime hashes. |
| 38 | `af2e80b1` | replayed | `352b2ac7` | Quote tracing after measurements. |
| 39 | `c894f030` | superseded | - | PR 1038 supports SVN-only CoRIM policy evaluation. |
| 40 | `fd1edd5d` | replayed | `97cfd7cf` | Local library and CoRIM workflow coverage. |
| 41 | `4e857370` | superseded | - | PR 1038 scopes missing status acceptance. |
| 42 | `5cf02af2` | superseded | - | PR 1038 includes the status-floor behavior and tests. |
| 43 | `ae709a03` | superseded | - | Obsolete local TDINFO check is already absent. |
| 44 | `35deacd1` | replayed | `945e457f` | SGX 2.30 prune layout. |
| 45 | `8ade28de` | adapted | `4bcdca1f` | Pointed the stability comment at the retained PR-compatible check. |
| 46 | `692674da` | replayed | `68f75bde` | SGX 2.30 source exports. |
| 47 | `aa291254` | adapted | `57875005` | Updated integration-owned design docs; retained PR policy docs, scripts, and code comments. |
| 48 | `9cc6401c` | superseded | - | PR 1038 already requires CA-authorized signer chains. |
| 49 | `33d26413` | replayed | `1876671d` | Azure request error documentation. |
| 50 | `605b0572` | replayed | `ac95eb24` | Removed GetTDReport report-data input. |
| 51 | `40d83813` | replayed | `aca45e2f` | SPDM source-export guidance. |
| 52 | `3c21a832` | replayed | `884baac1` | Wipe app context on exchange cancellation. |
| 53 | `dd5d6f90` | replayed | `62a4c780` | Complete cancellation-time session cleanup. |
| 54 | `2ce50deb` | replayed | `717c3c11` | Retained explicitly marked legacy GetTDReport compatibility. |
| 55 | `c017a31c` | adapted | `96a5c9d9` | Added immutable assignments and non-decreasing SVN enforcement to PR tooling. |
| 56 | `84dd7d3a` | superseded | - | PR 1038 rejects conflicting CoRIM hash-to-SVN assignments. |
| 57 | `aa62803c` | adapted | `424b02d4` | Added authenticated local fallback for the initial hash without weakening source-derived current SVN. |
| 58 | `dfb10d88` | superseded | - | Would replace PR explicit Azure values with relative `self` references. |
| 59 | `b80f9b58` | replayed | `e252a11b` | Azure architecture and kernel-free boot documentation. |
| 60 | `54490e81` | replayed | `5ceeb44b` | Runtime sequences and SVG architecture diagrams. |
| 61 | `3c7d47c5` | omitted | - | Session-local milestone helper repair; not source product behavior. |
| 62 | `4b4cdb5f` | adapted | `efe7dd9f` | Bypass limited to `AzCVMEmu`/`test_mock_report`; production and `use-mock-quote` enforce TH1 binding. |
| 63 | `4c0f164d` | adapted | `11d954a9` | Compile-time test fault modes plus corrected bypass documentation. |
| 64 | `74e7ace3` | replayed | `92ab6c20` | Enroller checksum patch; preparation rerun after replay. |
| 65 | `d3aae2bd` | replayed | `0c2e6e26` | Updated vendored OpenSSL source. |

## Validation approach

Every firmware or boundary-code replay was followed by the port gate:

1. `cargo fmt --check`
2. MigTD library tests and feature matrix
3. skip-RA and SPDM skip-RA emulation smoke tests

Additional focused checks covered `migtd-hash`, policy-v2 continuity, asymmetric
CoRIM fixture generation, migration fault modes, and the enroller preparation
patch.

The final milestone matrix passed all 8 scenarios. The CI gauntlet passed:

- preparation, formatting, Clippy, and dependency policy;
- MigTD library build and feature-matrix tests;
- all 32 release/debug, transport, ABI, and TLS/SPDM image builds; and
- all EMU scenarios, including direct-anchor CoRIM migration/rebind,
  asymmetric peer mappings, key and mapping-chain rotation, quote retry, and
  the expected `SignerRevoked` failure.

Final validation exposed stale integration-era assumptions in the local
gauntlet and asymmetric fixture generator. They were reconciled to PR 1038 by:

- removing the deleted `--corim-only` builder option and obsolete helper path;
- using the current `--signer-anchor-file` interface and checked-in PR CoRIM
  fixtures;
- generating V2 root+Subject/SAN+EKU anchors, a three-certificate chain, and an
  intermediate-issued CRL for asymmetric fixtures;
- preserving the complete `policyData` envelope and CoRIM-backed SVN rule;
- keeping both peers' running-hash assignment identical while adding a
  source-only historical mapping; and
- using the checked-in revoked CoRIM signer CRL for the negative test while
  carrying the concrete initialization error into the crash report.

The linux-sgx pruning safety test also passed. The pinned-container
reproducibility workflow could not run because Docker is unavailable in the
local environment. Fuzz execution was checked but is environment-blocked by
passwordless `sudo` and missing `cargo-afl`/`cargo-fuzz`; those CI workflows
remain the required coverage for those checks.
