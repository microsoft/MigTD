---
type: Reference
title: Init_TDINFO and ServtdExt Usage Summary
description: Definitions of TDINFO_STRUCT/ServtdExt and how they are used and cross-checked across the migration and rebinding paths.
tags: [attestation, tdinfo, servtd, migration, rebinding]
timestamp: 2026-07-26T00:14:16+00:00
---

# Init_TDINFO and ServtdExt Usage Summary

> Reflects the `one_hash` code. MigTD resolves the current SVN through the
> authenticated source mapping and resolves the initial SVN through the source
> mapping with an authenticated local fallback. The legacy Init_TDINFO wire
> field is accepted for framing but ignored.

## Definitions

### TDINFO_STRUCT (512 bytes) — `TdInfo`

The hardware-defined identity of a TD. Fields:

| Field | Size | Description |
|---|---|---|
| `attributes` | 8 B | TD attributes (debug, sept-ve-disable, etc.) |
| `xfam` | 8 B | Extended feature attribute mask |
| `mrtd` | 48 B | Measurement of the TD's initial memory contents |
| `mrconfig_id` | 48 B | Software-defined non-owner config ID |
| `mrowner` | 48 B | GHCI owner ID (provisioned as policy signing-key hash); retained for init/current continuity, but no longer the cross-peer signer trust anchor |
| `mrownerconfig` | 48 B | Owner-defined config (in MigTD: first 4 bytes = policy SVN as LE u32, rest zero) |
| `rtmr0..rtmr3` | 4×48 B | Runtime-extendable measurement registers |
| `servtd_hash` | 48 B | Hash of bound service TDs' TDINFO_STRUCTs |
| `reserved` | 64 B | Must be zero |

**Init_TDINFO** is the TDINFO_STRUCT of the *original MigTD* that was first
bound to the target TD at launch time. The legacy host field is accepted for
wire framing but cleared by `MigtdMigrationInformation::read_from_bytes`.
The completed one-hash design does not require the VMM to provide this
512-byte structure.

### SERVTD_EXT_STRUCT (272 bytes) — `ServtdExt`

Metadata stored in the target TD's TDCS, read by the *current* MigTD via `TDG.SERVTD.RD` (`read_servtd_ext()`, which always returns a populated `ServtdExt`). Fields:

| Field | Size | Description |
|---|---|---|
| `init_servtd_info_hash` | 48 B | SHA-384 identifying the *initial* bound MigTD: `SHA384(masked_init_TDINFO)`, set at first binding |
| `init_attr` | 8 B | SERVTD_ATTR at initial binding. Bits 15:0 = SERVTD_TYPE (0=MigTD). Higher bits = IGNORE flags controlling which TDINFO fields are zeroed before hashing |
| `init_cpusvn` | 16 B | Platform CPU SVN at initial binding |
| `init_tee_tcb_svn` | 16 B | TEE TCB SVN at initial binding |
| `init_tee_model` | 12 B | TEE model info at initial binding |
| `cur_servtd_info_hash` | 48 B | Hash identifying the *currently* bound MigTD |
| `cur_servtd_attr` | 8 B | SERVTD_ATTR of the currently bound MigTD |
| reserved fields | 116 B | Padding |

## One-hash init/current SVN ordering

The enforced verification is:

1. Verify the source quote/TDREPORT and measured policy.
2. Compute the authenticated source's current `tdinfo_hash` and resolve it
   through that source policy's verified JSON mapping or CoRIM.
3. Read `ServtdExt.init_servtd_info_hash` and resolve it through the verified
   source mapping, falling back to the authenticated destination mapping.
4. Reject conflicting source/local assignments for the initial hash.
5. Require `init_lookup.isvsvn <= current_lookup.isvsvn`.

A current-source miss or an initial hash missing from both mappings fails
closed. This supports returning to the originating release or moving to a
later cumulative release without requiring arbitrary historical multi-hop
compatibility. No VMM-provided full Init_TDINFO or MROWNER continuity check is
needed for SVN ordering.

---

## Usage in each path (SPDM)

### Migration (source → destination)

**Source side** (`spdm_req`): reads `ServtdExt` via `read_servtd_ext()` and
sends it with the legacy Init_TDINFO VDM element.

**Destination side** (`spdm_rsp` → `mig_policy::authenticate_migration_source_with_init_tdinfo`):
1. Receives ServtdExt and Init_TDINFO; stores ServtdExt in responder context.
2. `authenticate_remote_common`: verifies the source's quote, measured
   policy/event log, and signer anchor; it resolves the **current source
   TDINFO hash** through the source's verified JSON mapping or CoRIM to build
   `evaluation_data_src`.
3. Resolves `ServtdExt.init_servtd_info_hash` through the authenticated source
   mapping, then the authenticated local mapping as fallback. Conflicts and a
   miss from both mappings fail closed; require `init SVN <= current SVN`.
4. **Policy evaluation** — `evaluate_policy_common` + `evaluate_policy_backward` against `relative_reference = get_local_tcb_evaluation_info()` (the **local** MigTD's TCB, not Init_TDINFO).
5. **SERVTD_ATTR check** (at MSK exchange, `session.rs::exchange_msk`): both sides call `verify_servtd_attr()` on their own bound target, checking `cur_servtd_attr == EXPECTED_SERVTD_ATTR` (hardcoded `0x0`). The historical `cur == init_attr` comparison was **removed** (it could falsely reject after a legitimate rebind).
6. **Approved hash write**: destination computes `SHA384(ServtdExt with cur_servtd_info_hash + cur_servtd_attr zeroed)` and writes it to `APPROVED_SERVTD_EXT_HASH` (`write_approved_servtd_ext_hash`).

### Rebinding (old MigTD → new MigTD)

**Old MigTD side** (SPDM requester): same as migration source.

**New MigTD side** (SPDM responder, `spdm_rsp` → `mig_policy::authenticate_rebinding_old`):
1. `authenticate_rebinding_common`: verifies the old MigTD's **TDREPORT**,
   measured policy/event log, and signer anchor; it resolves the old MigTD's
   **current TDINFO hash** through that verified policy's JSON mapping or
   CoRIM to build `evaluation_data_src`.
2. Resolves `ServtdExt.init_servtd_info_hash` through the old MigTD's
   authenticated mapping, then the authenticated local mapping as fallback.
   Conflicts and a miss from both mappings fail closed; require
   `init SVN <= current SVN`.
3. **Local lookup is a fallback, not an allowlist.** A source hit remains
   sufficient, so an older destination need not predict future releases.
4. **Policy evaluation** — `evaluate_policy_backward` against `relative_reference = get_local_tcb_evaluation_info()` (local TCB, not Init_TDINFO).
5. **Approved hash write** + **rebind attr write** (`write_servtd_rebind_attr`, rebinding-specific).

---

## Migration vs rebinding

| Aspect | Migration (destination) | Rebinding (new MigTD) |
|---|---|---|
| Peer attestation | Quote + supplemental data | TDREPORT |
| Init/current SVN ordering | Source current + source/local initial; enforced | Source current + source/local initial; enforced |
| Legacy Init_TDINFO | Ignored | Ignored |
| Init image lookup in destination's local mapping | Fallback only | Fallback only |
| Policy-eval relative reference | local TCB (`get_local_tcb_evaluation_info`) | local TCB (`get_local_tcb_evaluation_info`) |
| Policy rules evaluated | common + backward | backward |
| `write_approved_servtd_ext_hash` | ✅ | ✅ |
| `write_servtd_rebind_attr` | ❌ | ✅ |

The one-hash flow does not use Init_TDINFO for continuity, integrity, or as
the policy-evaluation relative reference. Policy still evaluates the peer
against the local MigTD's TCB.

---

## Init_TDINFO continuity vs current-image TCB lookup

The two inputs serve different purposes:

| Check | What it verifies | Input |
|---|---|---|
| init/current continuity | The initially bound release is no newer than the authenticated current source release | Current report hash through the source mapping; `init_servtd_info_hash` through source then authenticated-local fallback |
| current-image TCB lookup | The authenticated current peer image resolves to SVN (and optional date/status) | Complete current `tdinfo_hash` via JSON mapping or CoRIM |
| cross-peer signer trust | Source and destination belong to the same signer authority while allowing leaf/intermediate rotation | RTMR1 signer anchor: root fingerprint + enrolled signer-purpose EKU |

Do not treat the destination mapping as authority for the current source hash
or restore dependence on the legacy Init_TDINFO wire contents.
