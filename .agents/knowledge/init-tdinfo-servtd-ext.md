---
type: Reference
title: Init_TDINFO and ServtdExt Usage Summary
description: Definitions of TDINFO_STRUCT/ServtdExt and how they are used and cross-checked across the migration and rebinding paths.
tags: [attestation, tdinfo, servtd, migration, rebinding]
timestamp: 2026-07-22T22:32:31+00:00
---

# Init_TDINFO and ServtdExt Usage Summary

> Reflects the `one_hash` code (SERVTD_EXT always opted-in; `verify_servtd_info_hash`
> direct-hash comparison). MigTD does **not** implement the SERVTD_EXT opt-out
> (TDCS.ATTRIBUTES bit 17) wire-protocol variant.

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

**Init_TDINFO** is the TDINFO_STRUCT of the *original MigTD* that was first bound to the target TD at launch time. The source-side MigTD obtains this from the VMM (`init_td_info_if_present()`) or falls back to its own self-report (`local_init_td_info()`).

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

---

## `verify_servtd_info_hash` — Init_TDINFO integrity check

`verify_init_tdinfo(init_tdinfo, servtd_ext)` is a thin wrapper over `verify_servtd_info_hash(init_tdinfo, servtd_ext.init_attr, servtd_ext.init_servtd_info_hash)`, which:

1. Parses Init_TDINFO bytes into a `TdInfo`.
2. Zeros the TDINFO fields flagged by the `init_attr` IGNORE bits (`SERVTD_ATTR_IGNORE_ATTRIBUTES`, `_XFAM`, `_MRTD`, `_MRCONFIGID`, `_MROWNER`, `_MROWNERCONFIG`, `_RTMR0..3`).
3. Computes `info_hash = SHA384(masked_tdinfo)`.
4. Compares `info_hash` **directly** to `init_servtd_info_hash`. **Hard fail** (`InvalidTdReport`) on mismatch.
5. Returns the parsed `TdInfo`.

> A single SHA-384 of the masked TDINFO, compared directly — there is **no**
> extra `SHA384(SHA384(tdinfo) || SERVTD_TYPE || attr)` wrapping.

---

## Usage in each path (SPDM)

### Migration (source → destination)

**Source side** (`spdm_req`): reads `ServtdExt` via `read_servtd_ext()`, obtains Init_TDINFO, sends both as VDM elements.

**Destination side** (`spdm_rsp` → `mig_policy::authenticate_migration_source_with_init_tdinfo`):
1. Receives ServtdExt and Init_TDINFO; stores ServtdExt in responder context.
2. `authenticate_remote_common`: verifies the source's quote, measured
   policy/event log, and signer anchor; it resolves the **current source
   TDINFO hash** through the source's verified JSON mapping or CoRIM to build
   `evaluation_data_src`.
3. **Policy evaluation** — `evaluate_policy_common` + `evaluate_policy_backward` against `relative_reference = get_local_tcb_evaluation_info()` (the **local** MigTD's TCB, not Init_TDINFO).
4. **Init-TDINFO verification — real hardware only** (gated `#[cfg(not(any(AzCVMEmu, test_mock_report, use-mock-quote)))]`; bypassed under EMU/mock where the emulated/mock TDINFO has no real measurements):
   - `verify_peer_init_tdinfo_against_suppl_data()` — cross-checks init `mrowner`/`mrownerconfig` against the **quote supplemental data** (init mrowner == quote mrowner; init policy SVN ≤ current policy SVN; `mrownerconfig[4..48]` all-zero).
   - `verify_init_tdinfo()` → `verify_servtd_info_hash()` — **integrity, enforced**.
5. **SERVTD_ATTR check** (at MSK exchange, `session.rs::exchange_msk`): both sides call `verify_servtd_attr()` on their own bound target, checking `cur_servtd_attr == EXPECTED_SERVTD_ATTR` (hardcoded `0x0`). The historical `cur == init_attr` comparison was **removed** (it could falsely reject after a legitimate rebind).
6. **Approved hash write**: destination computes `SHA384(ServtdExt with cur_servtd_info_hash + cur_servtd_attr zeroed)` and writes it to `APPROVED_SERVTD_EXT_HASH` (`write_approved_servtd_ext_hash`).

### Rebinding (old MigTD → new MigTD)

**Old MigTD side** (SPDM requester): same as migration source.

**New MigTD side** (SPDM responder, `spdm_rsp` → `mig_policy::authenticate_rebinding_old`):
1. `authenticate_rebinding_common`: verifies the old MigTD's **TDREPORT**,
   measured policy/event log, and signer anchor; it resolves the old MigTD's
   **current TDINFO hash** through that verified policy's JSON mapping or
   CoRIM to build `evaluation_data_src`.
2. **Init-TDINFO cross-check** (`verify_peer_init_tdinfo_against_owner`): uses `mrowner`/`mrownerconfig` from the old MigTD's **verified TDREPORT**. Same mrowner/SVN checks as migration. ⚠️ **TEST MODE** — logged, non-fatal.
3. **Init-TDINFO integrity** (`verify_init_tdinfo` → `verify_servtd_info_hash`): **enforced in all build modes** (not gated by AzCVMEmu, unlike migration).
4. **No local init-image allowlist.** Requiring the new MigTD's mapping to
   contain the old init image would force an older release to predict future
   rotations and would break bidirectional rebind.
5. **Policy evaluation** — `evaluate_policy_backward` against `relative_reference = get_local_tcb_evaluation_info()` (local TCB, not Init_TDINFO).
6. **Approved hash write** + **rebind attr write** (`write_servtd_rebind_attr`, rebinding-specific).

---

## Migration vs rebinding

| Aspect | Migration (destination) | Rebinding (new MigTD) |
|---|---|---|
| Peer attestation | Quote + supplemental data | TDREPORT |
| Init-TDINFO cross-check (mrowner + SVN) | vs quote suppl data; real-HW only | vs TDREPORT; TEST MODE (logged, non-fatal) |
| Init-TDINFO integrity vs `init_servtd_info_hash` | ✅ enforced; real-HW only (bypassed in EMU/mock) | ✅ enforced; all build modes |
| Init image lookup in destination's local mapping | ❌ deliberately absent | ❌ deliberately absent |
| Policy-eval relative reference | local TCB (`get_local_tcb_evaluation_info`) | local TCB (`get_local_tcb_evaluation_info`) |
| Policy rules evaluated | common + backward | backward |
| `write_approved_servtd_ext_hash` | ✅ | ✅ |
| `write_servtd_rebind_attr` | ❌ | ✅ |

Both paths use Init_TDINFO only for continuity/integrity against the
hardware-attested `init_servtd_info_hash`; they do **not** look it up in the
destination's local TCB mapping. The one-hash mapping/CoRIM lookup is performed
on the peer's authenticated **current** TDINFO when building its evaluation
data. **Neither uses Init_TDINFO as the policy-evaluation relative reference**
— both evaluate the peer against the local MigTD's TCB.

---

## Init_TDINFO continuity vs current-image TCB lookup

The two inputs serve different purposes:

| Check | What it verifies | Input |
|---|---|---|
| init/current continuity | Init TDINFO belonged to the same peer signer key at an SVN no newer than that peer's authenticated current report | Init and current-peer `mrowner`, `mrownerconfig` |
| Init_TDINFO integrity | The wire TDINFO hashes to `ServtdExt.init_servtd_info_hash` after SERVTD_ATTR masking | Complete Init_TDINFO + `ServtdExt` |
| current-image TCB lookup | The authenticated current peer image resolves to SVN (and optional date/status) | Complete current `tdinfo_hash` via JSON mapping or CoRIM |
| cross-peer signer trust | Source and destination belong to the same signer authority while allowing leaf/intermediate rotation | RTMR1 signer anchor: root fingerprint + enrolled signer-purpose EKU |

Do not add a destination-local lookup of Init_TDINFO. The signed one-hash
endorsement authenticates each peer's current release, while ServtdExt and the
peer report authenticate continuity back to the initially bound MigTD.
