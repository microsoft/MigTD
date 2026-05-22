# Init_TDINFO and ServtdExt Usage Summary

*Last updated after commit `bae6f54` (feat: verify init_TDINFO integrity and policy on migration destination) and subsequent patches.*

## Definitions

### TDINFO_STRUCT (512 bytes) — `TdInfo`

The hardware-defined identity of a TD. Fields:

| Field | Size | Description |
|---|---|---|
| `attributes` | 8 B | TD attributes (debug, sept-ve-disable, etc.) |
| `xfam` | 8 B | Extended feature attribute mask |
| `mrtd` | 48 B | Measurement of the TD's initial memory contents |
| `mrconfig_id` | 48 B | Software-defined non-owner config ID |
| `mrowner` | 48 B | Software-defined owner ID (in MigTD: hash of policy signing key) |
| `mrownerconfig` | 48 B | Owner-defined config (in MigTD: first 4 bytes = policy SVN as LE u32, rest zero) |
| `rtmr0..rtmr3` | 4×48 B | Runtime-extendable measurement registers |
| `servtd_hash` | 48 B | Hash of bound service TDs' TDINFO_STRUCTs |
| `reserved` | 64 B | Must be zero |

**Init_TDINFO** is the TDINFO_STRUCT of the *original MigTD* that was first bound to the target TD at launch time. The source-side MigTD obtains this from the VMM (or falls back to its own self-report if VMM doesn't provide it).

### SERVTD_EXT_STRUCT (272 bytes) — `ServtdExt`

Metadata stored in the target TD's TDCS, read by the *current* MigTD via `TDG.SERVTD.RD`. Fields:

| Field | Size | Description |
|---|---|---|
| `init_servtd_info_hash` | 48 B | SHA-384 hash identifying the *initial* bound MigTD (computed from init TDINFO + type + attr; set at first binding) |
| `init_attr` | 8 B | SERVTD_ATTR at initial binding time. Bits 15:0 = SERVTD_TYPE (0=MigTD). Bits 40:32 = IGNORE flags controlling which TDINFO fields are zeroed before hashing |
| `init_cpusvn` | 16 B | Platform CPU SVN at initial binding |
| `init_tee_tcb_svn` | 16 B | TEE TCB SVN at initial binding |
| `init_tee_model` | 12 B | TEE model info at initial binding |
| `cur_servtd_info_hash` | 48 B | Hash identifying the *currently* bound MigTD |
| `cur_servtd_attr` | 8 B | SERVTD_ATTR of the currently bound MigTD |
| reserved fields | 116 B | Padding |

---

## Usage in each path (SPDM only)

### Migration (source → destination)

**Source side** (`spdm_req`):
1. Reads `ServtdExt` from its bound target TD via `TDG.SERVTD.RD` (`read_servtd_ext()`).
2. Obtains Init_TDINFO from VMM or local fallback.
3. Sends both as VDM elements to the destination.

**Destination side** (`spdm_rsp` → `authenticate_migration_source_with_init_tdinfo`):
1. Receives ServtdExt and Init_TDINFO from wire.
2. Stores ServtdExt in responder context for later use.
3. **Standard policy checks** (POL-SRCv2-01..04): `authenticate_remote_common` (quote verification, event log, policy signature) → `evaluate_policy_common` + `evaluate_policy_backward` with local TCB as relative reference.
4. **Init_TDINFO cross-check** (POL-SRCv2-05): calls `verify_peer_init_tdinfo_against_suppl_data()` — extracts `mrowner` and `mrownerconfig` from the source's *verified quote supplemental data*, then checks:
   - Init_TDINFO's `mrowner` == source's quote `mrowner` (same policy signer)
   - Init_TDINFO's `mrownerconfig[0..4]` (init policy SVN) ≤ source's quote `mrownerconfig[0..4]` (current policy SVN)
   - Both `mrownerconfig[4..48]` must be all zeros
   - ⚠️ **REVERT_ME TEST MODE**: failures are logged but do not abort.
5. **Init_TDINFO integrity verification** (POL-SRCv2-06..07): calls `verify_init_tdinfo()` → `verify_servtd_hash()`:
   - If `init_servtd_info_hash` is **all-zero** (host never provisioned it): skips hash check, returns parsed `TdInfo`. The allowlist gate in step 6 still validates the measurements.
   - Otherwise: computes `SHA384(SHA384(masked_tdinfo) || SERVTD_TYPE || init_attr)` and compares to `init_servtd_info_hash`.
   - ⚠️ **REVERT_ME TEST MODE**: hash mismatch is logged but returns `Ok` (soft-fail).
   - **Enforced**: parse failure or all-zero bypass is hard-fail on malformed input.
6. **Allowlist gate** (POL-SRCv2-08): `get_engine_svn_by_measurements()` — init MigTD's `mrtd`, `rtmr0`, `rtmr1` must be in `servtd_tcb_mapping`. **Enforced** (hard-fail on `SvnMismatch`). Skipped under `use-mock-quote` feature (mock binary has different MRTD).
7. **Policy eval with init reference** (POL-SRCv2-09..10): `setup_evaluation_data_with_tdinfo()` → `evaluate_policy_common(eval_data_src, init_reference, skip_global=true)`. **Enforced** — policy failure aborts.
8. **SERVTD_ATTR check** (at MSK exchange, `exchange_msk` in `session.rs`): both source and destination call `verify_servtd_attr()` on their own bound target TD. Reads `CURR_SERVTD_ATTR` from TDCS via `TDG.SERVTD.RD` and checks:
   - `cur_servtd_attr == EXPECTED_SERVTD_ATTR` (hardcoded `0x0`) — ensures the VMM wrote the correct SERVTD_ATTR value (since SERVTD_ATTR is written by the untrusted VMM)
9. **Approved hash write**: after MSK exchange, destination computes `SHA384(ServtdExt with cur_servtd_info_hash and cur_servtd_attr zeroed)` and writes it to `APPROVED_SERVTD_EXT_HASH` in TDCS.

### Rebinding (old MigTD → new MigTD)

**Old MigTD side** (SPDM requester, `spdm_req`):
1. Reads `ServtdExt` from its bound target TD via `TDG.SERVTD.RD`.
2. Obtains Init_TDINFO from VMM or local fallback.
3. Sends both as VDM elements to the new MigTD.

**New MigTD side** (SPDM responder, `spdm_rsp`):
1. Receives ServtdExt and Init_TDINFO from wire.
2. Calls `authenticate_rebinding_old()` which does:
   - **Init_TDINFO cross-check against TDREPORT**: calls `verify_peer_init_tdinfo_against_owner()` — uses `mrowner` and `mrownerconfig` from the old MigTD's *verified TDREPORT* (not quote supplemental data). Same checks as migration: mrowner match + init SVN ≤ current SVN. ⚠️ **REVERT_ME TEST MODE**: logged, non-fatal.
   - **Init_TDINFO integrity verification against ServtdExt**: calls `verify_init_tdinfo()` → `verify_servtd_hash()`. Same logic as migration (all-zero bypass + TEST MODE soft-fail on mismatch). See migration step 5 above.
   - **Allowlist gate**: same `get_engine_svn_by_measurements()` check as migration step 6.
   - **Policy evaluation using Init_TDINFO as relative reference**: see [detailed breakdown below](#policy-evaluation-with-init_tdinfo-as-relative-reference).
3. Stores ServtdExt in responder context.
4. **Approved hash write**: same as migration — computes `SHA384(ServtdExt with cur fields zeroed)` and writes to `APPROVED_SERVTD_EXT_HASH`.
5. **Rebind attr write**: additionally writes `ServtdExt.cur_servtd_attr` via `write_servtd_rebind_attr()` — rebind-specific, not done in migration. For migration, MigTD only reads and verifies `cur_servtd_attr == 0x0` (hardcoded). For rebind, the new MigTD writes the expected value and the TDX module enforces that the actual SERVTD_ATTR matches what the MigTD wrote.

---

## Differences between migration and rebinding

| Check | Migration (destination) | Rebinding (new MigTD) |
|---|---|---|
| Init_TDINFO integrity vs `ServtdExt.init_servtd_info_hash` | ✅ `verify_init_tdinfo` (TEST MODE soft-fail) | ✅ `verify_init_tdinfo` (TEST MODE soft-fail) |
| Init_TDINFO cross-check (mrowner + SVN) | ✅ Against quote suppl data (TEST MODE) | ✅ Against TDREPORT (TEST MODE) |
| Init_TDINFO used as policy eval reference | ✅ `evaluate_policy_common` with `skip_global=true` | ✅ Same |
| Allowlist gate (`get_engine_svn_by_measurements`) | ✅ Enforced (skipped under `use-mock-quote`) | ✅ Same |
| `verify_servtd_attr` (cur==hardcoded) | ✅ Both sides, at MSK exchange | ✅ Old side at MSK exchange; new side reads full ServtdExt |
| `write_approved_servtd_ext_hash` | ✅ Destination writes | ✅ New MigTD writes |
| `write_servtd_rebind_attr` | ❌ Not needed (MigTD verifies `cur == 0x0`) | ✅ New MigTD writes `cur_servtd_attr`; TDX module enforces match |

After commit `bae6f54`, migration and rebinding are **nearly symmetric** for Init_TDINFO verification. The only structural difference is `write_servtd_rebind_attr` (rebinding-only) and the cross-check data source (quote suppl data vs TDREPORT).

### REVERT_ME / TEST MODE summary

Several checks are currently soft-fail to enable testing against hosts that haven't been fully updated:

| Check | Status | Notes |
|---|---|---|
| `verify_peer_init_tdinfo_against_suppl_data` / `_against_owner` | ⚠️ Soft-fail | MROWNER/MROWNERCONFIG may not be provisioned yet |
| `verify_servtd_hash` (hash mismatch) | ⚠️ Soft-fail | Returns `Ok` on mismatch with diagnostic dump |
| `verify_servtd_hash` (all-zero init hash) | Bypass | Skips check entirely, relies on allowlist gate |
| `verify_init_tdinfo` (parse + dispatch) | Enforced | Malformed input is a hard error |
| `get_engine_svn_by_measurements` | Enforced | Hard-fail on `SvnMismatch` (skipped under `use-mock-quote`) |
| `evaluate_policy_common` (init reference) | Enforced | Policy failure aborts migration |

---

## Policy evaluation with Init_TDINFO as relative reference

This section details how `evaluate_policy_common()` uses Init_TDINFO-derived values as the relative reference. This applies to both migration destination (`authenticate_migration_source_with_init_tdinfo`) and rebinding (`authenticate_rebinding_old`).

### Step 1: Build the peer MigTD's evaluation data (`evaluation_data_src`)

Built from the peer's verified quote/TDREPORT + event log via `authenticate_remote_common()` (migration) or `authenticate_rebinding_common()` (rebinding). Contains the peer's *current* TCB info: `migtd_isvsvn`, `migtd_tcb_date`, `migtd_tcb_status`, platform `tee_tcb_svn`, `fmspc`, etc. This is the **subject** being evaluated.

### Step 2: Build the relative reference from Init_TDINFO (`setup_evaluation_data_with_tdinfo`)

```
Init_TDINFO.mrtd + rtmr0 + rtmr1
    → servtd_tcb_mapping.get_engine_svn_by_measurements()
    → engine_svn (Option<u16>)
    → servtd_identity.get_tcb_level_by_svn(svn)
    → tcb_date, tcb_status (Option)
```

This produces a `PolicyEvaluationInfo` with only three fields populated (all `Option` — `None` if lookup fails):
- `migtd_isvsvn`: the SVN of the *initial* MigTD
- `migtd_tcb_date`: the TCB date for that SVN level
- `migtd_tcb_status`: the TCB status for that SVN level

All platform fields (`tee_tcb_svn`, `fmspc`, `tcb_date`, etc.) are `None`.

### Step 3: Evaluate policy rules

`evaluate_policy_common(evaluation_data_src, relative_reference, skip_global=true)` iterates over policy rules. With `skip_global=true`, only `ServtdPolicy` rules run (platform TCB and CRL rules are skipped). `ServtdPolicy` checks up to three properties: `isvsvn`, `tcb_date`, `tcb_status_accepted`.

### How rules resolve — absolute vs relative

Each policy rule has an `operation` and a `reference`. The reference determines whether the rule is absolute or relative:

**Absolute rule** — reference is a literal value:
```json
{ "operation": "greater-or-equal", "reference": 3 }
```
Evaluates `peer_migtd_svn >= 3`. The `relative_reference` (Init_TDINFO-derived values) is **completely ignored**.

**Relative rule** — reference is `"self"` or `"init"`:
```json
{ "operation": "greater-or-equal", "reference": "init" }
```
Evaluates `peer_migtd_svn >= init_migtd_svn`. The Init_TDINFO-derived SVN from the relative reference is used as the comparison target.

### What happens with only absolute rules?

If the policy contains only absolute rules, the Init_TDINFO-derived relative reference values are **never read** during the actual policy comparison. However, Init_TDINFO still has an effect:

1. **The allowlist gate** (step 6 in migration, before policy eval): `get_engine_svn_by_measurements()` must find the Init_TDINFO's measurements (`mrtd`, `rtmr0`, `rtmr1`) in the mapping table. If the initial MigTD's measurements are not in the allowlist, this fails with `SvnMismatch` regardless of what policy rules exist. This acts as an **identity allowlist check** on the initial MigTD.

2. The actual policy comparison (`value >= 3`) runs against the peer MigTD's current evaluation data and succeeds or fails based solely on the absolute threshold.

**Bottom line**: with purely absolute policy rules, Init_TDINFO's role during policy evaluation reduces to a gatekeeper — its measurements must be recognized in `servtd_tcb_mapping`. The relative reference comparison only activates when the policy uses `"reference": "self"` or `"reference": "init"`.

### Why the cross-check and policy evaluation are not redundant

The Init_TDINFO cross-check (`verify_peer_init_tdinfo_against_owner` / `_against_suppl_data`) and the allowlist gate (`get_engine_svn_by_measurements`) verify **different aspects** of the initial MigTD's identity:

| Check | What it verifies | TDINFO fields used |
|---|---|---|
| `verify_peer_init_tdinfo_against_{owner,suppl_data}` | **Policy signer identity + policy SVN ordering**: the init MigTD had the same policy signer, and init policy SVN ≤ current policy SVN | `mrowner` (policy signer hash), `mrownerconfig[0..4]` (policy SVN) |
| Allowlist gate (`get_engine_svn_by_measurements`) | **MigTD binary identity**: the init MigTD's code measurements are in the known-good allowlist | `mrtd`, `rtmr0`, `rtmr1` (code measurements) |

These are orthogonal: a MigTD could have the correct policy signer (`mrowner`) but be running an unauthorized binary (`mrtd`/`rtmr` not in the allowlist), or vice versa. Both checks are needed to fully validate the initial MigTD's identity.

---

## Historical notes — commit origins

| Check | Function | Commit | Author |
|---|---|---|---|
| Startup self-check: `MROWNER==signer`, `MROWNERCONFIG==SVN` | `verify_own_tdinfo()` | `67b49e5` feat: support tdinfo_init | Michal Tarnacki |
| Init MigTDData binding: `MROWNER==signer`, `SVN<=my SVN` | `verify_init_migtd_data_policy_binding()` | `67b49e5` (same) | Michal Tarnacki |
| Peer cross-check against TDREPORT owner fields | `verify_peer_init_tdinfo_against_owner()` | `ccfd611` refactor: move init-TDINFO cross-check into policy layer | Haitao Huang |
| Peer cross-check against quote suppl data | `verify_peer_init_tdinfo_against_suppl_data()` | `ccfd611` (same) | Haitao Huang |
| Destination-side init_TDINFO integrity + policy eval | `authenticate_migration_source_with_init_tdinfo()` | `bae6f54` feat: verify init_TDINFO integrity and policy on migration destination | Haitao Huang |
| `SERVTD_ATTR` hardcoded check (`cur == 0x0`) | `verify_servtd_attr()` | `a7c6ac0` feat: verify SERVTD_ATTR using SERVTD.RD api | Michal Tarnacki |
| `SERVTD_ATTR` vs `INIT_ATTR` check (`cur == init`) | `verify_servtd_attr()` | `d4336bb` fix: verify SERVTD_ATTR against INIT_ATTR (PR [#832](https://github.com/intel/MigTD/pull/832), issue [#831](https://github.com/intel/MigTD/issues/831), no review comments). **Reverted** — after rebind, `CURR_SERVTD_ATTR` can legitimately differ from `INIT_ATTR` | Stanislaw Grams |
