# MigTD Boot Measurements — Who Measures What, When, and How

*Companion summary to `docs/One_Hash_Endorsement.md`. Focuses on the
**mechanics** of how each TDX measurement register gets populated for a
MigTD launch, with file-line citations. The "what the values mean for
attestation" question is covered in the One-Hash doc.*

> **Scope.** All addresses and section attributes shown here are for the
> production **IGVM** build (Azure OS). TDVF builds differ only in how
> MRTD is populated at TD launch (BIOS-style metadata vs IGVM directives)
> — the RTMR0–3 portion is identical.

---

## TL;DR table

| Register | Contents (in order) | Who extends it | When | How (TDX op) |
|---|---|---|---|---|
| **MRTD** | td-shim BFV pages **+** MigTD payload pages **+** GPA layout of every region | IGVM loader (host) / TDX module | TD launch, **before any TD code runs** | `TDH.MEM.PAGE.ADD` (all pages) + `TDH.MR.EXTEND` (pages without `unmeasured` flag); sealed by `TDH.MR.FINALIZE` |
| **RTMR0** | `EV_SEPARATOR` = `SHA384(0x00000000)` extended once from zero | td-shim | Inside `boot_builtin_payload`, just before jumping to MigTD entry | `tdcall_extend_rtmr(rtmr_index=0)` |
| **RTMR1** | `EV_SEPARATOR` (same as RTMR0), then `policy_issuer_chain` digest | td-shim (separator) → MigTD (issuer chain) | td-shim runtime, then MigTD `do_measurements()` | `tdcall_extend_rtmr(rtmr_index=1)` |
| **RTMR2** | **One extend**: canonical `policyData` with `servtdCollateral.servtdTcbMapping` removed (`policy_v2`) — or, in legacy `not(policy_v2)` builds, the full policy blob followed by `root_ca` | MigTD | MigTD `do_measurements()`, before any migration handling | `tdcall_extend_rtmr(rtmr_index=2)` |
| **RTMR3** | Unused (always zero) in production builds | — | — | — |

Test/debug variant: when `test_disable_ra_and_accept_all` is on,
`do_measurements()` short-circuits and extends **only**
`TEST_DISABLE_RA_AND_ACCEPT_ALL_EVENT` into RTMR2; no policy / issuer
chain measurements are made. (`src/migtd/src/bin/migtd/main.rs:155-158,
183-186`)

---

## 1. MRTD — populated at TD launch by the IGVM loader

### What's in it

For the MigTD IGVM image, the IGVM loader processes one
`IgvmDirectiveHeader::PageData` per 4 KB page. Each page hits MRTD as:

1. **`TDH.MEM.PAGE.ADD`** — for every non-shared page (records the GPA
   regardless of whether content is measured).
2. **`TDH.MR.EXTEND`** — only for pages where `IgvmPageDataFlags.unmeasured`
   is **clear**. Extends MRTD with the page content in 256-byte chunks.

So MRTD reflects both the **GPA layout** of every region AND the **byte
content** of every "measured" region.

### Section breakdown (per `MigTD/config/metadata.json`)

| Section | GPA (in MigTD layout) | `attributes` | `unmeasured` in IGVM? | What's in it |
|---|---|---|---|---|
| **CFV** | `0xFF000000`, `0xA0000` | `0x0` | **yes** (GPA-only) | Policy JSON, policy issuer cert chain (PEM), root CA — measured later into RTMR1/RTMR2 |
| **TempMem** (stack, heap, mailbox, etc.) | various | `0x0` | yes (GPA-only) | Zero-fill at launch |
| **PermMem** | `0x0`, `0x2000000` | `0x2` | yes (GPA-only) | Reserved memory for runtime use |
| **Payload** | `0xFF0C1000`, `0xEE6000` (~15 MB) | `0x1` (EXTENDMR) | **no** — measured | The **MigTD binary** (PE/COFF, wrapped as a DXE_CORE FV file) |
| **BFV** | `0xFFFA7000`, `0x59000` (~356 KB) | `0x1` (EXTENDMR) | **no** — measured | td-shim metadata + IPL + reset vector |

### The code path that emits these directives

1. **`MigTD/config/metadata.json`** declares the sections and their
   `Attributes`. This is the *source of truth* for the MigTD IGVM build.

2. **`td-shim-ld -i igvm`** (invoked by
   `MigTD/xtask/src/build.rs:204-206,260-261`) calls
   `TdShimLinker::build_igvm()`.

3. **`MigTD/deps/td-shim/td-shim-tools/src/linker.rs::build_igvm`**
   (lines `424-627`) emits one `IgvmDirectiveHeader::PageData` per page,
   per region. The crucial calls:

   ```rust
   // CFV — unmeasured iff metadata attributes==0 (true for MigTD)
   insert_igvm_pages(..., TD_SHIM_CONFIG_BASE, ..., &vec![], cfv_unmeasured); // L445-451
   // Mailbox / TempStack / TempHeap — always unmeasured
   insert_igvm_pages(..., MAILBOX,    &vec![], true);                          // L453-459
   insert_igvm_pages(..., TEMP_STACK, &vec![], true);                          // L461-467
   insert_igvm_pages(..., TEMP_HEAP,  &vec![], true);                          // L469-475
   // MigTD payload binary — MEASURED into MRTD
   insert_igvm_pages(..., TD_SHIM_PAYLOAD_BASE, &payload_data, false);         // L495-501
   // td-shim BFV (metadata + IPL + reset vector) — MEASURED into MRTD
   insert_igvm_pages(..., TD_SHIM_METADATA_BASE, &bfv_data, false);            // L577-583
   ```

4. **`insert_igvm_pages`** (`linker.rs:344-374`) translates the
   `unmeasured` arg into the on-wire IGVM page flag:

   ```rust
   let mut flags = IgvmPageDataFlags::new();
   if unmeasured { flags.set_unmeasured(true); }       // L362-365
   directive_headers.push(IgvmDirectiveHeader::PageData {
       gpa: base + i * PAGE_SIZE_4K, flags, data, ...  // L366-372
   });
   ```

5. The `EXTENDMR` attribute (`0x1`) → "not unmeasured" → `TDH.MR.EXTEND`
   on every page in the section. Defined at
   `MigTD/deps/td-shim/td-shim-interface/src/metadata.rs:68`.

### Common misconception: "td-shim loads the payload, so the payload isn't in MRTD"

**Wrong.** TD-shim *does* find/relocate/jump-to the payload at runtime,
but that's a separate concern from measurement. The payload **bytes**
are placed into TD memory by the **IGVM loader** at TD launch and
extended into MRTD at that moment — well before td-shim's first
instruction executes. TD-shim's runtime work:

- Reads the payload from `SliceType::ShimPayload` (the read-only FV
  region the IGVM loader populated). `td-layout/src/memslice.rs:72-75`
  for the slice; `td-shim/src/bin/td-shim/main.rs:217-223` for the read.
- Optionally PE-relocates into a **separate** writable region
  `SliceType::Payload`
  (`td-shim/src/bin/td-shim/main.rs:238-240`).
- Jumps to the relocated entry point
  (`td-shim/src/bin/td-shim/main.rs:266-`).

The execution-region writes happen AFTER `TDH.MR.FINALIZE`, so they do
not affect MRTD. Only the as-shipped, pre-execution image in the FV is
measured.

### The "MRTD vs RTMR1" toggle for payload (`payload_extend_rtmr`)

`td-shim/src/bin/td-shim/shim_info.rs:84-92,116-118` makes a runtime
decision:

```rust
if section.r#type == TDX_METADATA_SECTION_TYPE_PAYLOAD && section.attributes == 0 {
    payload_extend_rtmr = true;   // payload was NOT measured into MRTD
}                                 // → fall back to logging it into RTMR1 at runtime
```

If `payload_extend_rtmr()` is true, `boot_builtin_payload` calls
`log_payload_binary(payload_bin, event_log)` which extends RTMR1
(`td-shim/src/bin/td-shim/event_log.rs:76-92`, mr_index=2 →
rtmr_index=1).

**For MigTD's IGVM build the Payload section has `attributes=0x1`, so
`payload_extend_rtmr` is `false` → the payload is in MRTD only, NOT
also in RTMR1.** This is what makes RTMR1 deterministic (separator +
issuer chain only).

---

## 2. RTMR0 — `EV_SEPARATOR` only

Extended exactly once, by td-shim, in
`MigTD/deps/td-shim/cc-measurement/src/log.rs:58-67`:

```rust
pub fn create_seperator(&mut self) -> Result<()> {
    let separator = u32::to_le_bytes(0);
    // Measure 0x0000_0000 into RTMR[0] and RTMR[1]
    let _      = self.calculate_digest_and_extend(&separator, 1)?;  // mr_index 1 → RTMR0
    let sha384 = self.calculate_digest_and_extend(&separator, 2)?;  // mr_index 2 → RTMR1
    self.log_cc_event(1, EV_SEPARATOR, &[&separator], &sha384)?;
    self.log_cc_event(2, EV_SEPARATOR, &[&separator], &sha384)
}
```

Call site for the MigTD path:
`td-shim/src/bin/td-shim/main.rs:236` (inside `boot_builtin_payload`,
after the optional `log_payload_binary` and before jumping to the
payload entry point).

**Why RTMR0 is a deterministic constant in MigTD IGVM builds:**

- `log_hob_list` (which would extend RTMR0) is **skipped** because
  MigTD's `metadata.json` declares no `TD_HOB` section, so
  `BootTimeDynamic::td_hob()` returns `None` and the `if let Some(td_hob)`
  branch in `td-shim/src/bin/td-shim/main.rs:131-134` is not taken.
- `log_payload_binary` (which would extend RTMR1) is **skipped** because
  `payload_extend_rtmr` is `false` (see §1).
- The only thing left is the separator → RTMR0 ends up as a fixed
  function of `SHA384(0x0000_0000)` extended from zeros.

The mr_index→RTMR translation is in
`MigTD/src/migtd/src/event_log.rs:164-175`:
```rust
let rtmr_index = match mr_index { 1..=4 => mr_index - 1, _ => err };
tdcall_extend_rtmr(&digest, rtmr_index)?;
```

---

## 3. RTMR1 — `EV_SEPARATOR` + policy issuer chain

Two extensions, in order:

| # | What | Where |
|---|---|---|
| 1 | Separator `SHA384(0x0000_0000)` | td-shim `create_seperator()` — see §2 |
| 2 | Digest of CFV's policy-issuer-chain PEM | MigTD `get_policy_issuer_chain_and_measure()` |

The MigTD-side extension lives in `MigTD/src/migtd/src/bin/migtd/main.rs:298-327`
(only present when the `policy_v2` feature is on, which is the
production setting):

```rust
fn get_policy_issuer_chain_and_measure(event_log: &mut [u8]) {
    let policy_issuer_chain = config::get_policy_issuer_chain()...;       // CFV read
    event_log::write_tagged_event_log(
        event_log,
        MR_INDEX_POLICY_ISSUER_CHAIN,   // = 0x2 → rtmr_index 1 → RTMR1
        policy_issuer_chain,
        TAGGED_EVENT_ID_POLICY_ISSUER_CHAIN,
        policy_issuer_chain,
    );
}
```

`MR_INDEX_POLICY_ISSUER_CHAIN = 0x2` is at
`MigTD/src/migtd/src/event_log.rs:34`; the actual TDCALL is at
`MigTD/src/migtd/src/event_log.rs:164-175`.

Called from `runtime_main()` → `do_measurements()` →
`get_policy_issuer_chain_and_measure(event_log)`
(`MigTD/src/migtd/src/bin/migtd/main.rs:108,188`).

---

## 4. RTMR2 — policy binding (and root CA on legacy v1)

### policy_v2 build (current default)

**One extension**: the canonical bytes of `policyData` with
`servtdCollateral.servtdTcbMapping` removed. By construction this binds
every other top-level `policyData` field — `version`, `id`, `policySvn`,
`policy`, `forwardPolicy`, `backwardPolicy`, `collaterals`, and the rest
of `servtdCollateral` (`majorVersion`, `minorVersion`, the issuer-signed
`{tdIdentity, signature}`, `servtdIdentityIssuerChain`,
`servtdTcbMappingIssuerChain`). Redacting `servtdTcbMapping` is the only
escape hatch and is what makes the mapping updateable after the IGVM is
shipped without rebuilding.

| # | Bytes hashed | Tag ID constant | EventName |
|---|--------------|-----------------|-----------|
| 1 | canonical `policyData` with `servtdCollateral.servtdTcbMapping` removed (object bytes including outer `{ }`) | `TAGGED_EVENT_ID_POLICY_DATA = 0x9` | `MigTdPolicyData` |

Canonicalization is RFC-8785-style: object keys are sorted lexicographically at every level, arrays preserve order, whitespace is stripped. The extractor (`policy::v2::measurement::extract_canonical_policy_data_bytes`) accepts either the bare `policyData` object or the `{policyData, signature}` envelope, performs a single top-level type check (must be a JSON object), and rejects malformed inputs *before* hashing. Any deeper validation is left to the runtime policy parser, because a malformed policy simply produces a `tdinfo_hash` that does not match any `svnMappings[]` entry and the migration fails closed.

`get_policy_and_measure()` in `MigTD/src/migtd/src/bin/migtd/main.rs` calls
`event_log::write_tagged_event_log` exactly once for this extend, with
`MR_INDEX_POLICY = 0x3 → rtmr_index 2 → RTMR2`. The `tagged_event_data`
payload that lands in the event log is the small `version.as_bytes()`
string — the full canonical-bytes payload is only fed into the digest,
keeping CCEL size bounded.

Sketch:

```rust
// policyData (with servtdCollateral.servtdTcbMapping redacted) → SHA-384
let policy_bytes = migtd::policy::extract_canonical_policy_data_bytes(policy)?;
event_log::write_tagged_event_log(
    event_log,
    MR_INDEX_POLICY,                      // = 0x3 → RTMR2
    &policy_bytes,                        // bytes that get SHA-384'd
    TAGGED_EVENT_ID_POLICY_DATA,          // = 0x9
    event_data,                           // version.as_bytes() — small event payload
);
```

Why one redacted-policyData extend instead of either (a) a single
signed-blob hash or (b) per-field whitelist:

- A signed-blob hash would re-introduce the original circularity (the
  signed file must exist before the image is built).
- A per-field whitelist (the previous "six extends" scheme) required
  reviewer discipline to remember to add every new `policyData` field to
  the measurement code path. The single-extend redacted scheme
  automatically binds every newly added field (`forwardPolicy` /
  `backwardPolicy` are concrete examples that the previous scheme
  silently failed to measure), and it automatically measures both
  issuer chains (`servtdIdentityIssuerChain` and
  `servtdTcbMappingIssuerChain`) — closing the door on a malicious peer
  swapping in a different trust anchor for the embedded signed
  identity.
- The dummy policy embedded in the base IGVM's CFV pre-computes the same
  RTMR2 as the final signed policy as long as the canonical
  `policyData` (minus `servtdTcbMapping`) agrees byte-for-byte — see
  `docs/tcb_mapping_redesign.md`.

The **hashed bytes** are the canonical redacted-`policyData` bytes (sorted-key, whitespace-free); the **event-log payload field** is the small version string. Peers replay the event log and compare digests, not raw payloads — `check_policy_integrity` recomputes the canonical bytes via the same `extract_canonical_policy_data_bytes` helper to verify the single digest.

Mirror in `MigTD/tools/migtd-hash/src/lib.rs` (`rtmr2()`): offline simulator
performs the same single `rtmr2.extend_with_raw_data(...)` call so the build
pipeline's `tdinfo_hash` matches the runtime RTMR2 exactly.

### Legacy `not(policy_v2)` build

Two extensions in order: `policy` then `root_ca`
(`MigTD/src/migtd/src/bin/migtd/main.rs:329-348`,
`MR_INDEX_ROOT_CA = 0x3` → RTMR2). Not used in current production.

### Test mode

`measure_test_feature()` (`MigTD/src/migtd/src/bin/migtd/main.rs:194-210`)
extends RTMR2 (`MR_INDEX_TEST_FEATURE = 0x3`) with the literal bytes
`b"test_disable_ra_and_accept_all"` and returns early, replacing the
normal policy / issuer-chain measurements. **Only present when the
`test_disable_ra_and_accept_all` feature is built in — not in production
images.**

---

## 5. Boot sequence — who runs when

```
                                                       Measurement
─────────────────────────────────────────────────────────────────────────
Host: IGVM loader processes migtd.igvm
  ├─ For each PageData directive:
  │    ├─ TDH.MEM.PAGE.ADD (GPA)                      → MRTD (GPA only)
  │    └─ if !unmeasured: TDH.MR.EXTEND (content)     → MRTD (content)
  │       (BFV pages + Payload pages get this; CFV / TempMem do not)
  └─ TDH.MR.FINALIZE                                  → MRTD sealed
─────────────────────────────────────────────────────────────────────────
TD launch — first instruction is reset vector @ 0xFFFFFFF0
  └─ reset_vector → IPL → switch to long mode
─────────────────────────────────────────────────────────────────────────
td-shim main() runs                                   (deps/td-shim/td-shim/src/bin/td-shim/main.rs)
  ├─ Parse metadata, build BootTimeStatic / BootTimeDynamic
  ├─ if td_hob.is_some(): log_hob_list                → RTMR0 (NOT for MigTD IGVM)
  ├─ Build payload memory, set up paging, etc.
  └─ boot_builtin_payload():
       ├─ Read payload from SliceType::ShimPayload FV (no measurement)
       ├─ if payload_extend_rtmr: log_payload_binary  → RTMR1 (NOT for MigTD IGVM)
       ├─ event_log.create_seperator()                → RTMR0 + RTMR1 (separator)
       ├─ PE-relocate payload into SliceType::Payload (writable, runtime, NOT measured)
       └─ switch stack / jump to MigTD entry point
─────────────────────────────────────────────────────────────────────────
MigTD runtime_main() runs                             (src/migtd/src/bin/migtd/main.rs:83)
  └─ do_measurements():
       ├─ get_policy_issuer_chain_and_measure        → RTMR1 (issuer chain)
       └─ get_policy_and_measure                     → RTMR2 (policy)
       (test mode replaces both with a single RTMR2 test-feature event)
  └─ register migration callback, handle_pre_mig() …
```

After this point, the TD report's `tdinfo` is frozen at:

```
mrtd   = SHA384( all measured pages of td-shim + payload )      [deterministic per image]
rtmr0  = SHA384(0 || SHA384(separator))                          [deterministic per td-shim version]
rtmr1  = extend(extend(0, separator), SHA384(issuer_chain))      [varies by issuer chain]
rtmr2  = extend(0, SHA384(policy))                               [varies by policy content]
rtmr3  = 0                                                       [unused]
```

---

## 6. Why this matters for endorsement

(See `docs/One_Hash_Endorsement.md` for the full story; this is the
one-paragraph summary.)

- **`tcb_mapping.json`** maps `{mrtd, rtmr0, rtmr1}` → SVN. Because
  RTMR0 is a constant, this is effectively `{mrtd, rtmr1}` →
  `{core code, issuer chain}` → SVN. **Policy content is intentionally
  NOT in the TCB mapping** — one TCB level covers many policies that
  share the same code + issuer.
- **CoRIM `servtdHash`** (used by MAA) covers the entire 512-byte
  TDINFO struct (with `servtd_attr=0`, no IGNORE bits), so it is
  policy-specific: changing RTMR2 ⇒ different `servtdHash` ⇒ different
  endorsement entry.

---

## 7. Quick code reference index

| Concern | File | Key lines |
|---|---|---|
| What goes into MRTD | `MigTD/config/metadata.json` | whole file |
| Build-time IGVM directive generation | `MigTD/deps/td-shim/td-shim-tools/src/linker.rs` | `424-627` (build_igvm), `344-374` (insert_igvm_pages) |
| `EXTENDMR` constant | `MigTD/deps/td-shim/td-shim-interface/src/metadata.rs` | `68` |
| Default metadata sections (fallback when no `-m`) | `MigTD/deps/td-shim/td-shim-tools/src/metadata.rs` | `111-192`, `194-253` |
| `payload_extend_rtmr` toggle | `MigTD/deps/td-shim/td-shim/src/bin/td-shim/shim_info.rs` | `84-92`, `116-118` |
| TD-shim payload load + jump | `MigTD/deps/td-shim/td-shim/src/bin/td-shim/main.rs` | `210-272` (boot_builtin_payload) |
| Separator extension | `MigTD/deps/td-shim/cc-measurement/src/log.rs` | `58-67` (create_seperator) |
| td-shim event-log helpers (RTMR1) | `MigTD/deps/td-shim/td-shim/src/event_log.rs` | `71-102` |
| MigTD MR_INDEX constants | `MigTD/src/migtd/src/event_log.rs` | `34-37` |
| MigTD `tdcall_extend_rtmr` wrapper | `MigTD/src/migtd/src/event_log.rs` | `116-175` |
| MigTD `do_measurements` (policy_v2) | `MigTD/src/migtd/src/bin/migtd/main.rs` | `167-192` |
| MigTD policy / issuer-chain extension | `MigTD/src/migtd/src/bin/migtd/main.rs` | `245-296`, `298-327` |
| Event log replay / RTMR comparison | `MigTD/src/migtd/src/event_log.rs` | `228-288` |

---

## 8. Common gotchas

1. **"td-shim loads the payload"** is true at the *runtime relocation*
   level but **misleading for measurement**. Payload bytes are in MRTD
   before td-shim runs; see §1.
2. **`Attributes: 0x1` (EXTENDMR) ↔ IGVM `unmeasured=false` ↔ MRTD**;
   `Attributes: 0x0` ↔ `unmeasured=true` ↔ GPA-only. There is no
   middle ground — the bit either extends or doesn't.
3. **CFV content is NOT in MRTD.** Changing policy/issuer chain does not
   change MRTD. It changes RTMR1 and/or RTMR2 instead.
4. **`mr_index` in event-log code is PCR-style** (1-based), the
   `tdcall_extend_rtmr` `rtmr_index` is 0-based. Off-by-one bugs are
   easy here — see `event_log.rs:164-175`.
5. **`MR_INDEX_POLICY` and `MR_INDEX_ROOT_CA` and `MR_INDEX_TEST_FEATURE`
   are all `0x3`** — they all extend the same register (RTMR2). The
   tagged-event-ID is what distinguishes them at replay time.
6. **`payload_extend_rtmr` is mutually exclusive with `EXTENDMR`** on
   the Payload section. A misconfigured `metadata.json` that sets
   `Attributes: 0x0` on Payload would silently shift the measurement
   from MRTD to RTMR1, breaking endorsement matching.
7. **`test_disable_ra_and_accept_all` replaces, not adds.** Test builds
   omit the policy / issuer-chain measurements entirely, so their RTMR1
   and RTMR2 are completely different from production. Never reuse a
   test-build event-log replay against a production endorsement.
8. **`payload_v1` vs `policy_v2`**: legacy v1 builds also extend
   `root_ca` into RTMR2 *after* policy. policy_v2 builds do not — the
   root is part of the issuer chain. This means a v1→v2 transition
   changes both RTMR1 *and* RTMR2.
