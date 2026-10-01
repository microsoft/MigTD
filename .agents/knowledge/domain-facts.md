---
type: Reference
title: MigTD Domain Facts (Trust Model, Attestation, Transport, Heap)
description: Non-obvious architectural facts to internalize before flagging anything as a bug — trust model, rebind vs. migration verifiers, TDINFO semantics, vmcall invariants, heap sizing, and rejected hypotheses.
tags: [trust-model, attestation, tdinfo, vmcall, heap, rejected-hypotheses]
timestamp: 2026-07-26T00:14:16+00:00
---

# MigTD Domain Facts

> Condensed in the root [agent guide](../../AGENTS.md). Read before flagging
> anything as a bug.

## Trust model

- Single-core, single-threaded `no_std` Rust firmware. No `Sync`/`Send`
  races except via interrupts.
- **VMM is untrusted but can DoS.** DoS-via-VMM is *not* a finding.
- **Root of trust = `MRTD` + `RTMR0..3`** (attested). Certificate chains
  carry signatures, but policy-v2 signer identity is bound by the RTMR1
  signer anchor: root-certificate SHA-384 fingerprint + one enrolled
  signer-purpose EKU. CoRIM verification tries every EKU asserted by the leaf
  and accepts only the one reproducing the measured anchor; legacy PEM paths
  still require a single unambiguous EKU.
- After `mig_policy::init_policy()` succeeds, `VERIFIED_POLICY` is trusted.
- The one-hash TCB mapping (JSON or CoRIM) maps the complete 48-byte
  `tdinfo_hash` / `SERVTD_INFO_HASH` directly to MigTD SVN. When a signed
  CoRIM is enrolled it is the sole lookup authority; a miss does not fall
  back to JSON collateral.
- Init/current SVN continuity in the completed one-hash design uses the
  authenticated source's verified mapping twice: map
  `ServtdExt.init_servtd_info_hash` to init SVN, map the source's authenticated
  current-report `tdinfo_hash` to current SVN, and require
  `init SVN <= current SVN`. Do not query the destination's local mapping.
- Migration and rebinding both enforce this mapped-SVN ordering. A missing
  init or current mapping fails closed; the legacy wire Init_TDINFO is ignored.

## Rebind vs Migration attestation — DIFFERENT verifiers

- **Regular migration** → uses **quotes**. REPORTDATA at byte offset **520**.
  Helper: `verify_report_data_binding`.
- **Rebind** → uses **TDREPORT** (no quote). REPORTDATA at byte offset
  **128**. Helper: `verify_tdreport_data_binding`.
- **Mixing them = bug.** See commit `94975ec` (TH1 binding fix).

See [Init_TDINFO and ServtdExt Usage Summary](init-tdinfo-servtd-ext.md) for
full detail on how each path verifies TDINFO, and
[Security Bypasses](security-bypasses.md) for which of these checks are
bypassed under which build feature.

## TDINFO / MROwner / MROwnerConfig semantics

- **MROwner** is provisioned by GHCI as the hash of the policy signer's
  public key, but it is no longer the cross-peer signer trust anchor.
- **MROwnerConfig** = MigTD policy SVN (a.k.a. "migtd svn").
- There is no local startup check comparing `MROwnerConfig` with policy SVN.
  The policy is bound through measured RTMR2 data, while migration continuity
  uses authenticated peer measurements and their verified one-hash mapping.
- Cross-peer signer compatibility is the RTMR1 anchor equality
  (root fingerprint + leaf EKU). Leaf and intermediate keys may rotate
  independently under the same anchor.
- The legacy wire field **`init_td_info`** is accepted for framing
  compatibility but cleared by `MigtdMigrationInformation::read_from_bytes`;
  callers see it as absent. The completed one-hash flow must use
  `ServtdExt.init_servtd_info_hash` directly and must not depend on a
  VMM-supplied 512-byte Init_TDINFO.
- Existing `REVERTME` commits typically bypass MROwner/MROwnerConfig checks
  because the host isn't ready to plumb them through; these are test-only
  and must be reverted before upstreaming.

## Migration version roles

- The source must call `exchange_info(..., true)` to read the TDX module's
  EXPORT bounds; the destination uses `false` for IMPORT bounds. The SPDM
  requester serializes its local range as `MigrationExportVersion`.
- Equal import/export ranges hide a wrong source-role argument. Keep the
  source role consistent through `exchange_info` and `cal_mig_version`.

## vmcall / transport invariants

- `vmcall-raw` **never returns `Ok(0)` / EOF**. It blocks until data or
  error. "What if VMM returns 0 bytes?" is already defended at the transport
  layer.
- Each migration session has its own shared buffer with **`data_status` as
  ground truth**. Broadcast interrupt wakes are filtered by the per-buffer
  status check — correct by design.

## Heap allocator

- `ATTEST_HEAP_SIZE` is currently **2 MiB**. It was bumped from 512 KiB after
  commit `3c44ea9` removed the `LOCAL_TCB_INFO` cache, raising per-migration
  `verify_quote_integrity_ex` calls from 2 → 4 in loopback migration; the 3rd call
  exhausted the old heap (#UD inside the C verifier).
- The C verifier (`verify_quote_integrity_ex` from Intel DCAP `servtd_attest`)
  uses **SgxSSL libcrypto** internally — host-glibc-libcrypto repro tools
  **under-report** heap pressure. Host repros must link the same allocator
  (tlibc dlmalloc/sbrk) and the same libcrypto (SgxSSL) as the in-image build.
- Single-thread heap **does** reuse freelists across calls; "leak across
  calls" was rejected as a hypothesis. The 2 MiB bump is the accepted answer.
- See [Memory Budget](memory-budget.md) for the stack/heap/shared-memory
  sizing methodology and current equations.

## Rejected hypotheses — do not reopen without strong new evidence

- **Singleton GetQuote vector hijacking MigTD vector**: host VMM team
  definitively rejected this. `GhciRequestContext` omits
  `NotificationInterrupt` by spec; Send/Receive vectors are re-supplied each
  call. Don't propose fixes founded on this hypothesis.
