---
type: Reference
title: MigTD Domain Facts (Trust Model, Attestation, Transport, Heap)
description: Non-obvious architectural facts to internalize before flagging anything as a bug — trust model, rebind vs. migration verifiers, TDINFO semantics, vmcall invariants, heap sizing, and rejected hypotheses.
tags: [trust-model, attestation, tdinfo, vmcall, heap, rejected-hypotheses]
timestamp: 2026-07-10T19:26:55+00:00
---

# MigTD Domain Facts

> Condensed in the root [agent guide](../../AGENTS.md). Read before flagging
> anything as a bug.

## Trust model

- Single-core, single-threaded `no_std` Rust firmware. No `Sync`/`Send`
  races except via interrupts.
- **VMM is untrusted but can DoS.** DoS-via-VMM is *not* a finding.
- **Root of trust = `MRTD` + `RTMR0..3`** (attested). Cert chains are
  transport; the Root CA for `policy_v2` is itself measured into RTMR.
- After `mig_policy::init_policy()` succeeds, `VERIFIED_POLICY` is trusted.

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

- **MROwner** = hash of the policy signer's public key.
- **MROwnerConfig** = MigTD policy SVN (a.k.a. "migtd svn").
- Each MigTD checks on startup that its **own** TDREPORT's `MROwner` matches
  the policy signer it has, and `MROwnerConfig` matches its policy SVN.
- For migration / rebind: destination verifies, using the report received
  from source, that source's `MROwner` == destination's (same signer) and
  source's `MROwnerConfig` >= destination's (i.e. dest SVN ≤ source SVN).
- The wire field carrying source's TDREPORT-derived init info is
  **`init_td_info`** (raw 512-byte `TdInfo`). It is the **only** thing the
  spec requires — there is **no separate** `init_migtd_data` /
  "init migtd hash" / `mig_policy_init_hash_src` blob. If you see one being
  added, push back. Past sessions removed those redundancies; merges from
  Intel occasionally re-introduce them.
- Under the **`AzCVMEmu`** feature, **skip the `verify_own_tdinfo()`
  MROwner/MROwnerConfig check** rather than emulating it via env vars. The
  env-var emulation approach was tried (commit `8ce39a3`) and abandoned as
  "too much to maintain". Current pattern: feature-gate-skip on `AzCVMEmu`.
- Existing `REVERTME` commits typically bypass MROwner/MROwnerConfig checks
  because the host isn't ready to plumb them through; these are test-only
  and must be reverted before upstreaming.

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
  `verify_quote_integrity_ex` calls from 2 → 4 in TiP loopback; the 3rd call
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
