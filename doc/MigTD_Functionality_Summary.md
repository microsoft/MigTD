# MigTD — Implemented Functionality Summary (Azure Build)

A high-level summary of the **main functionalities** implemented in this MigTD
(Migration TD) codebase, focused on the **Azure TDX CVM build configuration**.
MigTD is a no_std Rust TDX **Service TD** that evaluates whether a migration
source and destination platform both satisfy the TD Migration Policy, then
securely transfers the **Migration Session Key (MSK)** between them so the VMM
can live-migrate a user TD.

> **Focus / scope.** This document describes the **Azure build**, which uses:
> - **IGVM** image format
> - **`igvm-attest`** for quote retrieval (attestation)
> - **`vmcall-raw`** for the GHCI guest–host channel
> - **SPDM** as the mutual-attestation / secure-session protocol
> - **policy v2** (signed policy + ServTD collateral)
>
> Build feature set (`sh_script/Azure/Makefile`):
> `vmcall-raw, stack-guard, main, vmcall-interrupt, oneshot-apic,
> spdm_attestation, igvm-attest` built with `--image-format igvm --policy-v2`.
>
> The recent proof-of-concept work for the **one-hash TCB-mapping with CoRIM
> hash endorsement** (the `servtd_corim` feature / latest redesign commits) is
> intentionally **excluded** here; the pre-existing policy v2 / ServTD-collateral
> functionality *is* covered. Non-Azure options (RA-TLS, virtio/vsock
> transports, `bin` image format) are out of scope.

---

## 1. Overview & Role

- MigTD runs as a TDX Service TD (`SERVTD_TYPE = 0`) bound to a user TD via
  `TDH.SERVTD.BIND` / `TDH.SERVTD.PREBIND`.
- It is the migration-policy decision point: the source MigTD (MigTD-S) and the
  destination MigTD (MigTD-D) **mutually remote-attest** each other over SPDM,
  check each other against policy v2, and only then exchange the MSK.
- Built for `x86_64-unknown-none` on top of the **td-shim** payload framework and
  packaged as an **IGVM** image for Azure. It can also be built as a normal
  user-space app for Azure CVM emulation (**AzCVMEmu**).
- Entry point: `src/migtd/src/lib.rs` (`_start`) → runtime init → `main()` in
  `src/migtd/src/bin/migtd/main.rs`.

---

## 2. End-to-End Migration Flow

Orchestrated in `src/migtd/src/bin/migtd/main.rs` and
`src/migtd/src/migration/session.rs`:

1. **Boot & self-measurement** (`do_measurements`): read the signed policy and
   the policy issuer chain from the Configuration Firmware Volume (CFV), verify
   the policy, and extend the measurements into RTMRs via the CCEL event log.
2. **VMM logging init** (`init_vmm_logger`, `create_logarea`): set up per-vCPU
   log areas for the `vmcall-raw` channel.
3. **Wait for request** (`wait_for_request`): receive a request from the VMM over
   the `vmcall-raw` GHCI channel. An async dispatcher supports up to **12
   concurrent** requests.
4. **Dispatch** by request type (see §3) — for a migration, `exchange_msk` sets
   up the transport, performs the SPDM mutual attestation, negotiates the
   migration version, and exchanges the MSK.
5. **Write MSK & report status** (`write_msk`, `report_status`): write the MSK
   into the TDX module and report success/error back to the VMM.

### MSK handling
- `MigrationSessionKey` = 4 × `u64`, **zeroize-on-drop**
  (`src/migtd/src/migration/data.rs`).
- Read from the TDX module via `tdcall_servtd_rd` (`TDCS_FIELD_MIG_ENC_KEY`),
  written via `tdcall_servtd_wr` (`TDCS_FIELD_MIG_DEC_KEY`)
  (`session.rs: read_msk` / `write_msk`).
- **Migration version negotiation** (`exchange_info`, `cal_mig_version`,
  `set_mig_version`) reads the TDX-module export/import min/max version fields and
  computes a common version. The forward/backward MSK and versions are carried
  inside the SPDM session.

---

## 3. MigTD ↔ VMM Interface (`vmcall-raw` GHCI)

Implemented in `src/migtd/src/migration/{data.rs, session.rs, event.rs}`:

- Guest–host communication uses the **`vmcall-raw`** channel (TDVMCALL), with a
  shared **request/response data buffer** (`RequestDataBuffer` /
  `RequestDataBufferHeader { datastatus, length }`).
- Event-driven notification via `SetupEventNotifyInterrupt` (interrupt vector
  `0x50`, `event.rs`).
- Request set (`WaitForRequestResponse`):
  - `StartMigration` — run the MSK key-exchange flow.
  - `StartRebinding` — approve rebinding the user TD to a new MigTD (policy v2).
  - `GetTdReport` — return a TD report for given report data.
  - `EnableLogArea` — enable/raise the VMM log level for a request.
  - `GetMigtdData` — return MigTD attestation data (policy v2).
- `ReportStatus` returns the per-request result (`ReportStatusResponse` carries
  the pre-migration status + error code).
- **Guest-crash reporting**: fatal init/runtime failures call
  `panic_with_guest_crash_reg_report`, surfacing a crash code/message to the VMM
  via MSR (`driver/crash.rs`, `driver/vmcall_raw.rs`).
- HOB parsing for migration information and policy (`data.rs: read_mig_info`).

---

## 4. Remote Attestation (`igvm-attest`)

### Quote generation (`src/attestation/src/igvmattest.rs`, `quote.rs`)
- Produce a TD report (`tdcall_report`) over the report data, then obtain a quote
  through the **IGVM attest** path:
  - `get_quote_igvm` builds a `ServtdTdxQuoteHdr` + the TD report into a 16-page
    shared request buffer and calls `servtd_get_quote` (GHCI `GetQuote` via
    TDVMCALL); the VMM fills in the quote, which is then extracted.
  - `get_quote_with_retry` retries `Busy` with exponential backoff.

### Quote verification (`src/attestation/src/attest.rs`)
- Wraps the Intel attestation verification library via FFI. The Azure build (via
  policy v2 → `attest-lib-ext`) uses **`verify_quote_integrity_ex`** with the
  **collateral** (`QveCollateral`) sourced from **Azure THIM**
  (`config/Azure/collateral_thim.json`).
- Verifies against the enrolled Intel SGX root CA public key
  (`attestation::root_ca`), returning an 822-byte verified TD report block that
  policy evaluation consumes.

### Measurement & Event Log (`src/migtd/src/event_log.rs`)
- `write_tagged_event_log`: SHA-384 of measured data → `tdcall_extend_rtmr` →
  append a tagged CCEL event.
- Measured items: the **policy issuer chain** (RTMR1, as a stable *signer
  anchor*) and the canonical **`policyData`** bytes (RTMR2, with
  `servtdTcbMapping` redacted so it stays updatable).
- `verify_event_log` replays the event log against the RTMRs from the verified
  quote (bypassed under `AzCVMEmu` / `use-mock-quote` test builds).

---

## 5. Mutual Attestation & Secure Session (**SPDM**)

The `spdm_attestation` feature makes **SPDM** the mutual-attestation and
secure-session protocol that carries both the attestation evidence and the MSK
exchange (`src/migtd/src/spdm/`, `migration/spdm_session.rs`):

- **SPDM 1.2** over `spdm-rs` (`spdmlib` with `spdm-ring`): ECDSA P-384 /
  SHA-384 / SECP384R1 / AES-256-GCM, **mutual authentication**, key exchange,
  public-key-ID auth, chunking.
- Requester = MigTD-S, Responder = MigTD-D, both driven through
  `finalize_spdm_session` (60-second timeout). The SPDM transport is VMM-mediated
  via `MigtdTransport` implementing `SpdmDeviceIo` over the `vmcall-raw` channel.
- Attestation material, policy, versions and keys are exchanged via
  **vendor-defined messages (VDM)**:
  - `ExchangePubKey` — provision peer public keys before attestation.
  - `ExchangeMigrationAttestInfo` — exchange **quote**, **event log**, **policy
    hash**, **SERVTD_EXT**, and **init TD info**.
  - `ExchangeMigrationInfo` — exchange migration export/import versions and the
    **forward/backward Migration Session Key**.
  - plus **rebind** variants for the `StartRebinding` flow.
- Security hygiene: the session is torn down on policy-hash mismatch and the
  requester app-context buffer is zeroized on all paths.

### Pre-session policy exchange
Because policy + issuer-chain data can exceed the secure-session message size,
they are exchanged up-front via `pre_session_data_exchange`
(`migration/pre_session_data.rs`, 60-second timeout) and then bound during SPDM
attestation.

---

## 6. Migration Policy (v2)

Implemented in `src/policy/` and `src/migtd/src/mig_policy.rs`; the signed policy
is enrolled into the IGVM image and measured into RTMR at boot.

### What it enforces
- Platform/quote collateral: FMSPC, TCB info, TCB status & date, TCB evaluation
  data number, PCK/root-CA CRLs, QE identity, TDX-module identity (from THIM
  collateral).
- MigTD/ServTD identity: TD `ATTRIBUTES`, `XFAM`, `MRTD`, `MRCONFIGID`,
  `MROWNER`, `MROWNERCONFIG`, `RTMR0–3` from the verified report.

### Policy v2 structure & verification
- A **signed `policyData` wrapper**, a **policy issuer chain** (X.509 v3,
  ECDSA-P384/SHA-384), and **signed ServTD collateral** containing a signed **TD
  identity** and **TCB mapping**, each with their own issuer chains.
- Runtime: `init_policy` verifies the signed policy and sets the root CA;
  `authenticate_remote*` verifies the quote/TDREPORT, event-log integrity, policy
  signature & integrity, peer issuer-chain compatibility, and TCB relationships.
- **Measurement binding:** RTMR1 ← issuer-chain *signer anchor*; RTMR2 ←
  canonical `policyData` (with `servtdTcbMapping` redacted). The same canonical
  bytes are reproduced offline by `migtd-hash --policy-v2`.
- Migration continuity: MigTD resolves the authenticated source's initial and
  current `SERVTD_INFO_HASH` values through the source's verified one-hash
  mapping and requires the mapped initial SVN not to exceed the current SVN.
  There is no separate local TDINFO-to-policy-SVN startup check.
- See `doc/policy_v2.md` and `doc/policy_v2_measurements.md`.

---

## 7. TD Binding, Pre-binding & Rebinding

- **Binding / pre-binding** (`readme.md`): MigTD is bound to a user TD by process
  ID (`TDH.SERVTD.BIND`) or pre-bound by `SERVTD_INFO_HASH`
  (`TDH.SERVTD.PREBIND`).
- **`verify_servtd_attr`** validates `SERVTD_ATTR` against a hardcoded expected
  value to defend against a malicious VMM.
- **SERVTD_EXT** (`migration/servtd_ext.rs`): optional extended Service-TD
  binding info (gated on TDCS `ATTRIBUTES` bit 17) — init SERVTD info hash, init
  attributes, CPUSVN, and TEE TCB SVN.
- **Rebinding** (`migration/rebinding.rs`): the `StartRebinding` flow approves
  rebinding a user TD to a new MigTD on the destination using
  `tdcall_servtd_rebind_approve` and a rebind accept token.

---

## 8. Guest–Host Transport (`vmcall-raw`)

- The migration channel uses the **`vmcall-raw`** transport — a raw migration
  channel built directly on TDVMCALL/VMCALL (`src/devices/vmcall_raw`,
  `migration/transport.rs`).
- A transport abstraction (`setup_transport` / `shutdown_transport`) keeps the
  session code transport-agnostic; the Azure build selects `vmcall-raw`
  (`VmcallRaw::new_with_mid(...).connect()`).
- An **8-second** connection timeout is enforced after a migration is triggered.

---

## 9. Cryptography (`src/crypto`)

- Provides the primitives used by SPDM and policy v2: **ECDSA P-384 / SHA-384**
  sign/verify (via `ring`), **SHA-384** hashing, secure random.
- X.509 / PEM handling: PEM↔DER, minimal cert builder, chain split/validation,
  signature verification, **COSE_Sign1 (ES384 + x5chain)** verification, and CRL
  number parsing — used to validate the signed policy, ServTD collateral, and
  issuer chains.

---

## 10. Device Drivers & Async Runtime

- **Drivers** (`src/migtd/src/driver/`, `src/devices/`) relevant to the Azure
  build: the **`vmcall-raw`** channel, the **APIC timer** with one-shot mode
  (`oneshot-apic`, used when TSC-deadline is unavailable), the **system tick**
  clock, and **guest-crash MSR reporting**.
- **Async runtime** (`src/async/async_runtime`, `src/async/async_io`): a tiny
  single-threaded no_std executor (poll-based futures, `ArcWake`, task queue)
  with `AsyncRead`/`AsyncWrite` traits and timeout combinators. It lets the
  single-threaded firmware drive asynchronous migration I/O. Under AzCVMEmu a real
  **tokio** runtime is used instead.

---

## 11. Build, IGVM Image & Hashing

- **`cargo image --image-format igvm`** builds the MigTD **IGVM** image and
  enrolls the signed policy, policy issuer chain, and root CA into the CFV
  (`xtask`). Supports `--log-level` and `--debug`.
- The **Azure Makefile** (`sh_script/Azure/Makefile`) is the canonical build:
  `cargo image --no-default-features --features
  vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,spdm_attestation,igvm-attest
  --image-format igvm --policy-v2 ...`.
- **`cargo hash` / `migtd-hash --policy-v2`** computes `SERVTD_INFO_HASH`
  (for pre-binding) and reproduces the RTMR2 canonical `policyData` digest for the
  IGVM image.
- Hardening: **`stack-guard`** is enabled in the Azure build (with optional
  `cet-shstk`).

---

## 12. Developer Tools (`tools/`)

- **migtd-hash** — compute MigTD measurements (`SERVTD_INFO_HASH`) and, in v2
  mode, the `tdinfo_hash` for `tcb_mapping.json`.
- **migtd-collateral-generator** — fetch platform collateral from **Azure THIM**
  (or Intel PCS) and emit collateral JSON.
- **migtd-policy-generator** — generate v2 `policyData` by merging base policy +
  platform collateral + ServTD collateral.
- **servtd-collateral-generator** — bundle signed ServTD identity + signed TCB
  mapping + issuer chains.
- **json-signer** — sign / finalize / verify JSON for `policyData`, `tdIdentity`,
  and `tdTcbMapping`.
- **migtd-policy-verifier** — verify a signed policy JSON and its issuer chain.

---

## 13. AzCVMEmu Emulation Mode

- Builds MigTD as a **standard Rust user-space app** that runs inside an Azure
  TDX CVM for development/testing (`doc/AzCVMEmu.md`,
  `src/migtd/src/bin/migtd/cvmemu.rs`).
- Replaces TDX payload/tdcall interfaces with `*-emu` shims, uses a tokio
  runtime, and reads policy/root-CA from environment/files.
- Uses the same **`vmcall-raw`** transport as the production Azure build; supports
  real or mocked (`use-mock-quote`, `test_mock_report`) attestation for
  end-to-end flow testing.

---

## 14. Testing & Quality

- **Azure mock-quote test flow** (`sh_script/Azure/Makefile`,
  `build_azure_mock_test.sh`): build IGVM variants with allow-all / bad-FMSPC
  (reject) / mock-quote v2 policies to exercise accept and reject paths without a
  real quoting service.
- **Unit tests** across crates, with coverage tooling
  (`sh_script/unit_test_coverage.sh`).
- **Integration tests** (QEMU + pytest) and **fuzzing** harnesses for migtd,
  policy, crypto, virtio, virtio-serial, vsock, and vmcall-raw.
- **Security** and **memory-usage** test documentation
  (`doc/security_test.md`, `doc/memory_usage_test.md`).
- **Test bypass** `test_disable_ra_and_accept_all` exists for test images and is
  **compile-time blocked** from combining with production attestation features
  (`spdm_attestation` / `policy_v2`) in non-emulator builds.

---

## 15. Configuration & Feature Flags

### Azure config files (`config/Azure/`)
- `collateral_thim.json` — Azure THIM platform collateral.
- `policy_data_raw.json` / `policy_v2_signed.json` — v2 policy (raw / signed).
- `td_identity.json`, `tcb_mapping.json` — ServTD collateral inputs.
- `servtd_info.json` — TD config manifest used for hashing.

### Azure build feature flags (`src/migtd/Cargo.toml`)
- `vmcall-raw` — GHCI / migration transport.
- `igvm-attest` — IGVM quote retrieval.
- `spdm_attestation` — SPDM mutual-attestation secure session.
- `policy_v2` — signed policy + ServTD collateral (also enables
  `attestation/attest-lib-ext` collateral verification).
- `stack-guard`, `vmcall-interrupt`, `oneshot-apic`, `main` — hardening, event
  interrupt, APIC one-shot timer, and the migration binary.

---

## 16. Migration Error Codes (host-visible)

| Code | Cause |
|:----:|-------|
| 1 | VMM-provided data not as expected |
| 3 | Out of memory |
| 4 | TDX module error (often mismatched `SERVTD_INFO_HASH`) |
| 5 | Failed to establish host communication channel |
| 6 | SPDM/secure-session error (e.g. remote quote verification or handshake aborted) |
| 7 | Unable to obtain the quote |
| 8 | Remote quote does not satisfy the migration policy |
