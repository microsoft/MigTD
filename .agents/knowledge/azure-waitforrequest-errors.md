---
type: Reference
title: Azure WaitForRequest Error and ReportStatus Map
description: Error logging and host-visible ReportStatus behavior for the Azure IGVM vmcall-raw path with SPDM attestation and policy v2.
tags: [azure, igvm, vmcall-raw, spdm, waitforrequest, reportstatus, errors]
timestamp: 2026-09-04T20:38:52+00:00
---

# Azure WaitForRequest Error and ReportStatus Map

Verified against `ms/integration` commit `a3bc5382`.

## Scope

This reference covers the production Azure IGVM path built with:

- `vmcall-raw`;
- `spdm_attestation`; and
- `policy_v2`.

The dispatch loop is in `src/migtd/src/bin/migtd/main.rs`.
Request parsing and status reporting are in
`src/migtd/src/migration/session.rs`.

## Host-visible status encoding

`report_status()` sends success with `pre_migration_status = 0`. For a
recognized failure, it sends `pre_migration_status = 1` and puts the numeric
`MigrationResult` in `error_code`.

| Code | `MigrationResult` |
| ---: | --- |
| 0 | `Success` |
| 1 | `InvalidParameter` |
| 2 | `Unsupported` |
| 3 | `OutOfResource` |
| 4 | `TdxModuleError` |
| 5 | `NetworkError` |
| 6 | `SecureSessionError` |
| 7 | `MutualAttestationError` |
| 8 | `PolicyUnsatisfiedError` |
| 9 | `InvalidPolicyError` |
| 10 | `VmmCanceled` |
| 11 | `VmmInternalError` |
| 12 | `UnsupportedOperationError` |
| 255 | `InitializationError` |

The ordinary Azure/SPDM request-processing paths primarily return codes
1, 3, 4, 5, 6, 7, 8, 11, and 12. SPDM vendor-defined errors preserve any
recognized `MigrationResult` supplied by the peer.

## Pre-dispatch `WaitForRequest` paths

| Failure | Code | Log emitted? | ReportStatus attempted? |
| --- | ---: | --- | --- |
| Policy unavailable while sizing the shared buffer | 1 | No direct log | No request ID is available |
| Event log unavailable while sizing the shared buffer | 1 | No direct log | No request ID is available |
| Shared request-buffer allocation fails | 3 | Yes | No request ID is available |
| Initial WaitForRequest VMCALL fails | normally 1 | Yes | No request ID is available |
| Shared response cannot be copied to private memory | 3 | Yes | No |
| VMM data-status byte reports failure | 11 | Yes | Yes, if the request ID is readable |
| Operation byte is unknown or feature-disabled | 12 | Yes | Yes, if the request ID is readable |
| Payload range overflows or exceeds the shared buffer | 1 | Yes | Yes, if the request ID is readable |
| Payload size, reserved fields, or optional-field framing is invalid | 1 | Generic decode log | Yes, if the request ID is readable |

The outer loop uses:

```rust
if let Ok(request) = wait_for_request().await {
    *PENDING_REQUEST.lock() = Some(request);
}
```

It therefore discards every `wait_for_request()` error without an additional
caller-level log. Most lower-level errors already log, but the policy/event-log
lookups in `calculate_shared_page_nums()` do not. Policy absence is normally
caught earlier by policy initialization; the helper itself nevertheless has a
silent error path.

Malformed requests shorter than the eight-byte request ID can be logged but
cannot receive ReportStatus. `reject_request()` schedules the error report only
when `read_request_id()` succeeded.

`try_accept_request()` handles a duplicate migration request ID by returning
`Poll::Pending`. This is not represented as an error, produces no log, and
sends no ReportStatus; the request remains stalled.

## Dispatched operation status map

Every dispatched handler failure receives a generic operation-level error log
containing its final numeric status. Lower layers often provide a more specific
cause.

| Operation or stage | Final status |
| --- | --- |
| Raw transport creation, connect, or shutdown failure | 1 |
| Malformed pre-session framing or peer-data blob | 1 |
| Pre-session transport failure or timeout | 5 |
| SPDM requester/responder construction failure | 6 |
| Generic SPDM negotiation, protocol, transcript, crypto, VDM, or state failure | 6 |
| TDX metadata, migration-version, or key operation failure preserved through SPDM | 4 |
| Incompatible migration versions | 1 |
| Local quote generation/GetQuote failure | 7 |
| Explicit REPORTDATA/TH1 binding failure | 7 |
| Policy-v2 authentication failure, including peer quote verification | 8 |
| `GetTdReport` TDG.MR.REPORT failure | 4 |
| `GetTdReport` output-length invariant failure | 1 |
| `GetMigtdData` local report-generation failure | 1 |
| `EnableLogArea` before a log area exists | 12 |
| `EnableLogArea` with an invalid level | 1 |

SPDM conversion is intentionally lossy for ordinary protocol errors:
non-vendor `SpdmStatus` values become `SecureSessionError` (6). Application
errors encoded as SPDM vendor-defined values are decoded back to their
`MigrationResult`, preserving codes such as 4, 7, and 8.

## GetQuote is not uniquely identifiable

The Azure IGVM quote path is:

```text
quote-service Busy/GetQuote error
  -> retry exhaustion or non-retriable failure
  -> QuoteGenerationFailed
  -> gen_quote_spdm logs the error
  -> MutualAttestationError
  -> ReportStatus error_code 7
```

REPORTDATA binding failures also use code 7. ReportStatus therefore cannot
distinguish quote acquisition from a session-binding failure. Under policy v2,
peer quote verification occurs inside policy authentication and reports code 8
instead. Logs are required to identify the exact stage.

## ReportStatus delivery behavior

`StartMigration`, `StartRebinding`, and `EnableLogArea` add caller-level logging
when `report_status()` returns an error. `GetTdReport` and `GetMigtdData`
discard that result, but all currently returned errors are logged inside
`report_status()`:

- shared-memory allocation failure;
- invalid status code; and
- the initial ReportStatus VMCALL failure.

The latter two call sites still lose operation-specific caller context and
should not be described as completely silent.

The ReportStatus confirmation loop has no timeout. If the host never changes
the per-buffer status to success, the future remains pending indefinitely
while emitting `Pending confirmation` at info level on each relevant wake.

## Logging interpretation

“Log emitted” in this document means that the code invokes a logging macro.
Whether the VMM can retrieve that record depends on log-area initialization
and provisional-log configuration. Do not equate a code-level log call with
guaranteed host-visible diagnostics.
