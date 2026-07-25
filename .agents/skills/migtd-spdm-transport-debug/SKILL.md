---
name: migtd-spdm-transport-debug
description: Debug MigTD SPDM transport and key-exchange failures during TDX migration or rebinding, especially `TRANSPORT(RECEIVE_FAIL)`, `spdm_requester_transfer_msk`, status code 6, pending receives with zero bytes, and cross-node source/destination trace mismatches. Use when MigTD reports an SPDM requester/responder transport error, when source MigTD times out waiting for a peer, or when Hyper-V migration fails before the destination MigTD receives a request.
---

# MigTD SPDM Transport Debugging

Use this skill to find the first causal failure behind MigTD SPDM transport
errors. A requester-side `TRANSPORT(RECEIVE_FAIL)` is often a secondary symptom:
the source waited for a response that the destination host never produced.

Do not diagnose this class of failure from one MigTD error line. Correlate the
source and destination host traces, both MigTD logs, deployed image hashes, and
the exact source revisions matching the test.

## Required access and evidence

Before analyzing code or assigning a root cause, collect or ask the user for:

| Requirement | Why it is required |
|---|---|
| Source-node ETL | Shows request creation, bytes sent/received, cancellation, and source `MigTdLog` events. |
| Destination-node ETL | Usually contains the first host-side failure that prevented a response. |
| Source and destination MigTD serial logs | Shows whether either MigTD booted, received the request, and logged a terminal error. |
| Exact host build on each node | Determines the matching Windows OS source branch and event schema. |
| Access to the matching Windows OS source branch | File/line references in VMMS and Worker traces are meaningful only against the matching build. |
| Exact deployed MigTD repository, branch, commit/tag, and feature set | Local `main`, `integration`, or `integration2` may not match the deployed image. |
| Source and destination IGVM files and `.igvm.hash` files | Verifies that both nodes use the intended image and expected prebind hash. |
| MigTD HCS IDs, target VM IDs, migration request ID, and repro time/time zone | Required to filter concurrent health checks and unrelated migrations. |
| MigTD package/build manifest, if available | Prevents comparing traces against a locally rebuilt but different image. |

If any branch, build, or repository is unknown, stop and ask for it. Never
silently use the currently checked-out branch as a substitute for deployed
source.

For cross-node traces, confirm whether clocks are synchronized and normalize
timestamps to one time zone before ordering events.

## Source repositories

These are the source repositories used for this investigation. Agents may need
the user to grant access, provide a checkout, or identify the correct branch.

| Repository | Access and revision requirement | Relevant source |
|---|---|---|
| Microsoft MigTD: `https://github.com/microsoft/MigTD.git` or the user's deployment fork | Use the exact deployed branch/commit/tag. Record submodule SHAs. | `src/migtd/src/bin/migtd/main.rs`, `src/migtd/src/migration/session.rs`, `src/migtd/src/migration/spdm_session.rs`, `src/migtd/src/migration/transport.rs`, `src/migtd/src/migration/mod.rs`, `src/migtd/src/spdm/`, `src/devices/vmcall_raw/src/` |
| spdm-rs: `https://github.com/ccc-spdm-tools/spdm-rs` | Use the SHA pinned by the deployed MigTD commit, not the submodule's upstream head. | `spdmlib/src/requester/context.rs`, `spdmlib/src/error.rs`, requester/responder handshake code |
| td-shim: `https://github.com/confidential-containers/td-shim` | Use the SHA pinned by the deployed MigTD commit. | `tdx-tdcall/src/tdx.rs`, `tdx-tdcall/src/lib.rs`; MigTD TDVMCALL WaitForRequest, ReportStatus, Send, and Receive leaves |
| Windows OS source (`os.2020`): `https://microsoft.visualstudio.com/DefaultCollection/OS/_git/os.2020` | Restricted Azure DevOps/GVFS repository. Ask for access and the branch matching the source and destination host build. Do not use an arbitrary OS branch because line numbers and behavior drift. | Paths listed below |
| ACC-CVM-IgvmAgent: `https://dev.azure.com/msazure/One/_git/ACC-CVM-IgvmAgent` | Optional but needed when health-check/GetTDReport or agent forwarding behavior is part of the timeline. Ask for the branch deployed on the host. | Search for `MigTdReport`, host API forwarding, and MigTD health-check code |

Important Windows OS source paths:

```text
src/onecore/vm/vmms/migration/vmmsvmmigrationbase.cpp
src/onecore/vm/common/migration/vmmigrationtcptransport.cpp
src/onecore/vm/common/migration/vmmigrationconnection.cpp
src/onecore/vm/worker/migration/TdxProtocol.cpp
src/onecore/vm/dv/chipset/ghci/GhciDevice.cpp
src/onecore/vm/dv/chipset/ghci/GhciRequestManager.cpp
src/onecore/vm/dv/chipset/ghci/GhciLogHandler.cpp
src/onecore/vm/dv/chipset/ghci/GhciTypes.h
src/onecore/vm/dv/chipset/ghci/*RequestContext.cpp
src/onecore/vm/test/common/powershell/PowerTest/LiveMigrationUtilities.psm1
src/onecore/vm/test/common/powershell/PowerTest/TdxLiveMigrationUtilities.psm1
```

Record provenance before reading source:

```bash
git -C <MIGTD_ROOT> remote -v
git -C <MIGTD_ROOT> branch --show-current
git -C <MIGTD_ROOT> rev-parse HEAD
git -C <MIGTD_ROOT> submodule status deps/spdm-rs deps/td-shim
```

For the Windows GVFS checkout, use its supported Windows-side `git.cmd` or
GVFS tooling and record at least the remote, branch, and commit. If the agent
cannot access the checkout or hydrate a required file, ask the user rather than
guessing from another branch.

## Tools used

### Trace capture and decoding

| Tool | Use |
|---|---|
| PowerShell 7 (`pwsh`) | Runs the diagnostic scripts and preserves structured event properties. |
| `wpr.exe` | Captures focused ETW traces on source and destination nodes. |
| `logman.exe query providers` | Confirms provider registration and GUIDs. |
| `tracerpt.exe` | Converts ETL to raw XML/CSV when `Get-WinEvent` cannot decode all providers. |
| `Get-WinEvent` | Reads event channels and decodes ETL events when manifests are available. |
| `wevtutil.exe` | Temporarily enables VMMS/Worker analytic channels. |
| Windows Performance Analyzer (WPA) | Manual fallback for provider/event inspection when scripted decoding is incomplete. |
| `wslpath` | Converts WSL paths before invoking Windows trace tools from WSL. |

### Timeline and source analysis

| Tool | Use |
|---|---|
| `rg` | Filters event timelines by request ID, VM ID, timestamps, HRESULT, file, and message. |
| `awk` | Converts `tracerpt` XML into compact chronological provider/task/data timelines. |
| `sed`, `cut`, `sort` | Normalizes fields and counts event/task names. |
| `git` and Windows/GVFS `git.cmd` | Confirms exact branches, commits, remotes, and submodule revisions. |
| `strings` | Last-resort ETL sanity check only; never use strings output as the sole diagnostic evidence. |

### Existing MigTD diagnostic scripts

Reuse these instead of inventing a different capture path:

```text
.agents/skills/migtd-tip-troubleshoot/scripts/Invoke-TdxLmDiagnosticCapture.ps1
.agents/skills/migtd-tip-troubleshoot/scripts/Invoke-GhciVDevDiagnosticCapture.ps1
.agents/skills/migtd-tip-troubleshoot/scripts/Export-GhciVDevEvents.ps1
.agents/skills/migtd-tip-troubleshoot/scripts/TdxLmTraceProfile.wprp
.agents/skills/migtd-tip-troubleshoot/scripts/Test-MigTdHashBinding.ps1
.agents/skills/migtd-spdm-transport-debug/scripts/Export-MigTdMigrationTimeline.ps1
.agents/skills/migtd-spdm-transport-debug/scripts/Compare-MigTdNodeTraces.ps1
.agents/skills/migtd-spdm-transport-debug/scripts/Get-MigTdDeploymentProvenance.ps1
.agents/skills/migtd-spdm-transport-debug/scripts/Test-CrossNodeMigTdBinding.ps1
```

The GHCI VDev provider is:

```text
Name: Microsoft.Windows.HyperV.GhciVDev
GUID: AEFC8638-19A2-553A-06CB-C3984FFC7EE8
```

## Reusable scripted workflow

Capture provenance on both nodes before changing mappings or packages:

```powershell
.\Get-MigTdDeploymentProvenance.ps1 `
    -MigTdRepoPath <MIGTD_ROOT> `
    -OsRepoPath <OS_ROOT> `
    -IgvmFilePath <MIGTD.igvm> `
    -HashFilePath <MIGTD.igvm.hash> `
    -SerialLogPath <MIGTD_SERIAL.log> `
    -MigTdHcsId <MIGTD_HCS_ID> `
    -PowerTestPath <POWERTEST_PATH> `
    -OutputDir <PROVENANCE_OUTPUT>
```

On the destination, verify the source-required hash, runtime hash, host
mapping, and running MigTD instance before `Move-VM`:

```powershell
.\Test-CrossNodeMigTdBinding.ps1 `
    -SourceHashFilePath <SOURCE_MIGTD.igvm.hash> `
    -DestinationSerialLogPath <DESTINATION_MIGTD_SERIAL.log> `
    -DestinationMigTdHcsId <DESTINATION_MIGTD_HCS_ID> `
    -PowerTestPath <POWERTEST_PATH> `
    -RequireRuntimeHash
```

After collecting source and destination ETLs, normalize both traces:

```powershell
.\Export-MigTdMigrationTimeline.ps1 `
    -EtlPath <SOURCE.etl> `
    -Node Source `
    -OutputDir <SOURCE_TIMELINE_DIR>

.\Export-MigTdMigrationTimeline.ps1 `
    -EtlPath <DESTINATION.etl> `
    -Node Destination `
    -OutputDir <DESTINATION_TIMELINE_DIR>
```

Then align the request window:

```powershell
.\Compare-MigTdNodeTraces.ps1 `
    -SourceTimelinePath <SOURCE_TIMELINE_DIR>\migtd-migration-timeline.csv `
    -DestinationTimelinePath <DESTINATION_TIMELINE_DIR>\migtd-migration-timeline.csv `
    -RequestId <MIGRATION_REQUEST_ID> `
    -OutputDir <COMPARISON_DIR>
```

Use `-DestinationClockOffsetMilliseconds` only when clock comparison proves a
known offset. The comparison script marks a first destination failure
*candidate*; verify that event against the exact matching Windows OS source.

## Investigation workflow

### 1. Establish exact provenance

Create a short evidence header before interpreting any event:

```text
Source host build:
Destination host build:
Windows OS source branch/commit:
MigTD repository/branch/commit:
spdm-rs submodule SHA:
td-shim submodule SHA:
Source IGVM/hash:
Destination IGVM/hash:
Source MigTD HCS ID:
Destination MigTD HCS ID:
Target VM ID:
Migration request ID:
Trace time zone:
```

If source and destination host builds differ, obtain both matching OS branches
or explicitly document which side cannot be source-correlated.

### 2. Capture both sides around one clean repro

Start the destination capture first, then the source capture, reproduce once,
and stop both captures immediately afterward. Include:

- VMMS, Worker, VID, VmsIf, HCL, and GHCI VDev ETW providers.
- VMMS/Worker Admin, Operational, and temporarily enabled Analytic channels.
- Both MigTD serial logs.
- Test console output.
- IGVMAgent process health when the image depends on the agent.

Use `Invoke-TdxLmDiagnosticCapture.ps1 -CaptureEtw -EnableAnalytic` where
possible. A GHCI-only trace is useful for request sequencing but is not enough
to identify a VMMS or transport-connection failure.

### 3. Export ETL data without discarding raw evidence

Create the normalized cross-provider timeline:

```powershell
.\Export-MigTdMigrationTimeline.ps1 `
    -EtlPath <TRACE.etl> `
    -Node <Source|Destination> `
    -OutputDir <OUTPUT_DIR>
```

For a GHCI-only provider export, use:

```powershell
.\Export-GhciVDevEvents.ps1 `
    -EtlPath <TRACE.etl> `
    -OutputDir <OUTPUT_DIR>
```

For a complete raw trace:

```powershell
tracerpt.exe <TRACE.etl> -of XML -o <TRACE.xml> -y
tracerpt.exe <TRACE.etl> -of CSV -o <TRACE.csv> -y
```

Keep the original ETL. Compact timelines may be retained for analysis, but do
not replace the original trace with a filtered file.

### 4. Analyze the destination first

The requester error says only that no acceptable response arrived. Find the
destination's first fatal event before analyzing the source timeout.

Order destination events and answer:

1. Did migration reach the destination host?
2. Did compatibility validation complete?
3. Which MigTD hash was supplied to target-TD prebind?
4. Was the target VM realized?
5. Was a destination `CreateTdxPrepareMigrationRequest` emitted with
   `IsSource=0`?
6. Did destination MigTD send or receive any bytes for the request?
7. What is the first error before later timeout/message-order errors?

If no destination prepare-migration request exists, the failure occurred before
destination MigTD or SPDM processing. Do not blame destination SPDM policy,
attestation, or transport code without evidence that MigTD received a request.

Search the matching Windows OS source for the first trace file and line. Read
the surrounding function, not just the line. Line numbers from a different
branch are not reliable.

### 5. Build the source request timeline

Filter by the migration request ID and retain these GHCI events:

```text
GetCachedTdInfo_Success
GetMaxReceiveBufferCapacity
CreateTdxPrepareMigrationRequest
PrepareMigrationRequest_FillBuffer
SubmitRequest_Sent
PrepareMigration_ProcessSendRequest
PrepareMigration_GetSendData
PrepareMigration_ProcessReceiveRequest_Queued
PrepareMigrationRequest_Cancel
CancelRequest
PrepareMigrationRequest_ReportStatus_AlreadyCancelled
HandleReportStatus
MigTdLog
```

Always report:

- `IsSource`
- request ID in decimal and hexadecimal
- bytes sent and received
- whether send/receive entries were pending at cancellation
- cancellation HRESULT
- `PreMigrationStatus`
- all `MigTdLog` entries attached to the request

A sequence of `Sent > 0`, `Received = 0`, queued receive, host cancellation,
and then `TRANSPORT(RECEIVE_FAIL)` means the source error was produced after
the host aborted an unanswered receive. It does not identify why the
destination failed to respond.

### 6. Correlate source, destination, and health checks

Produce one time-ordered table:

| Time | Node | Provider | Request/VM | Event | Interpretation |
|---|---|---|---|---|---|

Place the destination's first failure and the source's later cancellation in
the same table. Calculate the delay; a stable 30- or 60-second gap usually
identifies a host or session timeout boundary.

Separate periodic `GetTDReport` health checks from migration requests by
request ID. Successful health checks before, during, or after the failure prove
that MigTD is alive and its basic GHCI request path works. They do not prove
that migration reached destination MigTD.

### 7. Trace the software error mapping

In the exact deployed MigTD source, follow:

```text
handle_pre_mig
  -> exchange_msk
  -> migration_src_exchange_msk / migration_dst_exchange_msk
  -> spdm_requester_transfer_msk / spdm_responder_transfer_msk
  -> spdmlib RequesterContext::receive
  -> vmcall_raw receive
  -> TDVMCALL<MigTD> Receive
```

Current source maps:

```text
spdmlib transport RECEIVE_FAIL
    -> SpdmStatus TRANSPORT(RECEIVE_FAIL)
    -> MigrationResult::SecureSessionError
    -> status code 6
```

Verify this mapping on the deployed branch. Do not assume status values are
unchanged.

For a requester receive failure, inspect:

```text
deps/spdm-rs/spdmlib/src/requester/context.rs
deps/spdm-rs/spdmlib/src/error.rs
src/migtd/src/spdm/spdm_req.rs
src/migtd/src/migration/spdm_session.rs
src/migtd/src/migration/session.rs
src/devices/vmcall_raw/src/transport/vmcall.rs
deps/td-shim/tdx-tdcall/src/tdx.rs
```

### 8. Verify destination MigTD mapping and runtime hash

On the destination host:

```powershell
Get-VmHostMigrationTdMapping
```

Parse the mapping and verify:

```text
source VM's required MigTdHash -> destination MigTD HCS ID
```

Do not confuse:

```text
expected host/prebind hash from .igvm.hash
actual runtime TD Info Hash printed by MigTD
outer TDREPORT SERVTD_HASH
```

The ETL can show the hash requested for prebind, but it may not prove the
runtime TD Info Hash of the destination MigTD. Obtain the actual value from:

- destination MigTD serial `TD Info Hash:` output;
- the exact destination `.igvm.hash` plus matching build provenance; or
- a parsed TDREPORT obtained from an explicit `MigTdReport` request.

### 9. Classify primary and secondary failures

Use these rules:

| Evidence | Classification |
|---|---|
| Destination VMMS fails before destination `CreateTdxPrepareMigrationRequest` | Host setup, mapping, prebind, realization, or connection failure; not a destination SPDM failure. |
| Destination request exists but no MigTD send/receive progress | GHCI/transport dispatch boundary. |
| Both sides exchange bytes and destination MigTD logs policy/attestation failure | MigTD/SPDM/policy failure; inspect destination log first. |
| Source receive is canceled with zero bytes after a destination error | Source `RECEIVE_FAIL` is secondary. |
| Later packet-header timeout or unexpected message ID follows an earlier error | Consequence of the first failure; do not report it as root cause. |
| Periodic GetTDReport continues succeeding | MigTD remains alive; migration-specific path failed. |

## Current logging caveat

On the current `integration2` implementation, production handlers for
`StartMigration`, `StartRebinding`, `GetTDReport`, `EnableLogArea`, and
`GetMigtdData` use `TRACE` for request entry and success in
`src/migtd/src/bin/migtd/main.rs`. Error paths use `ERROR`.

Therefore, absence of an `INFO`-level `MigTdLog` entry is not proof that a
request was never handled. Prefer GHCI request events and byte counters, and
verify logging levels again on the deployed branch.

## Required report format

Deliver the result in this order:

1. **Provenance**: source/destination builds, branches, commits, image hashes,
   request ID, and time zone.
2. **Destination timeline**: first causal error highlighted.
3. **Source timeline**: send, pending receive, cancellation, report status,
   and `MigTdLog`.
4. **Cross-node correlation**: time difference between the first destination
   failure and source cancellation.
5. **Root cause**: one evidence-backed sentence.
6. **Secondary symptoms**: requester `RECEIVE_FAIL`, timeouts, and
   message-order errors.
7. **Evidence gaps**: missing source access, branch, actual runtime hash, or
   undecoded provider data.
8. **Corrective action**: exact mapping, deployment, source, or code change
   needed to remove the first failure.

Never report `TRANSPORT(RECEIVE_FAIL)` alone as the root cause.

## Detailed worked example

Read `references/spdm-receive-fail-case-study.md` for the event sequence and
reasoning from the cross-node failure that motivated this skill.
