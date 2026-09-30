# SPDM RECEIVE_FAIL Cross-Node Case Study

This case demonstrates why source MigTD's requester error was not the original
failure.

## Symptom

Source MigTD logged:

```text
exchange_msk: spdm_requester_transfer_msk error:
SpdmStatus {
  severity: ERROR,
  status_code: TRANSPORT(RECEIVE_FAIL),
  error_data: None
}

Failure during key exchange status code: 6
```

In the matching MigTD source, status `6` was
`MigrationResult::SecureSessionError`.

## Source sequence

Migration request `19` (`0x13`) ran against MigTD HCS instance
`9DC12BB6-66F9-5D1A-BB9C-B7A887C4DE34`:

```text
17:18:47.283112  GetCachedTdInfo_Success
17:18:47.402795  CreateTdxPrepareMigrationRequest
                     RequestId=19, IsSource=1
17:18:47.403544  SubmitRequest_Sent
17:18:47.403983  PrepareMigration_ProcessSendRequest
                     Bytes=16
17:18:47.404110  PrepareMigration_GetSendData
                     TotalBytesSent=16
                     TotalBytesReceived=0
17:18:47.404276  PrepareMigration_ProcessReceiveRequest_Queued
                     MaxPayloadSize=65524
                     TotalBytesSent=16
                     TotalBytesReceived=0

17:18:53.394723  GetTdReportRequest_Success
                     RequestId=20

17:19:17.412656  PrepareMigrationRequest_Cancel
                     ReceiveEntryPending=true
                     SendEntryPending=false
                     TotalBytesSent=16
                     TotalBytesReceived=0
17:19:17.412711  CancelRequest
17:19:17.419277  PrepareMigrationRequest_ReportStatus_AlreadyCancelled
                     ExistingStatus=0x800704C7
17:19:17.419301  HandleReportStatus
                     PreMigrationStatus=0x0601
17:19:17.419315  MigTdLog
                     TRANSPORT(RECEIVE_FAIL)
17:19:17.419317  MigTdLog
                     RequestId=0x13
                     status code=6

17:19:23.412011  GetTdReportRequest_Success
                     RequestId=21
```

Interpretation:

- Source MigTD sent its initial 16 bytes.
- It received no response bytes.
- The host canceled the pending receive approximately 30 seconds later.
- The cancellation surfaced through spdm-rs as `RECEIVE_FAIL`.
- Successful health checks during and after the failure showed that source
  MigTD remained alive.

## Destination sequence

The destination trace showed:

```text
17:18:34.207  GetTDReport health check succeeds
17:18:47.274  Migration starts
17:18:47.294  Compatibility validation succeeds
17:18:47.370  Target TD prebind uses MigTdHash
                 2F4214E871FD6037A95F71FE9F03A16A
                 E8E0E0C34245ACF026538A6DB57F0D41
                 45FFB780F25914C44B1484B70D0901A7
17:18:47.396  VM realization succeeds
17:18:47.407805 VMMS fails with 0x8007000D
                 vmmsvmmigrationbase.cpp:7285
17:19:04.225  Destination MigTD health check succeeds
17:19:17.411  TCP packet-header read times out, 0x800705B4
17:19:29.422  Unexpected message ID 6, expected 38, 0x80048055
```

There was no destination:

```text
CreateTdxPrepareMigrationRequest IsSource=0
```

and no destination migration `MigTdLog`. Migration never reached destination
MigTD.

## Source-code correlation

The exact host source matching the trace showed that
`vmmsvmmigrationbase.cpp:7285` reported:

```text
Failed to find Migration TD instance for the given hash
```

The later TCP timeout and unexpected message ID occurred only after that
mapping lookup failure.

Relevant host files were:

```text
src/onecore/vm/vmms/migration/vmmsvmmigrationbase.cpp
src/onecore/vm/common/migration/vmmigrationtcptransport.cpp
src/onecore/vm/common/migration/vmmigrationconnection.cpp
src/onecore/vm/test/common/powershell/PowerTest/LiveMigrationUtilities.psm1
```

## Root cause

The destination host could not resolve the source VM's required MigTD hash to
a running destination MigTD instance. Because the destination never submitted
a migration request to MigTD, it never produced an SPDM response. The source
host eventually canceled its pending receive, which source MigTD reported as
`TRANSPORT(RECEIVE_FAIL)`.

Required mapping:

```text
2f4214e871fd6037a95f71fe9f03a16ae8e0e0c34245acf026538a6db57f0d4145ffb780f25914c44b1484b70d0901a7
    ->
9DC12BB6-66F9-5D1A-BB9C-B7A887C4DE34
```

## Validation commands

The reusable preflight command for this case is:

```powershell
.\Test-CrossNodeMigTdBinding.ps1 `
    -SourceMigTdHash `
      2f4214e871fd6037a95f71fe9f03a16ae8e0e0c34245acf026538a6db57f0d4145ffb780f25914c44b1484b70d0901a7 `
    -DestinationSerialLogPath .\destination-migtd.serial.log `
    -DestinationMigTdHcsId 9DC12BB6-66F9-5D1A-BB9C-B7A887C4DE34 `
    -PowerTestPath <POWERTEST_PATH> `
    -RequireRuntimeHash
```

The underlying destination mapping can also be inspected directly:

```powershell
Get-VmHostMigrationTdMapping

$expected =
    '2f4214e871fd6037a95f71fe9f03a16ae8e0e0c34245acf026538a6db57f0d4145ffb780f25914c44b1484b70d0901a7'

$mapping = (Get-VmHostMigrationTdMapping |
    ConvertFrom-Json -AsHashtable).mappings

$mapping.GetEnumerator() | Format-Table Key, Value
$mapping[$expected]
```

Also verify:

1. Source and destination deployment packages contain the intended IGVM.
2. Their `.igvm.hash` values match the required mapping key.
3. Destination MigTD serial `TD Info Hash:` equals the intended runtime hash.
4. The mapping value is the HCS ID of the running destination MigTD instance.

## Evidence limitations

The ETL exposed the hash requested for prebind but did not prove the actual
runtime TD Info Hash of destination MigTD. That value required serial output,
the exact build artifact, or a parsed TDREPORT.

Likewise, successful destination GetTDReport health checks proved the
destination MigTD was alive; they did not prove that the migration request
reached it.
