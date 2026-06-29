# MigTD TiP Loopback Test Package

Self-contained TDX live-migration test for a labblade. Build on Linux, copy the
package to the TDX host, run loopback migrations manually.

## 1. Build (Linux)

```bash
./sh_script/Azure/tip/build_tip_package.sh --out out/tip-package --fetch-collaterals
```

Produces in `out/tip-package/`:

| File | Role |
|------|------|
| `test-migtd-accept-all.igvm` + `.hash` | allow-all policy → migration succeeds |
| `test-migtd-reject-all.igvm` + `.hash` | bad-FMSPC policy → migration rejected |
| `test-migtd-real.igvm` + `.hash` | `config/Azure/policy_data_raw.json` → succeeds if node FMSPC/TCB match |
| `test-migtd-getquote-all.igvm` + `.hash` | GetQuote init image |
| `Invoke-TdxLmLoopback.ps1`, `Run-TipTests.ps1` | host test scripts |

`.hash` is the plain servtd hash the host reads as `MigTdHash`. Built with
MigTD-native tooling only (`cargo image`, `migtd-hash`, `build_azure_mock_test.sh`).

## 2. Run (TDX labblade, elevated PowerShell)

Copy `out/tip-package` to the host, then:

```powershell
# one-time host prep (loopback migration, test SecFw — may reboot)
.\Run-TipTests.ps1 -PackageDir . -PowerTestPath C:\path\to\PowerTest -InitializeHost

# single case
.\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-accept-all.igvm -PowerTestPath C:\path\to\PowerTest
.\Invoke-TdxLmLoopback.ps1 -IgvmFilePath .\test-migtd-reject-all.igvm -ExpectReject -PowerTestPath C:\path\to\PowerTest
```

Each case: start MigTD → register hash → create TDX VM → `Move-VM -DestinationHost
localhost` → assert → cleanup (`AlwaysDisabled`, remove mapping/VM). Requires
PowerTest `TdxLiveMigrationUtilities` for `New-TestHcsMigTd`. Rebind: re-run with a
second image (different hash) while a TD is bound.

Design: `MigTD/doc/integration_test_azure_tip.md`.
