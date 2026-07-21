---
type: Reference
title: Integration Testing — QEMU/vsock and Azure TiP
description: The two non-EMU integration test layers — local QEMU+pytest (vsock/serial) and real-hardware Azure TDX loopback migration (TiP) — with build/run commands and current status.
tags: [integration-test, qemu, azure, tip, pytest]
timestamp: 2026-07-13T22:37:00+00:00
---

# Integration Testing — QEMU/vsock and Azure TiP

Two distinct real(er)-transport integration layers exist **in addition to**
the AzCVMEmu-based `migtdemu.sh` / EMU gauntlet layer covered in
[verification-and-checklist.md](verification-and-checklist.md) and the
`migtd-review` skill. Don't confuse the three.

## 1. Local QEMU + pytest (vsock/serial transports)

Canonical source: [doc/integration_test.md](../../doc/integration_test.md).

```bash
./sh_script/preparation.sh
cd sh_script/test   # configure conf/pyproject.toml first
# Vsock build
cargo image --policy config/policy_pre_production_fmspc.json \
    --root-ca config/Intel_SGX_Provisioning_Certification_RootCA_preproduction.cer
sudo pytest -k "cycle"        # stress_test_cycles must be 1 in the config
sudo pytest -k "not cycle"    # after: bash sh_script/build_final.sh -t test -c -a on
```

Serial transport variant swaps `--features stack-guard,virtio-serial` and
adds `--device_type serial` to the pytest invocations. This is the **only**
layer that exercises the real no_std firmware image end-to-end without Azure.

## 2. Azure TiP (real TDX hardware, loopback live migration)

Canonical source: [doc/integration_test_azure_tip.md](../../doc/integration_test_azure_tip.md).
**Status: Draft design**, not yet wired into CI (self-hosted TDX agent still
to be provisioned).

- Build host (Linux): Rust 1.88.0 + `rust-src` + `x86_64-unknown-none`,
  private `ms-crates-io` feed access, `./sh_script/preparation.sh`.
- Lab blade (Windows TDX host): test Secure Firmware DLL + registry key
  (reboot once), TDX-LM velocity feature `53058573`, `Enable-VMMigration`,
  `Enable-LoopbackMigration`.
- Build package:
  ```bash
  ./sh_script/Azure/tip/build_tip_package.sh \
      --out out/tip-package \
      --os-root /path/to/os.2020 \
      --hcstest-dir /path/to/prebuilt/HCSTest \
      --secfw-file /path/to/secfw_test_GenuineIntel.dll
  ```
  Produces `test-migtd.igvm` for the default real policy, named
  `test-migtd-{accept-all,reject-all,getquote-all}.igvm` policy variants, and
  `_mock_quote` counterparts. The default and mock-quote policy builds each
  also have a `_rebind` image whose otherwise identical policy has `policySvn` incremented
  by one and is signed by the same key. HCSTest must be a prebuilt package
  containing its v2 netfx DLL; source alone is insufficient. Regular images
  use IGVMAgent GetQuote; mock-quote images use built-in quote data.
- `migtd-hash --manifest config/Azure/servtd_info.json --image <image>
  --policy-v2` — the printed **last line** (96 hex chars) is the direct
  `SERVTD_INFO_HASH` written to `<image>.hash` (`MigTdHash` on the host side).
  Do not use `--calc-servtd-hash`; that outer TDREPORT hash fails prebind.
- Test cases: accept-all, reject-all, real-policy (FMSPC/TCB match),
  getquote-all, mock-quote/no-agent smoke test, ServTdExt prebind layout,
  rebind (same or different image through `Test-TdxLmRebind.ps1`), cycle
  (repeat N×).
- All TiP VM tests keep host migration policy `DisabledByDefault` and explicitly
  opt each test TD in with `EnabledIfHostPermits` before assigning its MigTD
  migration-policy hash.
- For lab-blade setup failures, generic `Move-VM` errors, MigTD serial capture,
  ServTD hash verification, and VMMS/Worker ETW diagnosis, use the
  [`migtd-tip-troubleshoot`](../skills/migtd-tip-troubleshoot/SKILL.md) skill.
- Out of scope here: production signing/release, and the QEMU/vsock/serial
  flow above (Azure uses `vmcall-raw`, not virtio/vsock).
