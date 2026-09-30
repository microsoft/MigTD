---
type: Reference
title: Integration Testing — QEMU/vsock
description: The non-EMU local QEMU+pytest integration layer using vsock or serial transports.
tags: [integration-test, qemu, pytest]
timestamp: 2026-07-13T22:37:00+00:00
---

# Integration Testing — QEMU/vsock

This real-transport integration layer exists **in addition to** the
AzCVMEmu-based `migtdemu.sh` / EMU gauntlet layer covered in
[verification-and-checklist.md](verification-and-checklist.md) and the
`migtd-review` skill.

## Local QEMU + pytest (vsock/serial transports)

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

Serial transport swaps `--features stack-guard,virtio-serial` and adds
`--device_type serial` to the pytest invocations. This layer exercises the real
no_std firmware image end-to-end without depending on a cloud-provider test
environment.

Provider-specific hardware validation, packaging, and operational procedures
are maintained by downstream integration repositories.
