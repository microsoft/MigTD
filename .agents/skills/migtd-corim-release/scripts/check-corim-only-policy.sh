#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$REPO_ROOT"

export SPDM_CONFIG="$REPO_ROOT/config/spdm_config.json"

cargo build \
  --no-default-features \
  --features "AzCVMEmu,policy_v2,test_mock_report,spdm_attestation,servtd_corim"

cargo test -p policy --features "policy_v2,servtd_corim"
