#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

"""Exercise component TCB rules with verified mock quotes, never skip-RA."""

import copy
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "target/component-tcb-policy"
COMPONENTS = ("platform", "tdxModule", "AttestationModule")


def rule(reference):
    return {"operation": "greater-or-equal", "reference": reference}


def run_case(base, name, components, reject=False, operation="migration"):
    policy = copy.deepcopy(base)
    policy["policyData"]["version"] = "2.1"
    policy["policyData"]["policy"].append({"global": components})
    policy_path = OUTPUT / f"{name}.json"
    policy_path.write_text(json.dumps(policy, separators=(",", ":")) + "\n")
    log_path = OUTPUT / f"{name}.log"
    guest_logs = [
        ROOT / f"migtd_{operation}_{role}.log" for role in ("source", "destination")
    ]
    for path in guest_logs:
        path.unlink(missing_ok=True)
    command = [
        "timeout", "--kill-after=10s", "300", "./migtdemu.sh",
        "--policy-v2", "--policy-file", str(policy_path),
        "--policy-issuer-chain-file", "./config/AzCVMEmu/policy_issuer_chain.pem",
        "--servtd-tcb-mapping-file", "./config/AzCVMEmu/tcb_mapping_signed.json",
        "--mock-report", "--features", "spdm_attestation",
        "--both", "--no-sudo", "--log-level", "info", "--operation", operation,
    ]
    with log_path.open("w") as log:
        result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    with log_path.open("a") as log:
        for path in guest_logs:
            if path.exists():
                log.write(f"\n=== {path.name} ===\n")
                log.write(path.read_text(errors="replace"))
    output = log_path.read_text(errors="replace")
    if reject:
        passed = result.returncode not in (0, 124, 137) and "TcbEvaluation" in output
    else:
        passed = (
            result.returncode == 0
            and f"SUCCESS: ({operation}) completed!" in output
            and "TcbEvaluation" not in output
        )
    if not passed:
        print("\n".join(output.splitlines()[-60:]), flush=True)
        raise SystemExit(f"FAIL {name}: exit={result.returncode}; see {log_path}")
    print(f"PASS {name}", flush=True)


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    base = json.loads((ROOT / "config/AzCVMEmu/policy_v2_signed.json").read_text())
    relative = {
        name: {"tcbDate": rule("self"), "tcbEvaluationDataNumber": rule("self")}
        for name in COMPONENTS
    }
    absolute = {
        name: {"tcbDate": rule("2000-01-01T00:00:00Z"), "tcbEvaluationDataNumber": rule(1)}
        for name in COMPONENTS
    }
    run_case(base, "relative", relative)
    run_case(base, "absolute", absolute)
    for name in COMPONENTS:
        for field, floor in (
            ("tcbDate", "2100-01-01T00:00:00Z"),
            ("tcbEvaluationDataNumber", 0xFFFFFFFF),
        ):
            rules = copy.deepcopy(absolute)
            rules[name][field] = rule(floor)
            run_case(base, f"reject-{name}-{field}", rules, reject=True)
    impossible = {
        name: {"tcbDate": rule("2100-01-01T00:00:00Z"), "tcbEvaluationDataNumber": rule(0xFFFFFFFF)}
        for name in COMPONENTS
    }
    run_case(base, "rebind-skips-global", impossible, operation="rebind")


if __name__ == "__main__":
    main()
