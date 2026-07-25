# .agents/knowledge — topical reference index

## Workflow & conventions

* [Commit Hygiene, Remotes & Workflow Patterns](commit-and-workflow.md) - DCO sign-off, force-push rules, remote layout, rebase/cherry-pick patterns, issue filing.
* [Setup, Verification Gauntlet & Pre-done Checklist](verification-and-checklist.md) - Mandatory post-checkout setup, the four-CI-workflow gauntlet, EMU invocations, and the "am I done" checklist.
* [Code Style Preferences](code-style.md) - Diff minimization, error handling, logging discipline.
* [Anti-patterns — Things To NOT Do](anti-patterns.md) - Collected pushback items from past sessions.
* [Engineering Decisions Log](decisions-log.md) - Concrete decisions (feature/commit kept vs. dropped) with SHAs — append-only.

## Domain knowledge

* [MigTD Domain Facts](domain-facts.md) - Trust model, one-hash/CoRIM lookup, signer-anchor and MROWNER semantics, verifiers, vmcall invariants, and heap sizing.
* [MigTD Architecture Overview (Azure Build)](architecture-overview.md) - Navigation map of functional areas to source/doc.
* [Security Bypasses](security-bypasses.md) - Which verification checks are bypassed under dev/test build features, and why.
* [Boot Measurements](boot-measurements.md) - How MRTD/RTMR0-3 are populated, including the RTMR1 root+EKU anchor and redacted RTMR2 policyData.
* [Init_TDINFO and ServtdExt Usage Summary](init-tdinfo-servtd-ext.md) - Continuity/integrity checks, current-image one-hash lookup, and migration vs. rebinding behavior.
* [Memory Budget](memory-budget.md) - Stack/heap/shared-memory sizing equations for multi-session SPDM attestation.
* [Reproducible Build — Status & Limitations](reproducible-build.md) - What's implemented, verified, and still limited for MRTD-stable rebuilds.

## Build, release & test workflows

* [AzCVMEmu Build & Run — Agent Cheat Sheet](azcvmemu-build-and-run.md) - Feature-flag combinations, prerequisites, `migtdemu.sh` invocations.
* [Policy v2 Generation Workflow](policy-v2-workflow.md) - JSON/CoRIM packaging, signer-anchor enrollment, and measurement-stable mapping/key rotation.
* [Integration Testing — QEMU/vsock and Azure TiP](integration-testing.md) - The two non-EMU integration test layers, build/run commands, current status.
* [MigTD TiP Lab-Blade Troubleshooting Skill](../skills/migtd-tip-troubleshoot/SKILL.md) - PowerTest/HCSTest setup, host validation, serial/hash diagnosis, and Hyper-V ETW capture.
* [Release Process](release-process.md) - Version semantics, release content checklist, release steps.
* [Code Coverage Plan (Draft Status)](code-coverage-plan.md) - Proposed per-PR coverage flow — decided backend/tooling, phased plan, open questions.
