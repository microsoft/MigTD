---
type: Reference
title: Reproducible Build — Status & Limitations
description: What's implemented for MigTD build reproducibility (container normalization, --remap-path-prefix), what's verified, and what's still limited — directly affects MRTD stability across rebuilds.
tags: [reproducible-build, mrtd, determinism]
timestamp: 2026-07-13T22:37:00+00:00
---

# Reproducible Build — Status & Limitations

Canonical source: [doc/reproducible_build.md](../../doc/reproducible_build.md).
Relevant whenever an MRTD mismatch across rebuilds is under investigation —
read [Domain Facts § Trust model](domain-facts.md) first for why MRTD
stability matters (root of trust).

## Bottom line

**With the pinned container, or with native `cargo image` (via `xtask`), the
build is already reproducible.** `xtask` applies `--remap-path-prefix`
(`xtask/src/build.rs`, `remap_rustflags`) for both `td-shim` and `migtd`
compiles, mapping project root → `/migtd`, `CARGO_HOME` → `/cargo`,
`RUSTUP_HOME` → `/rustup`. Verified: clean builds in two different paths
produced identical sha256 for both Linux TDVF and Azure IGVM outputs.

`sh_script/Azure/docker_build_igvm.sh` can copy explicit policy, issuer-chain
or 48-byte signer-anchor, and signed ServTD CoRIM inputs into fixed container
paths. Release callers therefore do not need to mutate tracked template files
before using the pinned build environment.

## What's NOT covered by the fix

- **Raw `cargo build` invocations outside `xtask`** (e.g. test scripts) still
  embed real absolute paths.
- `td-shim-strip-info` is invoked **without `-s`** by `build_final.sh` → it's
  a no-op for path stripping on the ELF binaries (its PE-specific
  timestamp/PDB-GUID branches never apply — only `x86_64-unknown-uefi`
  targets have those). Even with `-s`, ~19 embedded paths remain.
- Symbols are never stripped (`strip = "symbols"` intentionally disabled —
  see `confidential-containers/td-shim#272`).
- No `SOURCE_DATE_EPOCH` (not currently needed — no observed timestamp
  variance in these ELF builds).
- **No CI enforcement** — nothing in CI builds twice and diffs sha256.

## If asked to "fix reproducibility"

Check whether the reported non-determinism is from a **raw `cargo build`**
bypassing `xtask`, or from a genuinely new source of variance — the
path-embedding problem (the historically dominant cause, tracked in
[intel/MigTD#51](https://github.com/intel/MigTD/issues/51)) is already solved
for the documented `cargo image` build path. Don't re-propose the container
or `--remap-path-prefix` as if they were missing.
