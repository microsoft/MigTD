# MigTD Reproducible Build: Support and Limitations

This document summarizes what reproducible-build support exists in the MigTD
repository and the limitations that callers should be aware of. Because the
MigTD payload bytes feed into the measured firmware image, reproducibility
directly affects the resulting **MRTD** and therefore attestation / policy
matching across rebuilds.

## What is implemented

### Build-environment normalization (the actual mechanism)

Reproducibility is achieved primarily by normalizing the build environment, not
by post-processing the binary. [`container/Dockerfile`](../container/Dockerfile)
pins everything that affects the output bytes:

- Base image `ubuntu:26.04` referenced by digest.
- Rust toolchain `1.88.0` plus the `rust-src` component and the
  `x86_64-unknown-none` target.
- `WORKDIR /root` and `git clone --recursive ... MigTD.git`, so the source is
  always built as the **root** user from the path `/root/MigTD`.

This forces the same system user and the same source-code path on every build,
which is the requirement called out in the README's *Reproducible Build* section
(see [`readme.md`](../readme.md)) and tracked in
[intel/MigTD#51](https://github.com/intel/MigTD/issues/51).

[`sh_script/docker.sh`](../sh_script/docker.sh) builds and runs the container:

```
./sh_script/docker.sh -f container
```

### Dependency and toolchain pinning

- `Cargo.lock` is committed and locks all transitive crate versions.
- `rust-toolchain` pins Rust `1.88.0`.
- [`doc/release.md`](./release.md) requires shipping `Cargo.lock` with every
  release to lock the dependency versions.

### Release profile (pinned, not a determinism mechanism)

The release profile in [`Cargo.toml`](../Cargo.toml) uses `panic = "abort"`,
`opt-level = "z"`, and `lto = true`. These are size/`no_std` choices, **not**
reproducibility features; what matters for reproducibility is only that they are
fixed in committed `Cargo.toml` so every build uses identical flags. Any
consistent settings reproduce equally.

### Native path independence via `--remap-path-prefix` (implemented)

`xtask` sets `RUSTFLAGS` with `--remap-path-prefix` for both the `td-shim` and
`migtd` compilations (`xtask/src/build.rs`, `remap_rustflags`), mapping the
project root → `/migtd`, `CARGO_HOME` → `/cargo`, and `RUSTUP_HOME` → `/rustup`.
Every `cargo image` build (Linux TDVF and Azure IGVM) thus produces identical
bytes regardless of checkout path or user, so native builds no longer require the
fixed-path container. Verified: clean builds in two different paths matched —
Linux TDVF `e3c67e7b…`, Azure IGVM `2c74e32f…`, with 0 absolute paths embedded.

### `td-shim-strip-info` tool

`deps/td-shim/td-shim-tools/.../td-shim-strip-info` can zero out sources of
non-determinism: the PE `TimeDateStamp`, the PDB GUID, and (only with the `-s` /
`--strip_path` flag) embedded `CARGO_HOME`, `RUSTUP_HOME`, and Rust source
paths. It is invoked from
[`sh_script/build_final.sh`](../sh_script/build_final.sh).

## Verification (empirical)

Tested with toolchain 1.88.0, target `x86_64-unknown-none`, features
`main,stack-guard,vmcall-vsock,policy_v2`:

| Test | Result | Verdict |
|------|--------|---------|
| Clean rebuild, same path | identical sha256 | deterministic |
| Rebuild after `touch` of a source file | identical sha256 | timestamp-independent |
| Build in a copied tree at a different path | sha256 **differs** | path-dependent |
| `td-shim-strip-info` without `-s` | bytes unchanged | no-op |
| `td-shim-strip-info` with `-s` | removed 56 items, 44 → 19 paths | partial strip |
| **Azure IGVM** (`build-igvm`), same path, two clean builds | identical sha256 | deterministic |
| **Azure IGVM** (`build-igvm`), different path | sha256 **differs** | path-dependent |

The Azure rows use the full `build-igvm` feature set
(`vmcall-raw,stack-guard,main,vmcall-interrupt,oneshot-apic,spdm_attestation,igvm-attest`,
`--policy-v2 --debug --image-format igvm`): same-path clean rebuilds were byte-identical,
while a from-scratch build in a copied tree embedded `/tmp/...` source paths and differed.

The same-path build embedded 44 absolute `/home/<user>/...` strings (both
`.cargo/registry/...` and `src/migtd/...`); the copied-tree build embedded the
new `/tmp/...` paths instead, producing different bytes. This confirms the core
path-dependence below.

## Limitations

1. **Path dependence — now resolved for `cargo image`.** The compiler embeds
   absolute source / `CARGO_HOME` / `RUSTUP_HOME` paths, so historically identical
   build user and path were mandatory (the container's job). `xtask` now applies
   `--remap-path-prefix` (see above), so `cargo image` Linux/Azure builds are
   byte-identical across paths. Raw `cargo build` invocations (e.g. test scripts)
   outside `xtask` still embed real paths. See
   [intel/MigTD#51](https://github.com/intel/MigTD/issues/51).

2. **`td-shim-strip-info` is a no-op as invoked.** Its PE `TimeDateStamp`/PDB
   branches only execute for `x86_64-unknown-uefi` targets or `.efi` / `.exe`
   names, so they never apply to the ELF MigTD/td-shim binaries. The source-path
   stripping (`-s`) *does* work on the ELF — a test run removed 56 items (44 → 19
   embedded paths) — but `build_final.sh` invokes the tool **without `-s`**, and
   even with `-s` ~19 paths remain. As invoked, the tool reads and writes back the
   ELF unchanged.

3. **The documented production build never strips.** The canonical build command
   `cargo image` (driven by `xtask`) does not invoke `td-shim-strip-info` at all.

4. **Symbols are not stripped.** `strip = "symbols"` is intentionally not enabled
   on `profile.release` due to stability concerns
   (cf. confidential-containers/td-shim#272), so symbol and path information
   remain in the binary.

5. **No `SOURCE_DATE_EPOCH`.** `--remap-path-prefix` is now applied via `xtask`,
   but `SOURCE_DATE_EPOCH` is still unset (no timestamp variance has been observed
   for these ELF builds, so this is not currently a problem).

6. **No CI verification.** No GitHub Actions workflow builds the Docker image or
   diffs rebuilt artifacts, so reproducibility is not enforced automatically.

## Impact on measurement

The MigTD ELF payload is linked into the final firmware image and contributes to
the ordered measurement that produces **MRTD**. Any non-reproducible bytes
(embedded paths, symbols, timestamps) therefore change MRTD, which breaks
attestation and policy matching between independently produced builds. Using the
provided container to fix the user and path is what keeps MRTD stable across
rebuilds.

## Recommended improvements

**Bottom line: with the pinned container, the binary is already reproducible.**
Two clean builds at the same user/path/toolchain produced byte-identical IGVMs
(`c5db9998…`), and a touch-rebuild was identical too — the ELF has no build
timestamp, so the only variable is the build path/user, which the container
fixes (`root`, `/root/MigTD`, `/root/.cargo`, `/root/.rustup`). The items below
are therefore mostly for **native** (non-container) builds and for hardening.

| # | Improvement | Docker | Native | Purpose |
|---|-------------|--------|--------|---------|
| 1 | `--remap-path-prefix` (root, CARGO_HOME, RUSTUP_HOME) via xtask | not needed | **DONE** | makes bytes path/user-independent |
| 2 | CI: build twice in two paths, diff sha256 | rebuild-twice check | path-diff check | enforces repro |
| 3 | `td-shim-strip-info -s` / strip `strip="symbols"` | optional | optional | reduces leaked paths/symbols, not repro |
| 4 | `SOURCE_DATE_EPOCH` / `TimeDateStamp=0` | not needed | not needed | no timestamp variance observed |

**Why also support native builds?** So independent third parties can reproduce
and verify MRTD without replicating the exact `/root/MigTD` path, on any
machine/CI checkout dir; and to drop the hard dependency on the container. Only
#1 is needed for that — the rest is hardening.

## Public policy-only enrollment artifact

The public Docker/Make build intentionally produces an **enrollment artifact**,
not a deployable MigTD:

```bash
make -C sh_script/Azure build-igvm
```

This target deterministically derives
`target/release/migtd.policy_v2.json` from the public
`config/Azure/policy_data_raw.json` production Azure source and the tracked
public quote collateral in `config/collateral_production_fmspc.json`:

```bash
jq -cS --slurpfile collaterals config/collateral_production_fmspc.json \
  '{policyData:(. + {collaterals:$collaterals[0]})}' \
  config/Azure/policy_data_raw.json
```

That source is the unsigned Azure policy input used by
`sh_script/Azure/build_azure_mock_test.sh`. The public target validates it is
bare policy data (not a signed wrapper), adds the complete production quote
collateral, contains no `servtdCollateral` or `servtdCrl`, and
contains exactly one production identity rule:
`servtd.migtdIdentity.isvsvn = {operation: "greater-or-equal", reference:
"self"}`. A missing or structurally different rule fails the build.

The image is built with `cargo image
--non-bootable-enrollment-artifact`. This mode enrolls the policy but rejects
root CA, issuer-chain, signer-anchor, and signed CoRIM inputs. The public output
therefore contains:

- deterministic MigTD code with `servtd_corim` support;
- the complete unsigned policy bytes, including public quote collateral;
- **no** root CA;
- **no** policy issuer chain;
- **no** signer anchor; and
- **no** signed TCB-mapping CoRIM.

With no RTMR1 signer-anchor source, firmware policy initialization fails
closed. The image is explicitly non-bootable until private enrollment.

`docker_build_igvm.sh` publishes the exact policy as
`migtd.policy_v2.json` beside `migtd.igvm`. Consumers must preserve this sidecar because private enrollment must use the
same policy bytes that were published with the reproducible image.

### Private release boundary

Private enrollment and final Azure signing are deliberately outside the public
reproducible build:

1. The public build publishes `migtd.igvm`, `migtd.policy_v2.json`, and their
   SHA-256 files.
2. A controlled private release pipeline enrolls the exact policy sidecar and
   production trust material.
3. The privately enrolled image is then finalized and Azure-signed.

The public target accepts no private key, production certificate chain, signed
collateral, or final Azure signature, and it does not invoke signing tools.
