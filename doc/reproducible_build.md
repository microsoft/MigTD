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

### Deterministic release profile

The release profile in [`Cargo.toml`](../Cargo.toml) uses `panic = "abort"`,
`opt-level = "z"`, and `lto = true`.

### `td-shim-strip-info` tool

`deps/td-shim/td-shim-tools/.../td-shim-strip-info` can zero out sources of
non-determinism: the PE `TimeDateStamp`, the PDB GUID, and (only with the `-s` /
`--strip_path` flag) embedded `CARGO_HOME`, `RUSTUP_HOME`, and Rust source
paths. It is invoked from
[`sh_script/build_final.sh`](../sh_script/build_final.sh).

## Limitations

1. **Not path-independent (core limitation).** The compiled binary embeds
   absolute source / `CARGO_HOME` / `RUSTUP_HOME` paths, so **identical build
   user and source path are mandatory** to reproduce identical bytes. Running
   the build inside the provided Docker container is the supported workaround.
   See [intel/MigTD#51](https://github.com/intel/MigTD/issues/51)
   ("Reproducible build fail in different path").

2. **`td-shim-strip-info` is effectively a no-op for MigTD artifacts.** Its
   PE-stripping branches only execute for `x86_64-unknown-uefi` targets or
   `.efi` / `.exe` names, but MigTD and td-shim are ELF binaries built for
   `x86_64-unknown-none`. In addition, `build_final.sh` invokes the tool
   **without `-s`**, so the source-path stripping never runs. As a result the
   tool reads and writes back the ELF essentially unchanged.

3. **The documented production build never strips.** The canonical build command
   `cargo image` (driven by `xtask`) does not invoke `td-shim-strip-info` at all.

4. **Symbols are not stripped.** `strip = "symbols"` is intentionally not enabled
   on `profile.release` due to stability concerns
   (cf. confidential-containers/td-shim#272), so symbol and path information
   remain in the binary.

5. **No path/timestamp canonicalization in the build flags.** There is no use of
   `--remap-path-prefix` or `SOURCE_DATE_EPOCH` anywhere in the build, so paths
   are not canonicalized and timestamps are not pinned beyond what
   `td-shim-strip-info` would otherwise handle.

6. **No CI verification.** No GitHub Actions workflow builds the Docker image or
   diffs rebuilt artifacts, so reproducibility is not enforced automatically.

## Impact on measurement

The MigTD ELF payload is linked into the final firmware image and contributes to
the ordered measurement that produces **MRTD**. Any non-reproducible bytes
(embedded paths, symbols, timestamps) therefore change MRTD, which breaks
attestation and policy matching between independently produced builds. Using the
provided container to fix the user and path is what keeps MRTD stable across
rebuilds.
