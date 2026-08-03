# Reproducible Azure IGVM Builds

This document describes the supported reproducible build path for the Azure
`migtd.igvm` image. It does not define reproducibility guarantees for other
image formats or build environments.

## Build interface

`docker_build_igvm.sh` builds MigTD with the environment defined by the Azure
`Dockerfile`, runs a target from the Azure `Makefile`, and extracts the IGVM
image and build records from a fresh container.

### Current working tree

Prepare the checkout, then build it:

```bash
git submodule update --init --recursive
bash sh_script/preparation.sh
sh_script/Azure/docker_build_igvm.sh \
  --rebuild-image \
  --output sh_script/Azure/output
```

This mode copies the current working tree into `/root/MigTD` in the container.
It includes local source changes but excludes `.git`, Cargo target directories,
and the Azure output directory. The default Make targets are `build-igvm` and
`generate-hash-v2`.

### Clean repository revision

Build a clean recursive clone at a full commit SHA:

```bash
sh_script/Azure/docker_build_igvm.sh \
  --clone <commit-sha> \
  --repo https://github.com/microsoft/MigTD.git \
  --rebuild-image \
  --output sh_script/Azure/output
```

Clone mode checks out the requested revision and uses the `build-igvm-all`
target, which initializes the required build inputs before producing the
image.

Use `--target` to select a different target from the Azure `Makefile`. The
target, its feature set, and all policy inputs are part of the image's
reproducibility inputs.

## Builder environment

The Azure `Dockerfile` provides:

- an Ubuntu base image pinned by digest;
- Rust `1.88.0`, `rust-src`, and the `x86_64-unknown-none` target;
- Clang, LLVM, NASM, and the SGX/DCAP attestation build dependencies; and
- a fixed `/root/MigTD` source path inside the container.

`--rebuild-image` rebuilds the builder image from the Dockerfile. Without that
option, the wrapper reuses the configured local image tag when it already
exists.

Dependency tracking is limited. At the repository level, dependency versions
are tracked only for Cargo dependencies through `Cargo.lock`. The Dockerfile
specifies Ubuntu APT package names rather than exact package versions, and the
Rust installer and toolchain artifacts are not locked by `Cargo.lock`.

Rebuilding the builder image later can therefore resolve different compiler or
system-package artifacts. For a release that must be reproduced later, retain
the built container image and record its image identifier instead of relying
only on rebuilding the Dockerfile.

## Reproducibility inputs

All output-affecting inputs must match:

- the MigTD commit and recursive submodule commits;
- `Cargo.lock`, `rust-toolchain`, and preparation patches;
- the built Azure builder image;
- the selected Azure Make target and its build options;
- policy, certificate, trust-anchor, collateral, and manifest files; and
- any generated inputs embedded in the IGVM.

Freshly generated keys, certificates, signatures, or fetched collateral may
change the final image. Preserve those inputs when an identical IGVM is
required.

## Build outputs

The output directory contains:

| File | Contents |
|------|----------|
| `migtd.igvm` | Azure IGVM image |
| `migtd.igvm.sha256` | SHA-256 checksum of the image |
| `migtd.igvm.measurements.txt` | Measurement-related lines from the build log |
| `build.log` | Complete container build log |

## CI verification

`.github/workflows/reproducible-igvm.yml` verifies this build path by:

1. checking out the requested revision with recursive submodules;
2. applying the repository preparation step;
3. building the Azure `build-igvm` target twice in separate containers that
   reuse the same builder image;
4. comparing the two IGVM SHA-256 values; and
5. failing and uploading both images when the values differ.

The workflow runs weekly, through manual dispatch, and for pull requests that
modify the Azure build environment or other listed build inputs.

Matching IGVM bytes produce the same MRTD. The CI job verifies repeatability
within one built Azure builder image; it does not compare independently rebuilt
builder images.

## Release records

Retain the following with each published Azure IGVM:

- the full MigTD commit and recursive submodule commits;
- the Azure builder image identifier;
- the exact wrapper command and Make target;
- all policy, trust, collateral, and manifest inputs;
- `migtd.igvm`, `migtd.igvm.sha256`, and
  `migtd.igvm.measurements.txt`; and
- `build.log`.

Reproducibility establishes output equality. Source, builder, policy, and
checksum provenance must be authenticated separately.
