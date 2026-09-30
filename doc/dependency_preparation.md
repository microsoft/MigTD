# Dependency Preparation

Run the repository preparation script after a fresh clone, submodule update, or
`git clean -fdx`:

```bash
bash sh_script/preparation.sh
```

## Why the script patches `ring`

Both `td-shim` and `spdm-rs` contain a `ring` submodule based on ring 0.17.14,
commit `2723abbca`. When they are built independently, each subproject prepares
its own copy. The MigTD workspace instead resolves every crates.io `ring`
dependency to the td-shim copy:

```toml
[patch.crates-io]
ring = { path = "deps/td-shim/library/ring" }
```

Consequently, spdm-rs's own `[patch.crates-io]` entry for
`deps/spdm-rs/external/ring` does not select that copy during a top-level MigTD
build. The SPDM-specific changes must be applied to
`deps/td-shim/library/ring`, which is the copy Cargo compiles.

Preparation happens in this order:

1. `deps/td-shim/sh_script/preparation.sh` resets td-shim's ring and applies
   its `x86_64-unknown-none` and CPU-feature patches.
2. MigTD applies spdm-rs patches `0003` and `0004` to that same ring tree.
3. `deps/spdm-rs/sh_script/pre-build.sh` prepares spdm-rs and its standalone
   ring copy.

The SPDM patches add APIs required to preserve intermediate SPDM context:

- `EphemeralPrivateKey::export_private_key_bytes` and
  `EphemeralPrivateKey::from_private_key_bytes` preserve an in-progress DHE
  key exchange.
- `digest::Context::to_bytes` and `digest::Context::from_bytes` preserve
  in-progress transcript hashes.

Without these APIs, builds using `spdm_attestation` fail because spdmlib calls
methods absent from the selected ring source.

## Why a ring upgrade does not remove the patches

The serialization APIs are downstream spdm-rs extensions, not APIs in ring
0.17.14 or the upstream development branch. In particular, exporting an
ephemeral private key and serializing digest implementation state do not
naturally fit ring's public abstractions.

Removing these preparation steps therefore requires either upstream support,
a single maintained ring fork shared by td-shim and spdm-rs, or an spdm-rs
checkpoint design that uses only upstream ring APIs. Merely changing the ring
version is not sufficient.
