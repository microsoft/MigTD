# ServTD CoRIM generator

`servtd-corim-generator` is a local-development signing tool. It creates a
signed TCB-mapping CoRIM for one supplied `tdinfo_hash` and writes the 48-byte
signer anchor derived from the supplied certificate chain.

It is not a complete production release pipeline: it does not maintain
cumulative production mappings, preserve historical releases, apply
revocations, or integrate with an approved production signing service.

## Usage

```bash
cargo run --release -p servtd-corim-generator -- \
  --tdinfo-hash <96-hex-character SHA-384 hash> \
  --svn <MigTD SVN> \
  --tag-version <CoMID tag version> \
  --cert-chain <leaf-first PEM chain> \
  --private-key <leaf P-384 PKCS#8 PEM key> \
  --signer-eku-oid 1.3.6.1.4.1.32473.1.1 \
  --output <tcb-mapping.cose> \
  --anchor-output <signer-anchor.bin>
```

The generator self-verifies the signed CoRIM and confirms that the requested
TDINFO hash resolves to the supplied SVN before writing either output.
