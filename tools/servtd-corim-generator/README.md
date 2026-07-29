# ServTD CoRIM generator

`servtd-corim-generator` creates a signed TCB-mapping CoRIM for MigTD EMU,
tests, and local development. It also writes the 48-byte signer anchor derived
from the supplied certificate chain. Production release systems must use their
approved signing service instead of local private keys.

## Usage

```bash
cargo run --release -p servtd-corim-generator -- \
  --tdinfo-hash <96-hex-character SHA-384 hash> \
  --svn <MigTD SVN> \
  --generation <monotonic policy generation> \
  --cert-chain <leaf-first PEM chain> \
  --private-key <leaf P-384 PKCS#8 PEM key> \
  --signer-eku-oid 1.3.6.1.4.1.32473.1.1 \
  --output <tcb-mapping.cose> \
  --anchor-output <signer-anchor.bin>
```

The generator self-verifies the signed CoRIM and confirms that the requested
TDINFO hash resolves to the supplied SVN before writing either output.

MigTD has no trusted wall clock, so generated artifacts omit CWT `nbf` and
`exp` claims. Freshness is enforced with the CoMID `tag-version`; callers must
set `--generation` to a monotonic value meeting the measured `policySvn`
floor.
