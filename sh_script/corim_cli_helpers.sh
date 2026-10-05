#!/usr/bin/env bash

CORIM_CLI_REV="8438b89051aac8e170c753c17540d24c2eb27650"

configure_corim_cli() {
    local repo_root="$1"
    CORIM_CLI_INSTALL_ROOT="${CORIM_CLI_INSTALL_ROOT:-$repo_root/target/corim-cli-$CORIM_CLI_REV}"
    CORIM_CLI_BIN="${CORIM_CLI:-$CORIM_CLI_INSTALL_ROOT/bin/corim-cli}"
}

install_corim_cli() {
    if [ ! -x "$CORIM_CLI_BIN" ]; then
        if [ -n "${CORIM_CLI:-}" ]; then
            echo "CORIM_CLI is not executable: $CORIM_CLI_BIN" >&2
            return 1
        fi

        echo "Installing official Azure/corim CLI at $CORIM_CLI_REV..."
        cargo install \
            --locked \
            --git https://github.com/Azure/corim \
            --rev "$CORIM_CLI_REV" \
            --root "$CORIM_CLI_INSTALL_ROOT" \
            corim-cli
    fi

    if ! "$CORIM_CLI_BIN" sign --help >/dev/null 2>&1; then
        echo "corim-cli does not support the required sign command: $CORIM_CLI_BIN" >&2
        echo "Use Azure/corim revision $CORIM_CLI_REV or a newer compatible build." >&2
        return 1
    fi
}

ecdsa_der_to_p1363() {
    local input="$1"
    local output="$2"

    python3 - "$input" "$output" <<'PY'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()

def read_length(offset):
    if offset >= len(data):
        raise ValueError("missing DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    width = first & 0x7f
    if width == 0 or width > 2 or offset + width > len(data):
        raise ValueError("invalid DER length")
    return int.from_bytes(data[offset:offset + width], "big"), offset + width

def read_integer(offset):
    if offset >= len(data) or data[offset] != 0x02:
        raise ValueError("expected DER INTEGER")
    length, offset = read_length(offset + 1)
    end = offset + length
    if length == 0 or end > len(data):
        raise ValueError("invalid DER INTEGER length")
    value = data[offset:end]
    if value[0] & 0x80:
        raise ValueError("negative ECDSA integer")
    value = value.lstrip(b"\x00")
    if len(value) > 48:
        raise ValueError("P-384 integer exceeds 48 bytes")
    return value.rjust(48, b"\x00"), end

if not data or data[0] != 0x30:
    raise ValueError("expected DER SEQUENCE")
sequence_length, offset = read_length(1)
if offset + sequence_length != len(data):
    raise ValueError("invalid DER SEQUENCE length")
r, offset = read_integer(offset)
s, offset = read_integer(offset)
if offset != len(data):
    raise ValueError("trailing data after ECDSA signature")

pathlib.Path(sys.argv[2]).write_bytes(r + s)
PY
}

compute_signer_anchor() {
    local root_cert="$1"
    local leaf_cert="$2"
    local signer_eku_oid="$3"
    local output="$4"
    local work_dir="$5"
    local root_der="$work_dir/corim-root.der"
    local leaf_der="$work_dir/corim-leaf.der"
    local eku_der="$work_dir/corim-signer-eku.der"

    openssl x509 -in "$root_cert" -outform DER -out "$root_der"
    openssl x509 -in "$leaf_cert" -outform DER -out "$leaf_der"
    openssl asn1parse -genstr "OID:$signer_eku_oid" -out "$eku_der" -noout

    python3 - "$root_der" "$leaf_der" "$eku_der" "$output" <<'PY'
import hashlib
import pathlib
import sys


def tlv_bounds(data, offset):
    start = offset
    tag = data[offset]
    offset += 1
    first = data[offset]
    offset += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        length = first
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, start, offset, end


root_der = pathlib.Path(sys.argv[1]).read_bytes()
leaf_der = pathlib.Path(sys.argv[2]).read_bytes()
eku_der = pathlib.Path(sys.argv[3]).read_bytes()

tag, _, certificate_content, certificate_end = tlv_bounds(leaf_der, 0)
if tag != 0x30 or certificate_end != len(leaf_der):
    raise ValueError("invalid leaf certificate DER")
tag, _, tbs_content, _ = tlv_bounds(leaf_der, certificate_content)
if tag != 0x30:
    raise ValueError("invalid TBSCertificate DER")

position = tbs_content
tag, _, _, end = tlv_bounds(leaf_der, position)
if tag == 0xA0:
    position = end
for _ in range(4):  # serial, signature, issuer, validity
    _, _, _, position = tlv_bounds(leaf_der, position)
tag, subject_start, _, subject_end = tlv_bounds(leaf_der, position)
if tag != 0x30:
    raise ValueError("invalid subject Name DER")

root_hash = hashlib.sha384(root_der).digest()
subject_hash = hashlib.sha384(leaf_der[subject_start:subject_end]).digest()
san_hash = hashlib.sha384(b"\x00").digest()
anchor = hashlib.sha384(
    b"\x00".join((
        b"MIGTD-RTMR1-ANCHOR-V2",
        root_hash,
        subject_hash,
        san_hash,
        eku_der,
    ))
).digest()
pathlib.Path(sys.argv[4]).write_bytes(anchor)
PY

    if [ "$(wc -c < "$output")" -ne 48 ]; then
        echo "Generated signer anchor is not 48 bytes" >&2
        return 1
    fi
}

generate_signed_corim() {
    local tdinfo_hash="$1"
    local svn="$2"
    local generation="$3"
    local cert_chain="$4"
    local private_key="$5"
    local output="$6"
    local work_dir="$7"
    local extra_tdinfo_hash="${8:-}"
    local extra_svn="${9:-0}"
    local template="$work_dir/tcb_mapping_corim.json"
    local unsigned="$work_dir/tcb_mapping_corim.cbor"
    local staging="$work_dir/tcb_mapping_corim.staging.cose"
    local tbs="$work_dir/tcb_mapping_corim.tbs"
    local signature_der="$work_dir/tcb_mapping_corim.sig.der"
    local signature_raw="$work_dir/tcb_mapping_corim.sig"
    local hash_base64
    local extra_hash_base64=""

    hash_base64=$(printf '%s' "$tdinfo_hash" | xxd -r -p | openssl base64 -A)
    if [ -n "$extra_tdinfo_hash" ]; then
        extra_hash_base64=$(printf '%s' "$extra_tdinfo_hash" | xxd -r -p | openssl base64 -A)
    fi
    jq -n \
        --arg hash "$hash_base64" \
        --argjson svn "$svn" \
        --arg extra_hash "$extra_hash_base64" \
        --argjson extra_svn "$extra_svn" \
        --argjson generation "$generation" \
        '([{hash: $hash, svn: $svn}] +
          (if $extra_hash == "" then [] else [{hash: $extra_hash, svn: $extra_svn}] end)) as $mappings
        | {
            "corim-id": "Microsoft/TDX/tcb-mapping",
            "comids": [{
                "tag-identity": {
                    "id": "1F2E3D4C-5B6A-4798-8A9B-0C1D2E3F4A5B",
                    "version": $generation
                },
                "triples": {
                    "reference-triples": ($mappings | map({
                        "ref-env": {
                            "class": {"vendor": "Intel", "model": "TDX"},
                            "instance": {"type": "bytes", "value": "bWlncmF0aW9uLXRk"}
                        },
                        "ref-claims": [{
                            "value": {"digests": [[7, .hash]]}
                        }]
                    })),
                    "conditional-endorsement-series-triples": [{
                        "common-condition": {
                            "environment": {
                                "class": {"vendor": "Intel", "model": "TDX"},
                                "instance": {"type": "bytes", "value": "bWlncmF0aW9uLXRk"}
                            },
                            "claims-list": []
                        },
                        "series": ($mappings | map({
                            "condition": [{
                                "value": {"digests": [[7, .hash]]}
                            }],
                            "addition": [{
                                "value": {"svn": {"type": "svn", "value": .svn}}
                            }]
                        }))
                    }]
                }
            }]
        }' > "$template"

    "$CORIM_CLI_BIN" generate "$template" -o "$unsigned"
    "$CORIM_CLI_BIN" sign prepare "$unsigned" \
        --alg ES384 \
        --signer-name "MigTD TCB Mapping Endorsement" \
        --x5chain "$cert_chain" \
        --out-staging "$staging" \
        --out-tbs "$tbs"
    openssl dgst -sha384 -sign "$private_key" -out "$signature_der" "$tbs"
    ecdsa_der_to_p1363 "$signature_der" "$signature_raw"
    "$CORIM_CLI_BIN" sign finalize "$staging" \
        --signature "$signature_raw" \
        -o "$output"
    "$CORIM_CLI_BIN" validate --skip-expiry "$output"
}
