#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent

"""Check the shell anchor producer against the native regression fixtures."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parent.parent
POLICY_FIXTURES = REPOSITORY / "src/policy/test/policy_v2"
CRYPTO_FIXTURES = REPOSITORY / "src/crypto/test/eku"


class SignerAnchorTests(unittest.TestCase):
    def anchor(self, chain, eku):
        certificates = re.findall(
            rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            chain.read_bytes(),
            re.DOTALL,
        )
        self.assertGreaterEqual(len(certificates), 2)
        with tempfile.TemporaryDirectory(prefix="migtd-signer-anchor-") as directory:
            work = Path(directory)
            root = work / "root.pem"
            leaf = work / "leaf.pem"
            output = work / "anchor.bin"
            root.write_bytes(certificates[-1])
            leaf.write_bytes(certificates[0])
            subprocess.run(
                [
                    "bash", "-euo", "pipefail", "-c",
                    'source "$1"; compute_signer_anchor "$2" "$3" "$4" "$5" "$6"',
                    "signer-anchor-test",
                    str(REPOSITORY / "sh_script/corim_cli_helpers.sh"),
                    str(root), str(leaf), eku, str(output), str(work),
                ],
                check=True,
            )
            anchor = output.read_bytes()
            self.assertEqual(len(anchor), 48)
            return anchor

    def test_pem_matches_native_fixed_vector(self):
        self.assertEqual(
            self.anchor(
                POLICY_FIXTURES / "cert_chain/policy_issuer_chain.pem",
                "1.3.6.1.4.1.32473.1.1",
            ).hex(),
            "eb3bc058948925774e75db118255748d08249cd1441f5db7f0295c6ec5f88c3a"
            "e7fb64298e387e6248a03362801d93ef",
        )

    def test_san_bearing_chain_matches_direct_anchor_fixture(self):
        self.assertEqual(
            self.anchor(
                POLICY_FIXTURES / "corim/issuer_chain.pem",
                "1.3.6.1.4.1.32473.1.1",
            ),
            (POLICY_FIXTURES / "corim/signer_anchor.bin").read_bytes(),
        )

    def test_key_and_san_rotation_preserve_anchor(self):
        eku = "1.3.6.1.4.1.311.76.59.1.43"
        original = self.anchor(CRYPTO_FIXTURES / "signer_identity_a.pem", eku)
        for name in ("signer_identity_rotated.pem", "signer_san_mismatch.pem"):
            with self.subTest(name=name):
                self.assertEqual(original, self.anchor(CRYPTO_FIXTURES / name, eku))
        self.assertNotEqual(
            original, self.anchor(CRYPTO_FIXTURES / "signer_subject_mismatch.pem", eku),
        )
        self.assertNotEqual(
            original,
            self.anchor(
                CRYPTO_FIXTURES / "signer_identity_other_eku.pem",
                "1.3.6.1.4.1.311.76.59.1.44",
            ),
        )


if __name__ == "__main__":
    unittest.main()
