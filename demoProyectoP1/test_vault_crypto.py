"""
Unit tests for vault_crypto.py
Run with:  python test_vault_crypto.py
"""

import base64
import json
import unittest

from vault_crypto import encrypt_file, decrypt_file, generate_key


class TestVaultCrypto(unittest.TestCase):

    def setUp(self):
        self.plaintext = b"Super secret document content."
        self.filename  = "secret.txt"

    # ── 1. Encrypt → Decrypt returns identical file ───────────────────────────
    def test_encrypt_decrypt_roundtrip(self):
        container = encrypt_file(self.plaintext, self.filename)
        recovered = decrypt_file(container, container["_key_b64"])
        self.assertEqual(recovered, self.plaintext)

    # ── 2. Wrong key fails ────────────────────────────────────────────────────
    def test_wrong_key_fails(self):
        container = encrypt_file(self.plaintext, self.filename)
        wrong_key  = base64.b64encode(generate_key()).decode()
        with self.assertRaises(ValueError):
            decrypt_file(container, wrong_key)

    # ── 3. Modified ciphertext fails ─────────────────────────────────────────
    def test_modified_ciphertext_fails(self):
        container = encrypt_file(self.plaintext, self.filename)
        tampered  = dict(container)
        # Flip one byte in the ciphertext.
        ct_bytes = bytearray(base64.b64decode(tampered["ciphertext_b64"]))
        ct_bytes[0] ^= 0xFF
        tampered["ciphertext_b64"] = base64.b64encode(bytes(ct_bytes)).decode()
        with self.assertRaises(ValueError):
            decrypt_file(tampered, container["_key_b64"])

    # ── 4. Modified metadata (AAD) fails ─────────────────────────────────────
    def test_modified_metadata_fails(self):
        container = encrypt_file(self.plaintext, self.filename)
        tampered  = dict(container)
        tampered["header"] = dict(tampered["header"])
        # Alter the stored AAD bytes.
        aad_bytes = bytearray(base64.b64decode(tampered["header"]["aad_b64"]))
        aad_bytes[0] ^= 0x01
        tampered["header"]["aad_b64"] = base64.b64encode(bytes(aad_bytes)).decode()
        with self.assertRaises(ValueError):
            decrypt_file(tampered, container["_key_b64"])

    # ── 5. Multiple encryptions produce different ciphertexts ─────────────────
    def test_multiple_encryptions_differ(self):
        c1 = encrypt_file(self.plaintext, self.filename)
        c2 = encrypt_file(self.plaintext, self.filename)
        self.assertNotEqual(c1["nonce_b64"],      c2["nonce_b64"])
        self.assertNotEqual(c1["ciphertext_b64"], c2["ciphertext_b64"])

    # ── 6. Modified auth tag fails ────────────────────────────────────────────
    def test_modified_auth_tag_fails(self):
        container = encrypt_file(self.plaintext, self.filename)
        tampered  = dict(container)
        tag_bytes = bytearray(base64.b64decode(tampered["auth_tag_b64"]))
        tag_bytes[0] ^= 0xAA
        tampered["auth_tag_b64"] = base64.b64encode(bytes(tag_bytes)).decode()
        with self.assertRaises(ValueError):
            decrypt_file(tampered, container["_key_b64"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
