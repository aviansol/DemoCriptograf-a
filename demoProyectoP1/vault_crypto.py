"""
Secure Digital Document Vault - Encryption Module
Uses AES-GCM (AEAD) for authenticated encryption.
"""

import os
import json
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─── Constants ────────────────────────────────────────────────────────────────
KEY_SIZE_BYTES = 32       # AES-256
NONCE_SIZE_BYTES = 12     # 96-bit nonce (recommended for GCM)
ALGORITHM_VERSION = "AES-GCM-256-v1"


# ─── Key Generation ───────────────────────────────────────────────────────────
def generate_key() -> bytes:
    """Generate a cryptographically secure 256-bit symmetric key."""
    return AESGCM.generate_key(bit_length=256)


# ─── Encrypt ──────────────────────────────────────────────────────────────────
def encrypt_file(plaintext: bytes, filename: str = "", key: bytes = None) -> dict:
    """
    Encrypt file contents using AES-GCM with metadata as AAD.

    Args:
        plaintext: Raw file bytes to encrypt.
        filename:  Original filename (stored in metadata, optional).
        key:       32-byte AES key. If None, a fresh key is generated.

    Returns:
        vault_container dict with:
            header, nonce, ciphertext, authentication_tag (embedded in ciphertext by GCM),
            and the key used (caller must store this securely).
    """
    if key is None:
        key = generate_key()

    # Fresh nonce for every encryption — NEVER reuse with the same key.
    nonce = os.urandom(NONCE_SIZE_BYTES)

    # Build metadata (will be used as AAD — authenticated but NOT encrypted).
    metadata = {
        "filename": filename,
        "algorithm": ALGORITHM_VERSION,
        "key_size_bits": KEY_SIZE_BYTES * 8,
        "nonce_size_bits": NONCE_SIZE_BYTES * 8,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    aad = json.dumps(metadata, separators=(",", ":")).encode()

    # AES-GCM: ciphertext includes the 16-byte auth tag appended at the end.
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)

    # Split ciphertext and tag for explicit storage.
    ciphertext = ciphertext_with_tag[:-16]
    auth_tag   = ciphertext_with_tag[-16:]

    container = {
        "header": {
            "metadata": metadata,
            "aad_b64": base64.b64encode(aad).decode(),
        },
        "nonce_b64":      base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "auth_tag_b64":   base64.b64encode(auth_tag).decode(),
        # key returned so the caller can persist it; NOT stored inside container.
        "_key_b64": base64.b64encode(key).decode(),
    }
    return container


# ─── Decrypt ──────────────────────────────────────────────────────────────────
def decrypt_file(container: dict, key_b64: str) -> bytes:
    """
    Decrypt a vault container.

    Args:
        container: dict produced by encrypt_file (without _key_b64 is fine).
        key_b64:   Base64-encoded AES key.

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError: If authentication fails (tampered ciphertext or metadata).
    """
    key        = base64.b64decode(key_b64)
    nonce      = base64.b64decode(container["nonce_b64"])
    ciphertext = base64.b64decode(container["ciphertext_b64"])
    auth_tag   = base64.b64decode(container["auth_tag_b64"])
    aad        = base64.b64decode(container["header"]["aad_b64"])

    # Reassemble ciphertext + tag as expected by cryptography library.
    ciphertext_with_tag = ciphertext + auth_tag

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
    except Exception:
        raise ValueError("Authentication failed — data may have been tampered with.")

    return plaintext


# ─── Quick self-test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample = b"Hello, Secure Vault!"
    print("=== Encrypt ===")
    container = encrypt_file(sample, filename="test.txt")
    key_b64 = container["_key_b64"]
    print(f"Nonce    : {container['nonce_b64']}")
    print(f"Ciphertext: {container['ciphertext_b64'][:32]}...")
    print(f"Auth Tag : {container['auth_tag_b64']}")

    print("\n=== Decrypt ===")
    recovered = decrypt_file(container, key_b64)
    assert recovered == sample, "Decryption mismatch!"
    print(f"Recovered: {recovered}")

    print("\n=== Tamper Detection ===")
    tampered = dict(container)
    tampered["ciphertext_b64"] = base64.b64encode(b"tampered_data").decode()
    try:
        decrypt_file(tampered, key_b64)
    except ValueError as e:
        print(f"Tamper detected: {e}")

    print("\nAll checks passed.")
