import os
import base64
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# crypto_utils.py
# Responsibilities:
# - Manage a symmetric AES-256-GCM key used for message encryption/decryption.
# - Provide simple `encrypt`/`decrypt` helpers that return/accept base64 tokens.
# Key loading order:
# 1. If `PSK_B64` environment variable is set, use it (base64-encoded key).
# 2. Else, if `secret.key` file exists, read raw bytes from it.
# 3. Else, generate a new key and write it to `secret.key` for local development.


KEY_FILE = 'secret.key'


def generate_and_store_key(path: str = KEY_FILE) -> bytes:
    """Generate a 256-bit AES key and store it to `path` (raw bytes).
    Returns the key bytes.
    """
    key = AESGCM.generate_key(bit_length=256)
    with open(path, 'wb') as f:
        f.write(key)
    return key


def load_key() -> bytes:
    """Load key from PSK_B64 env var (base64) or from `secret.key` file.
    If neither exists, a new key will be generated and stored to `secret.key`.
    """
    # Prefer environment-provided key for CI/production usage
    b64 = os.environ.get('PSK_B64')
    if b64:
        return base64.b64decode(b64)

    if not os.path.exists(KEY_FILE):
        return generate_and_store_key(KEY_FILE)

    with open(KEY_FILE, 'rb') as f:
        return f.read()


def encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> str:
    """Encrypt bytes and return base64(nonce + ciphertext).

    Implementation notes / flow:
    - Uses AES-GCM (authenticated encryption) with a 96-bit random nonce.
    - The output is: base64( nonce || ciphertext_with_tag ).
    - `aad` is optional additional authenticated data (not encrypted but authenticated).

    Usage:
      key = load_key()
      token = encrypt(key, b'my data')
      # send `token` to receiver which can call `decrypt(key, token)`
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return base64.b64encode(nonce + ct).decode('utf-8')


def decrypt(key: bytes, token_b64: str, aad: Optional[bytes] = None) -> bytes:
    """Decrypt base64(nonce + ciphertext) and return plaintext bytes.

    Raises cryptography exceptions on failure. Callers should catch and handle exceptions
    and avoid leaking internal errors to remote clients.
    """
    data = base64.b64decode(token_b64)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)
