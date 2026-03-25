"""Example device client that encrypts a JSON payload and POSTs to /scan.

This script demonstrates the device-side flow:
 1. Load the shared symmetric key (via `PSK_B64` env or `secret.key`).
 2. Encrypt a small JSON object containing `token` using AES-GCM.
 3. POST the base64 token to the server endpoint `/scan` as JSON `{ "payload": "..." }`.

Notes:
- In production use, the device should securely provision its copy of the key.
- For greater security, consider per-device keys derived via X25519 ECDH (not shown here).
"""

import os
import json
import requests
from crypto_utils import load_key, encrypt

# Server address — change to https:// and set VERIFY to cert path when using TLS.
SERVER = os.environ.get('SERVER_URL', 'http://localhost:5000')
VERIFY = True


def main():
    # 1) Load symmetric key (matches server's key)
    key = load_key()

    # 2) Prepare payload (device-specific token generated from QR)
    payload = json.dumps({'token': 'SAMPLE-PLATE-20260320120000'}).encode()

    # 3) Encrypt and send
    token = encrypt(key, payload)
    resp = requests.post(f'{SERVER}/scan', json={'payload': token}, verify=VERIFY)
    print('status', resp.status_code)
    print(resp.text)


if __name__ == '__main__':
    main()
