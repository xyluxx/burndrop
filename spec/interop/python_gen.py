"""Write python.json: ciphertext produced by the Python SDK for other implementations to open.

Run from sdk/python so the package is importable:

    uv run python ../../spec/interop/python_gen.py

The schema is documented in README.md next to this file. Secrets are
placeholders. Keys are generated for the file and have no other use.
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from burndrop import __version__, crypto
from burndrop.encoding import b64encode

OUT = Path(__file__).resolve().parent / "python.json"


def drop_case(
    name: str,
    secret_name: str,
    purpose: str,
    storage: str,
    retention: str,
    value: bytes,
) -> dict[str, Any]:
    public_key, private_key = crypto.generate_keypair()
    fingerprint = crypto.fingerprint(public_key)
    envelope = crypto.Envelope.drop(secret_name, purpose, storage, retention, fingerprint, value)
    plaintext = envelope.encode()
    sealed = crypto.seal(public_key, crypto.pad(plaintext, crypto.PAD_BLOCK))
    return {
        "name": name,
        "recipient_public_key": b64encode(public_key),
        "recipient_secret_key": b64encode(private_key),
        "fingerprint": fingerprint,
        "commitment": crypto.commitment(public_key),
        "sealed": b64encode(sealed),
        "plaintext": b64encode(plaintext),
        "envelope": json.loads(plaintext),
        "secret": b64encode(value),
    }


def reveal_case(name: str, display_name: str, keeps_copy: bool, value: bytes) -> dict[str, Any]:
    key = crypto.new_symmetric_key()
    nonce = os.urandom(crypto.NONCE_SIZE)
    envelope = crypto.Envelope.reveal(display_name, value)
    plaintext = envelope.encode()
    aad = crypto.reveal_aad(display_name, keeps_copy)
    blob = crypto.encrypt_aead(key, crypto.pad(plaintext, crypto.PAD_BLOCK), aad, nonce)
    return {
        "name": name,
        "key": b64encode(key),
        "nonce": b64encode(nonce),
        "display_name": display_name,
        "keeps_copy": keeps_copy,
        "aad": b64encode(aad),
        "blob": b64encode(blob),
        "plaintext": b64encode(plaintext),
        "envelope": json.loads(plaintext),
        "secret": b64encode(value),
    }


def build() -> dict[str, Any]:
    purpose = "Call the OpenAI API from the billing script"
    return {
        "version": 1,
        "producer": "python",
        "library": (
            f"burndrop-python {__version__}, PyNaCl {importlib.metadata.version('pynacl')}"
        ),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "drops": [
            drop_case(
                "drop text",
                "openai-api-key",
                purpose,
                "macOS Keychain",
                "until-revoked",
                b"sk-test-0123456789abcdef",
            ),
            drop_case(
                "drop json characters",
                "openai-api-key",
                'Line 1\nline 2 with <tag> & "quotes"',
                "the agent's process memory only",
                "session",
                'päss "quoted" <tag> & done \\ end'.encode(),
            ),
            drop_case(
                "drop binary",
                "client-cert",
                purpose,
                "an encrypted vault file on the agent's machine",
                "until:2030-01-01T00:00:00Z",
                bytes([0, 1, 2, 3, 250, 251, 252, 253, 254, 255]),
            ),
        ],
        "reveals": [
            reveal_case(
                "reveal text",
                "staging-db-url",
                True,
                b"postgres://app:s3cret@db.staging.example:5432/app",
            ),
            reveal_case("reveal binary no copy", "tls-key", False, bytes(range(0, 256, 3))),
            reveal_case("reveal empty secret", "staging-db-url", True, b""),
        ],
    }


def main() -> int:
    document = build()
    OUT.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        f"wrote {OUT} ({len(document['drops'])} drops, {len(document['reveals'])} reveals)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
