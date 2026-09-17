"""Password-protected reveals (crypto specification section 4.1).

A reveal link normally carries the whole decryption key. When the human has
set a reveal password, the agent mixes a password-derived key into the link
key: the link alone is not enough, and the password alone is not enough.
The Argon2id parameters are libsodium's interactive limits, so PyNaCl, the
browser (libsodium.js), and Go derive the same bytes.
"""

from __future__ import annotations

import hashlib
import os

import nacl.pwhash

from .crypto import KEY_SIZE, CryptoError, LengthError

SALT_SIZE = 16
"""Size of the per-reveal salt carried in the link."""

PASSWORD_OPSLIMIT = 2
"""Argon2id time cost (crypto_pwhash_OPSLIMIT_INTERACTIVE)."""

PASSWORD_MEMLIMIT = 64 * 1024 * 1024
"""Argon2id memory cost in bytes (crypto_pwhash_MEMLIMIT_INTERACTIVE, 64 MiB)."""

_DOMAIN = b"burndrop/reveal-password/v1"


def new_salt() -> bytes:
    """Return a random salt for one password-protected reveal."""
    return os.urandom(SALT_SIZE)


def password_key(password: str | bytes, salt: bytes) -> bytes:
    """Derive 32 bytes from a password with Argon2id 1.3 (time 2, memory 64 MiB, one lane).

    The password is used as typed, in UTF-8, with no normalization.
    """
    raw = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if not raw:
        raise CryptoError("password must not be empty")
    if len(salt) != SALT_SIZE:
        raise LengthError(f"salt must be {SALT_SIZE} bytes")
    derived = nacl.pwhash.argon2id.kdf(
        KEY_SIZE, raw, bytes(salt), opslimit=PASSWORD_OPSLIMIT, memlimit=PASSWORD_MEMLIMIT
    )
    return bytes(derived)


def reveal_key_with_password(link_key: bytes, password: str | bytes, salt: bytes) -> bytes:
    """Return BLAKE2b-256(domain || link_key || password_key).

    That is the XChaCha20-Poly1305 key of a password-protected reveal.
    """
    if len(link_key) != KEY_SIZE:
        raise LengthError(f"key must be {KEY_SIZE} bytes")
    material = _DOMAIN + bytes(link_key) + password_key(password, salt)
    return hashlib.blake2b(material, digest_size=KEY_SIZE).digest()
