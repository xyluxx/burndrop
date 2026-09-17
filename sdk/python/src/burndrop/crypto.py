"""The cryptographic core of burndrop.

It is deliberately small. Every operation maps to one libsodium primitive
exposed by PyNaCl, so the bytes produced here are consumed unchanged by the
Go reference implementation and by the TypeScript module, and vice versa.
The shared test vectors live in ``spec/vectors.json``.

Two encryption paths exist and nothing else:

* Drop (human to agent): a libsodium sealed box to the agent's per-request
  X25519 public key. Specification section 5.3.
* Reveal (agent to human): XChaCha20-Poly1305 (IETF) under a random 256-bit
  key with the display metadata as additional data. Section 5.4.

Plaintext is always an :class:`Envelope`, padded to a multiple of
:data:`PAD_BLOCK` bytes with ISO/IEC 7816-4 padding before encryption, so
the relay only ever learns a coarse size class.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, replace
from typing import Any

import nacl.bindings
import nacl.exceptions

from ._json import json_string
from ._time import parse_rfc3339
from .encoding import EncodingError, b64decode, b64encode

__all__ = [
    "AEAD_OVERHEAD",
    "FORMAT_BASE64",
    "FORMAT_TEXT",
    "HASH_LEN",
    "KEY_SIZE",
    "MAX_NAME_LEN",
    "MAX_PLAINTEXT",
    "MAX_TEXT_LEN",
    "NONCE_SIZE",
    "PAD_BLOCK",
    "RETENTION_SESSION",
    "RETENTION_UNTIL_PREFIX",
    "RETENTION_UNTIL_REVOKED",
    "SEALED_OVERHEAD",
    "TAG_SIZE",
    "TOKEN_BYTES",
    "TOKEN_LEN",
    "TYPE_DROP",
    "TYPE_REVEAL",
    "CryptoError",
    "DecryptError",
    "Envelope",
    "EnvelopeError",
    "LengthError",
    "PaddingError",
    "SizeError",
    "commitment",
    "decrypt_aead",
    "decrypt_envelope",
    "encrypt_aead",
    "encrypt_envelope",
    "fingerprint",
    "generate_keypair",
    "hash_token",
    "new_symmetric_key",
    "open_envelope",
    "open_sealed",
    "pad",
    "public_key_from_private",
    "random_token",
    "reveal_aad",
    "seal",
    "seal_envelope",
    "unpad",
    "valid_commitment",
    "valid_token",
    "validate_name",
    "validate_retention",
    "validate_text",
]

KEY_SIZE = 32
"""Size of X25519 keys and of XChaCha20-Poly1305 keys."""
NONCE_SIZE = 24
"""XChaCha20-Poly1305 nonce size (192 bits)."""
TAG_SIZE = 16
"""Poly1305 authentication tag size."""
SEALED_OVERHEAD = 48
"""Sealed box overhead: ephemeral public key (32) plus tag (16)."""
AEAD_OVERHEAD = NONCE_SIZE + TAG_SIZE
"""Reveal blob overhead: nonce (24) plus tag (16)."""
PAD_BLOCK = 256
"""Padding block size. Section 5.1."""
MAX_PLAINTEXT = 64 * 1024
"""Largest envelope accepted before padding."""
TOKEN_BYTES = 16
"""Entropy of every token and identifier: 128 bits. Section 5.2."""
TOKEN_LEN = 22
"""Encoded length of a token or identifier."""
HASH_LEN = 43
"""Encoded length of a SHA-256 hash."""

MAX_NAME_LEN = 100
MAX_TEXT_LEN = 200

TYPE_DROP = "drop"
TYPE_REVEAL = "reveal"
FORMAT_TEXT = "text"
FORMAT_BASE64 = "base64"
RETENTION_SESSION = "session"
RETENTION_UNTIL_REVOKED = "until-revoked"
RETENTION_UNTIL_PREFIX = "until:"

_FINGERPRINT_RE = re.compile(r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}")
_ENVELOPE_FIELDS = (
    "v",
    "type",
    "name",
    "purpose",
    "storage",
    "retention",
    "fingerprint",
    "format",
    "secret",
)
_OPTIONAL_DROP_FIELDS = ("purpose", "storage", "retention", "fingerprint")


class CryptoError(Exception):
    """Base class for every error raised by this module."""


class DecryptError(CryptoError):
    """Authentication failed.

    Deliberately the same for a wrong key, altered ciphertext, or altered
    additional data, so callers cannot distinguish them (and neither can an
    attacker).
    """


class PaddingError(CryptoError):
    """Padding is malformed after decryption."""


class SizeError(CryptoError):
    """An input exceeds :data:`MAX_PLAINTEXT`."""


class LengthError(CryptoError):
    """A key, nonce, or blob has the wrong length."""


class EnvelopeError(CryptoError, ValueError):
    """An envelope is malformed."""


def _check_key(key: bytes, what: str = "key") -> bytes:
    key = bytes(key)
    if len(key) != KEY_SIZE:
        raise LengthError(f"{what} must be {KEY_SIZE} bytes")
    return key


# Keys and sealed boxes (section 5.3).


def generate_keypair() -> tuple[bytes, bytes]:
    """Return a fresh X25519 ``(public_key, private_key)`` for one request."""
    public_key, private_key = nacl.bindings.crypto_box_keypair()
    return bytes(public_key), bytes(private_key)


def public_key_from_private(private_key: bytes) -> bytes:
    """Derive the X25519 public key from a private key."""
    return bytes(nacl.bindings.crypto_scalarmult_base(_check_key(private_key, "private key")))


def seal(recipient_public_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext to a public key as a libsodium sealed box.

    The output is ``ephemeral public key || XSalsa20-Poly1305 ciphertext``
    with the nonce derived as BLAKE2b-24 of both public keys, exactly
    ``crypto_box_seal``.
    """
    return bytes(nacl.bindings.crypto_box_seal(bytes(plaintext), _check_key(recipient_public_key)))


def open_sealed(public_key: bytes, private_key: bytes, sealed: bytes) -> bytes:
    """Decrypt a sealed box with the recipient keypair."""
    public_key = _check_key(public_key, "public key")
    private_key = _check_key(private_key, "private key")
    sealed = bytes(sealed)
    if len(sealed) < SEALED_OVERHEAD:
        raise DecryptError("decryption failed")
    try:
        return bytes(nacl.bindings.crypto_box_seal_open(sealed, public_key, private_key))
    except (nacl.exceptions.CryptoError, ValueError) as err:
        raise DecryptError("decryption failed") from err


# Symmetric encryption (section 5.4).


def new_symmetric_key() -> bytes:
    """Return a random 256-bit key for one reveal."""
    return os.urandom(KEY_SIZE)


def encrypt_aead(key: bytes, plaintext: bytes, aad: bytes, nonce: bytes | None = None) -> bytes:
    """Encrypt with XChaCha20-Poly1305 (IETF).

    Returns ``nonce || ciphertext || tag``, the wire format for reveal blobs.
    ``aad`` is authenticated but not encrypted. A nonce is drawn from the OS
    CSPRNG unless one is given (only the test vectors do that).
    """
    key = _check_key(key)
    if nonce is None:
        nonce = os.urandom(NONCE_SIZE)
    nonce = bytes(nonce)
    if len(nonce) != NONCE_SIZE:
        raise LengthError(f"nonce must be {NONCE_SIZE} bytes")
    sealed = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        bytes(plaintext), bytes(aad), nonce, key
    )
    return nonce + bytes(sealed)


def decrypt_aead(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Reverse :func:`encrypt_aead`. Any modification of blob or aad fails."""
    key = _check_key(key)
    blob = bytes(blob)
    if len(blob) < AEAD_OVERHEAD:
        raise DecryptError("decryption failed")
    try:
        out = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            blob[NONCE_SIZE:], bytes(aad), blob[:NONCE_SIZE], key
        )
    except (nacl.exceptions.CryptoError, ValueError) as err:
        raise DecryptError("decryption failed") from err
    return bytes(out)


# Padding (section 5.1).


def pad(data: bytes, block: int = PAD_BLOCK) -> bytes:
    """Apply ISO/IEC 7816-4 padding.

    Appends ``0x80`` and then ``0x00`` bytes up to the next multiple of
    ``block``. At least one byte is always added, so an input that is
    already aligned grows by a full block. Identical to ``sodium_pad``.
    """
    if block <= 0:
        raise ValueError("block must be positive")
    data = bytes(data)
    pad_len = block - len(data) % block
    return data + b"\x80" + b"\x00" * (pad_len - 1)


def unpad(data: bytes, block: int = PAD_BLOCK) -> bytes:
    """Reverse :func:`pad`.

    Scans back at most ``block`` bytes for the ``0x80`` marker and rejects
    anything else, like ``sodium_unpad``. It runs on authenticated
    plaintext, so its timing is not a concern.
    """
    if block <= 0:
        raise ValueError("block must be positive")
    data = bytes(data)
    if len(data) == 0 or len(data) % block != 0:
        raise PaddingError("invalid padding")
    stop = len(data) - block
    for i in range(len(data) - 1, stop - 1, -1):
        byte = data[i]
        if byte == 0x80:
            return data[:i]
        if byte != 0x00:
            raise PaddingError("invalid padding")
    raise PaddingError("invalid padding")


# Fingerprints, commitments, tokens (sections 5.2 and 5.3).


def fingerprint(public_key: bytes) -> str:
    """Return the human-comparable fingerprint of a public key.

    The first 64 bits of SHA-256(key) as four groups of four lowercase hex
    characters, for example ``a1b2-c3d4-e5f6-a7b8``. Section 5.3 step 4.
    """
    digest = hashlib.sha256(bytes(public_key)).hexdigest()[:16]
    return "-".join(digest[i : i + 4] for i in range(0, 16, 4))


def commitment(public_key: bytes) -> str:
    """Return SHA-256(key) as base64url.

    The agent registers it with the relay when it creates a slot and the
    browser sends it again with the upload, so a link whose key was altered
    in transit is rejected by an honest relay. Section 5.3 steps 2 and 8.
    """
    return b64encode(hashlib.sha256(bytes(public_key)).digest())


def random_token() -> str:
    """Return 16 random bytes encoded as base64url (22 characters)."""
    return b64encode(os.urandom(TOKEN_BYTES))


def hash_token(token: str) -> str:
    """Return the base64url SHA-256 of a token string, as the relay stores it."""
    return b64encode(hashlib.sha256(token.encode("utf-8")).digest())


def valid_token(token: str) -> bool:
    """Report whether a token or identifier is well formed.

    Exactly :data:`TOKEN_LEN` characters of canonical base64url decoding to
    :data:`TOKEN_BYTES` bytes.
    """
    if not isinstance(token, str) or len(token) != TOKEN_LEN:
        return False
    try:
        return len(b64decode(token)) == TOKEN_BYTES
    except EncodingError:
        return False


def valid_commitment(value: str) -> bool:
    """Report whether a commitment is well formed (43 characters, 32 bytes)."""
    if not isinstance(value, str) or len(value) != HASH_LEN:
        return False
    try:
        return len(b64decode(value)) == hashlib.sha256().digest_size
    except EncodingError:
        return False


# Envelope (section 5.5).


def validate_name(name: str) -> None:
    """Check a secret reference name.

    1 to :data:`MAX_NAME_LEN` characters, printable, no control characters,
    no leading or trailing whitespace.
    """
    if not name or len(name) > MAX_NAME_LEN:
        raise EnvelopeError(f"name must be 1 to {MAX_NAME_LEN} characters")
    if name.strip() != name:
        raise EnvelopeError("name has leading or trailing whitespace")
    for ch in name:
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            raise EnvelopeError("name contains a control character")


def validate_text(field: str, text: str) -> None:
    """Check a display text field (purpose, storage).

    At most :data:`MAX_TEXT_LEN` characters, valid UTF-8, no control
    characters except newline.
    """
    if len(text) > MAX_TEXT_LEN:
        raise EnvelopeError(f"{field} longer than {MAX_TEXT_LEN} characters")
    if not _valid_utf8(text):
        raise EnvelopeError(f"{field} is not valid UTF-8")
    for ch in text:
        code = ord(ch)
        if (code < 0x20 and ch != "\n") or code == 0x7F:
            raise EnvelopeError(f"{field} contains a control character")


def validate_retention(retention: str) -> None:
    """Accept ``session``, ``until-revoked``, or ``until:<RFC 3339>``."""
    if retention in (RETENTION_SESSION, RETENTION_UNTIL_REVOKED):
        return
    if retention.startswith(RETENTION_UNTIL_PREFIX):
        try:
            parse_rfc3339(retention[len(RETENTION_UNTIL_PREFIX) :])
        except ValueError as err:
            raise EnvelopeError("retention date is not RFC 3339") from err
        return
    raise EnvelopeError("unknown retention policy")


def reveal_aad(name: str, keeps_copy: bool) -> bytes:
    """Build the additional data for a reveal.

    The display fields the page shows, joined with newlines behind a fixed
    domain string, so a link whose display fields were altered fails to
    decrypt. The drop ID is not included because the relay assigns it after
    the ciphertext exists; the random per-reveal key already makes
    ciphertext from another reveal undecryptable. Section 5.6.
    """
    flag = "1" if keeps_copy else "0"
    return ("burndrop/reveal/v1\n" + name + "\n" + flag).encode("utf-8")


def _valid_utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _has_binary_control(value: bytes) -> bool:
    return any(b < 0x20 and b not in (0x09, 0x0A, 0x0D) for b in value)


def _sanitize(text: str) -> str:
    """Replace lone surrogates with U+FFFD, as Go's JSON decoder does."""
    if _valid_utf8(text):
        return text
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


@dataclass(frozen=True)
class Envelope:
    """The plaintext structure that is padded and encrypted. Section 5.5.

    For drops, the browser fills in the metadata it displayed (name, purpose,
    storage, retention, fingerprint) so the agent can verify that the human
    saw exactly what the agent asked for. For reveals only name, format and
    secret are set; the display fields travel as additional data instead.
    """

    v: int = 1
    type: str = ""
    name: str = ""
    purpose: str = ""
    storage: str = ""
    retention: str = ""
    fingerprint: str = ""
    format: str = ""
    secret: str = ""

    @classmethod
    def drop(
        cls,
        name: str,
        purpose: str,
        storage: str,
        retention: str,
        fingerprint: str,
        value: bytes,
    ) -> Envelope:
        """Build a drop envelope, choosing the secret format from the value."""
        env = cls(
            type=TYPE_DROP,
            name=name,
            purpose=purpose,
            storage=storage,
            retention=retention,
            fingerprint=fingerprint,
        )
        return env.with_secret(value)

    @classmethod
    def reveal(cls, name: str, value: bytes) -> Envelope:
        """Build a reveal envelope, choosing the secret format from the value."""
        return cls(type=TYPE_REVEAL, name=name).with_secret(value)

    def with_secret(self, value: bytes) -> Envelope:
        """Return a copy carrying value.

        Text when the value is valid UTF-8 without control characters other
        than tab, newline, and carriage return; base64url otherwise.
        """
        value = bytes(value)
        if not _has_binary_control(value):
            try:
                return replace(self, format=FORMAT_TEXT, secret=value.decode("utf-8"))
            except UnicodeDecodeError:
                pass
        return replace(self, format=FORMAT_BASE64, secret=b64encode(value))

    def secret_bytes(self) -> bytes:
        """Return the secret as raw bytes, decoding base64url if needed."""
        if self.format == FORMAT_BASE64:
            try:
                return b64decode(self.secret)
            except EncodingError as err:
                raise EnvelopeError("secret is not base64url") from err
        return self.secret.encode("utf-8")

    def validate(self) -> None:
        """Check every field against the specification."""
        if self.v != 1:
            raise EnvelopeError(f"unsupported version {self.v}")
        if self.type not in (TYPE_DROP, TYPE_REVEAL):
            raise EnvelopeError("unknown type")
        if self.format not in (FORMAT_TEXT, FORMAT_BASE64):
            raise EnvelopeError("unknown format")
        validate_name(self.name)
        validate_text("purpose", self.purpose)
        validate_text("storage", self.storage)
        if self.type == TYPE_DROP:
            validate_retention(self.retention)
            if _FINGERPRINT_RE.fullmatch(self.fingerprint) is None:
                raise EnvelopeError("malformed fingerprint")
        elif self.retention or self.fingerprint or self.purpose or self.storage:
            raise EnvelopeError("reveal envelopes carry no drop metadata")
        if self.format == FORMAT_BASE64:
            try:
                b64decode(self.secret)
            except EncodingError as err:
                raise EnvelopeError("secret is not base64url") from err
        elif not _valid_utf8(self.secret):
            raise EnvelopeError("secret is not valid UTF-8")

    def encode(self) -> bytes:
        """Validate and serialize as compact JSON, byte-identical to Go.

        Fields appear in the reference order, optional drop metadata is
        omitted when empty, and strings are escaped without HTML escaping.
        """
        self.validate()
        parts = [
            '"v":' + str(self.v),
            '"type":' + json_string(self.type),
            '"name":' + json_string(self.name),
        ]
        for name in _OPTIONAL_DROP_FIELDS:
            value: str = getattr(self, name)
            if value:
                parts.append('"' + name + '":' + json_string(value))
        parts.append('"format":' + json_string(self.format))
        parts.append('"secret":' + json_string(self.secret))
        return ("{" + ",".join(parts) + "}").encode("utf-8")

    @classmethod
    def decode(cls, data: bytes | str) -> Envelope:
        """Parse and validate an envelope. Unknown fields are rejected."""
        text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
        try:
            obj: Any = json.loads(text)
        except ValueError as err:
            raise EnvelopeError("malformed JSON") from err
        if not isinstance(obj, dict):
            raise EnvelopeError("envelope must be a JSON object")
        for key in obj:
            if key not in _ENVELOPE_FIELDS:
                raise EnvelopeError(f"unknown field {key!r}")
        version = obj.get("v", 0)
        if version is None:
            version = 0
        if isinstance(version, bool) or not isinstance(version, int):
            raise EnvelopeError("v must be an integer")
        strings: dict[str, str] = {}
        for key in _ENVELOPE_FIELDS[1:]:
            value = obj.get(key, "")
            if value is None:
                value = ""
            if not isinstance(value, str):
                raise EnvelopeError(f"{key} must be a string")
            strings[key] = _sanitize(value)
        env = cls(v=version, **strings)
        env.validate()
        return env


# Whole-envelope helpers.


def seal_envelope(recipient_public_key: bytes, envelope: Envelope) -> bytes:
    """Encode, pad, and seal an envelope to a recipient key."""
    plain = envelope.encode()
    if len(plain) > MAX_PLAINTEXT:
        raise SizeError("envelope too large")
    return seal(recipient_public_key, pad(plain, PAD_BLOCK))


def open_envelope(public_key: bytes, private_key: bytes, sealed: bytes) -> Envelope:
    """Open a sealed box, unpad, and decode the envelope."""
    if len(sealed) > MAX_PLAINTEXT + PAD_BLOCK + SEALED_OVERHEAD:
        raise SizeError("ciphertext too large")
    padded = open_sealed(public_key, private_key, sealed)
    return Envelope.decode(unpad(padded, PAD_BLOCK))


def encrypt_envelope(
    key: bytes, envelope: Envelope, aad: bytes, nonce: bytes | None = None
) -> bytes:
    """Encode, pad, and encrypt an envelope for a reveal."""
    plain = envelope.encode()
    if len(plain) > MAX_PLAINTEXT:
        raise SizeError("envelope too large")
    return encrypt_aead(key, pad(plain, PAD_BLOCK), aad, nonce)


def decrypt_envelope(key: bytes, blob: bytes, aad: bytes) -> Envelope:
    """Reverse :func:`encrypt_envelope`."""
    if len(blob) > MAX_PLAINTEXT + PAD_BLOCK + AEAD_OVERHEAD:
        raise SizeError("ciphertext too large")
    padded = decrypt_aead(key, blob, aad)
    return Envelope.decode(unpad(padded, PAD_BLOCK))
