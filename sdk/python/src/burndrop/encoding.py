"""base64url without padding, decoded strictly.

Every binary field in links, JSON bodies, and the shared test vectors uses
this encoding. Decoding is strict in the same sense as Go's
``base64.RawURLEncoding.Strict()``: the input must use only the URL-safe
alphabet, must not carry padding, and non-zero trailing bits are rejected, so
every byte string has exactly one encoding.
"""

from __future__ import annotations

import base64
import binascii
import re

__all__ = ["EncodingError", "b64decode", "b64encode"]

_ALPHABET = re.compile(r"[A-Za-z0-9_-]*")


class EncodingError(ValueError):
    """The input is not canonical base64url without padding."""


def b64encode(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def b64decode(text: str) -> bytes:
    """Decode base64url without padding, rejecting anything non-canonical."""
    if not isinstance(text, str) or _ALPHABET.fullmatch(text) is None:
        raise EncodingError("not base64url")
    if len(text) % 4 == 1:
        raise EncodingError("invalid base64url length")
    padded = text + "=" * (-len(text) % 4)
    try:
        out = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as err:
        raise EncodingError("invalid base64url") from err
    if b64encode(out) != text:
        raise EncodingError("non-canonical base64url")
    return out
