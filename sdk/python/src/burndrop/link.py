"""Build and parse burndrop links.

Everything a client needs travels after the ``#`` in the URL, so no server,
proxy, or link scanner ever receives an identifier, a token, or a key. See
the specification section 5.6 for the format. Parsing is strict: the
version must be 1, every required field must be present exactly once, no
unknown fields are allowed, binary fields must have their exact length, and
text fields are bounded.
"""

from __future__ import annotations

import string
import urllib.parse
from dataclasses import dataclass

from . import crypto
from .encoding import EncodingError, b64decode, b64encode
from .password import SALT_SIZE

__all__ = [
    "KIND_DROP",
    "KIND_REVEAL",
    "PATH_DROP",
    "PATH_REVEAL",
    "VERSION",
    "DropLink",
    "LinkError",
    "Parsed",
    "RevealLink",
    "normalize_origin",
    "parse",
    "parse_drop",
    "parse_reveal",
]

VERSION = "1"
KIND_DROP = "drop"
KIND_REVEAL = "reveal"
PATH_DROP = "/drop"
PATH_REVEAL = "/reveal"

MAX_LINK_BYTES = 8192
MAX_ORIGIN_BYTES = 512

_DROP_FIELDS = ("v", "i", "u", "k", "n", "p", "s", "t", "r")
_REVEAL_FIELDS = ("v", "i", "o", "k", "n", "c", "s", "r")
_KEY_CHARS = 43
_SALT_CHARS = 22
_HOST_CHARS = frozenset(string.ascii_letters + string.digits + "-._~%[]:")
_LOOPBACK = ("localhost", "127.0.0.1", "::1")


class LinkError(ValueError):
    """Raised for every parse or build failure."""


@dataclass(frozen=True, kw_only=True)
class DropLink:
    """A human-to-agent link: the request public key plus what the page shows.

    ``relay`` is the relay origin; empty means "same as the page origin".
    """

    relay: str = ""
    id: str
    upload_token: str
    recipient_key: bytes
    name: str
    purpose: str = ""
    storage: str = ""
    retention: str

    def validate(self) -> None:
        """Check every field of the link."""
        if self.relay:
            normalize_origin(self.relay)
        if not crypto.valid_token(self.id):
            raise LinkError("malformed drop id")
        if not crypto.valid_token(self.upload_token):
            raise LinkError("malformed upload token")
        if len(self.recipient_key) != crypto.KEY_SIZE:
            raise LinkError(f"recipient key must be {crypto.KEY_SIZE} bytes")
        try:
            crypto.validate_name(self.name)
            crypto.validate_text("purpose", self.purpose)
            crypto.validate_text("storage", self.storage)
            crypto.validate_retention(self.retention)
        except crypto.EnvelopeError as err:
            raise LinkError(str(err)) from err

    def build(self, page_origin: str) -> str:
        """Return the full link for a page served at ``page_origin``."""
        self.validate()
        origin = normalize_origin(page_origin)
        fields = [
            ("v", VERSION),
            ("i", self.id),
            ("u", self.upload_token),
            ("k", b64encode(self.recipient_key)),
            ("n", self.name),
            ("p", self.purpose),
            ("s", self.storage),
            ("t", self.retention),
        ]
        if self.relay:
            fields.append(("r", normalize_origin(self.relay)))
        return origin + PATH_DROP + "#" + _encode_fields(fields)

    def fingerprint(self) -> str:
        """Return the fingerprint of the recipient key."""
        return crypto.fingerprint(self.recipient_key)

    def relay_origin(self, page_origin: str) -> str:
        """Return the relay to talk to: the explicit field, else the page origin."""
        return self.relay or page_origin


@dataclass(frozen=True, kw_only=True)
class RevealLink:
    """An agent-to-human link: the reveal token and the decryption key."""

    relay: str = ""
    id: str
    reveal_token: str
    key: bytes
    name: str
    keeps_copy: bool
    salt: bytes = b""

    @property
    def password_protected(self) -> bool:
        """Whether opening the link needs the reveal password the human set."""
        return len(self.salt) > 0

    def validate(self) -> None:
        """Check every field of the link."""
        if self.relay:
            normalize_origin(self.relay)
        if not crypto.valid_token(self.id):
            raise LinkError("malformed drop id")
        if not crypto.valid_token(self.reveal_token):
            raise LinkError("malformed reveal token")
        if len(self.key) != crypto.KEY_SIZE:
            raise LinkError(f"key must be {crypto.KEY_SIZE} bytes")
        if self.salt and len(self.salt) != SALT_SIZE:
            raise LinkError(f"salt must be {SALT_SIZE} bytes")
        try:
            crypto.validate_name(self.name)
        except crypto.EnvelopeError as err:
            raise LinkError(str(err)) from err

    def build(self, page_origin: str) -> str:
        """Return the full link for a page served at ``page_origin``."""
        self.validate()
        origin = normalize_origin(page_origin)
        fields = [
            ("v", VERSION),
            ("i", self.id),
            ("o", self.reveal_token),
            ("k", b64encode(self.key)),
            ("n", self.name),
            ("c", "1" if self.keeps_copy else "0"),
        ]
        if self.salt:
            fields.append(("s", b64encode(self.salt)))
        if self.relay:
            fields.append(("r", normalize_origin(self.relay)))
        return origin + PATH_REVEAL + "#" + _encode_fields(fields)

    def aad(self) -> bytes:
        """Return the additional data that authenticates the display fields."""
        return crypto.reveal_aad(self.name, self.keeps_copy)

    def relay_origin(self, page_origin: str) -> str:
        """Return the relay to talk to: the explicit field, else the page origin."""
        return self.relay or page_origin


@dataclass(frozen=True)
class Parsed:
    """The result of :func:`parse`: exactly one of ``drop`` or ``reveal`` is set."""

    kind: str
    page_origin: str
    drop: DropLink | None = None
    reveal: RevealLink | None = None

    def relay_origin(self) -> str:
        """Return the relay a client should talk to."""
        if self.drop is not None and self.drop.relay:
            return self.drop.relay
        if self.reveal is not None and self.reveal.relay:
            return self.reveal.relay
        return self.page_origin


def parse(raw: str) -> Parsed:
    """Parse either kind of link."""
    origin, path, frag = _split_link(raw)
    if path == PATH_DROP:
        return Parsed(kind=KIND_DROP, page_origin=origin, drop=_parse_drop(frag))
    if path == PATH_REVEAL:
        return Parsed(kind=KIND_REVEAL, page_origin=origin, reveal=_parse_reveal(frag))
    raise LinkError(f"path must be {PATH_DROP} or {PATH_REVEAL}")


def parse_drop(raw: str) -> tuple[DropLink, str]:
    """Parse a drop link and return it with the page origin."""
    parsed = parse(raw)
    if parsed.drop is None:
        raise LinkError("not a drop link")
    return parsed.drop, parsed.page_origin


def parse_reveal(raw: str) -> tuple[RevealLink, str]:
    """Parse a reveal link and return it with the page origin."""
    parsed = parse(raw)
    if parsed.reveal is None:
        raise LinkError("not a reveal link")
    return parsed.reveal, parsed.page_origin


def normalize_origin(origin: str) -> str:
    """Validate an origin and return it as ``scheme://host[:port]`` in lowercase.

    Only https is accepted, except http for localhost and loopback addresses
    so local development works. Default ports are dropped, as browsers do in
    ``location.origin``.
    """
    if len(origin.encode("utf-8", "surrogateescape")) > MAX_ORIGIN_BYTES:
        raise LinkError("origin too long")
    scheme, netloc, path, query, fragment = _split_url(origin)
    if path not in ("", "/") or query or fragment:
        raise LinkError("origin must be scheme://host[:port] only")
    return _origin(scheme, netloc)


def _split_url(raw: str) -> tuple[str, str, str, str, str]:
    """Split a URL as strictly as Go's ``url.Parse`` for this purpose."""
    for ch in raw:
        code = ord(ch)
        if code < 0x21 or code == 0x7F:
            raise LinkError("origin contains an invalid character")
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError as err:
        raise LinkError(f"origin: {err}") from err
    if not parts.scheme:
        raise LinkError("origin must be scheme://host[:port] only")
    if "@" in parts.netloc:
        raise LinkError("origin must be scheme://host[:port] only")
    return (
        parts.scheme.lower(),
        parts.netloc,
        urllib.parse.unquote(parts.path),
        parts.query,
        parts.fragment,
    )


def _host_port(host: str) -> tuple[str, str]:
    """Split a lowercase ``host[:port]`` into hostname and port string."""
    if host.startswith("["):
        end = host.find("]")
        if end < 0:
            raise LinkError("origin has a malformed IPv6 host")
        hostname, rest = host[1:end], host[end + 1 :]
    else:
        colon = host.rfind(":")
        if colon >= 0:
            hostname, rest = host[:colon], host[colon:]
        else:
            hostname, rest = host, ""
    port = ""
    if rest:
        if not rest.startswith(":"):
            raise LinkError("origin has a malformed host")
        port = rest[1:]
        if any(ch not in string.digits for ch in port):
            raise LinkError("origin has an invalid port")
    for ch in hostname:
        if ch not in _HOST_CHARS:
            raise LinkError("origin has an invalid character in the host")
    return hostname, port


def _origin(scheme: str, netloc: str) -> str:
    host = netloc.lower()
    hostname, port = _host_port(host)
    if not hostname:
        raise LinkError("origin has no host")
    if scheme == "http":
        if hostname not in _LOOPBACK:
            raise LinkError("http is only allowed for localhost")
    elif scheme != "https":
        raise LinkError("origin scheme must be https")
    # Browsers omit the default port from location.origin and from the
    # Origin header, so it is dropped here too; otherwise an operator who
    # writes https://relay.example:443 would never match a page origin.
    if (scheme == "https" and port == "443") or (scheme == "http" and port == "80"):
        host = host[: -(len(port) + 1)]
    return scheme + "://" + host


def _encode_fields(fields: list[tuple[str, str]]) -> str:
    return "&".join(key + "=" + urllib.parse.quote_plus(value, safe="") for key, value in fields)


def _split_link(raw: str) -> tuple[str, str, str]:
    """Separate a raw link into page origin, path, and the raw fragment.

    The fragment is taken from the raw string so that percent-encoded field
    separators are not decoded prematurely.
    """
    if len(raw.encode("utf-8", "surrogateescape")) > MAX_LINK_BYTES:
        raise LinkError("link too long")
    hash_pos = raw.find("#")
    if hash_pos < 0:
        raise LinkError("no fragment")
    base, frag = raw[:hash_pos], raw[hash_pos + 1 :]
    scheme, netloc, path, query, _fragment = _split_url(base)
    if query:
        raise LinkError("links carry no query string or userinfo")
    origin = _origin(scheme, netloc)
    if path.endswith("/"):
        path = path[:-1]
    return origin, path, frag


def _query_unescape(text: str) -> str:
    """Decode a query component like Go's ``url.QueryUnescape``.

    ``+`` becomes a space, every ``%`` must be followed by two hex digits,
    and the decoded bytes must be valid UTF-8.
    """
    data = text.encode("utf-8", "surrogateescape")
    out = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        if byte == 0x25:
            if i + 2 >= len(data) or not _is_hex(data[i + 1]) or not _is_hex(data[i + 2]):
                raise LinkError("invalid percent escape")
            out.append(int(data[i + 1 : i + 3], 16))
            i += 3
        elif byte == 0x2B:
            out.append(0x20)
            i += 1
        else:
            out.append(byte)
            i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError as err:
        raise LinkError("field is not valid UTF-8") from err


def _is_hex(byte: int) -> bool:
    return chr(byte) in string.hexdigits


def _parse_fields(frag: str, allowed: tuple[str, ...]) -> dict[str, str]:
    if frag == "":
        raise LinkError("empty fragment")
    out: dict[str, str] = {}
    for part in frag.split("&"):
        eq = part.find("=")
        if eq <= 0:
            raise LinkError(f"malformed field {part!r}")
        key = part[:eq]
        if key not in allowed:
            raise LinkError(f"unknown field {key!r}")
        if key in out:
            raise LinkError(f"duplicate field {key!r}")
        out[key] = _query_unescape(part[eq + 1 :])
    if out.get("v") != VERSION:
        raise LinkError(f"unsupported link version {out.get('v', '')!r}")
    return out


def _require(fields: dict[str, str], *keys: str) -> None:
    for key in keys:
        if not fields.get(key):
            raise LinkError(f"missing field {key!r}")


def _decode_key(text: str) -> bytes:
    if len(text) != _KEY_CHARS:
        raise LinkError(f"key must be {_KEY_CHARS} base64url characters")
    try:
        key = b64decode(text)
    except EncodingError as err:
        raise LinkError("key is not valid base64url") from err
    if len(key) != crypto.KEY_SIZE:
        raise LinkError("key is not valid base64url")
    return key


def _decode_salt(text: str) -> bytes:
    if len(text) != _SALT_CHARS:
        raise LinkError(f"salt must be {_SALT_CHARS} base64url characters")
    try:
        salt = b64decode(text)
    except EncodingError as err:
        raise LinkError("salt is not valid base64url") from err
    if len(salt) != SALT_SIZE:
        raise LinkError("salt is not valid base64url")
    return salt


def _parse_drop(frag: str) -> DropLink:
    fields = _parse_fields(frag, _DROP_FIELDS)
    _require(fields, "i", "u", "k", "n", "t")
    relay = fields.get("r", "")
    link = DropLink(
        relay=normalize_origin(relay) if relay else "",
        id=fields["i"],
        upload_token=fields["u"],
        recipient_key=_decode_key(fields["k"]),
        name=fields["n"],
        purpose=fields.get("p", ""),
        storage=fields.get("s", ""),
        retention=fields["t"],
    )
    link.validate()
    return link


def _parse_reveal(frag: str) -> RevealLink:
    fields = _parse_fields(frag, _REVEAL_FIELDS)
    _require(fields, "i", "o", "k", "n", "c")
    flag = fields["c"]
    if flag not in ("0", "1"):
        raise LinkError("field c must be 0 or 1")
    relay = fields.get("r", "")
    link = RevealLink(
        relay=normalize_origin(relay) if relay else "",
        id=fields["i"],
        reveal_token=fields["o"],
        key=_decode_key(fields["k"]),
        name=fields["n"],
        keeps_copy=flag == "1",
        salt=_decode_salt(fields["s"]) if fields.get("s") else b"",
    )
    link.validate()
    return link
