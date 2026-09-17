"""Unit tests for burndrop.crypto, burndrop.encoding, and the helpers behind them."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import nacl.bindings
import pytest

from burndrop import crypto
from burndrop._json import json_string
from burndrop._time import format_rfc3339, parse_rfc3339
from burndrop.encoding import EncodingError, b64decode, b64encode

BS = chr(92)


# Padding.


def test_pad_matches_libsodium() -> None:
    for n in [*range(300), 511, 512, 513, 1000]:
        data = bytes(i % 251 for i in range(n))
        padded = crypto.pad(data)
        assert padded == nacl.bindings.sodium_pad(data, crypto.PAD_BLOCK)
        assert len(padded) % crypto.PAD_BLOCK == 0
        assert len(padded) > n
        assert crypto.unpad(padded) == data
        assert nacl.bindings.sodium_unpad(padded, crypto.PAD_BLOCK) == data


def test_pad_edge_cases() -> None:
    assert crypto.pad(b"", 4) == b"\x80\x00\x00\x00"
    assert crypto.pad(b"abc", 4) == b"abc\x80"
    assert crypto.pad(b"abcd", 4) == b"abcd\x80\x00\x00\x00"
    assert crypto.unpad(b"\x80\x00\x00\x00", 4) == b""
    assert crypto.unpad(b"\x00\x80\x00\x00", 4) == b"\x00"
    assert crypto.unpad(b"\x80\x80\x00\x00", 4) == b"\x80"
    with pytest.raises(ValueError, match="block"):
        crypto.pad(b"", 0)
    with pytest.raises(ValueError, match="block"):
        crypto.unpad(b"", 0)


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        b"abc",
        bytes(4),
        b"ab\x80\x01",
        b"\x80\x00\x00\x00" + bytes(4),
        b"\x80\x00\x00\x00\x00",
        b"\x81\x00\x00\x00",
    ],
)
def test_unpad_rejects(bad: bytes) -> None:
    with pytest.raises(crypto.PaddingError):
        crypto.unpad(bad, 4)


# Sealed boxes and AEAD.


def test_sealed_box_round_trip() -> None:
    public_key, private_key = crypto.generate_keypair()
    assert len(public_key) == 32
    assert len(private_key) == 32
    assert crypto.public_key_from_private(private_key) == public_key
    sealed = crypto.seal(public_key, b"hello")
    assert len(sealed) == 5 + crypto.SEALED_OVERHEAD
    assert crypto.open_sealed(public_key, private_key, sealed) == b"hello"
    assert crypto.seal(public_key, b"hello") != sealed, "sealed boxes are randomized"
    with pytest.raises(crypto.DecryptError):
        crypto.open_sealed(public_key, private_key, sealed[:-1])
    with pytest.raises(crypto.DecryptError):
        crypto.open_sealed(public_key, private_key, b"short")
    with pytest.raises(crypto.LengthError):
        crypto.open_sealed(public_key[:-1], private_key, sealed)
    with pytest.raises(crypto.LengthError):
        crypto.seal(b"x" * 31, b"hello")
    with pytest.raises(crypto.LengthError):
        crypto.public_key_from_private(b"")


def test_aead_round_trip() -> None:
    key = crypto.new_symmetric_key()
    assert len(key) == 32
    blob = crypto.encrypt_aead(key, b"payload", b"aad")
    assert len(blob) == 7 + crypto.AEAD_OVERHEAD
    assert crypto.decrypt_aead(key, blob, b"aad") == b"payload"
    assert crypto.encrypt_aead(key, b"payload", b"aad") != blob, "nonces are random"
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt_aead(key, blob, b"other")
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt_aead(key, blob[:-1], b"aad")
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt_aead(key, b"short", b"aad")
    with pytest.raises(crypto.LengthError):
        crypto.encrypt_aead(key[:-1], b"payload", b"aad")
    with pytest.raises(crypto.LengthError):
        crypto.encrypt_aead(key, b"payload", b"aad", nonce=b"short")
    with pytest.raises(crypto.LengthError):
        crypto.decrypt_aead(b"", blob, b"aad")
    empty = crypto.encrypt_aead(key, b"", b"")
    assert crypto.decrypt_aead(key, empty, b"") == b""


# Fingerprints, commitments, tokens.


def test_fingerprint_and_commitment_shape() -> None:
    public_key, _ = crypto.generate_keypair()
    fingerprint = crypto.fingerprint(public_key)
    assert len(fingerprint) == 19
    assert fingerprint.count("-") == 3
    assert all(ch in "0123456789abcdef-" for ch in fingerprint)
    commitment = crypto.commitment(public_key)
    assert len(commitment) == crypto.HASH_LEN
    assert crypto.valid_commitment(commitment)
    assert not crypto.valid_commitment(commitment + "A")
    assert crypto.valid_commitment("A" * 43), "all zero bits is canonical"
    assert not crypto.valid_commitment("A" * 42 + "B"), "non-zero trailing bits"
    assert not crypto.valid_commitment("")


def test_tokens() -> None:
    token = crypto.random_token()
    assert len(token) == crypto.TOKEN_LEN
    assert crypto.valid_token(token)
    assert crypto.random_token() != token
    assert not crypto.valid_token(token[:-1])
    assert not crypto.valid_token(token + "A")
    assert len(crypto.hash_token(token)) == crypto.HASH_LEN


# Field validation.


@pytest.mark.parametrize("name", ["a", "openai-api-key", "clé API", "a" * 100, "x y"])
def test_validate_name_accepts(name: str) -> None:
    crypto.validate_name(name)


@pytest.mark.parametrize(
    "name",
    ["", "a" * 101, " a", "a ", "\ta", "a\n", "a\x00b", "a\x7fb", chr(0xA0) + "a", "a\x1f"],
)
def test_validate_name_rejects(name: str) -> None:
    with pytest.raises(crypto.EnvelopeError):
        crypto.validate_name(name)


@pytest.mark.parametrize("text", ["", "a" * 200, "line 1\nline 2", " padded ", "päss <tag> & done"])
def test_validate_text_accepts(text: str) -> None:
    crypto.validate_text("purpose", text)


@pytest.mark.parametrize("text", ["a" * 201, "tab\there", "a\rb", "a\x7f", "\x00", chr(0xD800)])
def test_validate_text_rejects(text: str) -> None:
    with pytest.raises(crypto.EnvelopeError):
        crypto.validate_text("purpose", text)


@pytest.mark.parametrize(
    "retention",
    [
        "session",
        "until-revoked",
        "until:2027-03-04T05:06:07Z",
        "until:2027-03-04T05:06:07.123Z",
        "until:2027-03-04T05:06:07,5Z",
        "until:2027-03-04T05:06:07+02:00",
        "until:2027-03-04T05:06:07-05:30",
        "until:2028-02-29T00:00:00Z",
    ],
)
def test_validate_retention_accepts(retention: str) -> None:
    crypto.validate_retention(retention)


@pytest.mark.parametrize(
    "retention",
    [
        "",
        "forever",
        "until:",
        "until:2027-03-04",
        "until:2027-03-04 05:06:07Z",
        "until:2027-03-04t05:06:07Z",
        "until:2027-03-04T05:06:07z",
        "until:2027-03-04T05:06:07",
        "until:2027-02-30T00:00:00Z",
        "until:2027-02-29T00:00:00Z",
        "until:2027-13-01T00:00:00Z",
        "until:2027-03-04T24:00:00Z",
        "until:2027-03-04T05:60:00Z",
        "until:2027-03-04T05:06:60Z",
        "until:2027-03-04T05:06:07.Z",
        "until:2027-03-04T05:06:07+24:00",
        "until:2027-03-04T05:06:07+02:60",
        "until:2027-03-04T05:06:07+0200",
        "until:0000-01-01T00:00:00Z",
        "until: 2027-03-04T05:06:07Z",
        "until:2027-03-04T05:06:07Z ",
        "Session",
    ],
)
def test_validate_retention_rejects(retention: str) -> None:
    with pytest.raises(crypto.EnvelopeError):
        crypto.validate_retention(retention)


def test_reveal_aad() -> None:
    assert crypto.reveal_aad("n", True) == b"burndrop/reveal/v1\nn\n1"
    assert crypto.reveal_aad("n", False) == b"burndrop/reveal/v1\nn\n0"
    assert crypto.reveal_aad("clé", True) == "burndrop/reveal/v1\nclé\n1".encode()


# RFC 3339 helpers.


def test_parse_rfc3339() -> None:
    value = parse_rfc3339("2027-03-04T05:06:07Z")
    assert value == datetime(2027, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
    offset = parse_rfc3339("2027-03-04T05:06:07.25+02:00")
    assert offset.utcoffset() == timedelta(hours=2)
    assert offset.microsecond == 250000
    assert offset.astimezone(timezone.utc).hour == 3
    negative = parse_rfc3339("2027-03-04T05:06:07-05:30")
    assert negative.utcoffset() == -timedelta(hours=5, minutes=30)
    assert parse_rfc3339("2027-03-04T05:06:07.1234567890Z").microsecond == 123456
    with pytest.raises(ValueError, match="RFC 3339"):
        parse_rfc3339("yesterday")


def test_format_rfc3339() -> None:
    assert format_rfc3339(datetime(2027, 3, 4, 5, 6, 7, tzinfo=timezone.utc)) == (
        "2027-03-04T05:06:07Z"
    )
    naive = datetime(2027, 3, 4, 5, 6, 7)
    assert format_rfc3339(naive) == "2027-03-04T05:06:07Z"
    plus_two = datetime(2027, 3, 4, 5, 6, 7, tzinfo=timezone(timedelta(hours=2)))
    assert format_rfc3339(plus_two) == "2027-03-04T03:06:07Z"


# Encoding.


def test_b64_round_trip_and_strictness() -> None:
    for n in range(8):
        data = bytes(range(n))
        text = b64encode(data)
        assert "=" not in text
        assert b64decode(text) == data
    assert b64encode(b"\xff\xfe\xfd") == "__79"
    assert b64decode("AA") == b"\x00"
    for bad in ["AB", "AA==", "AA=", "A", "+/", "AA\n", "AA A", "Aé", "AAAAA"]:
        with pytest.raises(EncodingError):
            b64decode(bad)
    with pytest.raises(EncodingError):
        b64decode(b"AA")  # type: ignore[arg-type]


# JSON string escaping identical to Go.


def test_json_string_matches_go_rules() -> None:
    assert json_string("plain") == '"plain"'
    assert json_string('q"b') == '"q' + BS + '"b"'
    assert json_string("a" + BS + "b") == '"a' + BS + BS + 'b"'
    assert json_string("\n\r\t\b\f") == '"' + BS + "n" + BS + "r" + BS + "t" + BS + "b" + BS + 'f"'
    assert json_string("\x01\x1f") == '"' + BS + "u0001" + BS + 'u001f"'
    assert json_string("<>&") == '"<>&"'
    assert json_string("<>&", escape_html=True) == '"' + BS + "u003c" + BS + "u003e" + BS + 'u0026"'
    assert json_string(chr(0x2028) + chr(0x2029)) == '"' + BS + "u2028" + BS + 'u2029"'
    assert json_string("päss") == '"päss"'
    assert json_string("\x7f") == '"\x7f"'
    assert json_string(chr(0xD800)) == '"' + BS + 'ufffd"'


# Envelope.


def drop_envelope(**overrides: str) -> crypto.Envelope:
    fields = {
        "type": "drop",
        "name": "openai-api-key",
        "purpose": "Call the OpenAI API",
        "storage": "macOS Keychain",
        "retention": "until-revoked",
        "fingerprint": "7f4e-3996-5f9b-d725",
        "format": "text",
        "secret": "sk-live-0123456789abcdef",
    }
    fields.update(overrides)
    return crypto.Envelope(**fields)


def test_with_secret_picks_the_format() -> None:
    base = crypto.Envelope(type="reveal", name="n")
    assert base.with_secret(b"hello") == crypto.Envelope(
        type="reveal", name="n", format="text", secret="hello"
    )
    assert base.with_secret(b"tab\tnl\ncr\r").format == "text"
    assert base.with_secret(b"\x00\x01") == crypto.Envelope(
        type="reveal", name="n", format="base64", secret="AAE"
    )
    assert base.with_secret(b"\xff\xfe").format == "base64"
    assert base.with_secret(b"").format == "text"
    assert base.with_secret("päss".encode()).secret == "päss"
    for value in [b"", b"text", b"\x00\x01\x02", b"\xff", bytes(range(256))]:
        assert base.with_secret(value).secret_bytes() == value
    with pytest.raises(crypto.EnvelopeError):
        crypto.Envelope(type="reveal", name="n", format="base64", secret="AB=").secret_bytes()


def test_constructors() -> None:
    env = crypto.Envelope.drop("n", "p", "s", "session", "0000-0000-0000-0000", b"v")
    assert env == crypto.Envelope(
        type="drop",
        name="n",
        purpose="p",
        storage="s",
        retention="session",
        fingerprint="0000-0000-0000-0000",
        format="text",
        secret="v",
    )
    env.validate()
    assert crypto.Envelope.reveal("n", b"v") == crypto.Envelope(
        type="reveal", name="n", format="text", secret="v"
    )


def test_encode_is_compact_and_ordered() -> None:
    assert drop_envelope().encode() == (
        b'{"v":1,"type":"drop","name":"openai-api-key","purpose":"Call the OpenAI API",'
        b'"storage":"macOS Keychain","retention":"until-revoked",'
        b'"fingerprint":"7f4e-3996-5f9b-d725","format":"text","secret":"sk-live-0123456789abcdef"}'
    )
    assert drop_envelope(purpose="", storage="").encode() == (
        b'{"v":1,"type":"drop","name":"openai-api-key","retention":"until-revoked",'
        b'"fingerprint":"7f4e-3996-5f9b-d725","format":"text","secret":"sk-live-0123456789abcdef"}'
    )
    reveal = crypto.Envelope.reveal("staging-db-url", b'p\xc3\xa4ss "quoted" <tag> & done\n')
    expected = (
        '{"v":1,"type":"reveal","name":"staging-db-url","format":"text","secret":"päss '
        + BS
        + '"quoted'
        + BS
        + '" <tag> & done'
        + BS
        + 'n"}'
    )
    assert reveal.encode() == expected.encode("utf-8")
    assert crypto.Envelope.reveal("n", b"\x01").encode() == (
        b'{"v":1,"type":"reveal","name":"n","format":"base64","secret":"AQ"}'
    )
    control = crypto.Envelope(type="reveal", name="n", format="text", secret="\x01").encode()
    expected_control = (
        '{"v":1,"type":"reveal","name":"n","format":"text","secret":"' + BS + 'u0001"}'
    )
    assert control == expected_control.encode()
    separator = crypto.Envelope.reveal("n", chr(0x2028).encode()).encode()
    assert separator.endswith(('"secret":"' + BS + 'u2028"}').encode())


def test_encode_validates() -> None:
    with pytest.raises(crypto.EnvelopeError):
        drop_envelope(v=2).encode()  # type: ignore[arg-type]
    with pytest.raises(crypto.EnvelopeError):
        drop_envelope(retention="forever").encode()


@pytest.mark.parametrize(
    "env",
    [
        drop_envelope(),
        drop_envelope(purpose="", storage=""),
        drop_envelope(retention="until:2027-03-04T05:06:07Z"),
        drop_envelope(retention="session", name="x y", secret='päss <tag> & "done"\n'),
        crypto.Envelope.reveal("staging-db-url", b"postgres://app:s3cret@db.staging.example:5432/app"),
        crypto.Envelope.reveal("n", b""),
        crypto.Envelope.reveal("n", b"\x00\x01\xff"),
        crypto.Envelope.reveal("n", b"\x01\x1f\x7f"),
        crypto.Envelope.reveal("n", (chr(0x2028) + chr(0x2029) + "é").encode()),
    ],
)
def test_decode_round_trip(env: crypto.Envelope) -> None:
    encoded = env.encode()
    assert crypto.Envelope.decode(encoded) == env
    assert crypto.Envelope.decode(encoded.decode("utf-8")) == env
    assert json.loads(encoded) == json.loads(encoded)


def test_decode_rejects_unknown_and_mistyped_fields() -> None:
    base = json.loads(drop_envelope().encode())
    cases: list[dict[str, object]] = [
        {**base, "extra": 1},
        {**base, "Name": "x"},
        {**base, "v": "1"},
        {**base, "v": True},
        {**base, "v": 1.0},
        {**base, "v": 2},
        {**base, "name": 5},
        {**base, "secret": ["x"]},
        {**base, "type": None},
        {k: v for k, v in base.items() if k != "v"},
        {k: v for k, v in base.items() if k != "format"},
    ]
    for case in cases:
        with pytest.raises(crypto.EnvelopeError):
            crypto.Envelope.decode(json.dumps(case).encode())
    for raw in [b"", b"null", b"[]", b'"x"', b"{", b"{} {}", b"\xef\xbb\xbf{}", b"1"]:
        with pytest.raises(crypto.EnvelopeError):
            crypto.Envelope.decode(raw)
    with pytest.raises(crypto.EnvelopeError):
        crypto.Envelope.decode(json.dumps(base).encode() + b" trailing")


def test_decode_mirrors_go_lenient_details() -> None:
    base = json.loads(drop_envelope().encode())
    # null means "not set", as in Go.
    assert crypto.Envelope.decode(json.dumps({**base, "purpose": None}).encode()).purpose == ""
    # Duplicate keys: the last one wins.
    body = '{"v":2,"v":1,"type":"reveal","name":"n","format":"text","secret":"s"}'
    assert crypto.Envelope.decode(body).v == 1
    with pytest.raises(crypto.EnvelopeError):
        crypto.Envelope.decode(
            '{"v":1,"v":2,"type":"reveal","name":"n","format":"text","secret":"s"}'
        )
    # Invalid UTF-8 inside a string becomes U+FFFD and stays valid.
    raw = b'{"v":1,"type":"reveal","name":"n","format":"text","secret":"a\xffb"}'
    assert crypto.Envelope.decode(raw).secret == "a" + chr(0xFFFD) + "b"
    # A lone surrogate escape becomes U+FFFD too.
    text = '{"v":1,"type":"reveal","name":"n","format":"text","secret":"' + BS + 'ud800"}'
    assert crypto.Envelope.decode(text).secret == chr(0xFFFD)
    # Surrogate pairs are combined.
    pair = (
        '{"v":1,"type":"reveal","name":"n","format":"text","secret":"'
        + BS
        + "ud83d"
        + BS
        + 'ude00"}'
    )
    assert crypto.Envelope.decode(pair).secret == chr(0x1F600)


def test_reveal_rejects_drop_metadata() -> None:
    for field in ("purpose", "storage", "retention", "fingerprint"):
        env = crypto.Envelope(type="reveal", name="n", format="text", secret="s", **{field: "x"})
        with pytest.raises(crypto.EnvelopeError, match="no drop metadata"):
            env.validate()


def test_base64_secret_must_be_canonical() -> None:
    crypto.Envelope(type="reveal", name="n", format="base64", secret="AAE").validate()
    for bad in ["AAE=", "AB", "A", "+/"]:
        with pytest.raises(crypto.EnvelopeError):
            crypto.Envelope(type="reveal", name="n", format="base64", secret=bad).validate()


def test_envelope_helpers_round_trip_and_bound_sizes() -> None:
    public_key, private_key = crypto.generate_keypair()
    env = drop_envelope()
    sealed = crypto.seal_envelope(public_key, env)
    assert (len(sealed) - crypto.SEALED_OVERHEAD) % crypto.PAD_BLOCK == 0
    assert crypto.open_envelope(public_key, private_key, sealed) == env
    key = crypto.new_symmetric_key()
    reveal = crypto.Envelope.reveal("n", b"value")
    blob = crypto.encrypt_envelope(key, reveal, crypto.reveal_aad("n", True))
    assert (len(blob) - crypto.AEAD_OVERHEAD) % crypto.PAD_BLOCK == 0
    assert crypto.decrypt_envelope(key, blob, crypto.reveal_aad("n", True)) == reveal
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt_envelope(key, blob, crypto.reveal_aad("n", False))
    huge = crypto.Envelope.reveal("n", b"x" * (crypto.MAX_PLAINTEXT + 1))
    with pytest.raises(crypto.SizeError):
        crypto.seal_envelope(public_key, huge)
    with pytest.raises(crypto.SizeError):
        crypto.encrypt_envelope(key, huge, b"")
    too_long = crypto.MAX_PLAINTEXT + crypto.PAD_BLOCK + crypto.SEALED_OVERHEAD + 1
    with pytest.raises(crypto.SizeError):
        crypto.open_envelope(public_key, private_key, bytes(too_long))
    with pytest.raises(crypto.SizeError):
        crypto.decrypt_envelope(key, bytes(too_long), b"")
    # Authenticated but malformed plaintext is rejected after decryption.
    with pytest.raises(crypto.PaddingError):
        crypto.open_envelope(public_key, private_key, crypto.seal(public_key, bytes(256)))
    with pytest.raises(crypto.EnvelopeError):
        crypto.open_envelope(public_key, private_key, crypto.seal(public_key, crypto.pad(b"{}")))
    with pytest.raises(crypto.PaddingError):
        crypto.decrypt_envelope(key, crypto.encrypt_aead(key, b"\x80", b""), b"")
