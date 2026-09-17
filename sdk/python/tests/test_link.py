"""Link building and parsing, mirroring internal/link/link_test.go."""

from __future__ import annotations

import dataclasses

import pytest

from burndrop import crypto, link
from burndrop.link import DropLink, LinkError, RevealLink, normalize_origin, parse

ID = "MTIzNDU2Nzg5MGFiY2RlZg"
TOKEN = "YWJjZGVmZ2hpamtsbW5vcA"
PAGE = "https://drop.example.com"


def key(byte: int) -> bytes:
    return bytes([byte]) * crypto.KEY_SIZE


def sample_drop() -> DropLink:
    return DropLink(
        id=ID,
        upload_token=TOKEN,
        recipient_key=key(7),
        name="openai-api-key",
        purpose="Call the OpenAI API from the billing script & report",
        storage="macOS Keychain",
        retention="until-revoked",
    )


def sample_reveal() -> RevealLink:
    return RevealLink(id=ID, reveal_token=TOKEN, key=key(9), name="staging-db-url", keeps_copy=True)


def test_drop_round_trip() -> None:
    drop = sample_drop()
    raw = drop.build(PAGE)
    assert raw.startswith(PAGE + "/drop#v=1&i=" + ID + "&u=" + TOKEN + "&k=")
    assert "?" not in raw
    got, origin = link.parse_drop(raw)
    assert origin == PAGE
    assert got == drop
    assert got.fingerprint() == crypto.fingerprint(key(7))
    parsed = parse(raw)
    assert parsed.kind == link.KIND_DROP
    assert parsed.drop == drop
    assert parsed.reveal is None
    assert parsed.relay_origin() == PAGE
    assert got.relay_origin(PAGE) == PAGE


def test_drop_with_relay_and_unicode() -> None:
    drop = dataclasses.replace(
        sample_drop(),
        relay="HTTPS://Relay.Example.com:8443/",
        name="clé API",
        purpose="Ligne 1\nligne 2 with + plus and % percent and #hash and =equals",
    )
    raw = drop.build(PAGE)
    got, _ = link.parse_drop(raw)
    assert got.relay == "https://relay.example.com:8443"
    assert got.name == drop.name
    assert got.purpose == drop.purpose
    assert parse(raw).relay_origin() == "https://relay.example.com:8443"
    assert got.relay_origin(PAGE) == "https://relay.example.com:8443"


def test_reveal_round_trip() -> None:
    reveal = sample_reveal()
    raw = reveal.build(PAGE)
    assert raw.startswith(PAGE + "/reveal#v=1&i=" + ID + "&o=" + TOKEN + "&k=")
    assert raw.endswith("&c=1")
    got, origin = link.parse_reveal(raw)
    assert origin == PAGE
    assert got == reveal
    assert got.aad() == crypto.reveal_aad("staging-db-url", True)
    parsed = parse(raw)
    assert parsed.kind == link.KIND_REVEAL
    assert parsed.reveal == reveal
    assert parsed.drop is None
    no_copy = dataclasses.replace(reveal, keeps_copy=False)
    got2, _ = link.parse_reveal(no_copy.build(PAGE))
    assert got2.keeps_copy is False
    with pytest.raises(LinkError, match="not a drop link"):
        link.parse_drop(raw)
    with pytest.raises(LinkError, match="not a reveal link"):
        link.parse_reveal(sample_drop().build(PAGE))
    with_relay = dataclasses.replace(reveal, relay="https://relay.example")
    parsed = parse(with_relay.build(PAGE))
    assert parsed.relay_origin() == "https://relay.example"
    assert parsed.reveal is not None
    assert parsed.reveal.relay_origin(PAGE) == "https://relay.example"


def invalid_links() -> dict[str, str]:
    good = sample_drop().build(PAGE)
    frag = good[good.index("#") + 1 :]
    reveal = sample_reveal().build(PAGE)
    return {
        "no fragment": PAGE + "/drop",
        "wrong path": PAGE + "/other#" + frag,
        "root path": PAGE + "/#" + frag,
        "double slash path": PAGE + "/drop//#" + frag,
        "query string": PAGE + "/drop?x=1#" + frag,
        "userinfo": "https://user@drop.example.com/drop#" + frag,
        "http origin": "http://drop.example.com/drop#" + frag,
        "no scheme": "drop.example.com/drop#" + frag,
        "empty fragment": PAGE + "/drop#",
        "wrong version": PAGE + "/drop#" + frag.replace("v=1", "v=2", 1),
        "missing version": PAGE + "/drop#" + frag.replace("v=1&", "", 1),
        "unknown field": PAGE + "/drop#" + frag + "&x=1",
        "duplicate field": PAGE + "/drop#" + frag + "&n=again",
        "missing id": PAGE + "/drop#" + frag.replace("i=" + ID, "i=", 1),
        "short id": PAGE + "/drop#" + frag.replace("i=" + ID, "i=abc", 1),
        "id with plus": PAGE + "/drop#" + frag.replace("i=" + ID, "i=" + ID[:-1] + "%2B", 1),
        "bad key": PAGE + "/drop#" + frag.replace("&k=", "&k=x", 1),
        "key wrong length": PAGE + "/drop#" + frag.replace("&k=", "&k=A", 1),
        "bad retention": PAGE + "/drop#" + frag.replace("t=until-revoked", "t=forever", 1),
        "bad relay scheme": PAGE + "/drop#" + frag + "&r=ftp%3A%2F%2Fx",
        "http relay": PAGE + "/drop#" + frag + "&r=http%3A%2F%2Frelay.example",
        "relay with path": PAGE + "/drop#" + frag + "&r=https%3A%2F%2Fx%2Fpath",
        "malformed escape": PAGE + "/drop#" + frag.replace("n=", "n=%zz", 1),
        "truncated escape": PAGE + "/drop#" + frag.replace("n=", "n=%4", 1),
        "invalid utf8 field": PAGE + "/drop#" + frag.replace("n=", "n=%FF", 1),
        "field without eq": PAGE + "/drop#" + frag + "&novalue",
        "empty key": PAGE + "/drop#" + frag + "&=x",
        "long name": PAGE + "/drop#" + frag.replace("n=openai-api-key", "n=" + "a" * 101, 1),
        "control in name": PAGE + "/drop#" + frag.replace("n=openai-api-key", "n=a%00b", 1),
        "space padded name": PAGE + "/drop#" + frag.replace("n=openai-api-key", "n=+a", 1),
        "long purpose": PAGE + "/drop#" + frag.replace("&p=", "&p=" + "a" * 201, 1),
        "reveal bad c": reveal.replace("&c=1", "&c=2", 1),
        "reveal missing c": reveal.replace("&c=1", "", 1),
        "reveal drop fields": reveal + "&t=session",
        "reveal empty name": reveal.replace("n=staging-db-url", "n=", 1),
        "too long": PAGE + "/drop#" + frag + "&p=" + "a" * 9000,
        "control in origin": "https://drop.example\n.com/drop#" + frag,
        "space in origin": "https://drop example.com/drop#" + frag,
        "bracket in origin": "https://drop{example.com/drop#" + frag,
        "empty": "",
        "hash only": "#",
    }


@pytest.mark.parametrize("raw", list(invalid_links().values()), ids=list(invalid_links()))
def test_invalid_links(raw: str) -> None:
    with pytest.raises(LinkError):
        parse(raw)


def test_build_validation() -> None:
    short_key = dataclasses.replace(sample_drop(), recipient_key=key(1)[:31])
    with pytest.raises(LinkError, match="recipient key"):
        short_key.build(PAGE)
    with pytest.raises(LinkError, match="http is only allowed"):
        sample_drop().build("http://drop.example.com")
    assert sample_drop().build("http://localhost:8080").startswith("http://localhost:8080/drop#")
    relay_path = dataclasses.replace(sample_drop(), relay="https://relay.example.com/api")
    with pytest.raises(LinkError):
        relay_path.build(PAGE)
    empty_name = dataclasses.replace(sample_reveal(), name="")
    with pytest.raises(LinkError, match="name"):
        empty_name.build(PAGE)
    bad_id = dataclasses.replace(sample_reveal(), id="short")
    with pytest.raises(LinkError, match="drop id"):
        bad_id.build(PAGE)
    bad_token = dataclasses.replace(sample_reveal(), reveal_token="short")
    with pytest.raises(LinkError, match="reveal token"):
        bad_token.build(PAGE)
    bad_upload = dataclasses.replace(sample_drop(), upload_token="short")
    with pytest.raises(LinkError, match="upload token"):
        bad_upload.build(PAGE)
    short_reveal_key = dataclasses.replace(sample_reveal(), key=b"x")
    with pytest.raises(LinkError, match="key must be"):
        short_reveal_key.build(PAGE)
    bad_relay = dataclasses.replace(sample_reveal(), relay="ftp://x")
    with pytest.raises(LinkError):
        bad_relay.build(PAGE)
    long_purpose = dataclasses.replace(sample_drop(), purpose="a" * 201)
    with pytest.raises(LinkError, match="purpose"):
        long_purpose.build(PAGE)
    long_storage = dataclasses.replace(sample_drop(), storage="a" * 201)
    with pytest.raises(LinkError, match="storage"):
        long_storage.build(PAGE)


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        ("https://Example.com", "https://example.com"),
        ("https://example.com/", "https://example.com"),
        ("https://example.com:8443", "https://example.com:8443"),
        ("http://localhost:3000", "http://localhost:3000"),
        ("http://127.0.0.1", "http://127.0.0.1"),
        ("http://[::1]:8080", "http://[::1]:8080"),
        ("https://[2001:db8::1]:443", "https://[2001:db8::1]"),
        ("https://[2001:DB8::1]", "https://[2001:db8::1]"),
        ("https://example.com:443/", "https://example.com"),
        ("http://localhost:80", "http://localhost"),
        ("http://localhost:8080", "http://localhost:8080"),
        ("https://sub.example.co.uk/", "https://sub.example.co.uk"),
        ("HTTPS://RELAY.EXAMPLE:443", "https://relay.example"),
        ("https://example.com:0443", "https://example.com:0443"),
        ("https://xn--bcher-kva.example", "https://xn--bcher-kva.example"),
    ],
)
def test_normalize_origin_accepts(raw: str, want: str) -> None:
    assert normalize_origin(raw) == want


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "example.com",
        "http://example.com",
        "https://",
        "https:///example.com",
        "https://example.com/path",
        "https://example.com?x=1",
        "https://example.com#f",
        "https://u:p@example.com",
        "https://@example.com",
        "ftp://example.com",
        "https://" + "a" * 600,
        "https://example.com:abc",
        "https://example.com:44 3",
        "https://[::1",
        "https://exa mple.com",
        "https://example.com\n",
        " https://example.com",
        "https://exam{ple.com",
        "mailto:someone",
        "http://localhost.example",
        "http://127.0.0.2",
    ],
)
def test_normalize_origin_rejects(raw: str) -> None:
    with pytest.raises(LinkError):
        normalize_origin(raw)


def test_link_length_is_reasonable() -> None:
    assert len(sample_drop().build(PAGE)) <= 400
    assert len(sample_reveal().build(PAGE)) <= 250


def test_query_encoding_round_trips_awkward_text() -> None:
    awkward = "a+b c%d&e=f#g/h?ié" + chr(0x2028) + "\nend"
    drop = dataclasses.replace(sample_drop(), purpose=awkward, storage=" spaced ")
    got, _ = link.parse_drop(drop.build(PAGE))
    assert got.purpose == awkward
    assert got.storage == " spaced "
    # Percent-encoded separators inside a value never split the fragment.
    assert drop.build(PAGE).count("&") == 7
