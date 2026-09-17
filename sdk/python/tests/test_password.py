"""Password-protected reveals: derivation vectors and the link salt."""

from __future__ import annotations

from typing import Any

import pytest

from burndrop import crypto, password
from burndrop.encoding import b64decode, b64encode
from burndrop.link import LinkError, RevealLink, parse_reveal
from support import load_vectors

V = load_vectors()
ORIGIN = "https://drop.example.com"
ID = "AAAAAAAAAAAAAAAAAAAAAA"
TOKEN = "MTIzNDU2Nzg5MGFiY2RlZg"


def test_vectors_exist() -> None:
    assert V["reveal_password"]


@pytest.mark.parametrize(
    "case", V["reveal_password"], ids=[c["name"] for c in V["reveal_password"]]
)
def test_vector(case: dict[str, Any]) -> None:
    salt = b64decode(case["salt"])
    link_key = b64decode(case["link_key"])
    assert b64encode(password.password_key(case["password"], salt)) == case["password_key"]
    derived = password.reveal_key_with_password(link_key, case["password"], salt)
    assert b64encode(derived) == case["key"]
    other = password.reveal_key_with_password(link_key, case["password"] + "x", salt)
    assert b64encode(other) != case["key"]


def test_rejects_bad_inputs() -> None:
    with pytest.raises(crypto.CryptoError):
        password.password_key("", b"\x00" * password.SALT_SIZE)
    with pytest.raises(crypto.CryptoError):
        password.password_key("pw", b"\x00" * (password.SALT_SIZE - 1))
    with pytest.raises(crypto.CryptoError):
        password.reveal_key_with_password(b"\x00" * 31, "pw", b"\x00" * password.SALT_SIZE)


def test_link_carries_the_salt() -> None:
    key = crypto.new_symmetric_key()
    salt = password.new_salt()
    link = RevealLink(id=ID, reveal_token=TOKEN, key=key, name="db", keeps_copy=True, salt=salt)
    url = link.build(ORIGIN)
    assert "&s=" in url
    parsed, origin = parse_reveal(url)
    assert origin == ORIGIN
    assert parsed.salt == salt
    assert parsed.password_protected
    assert parsed.key == key

    plain = RevealLink(id=ID, reveal_token=TOKEN, key=key, name="db", keeps_copy=True)
    plain_url = plain.build(ORIGIN)
    assert "&s=" not in plain_url
    assert not parse_reveal(plain_url)[0].password_protected
    with pytest.raises(LinkError):
        parse_reveal(plain_url + "&s=short")
    with pytest.raises(LinkError):
        parse_reveal(plain_url + "&s=" + "!" * 22)
    with pytest.raises(LinkError):
        RevealLink(
            id=ID, reveal_token=TOKEN, key=key, name="db", keeps_copy=True, salt=b"12"
        ).validate()
