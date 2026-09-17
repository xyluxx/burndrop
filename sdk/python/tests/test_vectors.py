"""Every section of spec/vectors.json, byte for byte."""

from __future__ import annotations

import json
from typing import Any

import pytest

from burndrop import crypto
from burndrop.encoding import b64decode
from support import load_vectors

V = load_vectors()
EXPECTED_SECTIONS = {
    "sealed_box",
    "xchacha20poly1305",
    "padding",
    "fingerprint",
    "envelope",
    "reveal_aad",
    "tokens",
    "reveal_password",
}


def _ids(section: str) -> list[str]:
    return [case.get("name", str(i)) for i, case in enumerate(V[section])]


def test_every_section_is_exercised() -> None:
    sections = {key for key, value in V.items() if isinstance(value, list)}
    assert sections == EXPECTED_SECTIONS
    assert V["version"] == 1
    assert V["pad_block"] == crypto.PAD_BLOCK
    for section in EXPECTED_SECTIONS:
        assert V[section], section


@pytest.mark.parametrize("case", V["sealed_box"], ids=_ids("sealed_box"))
def test_sealed_box(case: dict[str, Any]) -> None:
    public_key = b64decode(case["recipient_public_key"])
    private_key = b64decode(case["recipient_secret_key"])
    sealed = b64decode(case["sealed"])
    assert crypto.public_key_from_private(private_key) == public_key
    padded = crypto.open_sealed(public_key, private_key, sealed)
    assert padded == b64decode(case["padded_plaintext"])
    plain = crypto.unpad(padded, crypto.PAD_BLOCK)
    assert plain == b64decode(case["plaintext"])
    env = crypto.Envelope.decode(plain)
    assert env.type == crypto.TYPE_DROP
    assert env.encode() == plain, "encoding must be byte-identical to Go"
    assert crypto.open_envelope(public_key, private_key, sealed) == env
    assert env.fingerprint == crypto.fingerprint(public_key)
    with pytest.raises(crypto.DecryptError):
        crypto.open_sealed(public_key, private_key, sealed[:-1] + bytes([sealed[-1] ^ 1]))
    other_public, other_private = crypto.generate_keypair()
    with pytest.raises(crypto.DecryptError):
        crypto.open_sealed(other_public, other_private, sealed)


@pytest.mark.parametrize("case", V["xchacha20poly1305"], ids=_ids("xchacha20poly1305"))
def test_xchacha20poly1305(case: dict[str, Any]) -> None:
    key = b64decode(case["key"])
    nonce = b64decode(case["nonce"])
    aad = b64decode(case["aad"])
    padded = b64decode(case["plaintext"])
    blob = b64decode(case["blob"])
    assert blob[: crypto.NONCE_SIZE] == nonce
    assert crypto.encrypt_aead(key, padded, aad, nonce) == blob
    assert crypto.decrypt_aead(key, blob, aad) == padded
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt_aead(key, blob, aad + b"x")
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt_aead(key, blob[:-1] + bytes([blob[-1] ^ 1]), aad)
    with pytest.raises(crypto.DecryptError):
        crypto.decrypt_aead(bytes(32), blob, aad)
    env = crypto.decrypt_envelope(key, blob, aad)
    assert env.type == crypto.TYPE_REVEAL
    assert env.encode() == crypto.unpad(padded, crypto.PAD_BLOCK)
    assert crypto.encrypt_envelope(key, env, aad, nonce) == blob


@pytest.mark.parametrize("case", V["padding"], ids=_ids("padding"))
def test_padding(case: dict[str, Any]) -> None:
    unpadded = b64decode(case["unpadded"])
    padded = b64decode(case["padded"])
    assert crypto.pad(unpadded, case["block"]) == padded
    assert crypto.unpad(padded, case["block"]) == unpadded


@pytest.mark.parametrize("case", V["fingerprint"], ids=_ids("fingerprint"))
def test_fingerprint_and_commitment(case: dict[str, Any]) -> None:
    public_key = b64decode(case["public_key"])
    assert crypto.fingerprint(public_key) == case["fingerprint"]
    assert crypto.commitment(public_key) == case["commitment"]
    assert crypto.valid_commitment(case["commitment"])


@pytest.mark.parametrize("case", V["envelope"], ids=_ids("envelope"))
def test_envelope(case: dict[str, Any]) -> None:
    env = crypto.Envelope(**case["envelope"])
    encoded = json.dumps(case["envelope"]).encode("utf-8")
    if case["valid"]:
        env.validate()
        decoded = crypto.Envelope.decode(encoded)
        assert decoded == env
        assert crypto.Envelope.decode(env.encode()) == env
    else:
        with pytest.raises(crypto.EnvelopeError):
            env.validate()
        with pytest.raises(crypto.EnvelopeError):
            crypto.Envelope.decode(encoded)
        with pytest.raises(crypto.EnvelopeError):
            env.encode()


@pytest.mark.parametrize("case", V["reveal_aad"], ids=_ids("reveal_aad"))
def test_reveal_aad(case: dict[str, Any]) -> None:
    assert crypto.reveal_aad(case["name"], case["keeps_copy"]) == b64decode(case["aad"])


@pytest.mark.parametrize("case", V["tokens"], ids=[repr(c["token"]) for c in V["tokens"]])
def test_tokens(case: dict[str, Any]) -> None:
    assert crypto.valid_token(case["token"]) == case["valid"]
    assert crypto.hash_token(case["token"]) == case["sha256"]
