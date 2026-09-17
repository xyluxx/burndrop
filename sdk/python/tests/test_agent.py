"""Agent and human flows against the in-process fake relay."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator

import pytest

from burndrop import Agent, crypto, human, link
from burndrop.agent import (
    STATUS_EXPIRED,
    STATUS_GONE,
    STATUS_RECEIVED,
    STATUS_REJECTED,
    STATUS_REVOKED,
    STATUS_WAITING,
    AgentError,
    Request,
    parse_retention,
    validate_secret_name,
)
from burndrop.human import HumanError
from burndrop.relay import CODE_COMMITMENT, CODE_GONE, RelayClient, RelayError
from fake_relay import FakeRelay


@pytest.fixture
def relay() -> Iterator[FakeRelay]:
    fake = FakeRelay()
    try:
        yield fake
    finally:
        fake.close()


@pytest.fixture
def agent(relay: FakeRelay) -> Agent:
    return Agent(relay.origin)


def upload_envelope(request: Request, env: crypto.Envelope, page_origin: str) -> None:
    """Play a page that submits an arbitrary envelope for a request."""
    drop, _ = link.parse_drop(request.link)
    sealed = crypto.seal_envelope(drop.recipient_key, env)
    RelayClient(page_origin).upload(
        drop.id, drop.upload_token, crypto.commitment(drop.recipient_key), sealed
    )


def honest_envelope(request: Request, value: bytes = b"v") -> crypto.Envelope:
    drop, _ = link.parse_drop(request.link)
    return crypto.Envelope.drop(
        drop.name, drop.purpose, drop.storage, drop.retention, drop.fingerprint(), value
    )


def test_validate_secret_name() -> None:
    for name in ["a", "openai-api-key", "A1.b_c-d", "x" * 100]:
        validate_secret_name(name)
    for name in ["", "bad name", "-lead", ".lead", "a..b", "x" * 101, "clé", "a/b"]:
        with pytest.raises(ValueError, match="must"):
            validate_secret_name(name)


def test_parse_retention() -> None:
    assert parse_retention("session") is None
    assert parse_retention("until-revoked") is None
    expires = parse_retention("until:2099-01-01T00:00:00+01:00")
    assert expires is not None
    assert expires.isoformat() == "2098-12-31T23:00:00+00:00"
    with pytest.raises(ValueError, match="in the past"):
        parse_retention("until:2001-01-01T00:00:00Z")
    with pytest.raises(ValueError, match="RFC 3339"):
        parse_retention("until:tomorrow")
    with pytest.raises(ValueError, match="unknown retention"):
        parse_retention("forever")


def test_request_validation(agent: Agent) -> None:
    with pytest.raises(ValueError, match="must"):
        agent.request_secret("bad name", "x")
    with pytest.raises(ValueError, match="purpose is required"):
        agent.request_secret("k", "  ")
    with pytest.raises(ValueError, match="unknown retention"):
        agent.request_secret("k", "p", retention="forever")
    with pytest.raises(ValueError, match="ttl"):
        agent.request_secret("k", "p", ttl=0)
    with pytest.raises(ValueError, match="ttl"):
        agent.request_secret("k", "p", ttl=True)  # type: ignore[arg-type]
    with pytest.raises(crypto.EnvelopeError):
        agent.request_secret("k", "p", storage_label="s" * 201)
    with pytest.raises(crypto.EnvelopeError):
        agent.request_secret("k", "tab\tin purpose")


def test_request_fetch_receive(relay: FakeRelay, agent: Agent) -> None:
    request = agent.request_secret(
        "openai-api-key", "Call the OpenAI API for the nightly report", ttl=1800
    )
    assert crypto.valid_token(request.request_id)
    assert request.link.startswith(relay.origin + "/drop#")
    assert request.expires_at is not None
    assert request.storage == "the agent's process memory only"
    assert request.retention == "until-revoked"
    for needle in [
        request.link,
        request.fingerprint,
        "works once",
        "nightly report",
        "process memory only",
        "kept until deleted",
        "never see the value",
    ]:
        assert needle in request.message
    assert "private_key" not in repr(request)
    assert request.fetch_token not in repr(request)
    drop, page_origin = link.parse_drop(request.link)
    assert page_origin == relay.origin
    assert drop.relay == ""
    assert drop.fingerprint() == request.fingerprint
    assert drop.name == "openai-api-key"
    assert relay.requests[-1].json["ttl_seconds"] == 1800

    waiting = agent.fetch_secret(request, wait_seconds=1)
    assert waiting.status == STATUS_WAITING
    assert waiting.value is None
    assert "not submitted openai-api-key yet" in waiting.message
    assert "value" not in repr(waiting) or "value=None" in repr(waiting)

    fingerprint = human.submit(request.link, b"sk-live-secret-value-123")
    assert fingerprint == request.fingerprint
    fetched = agent.fetch_secret(request)
    assert fetched.status == STATUS_RECEIVED
    assert fetched.value == b"sk-live-secret-value-123"
    assert fetched.name == "openai-api-key"
    assert fetched.fingerprint == request.fingerprint
    assert fetched.request_id == request.request_id
    assert "sk-live" not in fetched.message
    assert "sk-live" not in repr(fetched)
    assert not any(request.private_key), "private key zeroed after use"
    assert (
        agent.redactor.redact("token=sk-live-secret-value-123") == "token=[redacted:openai-api-key]"
    )
    again = agent.fetch_secret(request)
    assert again.status == STATUS_GONE
    assert "already fetched" in again.message


def test_fetch_wakes_on_upload(relay: FakeRelay, agent: Agent) -> None:
    request = agent.request_secret("k", "p")
    threading.Timer(0.3, human.submit, args=(request.link, b"value")).start()
    start = time.monotonic()
    fetched = agent.fetch_secret(request, wait_seconds=10)
    assert fetched.status == STATUS_RECEIVED
    assert time.monotonic() - start < 5


def test_fetch_outcomes(relay: FakeRelay, agent: Agent) -> None:
    # Revoked by the human side.
    r1 = agent.request_secret("one", "p")
    drop, _ = link.parse_drop(r1.link)
    RelayClient(relay.origin).revoke_drop(drop.id, drop.upload_token)
    assert agent.fetch_secret(r1).status == STATUS_REVOKED
    # Expired on the relay.
    r2 = agent.request_secret("two", "p")
    relay.expire(r2.request_id)
    assert agent.fetch_secret(r2).status == STATUS_EXPIRED
    # Unknown to the relay.
    r3 = agent.request_secret("three", "p")
    relay.delete(r3.request_id)
    outcome = agent.fetch_secret(r3)
    assert outcome.status == STATUS_EXPIRED
    assert "no longer known" in outcome.message
    # Fetched by someone else first.
    r4 = agent.request_secret("four", "p")
    human.submit(r4.link, b"v4")
    RelayClient(relay.origin).fetch(r4.request_id, r4.fetch_token)
    outcome = agent.fetch_secret(r4)
    assert outcome.status == STATUS_GONE
    assert "treat the secret as exposed" in outcome.message
    # Negative and zero waits.
    r5 = agent.request_secret("five", "p")
    assert agent.fetch_secret(r5, wait_seconds=-1).status == STATUS_WAITING


def test_fetch_rejects_tampered_envelopes(relay: FakeRelay, agent: Agent) -> None:
    r1 = agent.request_secret("three", "p")
    upload_envelope(
        r1, crypto.Envelope(**{**vars(honest_envelope(r1)), "name": "evil"}), relay.origin
    )
    outcome = agent.fetch_secret(r1)
    assert outcome.status == STATUS_REJECTED
    assert "name" in outcome.message
    assert outcome.value is None

    r2 = agent.request_secret("four", "p", retention="session")
    tampered = crypto.Envelope(**{**vars(honest_envelope(r2)), "retention": "until-revoked"})
    upload_envelope(r2, tampered, relay.origin)
    outcome = agent.fetch_secret(r2)
    assert outcome.status == STATUS_REJECTED
    assert "retention" in outcome.message

    r3 = agent.request_secret("five", "p")
    wrong = crypto.Envelope(**{**vars(honest_envelope(r3)), "fingerprint": "0000-0000-0000-0000"})
    upload_envelope(r3, wrong, relay.origin)
    outcome = agent.fetch_secret(r3)
    assert outcome.status == STATUS_REJECTED
    assert "fingerprint" in outcome.message

    r4 = agent.request_secret("six", "p")
    upload_envelope(r4, crypto.Envelope.reveal("six", b"v6"), relay.origin)
    outcome = agent.fetch_secret(r4)
    assert outcome.status == STATUS_REJECTED
    assert "not a drop" in outcome.message

    r5 = agent.request_secret("seven", "p")
    drop, _ = link.parse_drop(r5.link)
    other_public, _ = crypto.generate_keypair()
    garbage = crypto.seal(other_public, crypto.pad(b"x"))
    RelayClient(relay.origin).upload(
        drop.id, drop.upload_token, crypto.commitment(drop.recipient_key), garbage
    )
    outcome = agent.fetch_secret(r5)
    assert outcome.status == STATUS_REJECTED
    assert "could not be decrypted" in outcome.message
    assert not any(r5.private_key)


def test_key_substitution_is_caught_by_the_commitment(relay: FakeRelay, agent: Agent) -> None:
    request = agent.request_secret("k", "p")
    drop, page_origin = link.parse_drop(request.link)
    attacker_public, _ = crypto.generate_keypair()
    altered = link.DropLink(**{**vars(drop), "recipient_key": attacker_public}).build(page_origin)
    with pytest.raises(RelayError) as refused:
        human.submit(altered, b"value")
    assert refused.value.code == CODE_COMMITMENT
    assert refused.value.status == 422
    assert agent.fetch_secret(request, wait_seconds=1).status == STATUS_WAITING


def test_revoke(relay: FakeRelay, agent: Agent) -> None:
    request = agent.request_secret("k", "p")
    assert agent.revoke(request) == "revoked"
    assert not any(request.private_key)
    assert agent.revoke(request) == "revoked", "state reported by the relay"
    with pytest.raises(RelayError) as spent:
        human.submit(request.link, b"value")
    assert spent.value.code == CODE_GONE
    assert agent.fetch_secret(request).status == STATUS_REVOKED
    other = agent.request_secret("k2", "p")
    relay.delete(other.request_id)
    assert agent.revoke(other) == "expired"


def test_unexpected_state_raises(relay: FakeRelay, agent: Agent) -> None:
    request = agent.request_secret("k", "p")
    relay.fail_next("/api/v1/drops/status", 200, {"state": "weird"})
    with pytest.raises(AgentError, match="weird"):
        agent.fetch_secret(request)


def test_split_origin_links(relay: FakeRelay) -> None:
    agent = Agent(relay.origin, page_origin="https://drop.example")
    request = agent.request_secret("n", "p")
    drop, page_origin = link.parse_drop(request.link)
    assert page_origin == "https://drop.example"
    assert drop.relay == relay.origin
    fingerprint = human.submit(request.link, b"value")
    assert fingerprint == request.fingerprint
    assert agent.fetch_secret(request).value == b"value"
    sent = agent.send_secret("s", b"sendable-value")
    reveal, page_origin = link.parse_reveal(sent.link)
    assert page_origin == "https://drop.example"
    assert reveal.relay == relay.origin
    assert human.open(sent.link) == b"sendable-value"


def test_send_and_open(relay: FakeRelay, agent: Agent) -> None:
    with pytest.raises(ValueError, match="must"):
        agent.send_secret("bad name", b"v")
    with pytest.raises(ValueError, match="ttl"):
        agent.send_secret("n", b"v", ttl=-1)
    with pytest.raises(ValueError, match="larger"):
        agent.send_secret("n", b"x" * (64 * 1024 + 1))
    value = b"generated-value-\x00\x01"
    sent = agent.send_secret("generated", value, ttl=2700)
    assert sent.link.startswith(relay.origin + "/reveal#")
    assert sent.keeps_copy
    assert sent.link in sent.message
    assert "I keep my copy" in sent.message
    assert "generated-value" not in sent.message
    assert sent.revoke_token not in repr(sent)
    assert relay.requests[-1].json["ttl_seconds"] == 2700
    reveal, page_origin = link.parse_reveal(sent.link)
    assert page_origin == relay.origin
    assert reveal.name == "generated"
    assert reveal.keeps_copy
    assert agent.redactor.redact("generated-value-\x00\x01") == "[redacted:generated]"

    flipped = sent.link.replace("&c=1", "&c=0")
    with pytest.raises(HumanError):
        human.open(flipped)
    sent = agent.send_secret("generated", value)
    assert human.open(sent.link) == value
    with pytest.raises(RelayError) as second:
        human.open(sent.link)
    assert second.value.code == CODE_GONE
    assert second.value.status == 410

    deleted = agent.send_secret("generated", b"plain-text-value", keeps_copy=False)
    assert not deleted.keeps_copy
    assert "deleted my copy" in deleted.message
    reveal, _ = link.parse_reveal(deleted.link)
    assert not reveal.keeps_copy
    ciphertext, _ = RelayClient(relay.origin).open(reveal.id, reveal.reveal_token)
    env = crypto.decrypt_envelope(reveal.key, ciphertext, reveal.aad())
    assert env.format == "text"
    assert env.secret == "plain-text-value"
    assert env.purpose == ""


def test_revoke_sent(relay: FakeRelay, agent: Agent) -> None:
    sent = agent.send_secret("n", b"value-1")
    assert agent.revoke_sent(sent) == "revoked"
    assert agent.revoke_sent(sent) == "revoked"
    with pytest.raises(RelayError) as gone:
        human.open(sent.link)
    assert gone.value.code == CODE_GONE
    relay.delete(sent.request_id)
    assert agent.revoke_sent(sent) == "expired"


def test_human_helpers_validate_input(relay: FakeRelay, agent: Agent) -> None:
    request = agent.request_secret("k", "p")
    with pytest.raises(ValueError, match="empty"):
        human.submit(request.link, b"")
    with pytest.raises(link.LinkError):
        human.submit("https://drop.example/reveal#v=1", b"x")
    with pytest.raises(link.LinkError):
        human.open(request.link)
    assert human.submit(request.link, b"value", relay=relay.origin) == request.fingerprint
    sent = agent.send_secret("n", b"value-1")
    assert human.open(sent.link, relay=relay.origin) == b"value-1"


def test_fetch_rejects_tampered_purpose_and_storage(relay: FakeRelay, agent: Agent) -> None:
    r1 = agent.request_secret("seven", "the real purpose")
    tampered = crypto.Envelope(
        **{**vars(honest_envelope(r1)), "purpose": "a purpose the agent never stated"}
    )
    upload_envelope(r1, tampered, relay.origin)
    outcome = agent.fetch_secret(r1)
    assert outcome.status == STATUS_REJECTED
    assert "purpose shown" in outcome.message
    assert outcome.value is None

    r2 = agent.request_secret("eight", "p")
    tampered = crypto.Envelope(**{**vars(honest_envelope(r2)), "storage": "somewhere else"})
    upload_envelope(r2, tampered, relay.origin)
    outcome = agent.fetch_secret(r2)
    assert outcome.status == STATUS_REJECTED
    assert "storage description shown" in outcome.message
