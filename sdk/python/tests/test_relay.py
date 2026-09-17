"""The relay client against an in-process fake relay."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

import pytest

from burndrop import crypto
from burndrop.link import LinkError
from burndrop.relay import (
    CLIENT_HEADER,
    CODE_BAD_TOKEN,
    CODE_COMMITMENT,
    CODE_CONNECTION,
    CODE_GONE,
    CODE_NOT_FOUND,
    CODE_NOT_UPLOADED,
    CODE_UNAUTHORIZED,
    DEFAULT_CLIENT_NAME,
    MAX_WAIT,
    STATE_CREATED,
    STATE_FETCHED,
    STATE_REVOKED,
    STATE_UPLOADED,
    DeadlineExceeded,
    RelayClient,
    RelayError,
    Status,
)
from fake_relay import FakeRelay

API_KEY = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"


@pytest.fixture
def relay() -> Iterator[FakeRelay]:
    fake = FakeRelay()
    try:
        yield fake
    finally:
        fake.close()


@pytest.fixture
def client(relay: FakeRelay) -> RelayClient:
    return RelayClient(relay.origin, API_KEY)


def sealed_for(public_key: bytes, name: str = "api-key") -> bytes:
    env = crypto.Envelope.drop(
        name, "test", "memory", "session", crypto.fingerprint(public_key), b"hunter2-value"
    )
    return crypto.seal_envelope(public_key, env)


def test_constructor_normalizes_and_rejects_origins() -> None:
    client = RelayClient("HTTPS://Relay.Example:443/", "k")
    assert client.origin == "https://relay.example"
    assert client.client_name == DEFAULT_CLIENT_NAME
    assert client.client_name.startswith("burndrop-python/")
    assert RelayClient("http://localhost:8080", client_name="x/1").client_name == "x/1"
    for bad in ["", "ftp://x", "http://example.com", "relay.example", "https://relay.example/p"]:
        with pytest.raises(LinkError):
            RelayClient(bad)


def test_drop_flow_with_headers_and_bodies(relay: FakeRelay, client: RelayClient) -> None:
    info = client.info()
    assert info.api == "v1"
    assert info.version == "fake"
    assert info.long_poll_max_seconds == 30
    assert info.agent_auth == "off"
    public_key, private_key = crypto.generate_keypair()
    commitment = crypto.commitment(public_key)
    created = client.create_drop(commitment, 120)
    assert crypto.valid_token(created.id)
    assert crypto.valid_token(created.upload_token)
    assert crypto.valid_token(created.fetch_token)
    assert created.expires_at is not None
    assert created.expires_at.tzinfo is not None
    status = client.drop_status(created.id)
    assert status.state == STATE_CREATED
    assert status.kind == "drop"
    assert not status.terminal
    assert status.created_at is not None
    with pytest.raises(RelayError) as early:
        client.fetch(created.id, created.fetch_token)
    assert early.value.code == CODE_NOT_UPLOADED
    assert early.value.status == 404
    assert early.value.state == STATE_CREATED
    sealed = sealed_for(public_key)
    client.upload(created.id, created.upload_token, commitment, sealed)
    with pytest.raises(RelayError) as again:
        client.upload(created.id, created.upload_token, commitment, sealed)
    assert again.value.code == "already_uploaded"
    assert again.value.status == 409
    assert client.drop_status(created.id).state == STATE_UPLOADED
    ciphertext, uploaded_at = client.fetch(created.id, created.fetch_token)
    assert ciphertext == sealed
    assert uploaded_at is not None
    assert crypto.open_envelope(public_key, private_key, ciphertext).secret == "hunter2-value"
    with pytest.raises(RelayError) as second:
        client.fetch(created.id, created.fetch_token)
    assert second.value.code == CODE_GONE
    assert second.value.status == 410
    assert second.value.state == STATE_FETCHED
    assert second.value.at is not None
    assert "gone (fetched)" in str(second.value)
    assert "[HTTP 410]" in str(second.value)
    with pytest.raises(RelayError) as revoke:
        client.revoke_drop(created.id, created.fetch_token)
    assert revoke.value.state == STATE_FETCHED

    for recorded in relay.requests:
        assert recorded.headers.get("x-client") == DEFAULT_CLIENT_NAME
        assert "?" not in recorded.path
        assert created.id not in recorded.path
        if recorded.method == "POST":
            assert recorded.headers["content-type"] == "application/json"
    posts = {r.path: r for r in relay.requests if r.method == "POST"}
    assert posts["/api/v1/drops"].headers["authorization"] == "Bearer " + API_KEY
    assert posts["/api/v1/drops/fetch"].headers["authorization"] == "Bearer " + API_KEY
    assert "authorization" not in posts["/api/v1/drops/upload"].headers
    assert "authorization" not in posts["/api/v1/drops/status"].headers
    assert posts["/api/v1/drops"].json == {"ttl_seconds": 120, "commitment": commitment}
    assert posts["/api/v1/drops/fetch"].json == {
        "drop_id": created.id,
        "fetch_token": created.fetch_token,
    }
    assert posts["/api/v1/drops/status"].json == {
        "drop_id": created.id,
        "wait_seconds": 0,
        "wait_while": "",
    }
    assert "authorization" not in relay.requests[0].headers, "info carries no key"
    assert relay.requests[0].headers.get(CLIENT_HEADER.lower()) == DEFAULT_CLIENT_NAME


def test_no_api_key_means_no_authorization_header(relay: FakeRelay) -> None:
    client = RelayClient(relay.origin)
    client.create_drop(crypto.commitment(bytes(32)))
    assert "authorization" not in relay.requests[-1].headers


def test_agent_auth(relay: FakeRelay) -> None:
    relay.api_key = API_KEY
    with pytest.raises(RelayError) as denied:
        RelayClient(relay.origin, "wrong-key-wrong-key").create_drop(crypto.commitment(bytes(32)))
    assert denied.value.code == CODE_UNAUTHORIZED
    assert denied.value.status == 401
    RelayClient(relay.origin, API_KEY).create_drop(crypto.commitment(bytes(32)))


def test_commitment_and_token_checks(relay: FakeRelay, client: RelayClient) -> None:
    public_key, _ = crypto.generate_keypair()
    other_key, _ = crypto.generate_keypair()
    created = client.create_drop(crypto.commitment(public_key))
    with pytest.raises(RelayError) as mismatch:
        client.upload(
            created.id, created.upload_token, crypto.commitment(other_key), sealed_for(public_key)
        )
    assert mismatch.value.code == CODE_COMMITMENT
    assert mismatch.value.status == 422
    with pytest.raises(RelayError) as bad:
        client.upload(
            created.id, created.fetch_token, crypto.commitment(public_key), sealed_for(public_key)
        )
    assert bad.value.code == CODE_BAD_TOKEN
    with pytest.raises(RelayError) as unknown:
        client.drop_status("MTIzNDU2Nzg5MGFiY2RlZg")
    assert unknown.value.code == CODE_NOT_FOUND


def test_revoke_and_terminal_wait(relay: FakeRelay, client: RelayClient) -> None:
    created = client.create_drop(crypto.commitment(bytes(32)))
    client.revoke_drop(created.id, created.upload_token)
    status = client.drop_status(created.id)
    assert status.state == STATE_REVOKED
    assert status.terminal
    assert status.revoked_at is not None
    assert client.wait_for_upload(created.id, time.time() + 5).state == STATE_REVOKED


def test_long_poll_wakes_and_times_out(relay: FakeRelay, client: RelayClient) -> None:
    public_key, _ = crypto.generate_keypair()
    commitment = crypto.commitment(public_key)
    created = client.create_drop(commitment)
    with pytest.raises(DeadlineExceeded) as timeout:
        client.wait_for_upload(created.id, time.time() + 0.6)
    assert timeout.value.last is not None
    assert timeout.value.last.state == STATE_CREATED
    waits = [r.json["wait_seconds"] for r in relay.requests if r.path.endswith("/status")]
    assert waits and all(1 <= w <= MAX_WAIT for w in waits)
    assert all(
        r.json["wait_while"] == STATE_CREATED for r in relay.requests if r.path.endswith("/status")
    )

    def upload_later() -> None:
        time.sleep(0.3)
        client.upload(created.id, created.upload_token, commitment, sealed_for(public_key))

    threading.Thread(target=upload_later).start()
    start = time.monotonic()
    status = client.wait_for_upload(created.id, time.time() + 10)
    assert status.state == STATE_UPLOADED
    assert status.uploaded_at is not None
    assert time.monotonic() - start < 5
    deadline = datetime.now(timezone.utc) - timedelta(seconds=1)
    with pytest.raises(DeadlineExceeded) as past:
        client.wait_for_upload(created.id, deadline)
    assert past.value.last is None


def test_wait_retries_server_errors_but_not_client_errors(
    relay: FakeRelay, client: RelayClient
) -> None:
    public_key, _ = crypto.generate_keypair()
    commitment = crypto.commitment(public_key)
    created = client.create_drop(commitment)
    client.upload(created.id, created.upload_token, commitment, sealed_for(public_key))
    relay.fail_next("/api/v1/drops/status", 500, {"error": "internal_error"})
    relay.fail_next("/api/v1/drops/status", 429, {"error": "rate_limited"})
    assert client.wait_for_upload(created.id, time.time() + 10).state == STATE_UPLOADED
    relay.fail_next("/api/v1/drops/status", 403, {"error": "bad_token"})
    with pytest.raises(RelayError) as denied:
        client.wait_for_upload(created.id, time.time() + 10)
    assert denied.value.code == CODE_BAD_TOKEN


def test_status_wait_is_clamped(relay: FakeRelay, client: RelayClient) -> None:
    created = client.create_drop(crypto.commitment(bytes(32)))
    client.drop_status(created.id, wait_seconds=90, wait_while="uploaded")
    assert relay.requests[-1].json["wait_seconds"] == MAX_WAIT
    assert relay.requests[-1].json["wait_while"] == "uploaded"
    client.drop_status(created.id, wait_seconds=-3)
    assert relay.requests[-1].json["wait_seconds"] == 0


def test_reveal_flow(relay: FakeRelay, client: RelayClient) -> None:
    key = crypto.new_symmetric_key()
    aad = crypto.reveal_aad("staging-db-url", True)
    blob = crypto.encrypt_envelope(key, crypto.Envelope.reveal("staging-db-url", b"value-1"), aad)
    created = client.create_reveal(blob, 600)
    assert crypto.valid_token(created.id)
    assert crypto.valid_token(created.reveal_token)
    assert crypto.valid_token(created.revoke_token)
    assert created.expires_at is not None
    assert relay.requests[-1].json == {
        "ttl_seconds": 600,
        "ciphertext": relay.requests[-1].json["ciphertext"],
    }
    assert client.reveal_status(created.id).state == STATE_CREATED
    with pytest.raises(RelayError) as wrong_kind:
        client.drop_status(created.id)
    assert wrong_kind.value.code == CODE_NOT_FOUND

    def open_later() -> None:
        time.sleep(0.3)
        ciphertext, created_at = client.open(created.id, created.reveal_token)
        assert ciphertext == blob
        assert created_at is not None

    threading.Thread(target=open_later).start()
    status = client.wait_for_open(created.id, time.time() + 10)
    assert status.state == "opened"
    assert status.opened_at is not None
    with pytest.raises(RelayError) as second:
        client.open(created.id, created.reveal_token)
    assert second.value.code == CODE_GONE
    assert second.value.state == "opened"
    other = client.create_reveal(blob)
    client.revoke_reveal(other.id, other.revoke_token)
    assert client.reveal_status(other.id).state == STATE_REVOKED
    with pytest.raises(RelayError) as gone:
        client.open(other.id, other.reveal_token)
    assert gone.value.code == CODE_GONE


def test_error_decoding_and_connection_failures(relay: FakeRelay, client: RelayClient) -> None:
    relay.fail_next("/api/v1/info", 500, {"error": ""})
    with pytest.raises(RelayError) as plain:
        client.info()
    assert plain.value.code == "http_500"
    assert plain.value.status == 500
    assert str(plain.value) == "relay: http_500 [HTTP 500]"
    relay.fail_next("/api/v1/info", 200, {"unexpected": "shape"})
    assert client.info().version == ""
    relay.fail_next("/api/v1/drops/fetch", 200, {"ciphertext": "not base64!"})
    with pytest.raises(RelayError) as malformed:
        client.fetch("MTIzNDU2Nzg5MGFiY2RlZg", "MTIzNDU2Nzg5MGFiY2RlZg")
    assert malformed.value.code == "malformed_response"
    relay.fail_next("/api/v1/drops/status", 410, {"error": "gone", "state": "expired", "at": "bad"})
    with pytest.raises(RelayError) as no_time:
        client.drop_status("MTIzNDU2Nzg5MGFiY2RlZg")
    assert no_time.value.at is None
    assert no_time.value.state == "expired"
    unreachable = RelayClient("http://127.0.0.1:1", timeout=2)
    with pytest.raises(RelayError) as refused:
        unreachable.info()
    assert refused.value.status == 0
    assert refused.value.code == CODE_CONNECTION
    assert str(refused.value).startswith("relay: connection_failed")


def test_page_hash(relay: FakeRelay, client: RelayClient) -> None:
    with pytest.raises(RelayError) as missing:
        client.page_hash()
    assert missing.value.code == "page_unavailable"
    assert missing.value.status == 503
    relay.page = b"<!doctype html><title>burndrop</title>"
    assert client.page_hash() == crypto.commitment(relay.page)


def test_status_dataclass_terminal() -> None:
    assert Status(state="fetched").terminal
    assert Status(state="opened").terminal
    assert Status(state="expired").terminal
    assert not Status(state="uploaded").terminal
    assert not Status(state="").terminal
