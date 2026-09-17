"""Both flows against the real Go relay, built from this repository.

Skipped when Go is not installed. The relay listens on 127.0.0.1:8080 when
that port is free, otherwise on a free port, with agent authentication off
and generous rate limits.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from burndrop import Agent, crypto, human, link
from burndrop.agent import (
    STATUS_GONE,
    STATUS_RECEIVED,
    STATUS_REJECTED,
    STATUS_REVOKED,
    STATUS_WAITING,
)
from burndrop.relay import CODE_COMMITMENT, CODE_GONE, CODE_NOT_FOUND, RelayClient, RelayError
from support import PROJECT_ROOT, find_go

GO = find_go()
pytestmark = pytest.mark.skipif(GO is None, reason="go is not installed")


def pick_port() -> int:
    for candidate in (8080, 0):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            port: int = sock.getsockname()[1]
            return port
    raise RuntimeError("no free port")


@dataclass
class Relay:
    origin: str
    process: subprocess.Popen[bytes]
    log_path: Path


@pytest.fixture(scope="module")
def relay(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Relay]:
    assert GO is not None
    build_dir = tmp_path_factory.mktemp("relay")
    exe = build_dir / ("burndrop-relay.exe" if sys.platform == "win32" else "burndrop-relay")
    build = subprocess.run(
        [GO, "build", "-o", str(exe), "./cmd/burndrop-relay"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if build.returncode != 0:
        pytest.fail("go build failed:\n" + build.stdout + build.stderr)
    port = pick_port()
    origin = f"http://127.0.0.1:{port}"
    env = dict(os.environ)
    env.update(
        {
            "BURNDROP_PUBLIC_ORIGIN": origin,
            "BURNDROP_AGENT_AUTH": "off",
            "BURNDROP_LISTEN": f"127.0.0.1:{port}",
            "BURNDROP_RATE_AGENT_PER_MIN": "10000",
            "BURNDROP_RATE_PAGE_PER_MIN": "10000",
            "BURNDROP_LOG_LEVEL": "warn",
        }
    )
    log_path = build_dir / "relay.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen([str(exe)], env=env, stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                with urllib.request.urlopen(origin + "/healthz", timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                pass
            if process.poll() is not None or time.monotonic() > deadline:
                pytest.fail("relay did not start:\n" + log_path.read_text(errors="replace"))
            time.sleep(0.1)
        yield Relay(origin=origin, process=process, log_path=log_path)
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


@pytest.fixture
def agent(relay: Relay) -> Agent:
    return Agent(relay.origin)


def test_info(relay: Relay) -> None:
    info = RelayClient(relay.origin).info()
    assert info.api == "v1"
    assert info.agent_auth == "off"
    assert info.long_poll_max_seconds == 30
    assert info.default_ttl_seconds == 3600
    assert info.max_ciphertext_bytes >= crypto.MAX_PLAINTEXT
    # The page is optional in a relay build; either outcome must be well formed.
    try:
        page_hash = RelayClient(relay.origin).page_hash()
    except RelayError as no_page:
        assert no_page.code == "page_unavailable"
        assert no_page.status == 503
    else:
        assert crypto.valid_commitment(page_hash)


def test_drop_flow_is_one_time(relay: Relay, agent: Agent) -> None:
    request = agent.request_secret(
        "openai-api-key", "Call the OpenAI API from the billing script", ttl=600
    )
    assert request.link in request.message
    assert request.fingerprint in request.message
    assert request.expires_at is not None
    assert agent.fetch_secret(request, wait_seconds=1).status == STATUS_WAITING
    fingerprint = human.submit(request.link, b"sk-live-0123456789abcdef")
    assert fingerprint == request.fingerprint
    fetched = agent.fetch_secret(request)
    assert fetched.status == STATUS_RECEIVED
    assert fetched.value == b"sk-live-0123456789abcdef"
    assert not any(request.private_key)
    # The relay deleted the ciphertext: the fetch token no longer works.
    client = RelayClient(relay.origin)
    with pytest.raises(RelayError) as second:
        client.fetch(request.request_id, request.fetch_token)
    assert second.value.code == CODE_GONE
    assert second.value.status == 410
    assert second.value.state == "fetched"
    assert agent.fetch_secret(request).status == STATUS_GONE
    # The upload token was consumed too.
    with pytest.raises(RelayError) as spent:
        human.submit(request.link, b"again")
    assert spent.value.status == 410


def test_long_poll_wakes_when_the_human_submits(relay: Relay, agent: Agent) -> None:
    request = agent.request_secret("db-password", "Connect to the staging database")
    threading.Timer(0.5, human.submit, args=(request.link, b"p\xc3\xa4ss w\xc3\xb6rd")).start()
    start = time.monotonic()
    fetched = agent.fetch_secret(request, wait_seconds=20)
    assert fetched.status == STATUS_RECEIVED
    assert fetched.value == "päss wörd".encode()
    assert time.monotonic() - start < 10


def test_reveal_flow_is_one_time(relay: Relay, agent: Agent) -> None:
    value = b"postgres://app:s3cret@db.staging.example:5432/app\x00\x01"
    sent = agent.send_secret("staging-db-url", value, ttl=600, keeps_copy=False)
    assert sent.link in sent.message
    assert "deleted my copy" in sent.message
    reveal, _ = link.parse_reveal(sent.link)
    assert reveal.keeps_copy is False
    status = RelayClient(relay.origin).reveal_status(sent.request_id)
    assert status.state == "created"
    assert human.open(sent.link) == value
    with pytest.raises(RelayError) as second:
        human.open(sent.link)
    assert second.value.code == CODE_GONE
    assert second.value.status == 410
    assert second.value.state == "opened"
    assert RelayClient(relay.origin).wait_for_open(sent.request_id, time.time() + 5).state == (
        "opened"
    )


def test_revoke(relay: Relay, agent: Agent) -> None:
    request = agent.request_secret("token", "Deploy the site")
    assert agent.revoke(request) == "revoked"
    with pytest.raises(RelayError) as spent:
        human.submit(request.link, b"value")
    assert spent.value.status == 410
    assert spent.value.state == "revoked"
    assert agent.revoke(request) == "revoked"
    assert agent.fetch_secret(request).status == STATUS_REVOKED
    sent = agent.send_secret("token", b"value-1")
    assert agent.revoke_sent(sent) == "revoked"
    with pytest.raises(RelayError) as gone:
        human.open(sent.link)
    assert gone.value.state == "revoked"


def test_tampered_link_is_rejected(relay: Relay, agent: Agent) -> None:
    request = agent.request_secret("api-key", "Call the API")
    drop, page_origin = link.parse_drop(request.link)
    honest = crypto.Envelope.drop(
        drop.name, drop.purpose, drop.storage, drop.retention, drop.fingerprint(), b"value"
    )
    # A page showing the wrong fingerprint (the envelope records what it showed).
    wrong = crypto.Envelope(**{**vars(honest), "fingerprint": "0000-0000-0000-0000"})
    client = RelayClient(page_origin)
    client.upload(
        drop.id,
        drop.upload_token,
        crypto.commitment(drop.recipient_key),
        crypto.seal_envelope(drop.recipient_key, wrong),
    )
    outcome = agent.fetch_secret(request)
    assert outcome.status == STATUS_REJECTED
    assert "fingerprint" in outcome.message
    assert outcome.value is None
    # A link whose key was swapped fails the relay's commitment check.
    request = agent.request_secret("api-key", "Call the API")
    drop, page_origin = link.parse_drop(request.link)
    attacker_public, _ = crypto.generate_keypair()
    altered = link.DropLink(**{**vars(drop), "recipient_key": attacker_public}).build(page_origin)
    with pytest.raises(RelayError) as refused:
        human.submit(altered, b"value")
    assert refused.value.code == CODE_COMMITMENT
    assert refused.value.status == 422
    # A link whose name was changed is rejected by the agent.
    renamed = link.DropLink(**{**vars(drop), "name": "evil"}).build(page_origin)
    human.submit(renamed, b"value")
    outcome = agent.fetch_secret(request)
    assert outcome.status == STATUS_REJECTED
    assert "name" in outcome.message


def test_unknown_identifiers(relay: Relay) -> None:
    client = RelayClient(relay.origin)
    with pytest.raises(RelayError) as unknown:
        client.drop_status("MTIzNDU2Nzg5MGFiY2RlZg")
    assert unknown.value.code == CODE_NOT_FOUND
    assert unknown.value.status == 404
    with pytest.raises(RelayError) as bad:
        client.drop_status("not-a-token")
    assert bad.value.status == 400
