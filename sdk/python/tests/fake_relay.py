"""A small in-memory relay speaking the real API, for tests that do not need Go.

It implements the state machines, the token and commitment checks, the
error bodies, and a shortened long poll, so the client, agent, and human
modules can be exercised end to end without a network or a build step.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from burndrop import crypto
from burndrop._time import format_rfc3339
from burndrop.encoding import EncodingError, b64decode, b64encode

TERMINAL = {"fetched", "opened", "revoked", "expired"}
MAX_FAKE_WAIT = 0.25
Response = tuple[int, dict[str, Any]]


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Slot:
    id: str
    kind: str
    expires_at: datetime
    state: str = "created"
    commitment: str = ""
    ciphertext: bytes = b""
    token_a: str = ""
    token_b: str = ""
    created_at: datetime = field(default_factory=_now)
    uploaded_at: datetime | None = None
    fetched_at: datetime | None = None
    revoked_at: datetime | None = None

    def status(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "state": self.state,
            "kind": self.kind,
            "created_at": format_rfc3339(self.created_at),
            "expires_at": format_rfc3339(self.expires_at),
        }
        if self.uploaded_at:
            body["uploaded_at"] = format_rfc3339(self.uploaded_at)
        if self.fetched_at:
            key = "opened_at" if self.kind == "reveal" else "fetched_at"
            body[key] = format_rfc3339(self.fetched_at)
        if self.revoked_at:
            body["revoked_at"] = format_rfc3339(self.revoked_at)
        return body

    def gone(self) -> Response:
        at = {
            "uploaded": self.uploaded_at,
            "fetched": self.fetched_at,
            "opened": self.fetched_at,
            "revoked": self.revoked_at,
            "expired": self.expires_at,
        }.get(self.state) or self.created_at
        return 410, {"error": "gone", "state": self.state, "at": format_rfc3339(at)}

    def tombstone(self, state: str) -> None:
        self.ciphertext = b""
        self.commitment = ""
        self.token_a = ""
        self.token_b = ""
        self.state = state
        if state in ("fetched", "opened"):
            self.fetched_at = _now()
        elif state == "revoked":
            self.revoked_at = _now()


@dataclass
class Recorded:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes

    @property
    def json(self) -> Any:
        return json.loads(self.body)


class FakeRelay:
    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key
        self.slots: dict[str, Slot] = {}
        self.requests: list[Recorded] = []
        self.canned: dict[str, list[Response]] = {}
        self.page: bytes | None = None
        self.cond = threading.Condition()
        relay = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def do_POST(self) -> None:
                relay._serve(self, "POST")

            def do_GET(self) -> None:
                relay._serve(self, "GET")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.routes: dict[str, Callable[[dict[str, Any], dict[str, str]], Response]] = {
            "/api/v1/drops": self._create_drop,
            "/api/v1/drops/upload": self._upload,
            "/api/v1/drops/status": lambda body, _h: self._status("drop", body),
            "/api/v1/drops/fetch": self._fetch,
            "/api/v1/drops/revoke": lambda body, _h: self._revoke("drop", body),
            "/api/v1/reveals": self._create_reveal,
            "/api/v1/reveals/open": lambda body, _h: self._open(body),
            "/api/v1/reveals/status": lambda body, _h: self._status("reveal", body),
            "/api/v1/reveals/revoke": lambda body, _h: self._revoke("reveal", body),
        }

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    # Test controls.

    def fail_next(self, path: str, status: int, body: dict[str, Any]) -> None:
        self.canned.setdefault(path, []).append((status, body))

    def expire(self, slot_id: str) -> None:
        with self.cond:
            self.slots[slot_id].tombstone("expired")
            self.cond.notify_all()

    def delete(self, slot_id: str) -> None:
        with self.cond:
            del self.slots[slot_id]
            self.cond.notify_all()

    # HTTP plumbing.

    def _serve(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        raw = handler.rfile.read(length) if length else b""
        headers = {key.lower(): value for key, value in handler.headers.items()}
        self.requests.append(Recorded(method, handler.path, headers, raw))
        status, body, content_type = self._dispatch(method, handler.path, headers, raw)
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)

    def _dispatch(
        self, method: str, path: str, headers: dict[str, str], raw: bytes
    ) -> tuple[int, dict[str, Any] | bytes, str]:
        queue = self.canned.get(path)
        if queue:
            status, body = queue.pop(0)
            return status, body, "application/json"
        if method == "GET" and path == "/drop":
            if self.page is None:
                return 503, b"no page", "text/plain"
            return 200, self.page, "text/html"
        if method == "GET" and path == "/api/v1/info":
            return 200, self._info(), "application/json"
        if method != "POST":
            return 405, {"error": "method_not_allowed"}, "application/json"
        if not headers.get("x-client"):
            return 400, {"error": "missing_client_header", "header": "X-Client"}, "application/json"
        if not headers.get("content-type", "").lower().startswith("application/json"):
            return 415, {"error": "unsupported_media_type"}, "application/json"
        try:
            body = json.loads(raw)
        except ValueError:
            return 400, {"error": "bad_request", "detail": "malformed JSON"}, "application/json"
        route = self.routes.get(path)
        if route is None:
            return 404, {"error": "not_found"}, "application/json"
        with self.cond:
            status, out = route(body, headers)
        return status, out, "application/json"

    def _info(self) -> dict[str, Any]:
        return {
            "version": "fake",
            "api": "v1",
            "default_ttl_seconds": 3600,
            "max_ttl_seconds": 86400,
            "max_ciphertext_bytes": 65840,
            "long_poll_max_seconds": 30,
            "agent_auth": "required" if self.api_key else "off",
            "page_served": self.page is not None,
            "page_version": "",
            "page_sha256": "",
        }

    # Handlers.

    def _auth(self, headers: dict[str, str]) -> Response | None:
        if self.api_key is None:
            return None
        if headers.get("authorization") != "Bearer " + self.api_key:
            return 401, {"error": "unauthorized"}
        return None

    def _new_slot(self, kind: str, ttl: Any) -> Slot:
        seconds = ttl if isinstance(ttl, int) and ttl > 0 else 3600
        slot = Slot(
            id=crypto.random_token(),
            kind=kind,
            expires_at=_now() + timedelta(seconds=seconds),
            token_a=crypto.random_token(),
            token_b=crypto.random_token(),
        )
        self.slots[slot.id] = slot
        return slot

    def _create_drop(self, body: dict[str, Any], headers: dict[str, str]) -> Response:
        denied = self._auth(headers)
        if denied:
            return denied
        if not crypto.valid_commitment(body.get("commitment", "")):
            return 400, {"error": "bad_request", "detail": "malformed commitment"}
        slot = self._new_slot("drop", body.get("ttl_seconds"))
        slot.commitment = body["commitment"]
        return 201, {
            "drop_id": slot.id,
            "upload_token": slot.token_a,
            "fetch_token": slot.token_b,
            "expires_at": format_rfc3339(slot.expires_at),
        }

    def _upload(self, body: dict[str, Any], _headers: dict[str, str]) -> Response:
        slot = self.slots.get(body.get("drop_id", ""))
        if slot is None or slot.kind != "drop":
            return 404, {"error": "not_found"}
        if slot.state == "uploaded":
            return 409, {"error": "already_uploaded", "state": "uploaded"}
        if slot.state in TERMINAL:
            return slot.gone()
        if body.get("upload_token") != slot.token_a:
            return 403, {"error": "bad_token"}
        if body.get("commitment") != slot.commitment:
            return 422, {"error": "commitment_mismatch", "detail": "key mismatch"}
        try:
            ciphertext = b64decode(body.get("ciphertext", ""))
        except EncodingError:
            return 400, {"error": "bad_request", "detail": "ciphertext"}
        if len(ciphertext) < crypto.SEALED_OVERHEAD + crypto.PAD_BLOCK:
            return 400, {"error": "bad_request", "detail": "ciphertext is too short to be valid"}
        slot.ciphertext = ciphertext
        slot.state = "uploaded"
        slot.uploaded_at = _now()
        self.cond.notify_all()
        return 200, {"state": "uploaded"}

    def _status(self, kind: str, body: dict[str, Any]) -> Response:
        slot = self.slots.get(body.get("drop_id", ""))
        if slot is None or slot.kind != kind:
            return 404, {"error": "not_found"}
        wait = body.get("wait_seconds", 0)
        if not isinstance(wait, int) or wait < 0 or wait > 30:
            return 400, {"error": "bad_request", "detail": "wait_seconds must be between 0 and 30"}
        wait_while = body.get("wait_while", "")
        if wait > 0 and slot.state not in TERMINAL and wait_while in ("", slot.state):
            current = slot.state
            self.cond.wait_for(lambda: slot.state != current, timeout=min(wait, MAX_FAKE_WAIT))
        return 200, slot.status()

    def _fetch(self, body: dict[str, Any], headers: dict[str, str]) -> Response:
        denied = self._auth(headers)
        if denied:
            return denied
        slot = self.slots.get(body.get("drop_id", ""))
        if slot is None or slot.kind != "drop":
            return 404, {"error": "not_found"}
        if slot.state in TERMINAL:
            return slot.gone()
        if body.get("fetch_token") != slot.token_b:
            return 403, {"error": "bad_token"}
        if slot.state == "created":
            return 404, {"error": "not_uploaded", "state": "created"}
        ciphertext = slot.ciphertext
        uploaded_at = slot.uploaded_at or _now()
        slot.tombstone("fetched")
        self.cond.notify_all()
        return 200, {
            "ciphertext": b64encode(ciphertext),
            "uploaded_at": format_rfc3339(uploaded_at),
        }

    def _revoke(self, kind: str, body: dict[str, Any]) -> Response:
        slot = self.slots.get(body.get("drop_id", ""))
        if slot is None or slot.kind != kind:
            return 404, {"error": "not_found"}
        if slot.state in TERMINAL:
            return slot.gone()
        if body.get("token") not in (slot.token_a, slot.token_b):
            return 403, {"error": "bad_token"}
        slot.tombstone("revoked")
        self.cond.notify_all()
        return 200, {"state": "revoked"}

    def _create_reveal(self, body: dict[str, Any], headers: dict[str, str]) -> Response:
        denied = self._auth(headers)
        if denied:
            return denied
        try:
            ciphertext = b64decode(body.get("ciphertext", ""))
        except EncodingError:
            return 400, {"error": "bad_request", "detail": "ciphertext"}
        if len(ciphertext) < crypto.AEAD_OVERHEAD + crypto.PAD_BLOCK:
            return 400, {"error": "bad_request", "detail": "ciphertext is too short to be valid"}
        slot = self._new_slot("reveal", body.get("ttl_seconds"))
        slot.ciphertext = ciphertext
        return 201, {
            "drop_id": slot.id,
            "reveal_token": slot.token_a,
            "revoke_token": slot.token_b,
            "expires_at": format_rfc3339(slot.expires_at),
        }

    def _open(self, body: dict[str, Any]) -> Response:
        slot = self.slots.get(body.get("drop_id", ""))
        if slot is None or slot.kind != "reveal":
            return 404, {"error": "not_found"}
        if slot.state in TERMINAL:
            return slot.gone()
        if body.get("reveal_token") != slot.token_a:
            return 403, {"error": "bad_token"}
        ciphertext = slot.ciphertext
        created_at = slot.created_at
        slot.tombstone("opened")
        self.cond.notify_all()
        return 200, {"ciphertext": b64encode(ciphertext), "created_at": format_rfc3339(created_at)}
