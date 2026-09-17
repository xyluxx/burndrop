"""Talk to a burndrop relay over its JSON API.

Every call is a POST with the identifiers in the body, so nothing sensitive
reaches a URL or an access log. Only the standard library is used for HTTP.
See the design document section 6.1 for the API.
"""

from __future__ import annotations

import http.client
import json
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ._time import parse_rfc3339
from ._version import __version__
from .crypto import commitment
from .encoding import EncodingError, b64decode, b64encode
from .link import normalize_origin

__all__ = [
    "CLIENT_HEADER",
    "CODE_ALREADY_UPLOADED",
    "CODE_BAD_TOKEN",
    "CODE_COMMITMENT",
    "CODE_CONNECTION",
    "CODE_GONE",
    "CODE_NOT_FOUND",
    "CODE_NOT_UPLOADED",
    "CODE_RATE_LIMITED",
    "CODE_UNAUTHORIZED",
    "DEFAULT_CLIENT_NAME",
    "MAX_WAIT",
    "STATE_CREATED",
    "STATE_EXPIRED",
    "STATE_FETCHED",
    "STATE_OPENED",
    "STATE_REVOKED",
    "STATE_UPLOADED",
    "Deadline",
    "DeadlineExceeded",
    "DropCreated",
    "Info",
    "RelayClient",
    "RelayError",
    "RevealCreated",
    "Status",
]

CLIENT_HEADER = "X-Client"
"""Must be present on every API request; the relay rejects requests without it."""
MAX_WAIT = 30
"""The longest single long poll the relay allows, in seconds."""
MAX_RESPONSE = 1 << 20
MAX_PAGE = 8 << 20
DEFAULT_TIMEOUT = MAX_WAIT + 15
DEFAULT_CLIENT_NAME = "burndrop-python/" + __version__

# Error codes returned by the relay.
CODE_NOT_FOUND = "not_found"
CODE_NOT_UPLOADED = "not_uploaded"
CODE_GONE = "gone"
CODE_BAD_TOKEN = "bad_token"
CODE_UNAUTHORIZED = "unauthorized"
CODE_RATE_LIMITED = "rate_limited"
CODE_COMMITMENT = "commitment_mismatch"
CODE_ALREADY_UPLOADED = "already_uploaded"
CODE_CONNECTION = "connection_failed"
"""Not from the relay: the request never produced an HTTP response."""

# States as reported by the relay.
STATE_CREATED = "created"
STATE_UPLOADED = "uploaded"
STATE_FETCHED = "fetched"
STATE_OPENED = "opened"
STATE_REVOKED = "revoked"
STATE_EXPIRED = "expired"
_TERMINAL = frozenset({STATE_FETCHED, STATE_OPENED, STATE_REVOKED, STATE_EXPIRED})

Deadline = float | datetime
"""An absolute deadline: seconds since the epoch (``time.time()``) or a datetime."""


class RelayError(Exception):
    """A relay error response, or a failure to reach the relay at all."""

    def __init__(
        self,
        status: int,
        code: str,
        detail: str = "",
        state: str = "",
        at: datetime | None = None,
    ) -> None:
        super().__init__(status, code, detail, state)
        self.status = status
        self.code = code
        self.detail = detail
        self.state = state
        self.at = at

    def __str__(self) -> str:
        text = "relay: " + self.code
        if self.state:
            text += " (" + self.state + ")"
        if self.detail:
            text += ": " + self.detail
        if self.status:
            text += f" [HTTP {self.status}]"
        return text


class DeadlineExceeded(TimeoutError):
    """A wait ended without the state changing. ``last`` is the last status seen."""

    def __init__(self, last: Status | None) -> None:
        super().__init__("deadline exceeded")
        self.last = last


@dataclass(frozen=True)
class DropCreated:
    """The result of :meth:`RelayClient.create_drop`."""

    id: str
    upload_token: str
    fetch_token: str
    expires_at: datetime | None


@dataclass(frozen=True)
class RevealCreated:
    """The result of :meth:`RelayClient.create_reveal`."""

    id: str
    reveal_token: str
    revoke_token: str
    expires_at: datetime | None


@dataclass(frozen=True)
class Status:
    """A drop or reveal status."""

    state: str
    kind: str = ""
    created_at: datetime | None = None
    expires_at: datetime | None = None
    uploaded_at: datetime | None = None
    fetched_at: datetime | None = None
    opened_at: datetime | None = None
    revoked_at: datetime | None = None

    @property
    def terminal(self) -> bool:
        """Report whether the state can no longer change."""
        return self.state in _TERMINAL


@dataclass(frozen=True)
class Info:
    """The relay's self description."""

    version: str
    api: str
    default_ttl_seconds: int
    max_ttl_seconds: int
    max_ciphertext_bytes: int
    long_poll_max_seconds: int
    agent_auth: str
    page_served: bool
    page_version: str
    page_sha256: str


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _integer(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return parse_rfc3339(value)
    except ValueError:
        return None


def _seconds_until(deadline: Deadline) -> float:
    if isinstance(deadline, datetime):
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        return (deadline - datetime.now(timezone.utc)).total_seconds()
    return float(deadline) - time.time()


def _decode_error(status: int, body: bytes) -> RelayError:
    try:
        obj = json.loads(body)
    except ValueError:
        obj = None
    if not isinstance(obj, dict) or not _text(obj.get("error")):
        return RelayError(status, f"http_{status}")
    return RelayError(
        status,
        _text(obj.get("error")),
        detail=_text(obj.get("detail")),
        state=_text(obj.get("state")),
        at=_time(obj.get("at")),
    )


def _status_from(obj: dict[str, Any]) -> Status:
    return Status(
        state=_text(obj.get("state")),
        kind=_text(obj.get("kind")),
        created_at=_time(obj.get("created_at")),
        expires_at=_time(obj.get("expires_at")),
        uploaded_at=_time(obj.get("uploaded_at")),
        fetched_at=_time(obj.get("fetched_at")),
        opened_at=_time(obj.get("opened_at")),
        revoked_at=_time(obj.get("revoked_at")),
    )


class RelayClient:
    """A client for one relay. Safe to share between threads."""

    def __init__(
        self,
        origin: str,
        api_key: str | None = None,
        *,
        client_name: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        self.origin = normalize_origin(origin)
        self.api_key = api_key or ""
        self.client_name = client_name or DEFAULT_CLIENT_NAME
        self.timeout = timeout
        if opener is None:
            hostname = urllib.parse.urlsplit(self.origin).hostname
            handlers: list[urllib.request.BaseHandler] = []
            if hostname in ("localhost", "127.0.0.1", "::1"):
                # Never send loopback traffic through a proxy from the environment.
                handlers.append(urllib.request.ProxyHandler({}))
            opener = urllib.request.build_opener(*handlers)
        self._opener = opener

    # Drops.

    def create_drop(self, commitment: str, ttl: int = 0) -> DropCreated:
        """Reserve a slot for a human to upload into.

        ``commitment`` is the base64url SHA-256 of the recipient public key;
        a ttl of zero uses the relay default.
        """
        out = self._post(
            "/api/v1/drops", {"ttl_seconds": int(ttl), "commitment": commitment}, auth=True
        )
        return DropCreated(
            id=_text(out.get("drop_id")),
            upload_token=_text(out.get("upload_token")),
            fetch_token=_text(out.get("fetch_token")),
            expires_at=_time(out.get("expires_at")),
        )

    def upload(self, drop_id: str, upload_token: str, commitment: str, ciphertext: bytes) -> None:
        """Store a sealed envelope in a drop slot. This is what the page does."""
        self._post(
            "/api/v1/drops/upload",
            {
                "drop_id": drop_id,
                "upload_token": upload_token,
                "commitment": commitment,
                "ciphertext": b64encode(ciphertext),
            },
            auth=False,
        )

    def drop_status(self, drop_id: str, wait_seconds: int = 0, wait_while: str = "") -> Status:
        """Report a drop's state.

        With ``wait_seconds`` above zero the relay holds the request for up
        to that long (at most :data:`MAX_WAIT`) while the state equals
        ``wait_while`` (or any live state when empty).
        """
        return self._status("/api/v1/drops/status", drop_id, wait_seconds, wait_while)

    def wait_for_upload(self, drop_id: str, deadline: Deadline) -> Status:
        """Long poll until the drop leaves the created state or the deadline passes."""
        return self._wait_while(
            lambda wait: self.drop_status(drop_id, wait, STATE_CREATED), STATE_CREATED, deadline
        )

    def fetch(self, drop_id: str, fetch_token: str) -> tuple[bytes, datetime | None]:
        """Download and delete the sealed envelope.

        Only the first call with a valid fetch token succeeds. Returns the
        ciphertext and the upload time.
        """
        out = self._post(
            "/api/v1/drops/fetch", {"drop_id": drop_id, "fetch_token": fetch_token}, auth=True
        )
        return self._ciphertext(out), _time(out.get("uploaded_at"))

    def revoke_drop(self, drop_id: str, token: str) -> None:
        """Cancel a request; either of its tokens is accepted."""
        self._post("/api/v1/drops/revoke", {"drop_id": drop_id, "token": token}, auth=False)

    # Reveals.

    def create_reveal(self, ciphertext: bytes, ttl: int = 0) -> RevealCreated:
        """Store an encrypted reveal for a human to open once."""
        out = self._post(
            "/api/v1/reveals",
            {"ttl_seconds": int(ttl), "ciphertext": b64encode(ciphertext)},
            auth=True,
        )
        return RevealCreated(
            id=_text(out.get("drop_id")),
            reveal_token=_text(out.get("reveal_token")),
            revoke_token=_text(out.get("revoke_token")),
            expires_at=_time(out.get("expires_at")),
        )

    def open(self, drop_id: str, reveal_token: str) -> tuple[bytes, datetime | None]:
        """Download and delete a reveal's ciphertext. This is what the page does."""
        out = self._post(
            "/api/v1/reveals/open", {"drop_id": drop_id, "reveal_token": reveal_token}, auth=False
        )
        return self._ciphertext(out), _time(out.get("created_at"))

    def reveal_status(self, drop_id: str, wait_seconds: int = 0, wait_while: str = "") -> Status:
        """:meth:`drop_status` for reveals."""
        return self._status("/api/v1/reveals/status", drop_id, wait_seconds, wait_while)

    def wait_for_open(self, drop_id: str, deadline: Deadline) -> Status:
        """Long poll until the reveal is opened, revoked, or expired."""
        return self._wait_while(
            lambda wait: self.reveal_status(drop_id, wait, STATE_CREATED), STATE_CREATED, deadline
        )

    def revoke_reveal(self, drop_id: str, token: str) -> None:
        """Delete an unopened reveal; the reveal or revoke token is accepted."""
        self._post("/api/v1/reveals/revoke", {"drop_id": drop_id, "token": token}, auth=False)

    # Relay.

    def info(self) -> Info:
        """Fetch the relay description."""
        request = urllib.request.Request(self.origin + "/api/v1/info", method="GET")
        request.add_header(CLIENT_HEADER, self.client_name)
        out = self._request(request)
        return Info(
            version=_text(out.get("version")),
            api=_text(out.get("api")),
            default_ttl_seconds=_integer(out.get("default_ttl_seconds")),
            max_ttl_seconds=_integer(out.get("max_ttl_seconds")),
            max_ciphertext_bytes=_integer(out.get("max_ciphertext_bytes")),
            long_poll_max_seconds=_integer(out.get("long_poll_max_seconds")),
            agent_auth=_text(out.get("agent_auth")),
            page_served=bool(out.get("page_served")),
            page_version=_text(out.get("page_version")),
            page_sha256=_text(out.get("page_sha256")),
        )

    def page_hash(self) -> str:
        """Fetch the served drop page and return its SHA-256 as base64url.

        Compare it with the published hash to verify a hosted page.
        """
        request = urllib.request.Request(self.origin + "/drop", method="GET")
        request.add_header(CLIENT_HEADER, self.client_name)
        status, body = self._raw(request, MAX_PAGE)
        if status != 200:
            raise RelayError(status, "page_unavailable")
        return commitment(body)

    # Internals.

    def _status(self, path: str, drop_id: str, wait_seconds: int, wait_while: str) -> Status:
        wait = min(max(int(wait_seconds), 0), MAX_WAIT)
        out = self._post(
            path, {"drop_id": drop_id, "wait_seconds": wait, "wait_while": wait_while}, auth=False
        )
        return _status_from(out)

    def _wait_while(self, poll: Callable[[int], Status], state: str, deadline: Deadline) -> Status:
        last: Status | None = None
        failures = 0
        while True:
            remaining = _seconds_until(deadline)
            if remaining <= 0:
                raise DeadlineExceeded(last)
            wait = min(math.ceil(remaining), MAX_WAIT)
            try:
                status = poll(wait)
            except RelayError as err:
                if err.status and err.status < 500 and err.code != CODE_RATE_LIMITED:
                    raise
                failures += 1
                if failures > 5:
                    raise
                time.sleep(min(float(failures), max(remaining, 0.0)))
                continue
            failures = 0
            last = status
            if status.state != state:
                return status

    @staticmethod
    def _ciphertext(out: dict[str, Any]) -> bytes:
        try:
            return b64decode(_text(out.get("ciphertext")))
        except EncodingError:
            raise RelayError(
                200, "malformed_response", "malformed ciphertext in response"
            ) from None

    def _post(self, path: str, body: dict[str, Any], auth: bool) -> dict[str, Any]:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(self.origin + path, data=data, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header(CLIENT_HEADER, self.client_name)
        if auth and self.api_key:
            request.add_header("Authorization", "Bearer " + self.api_key)
        return self._request(request)

    def _raw(self, request: urllib.request.Request, limit: int) -> tuple[int, bytes]:
        """Perform the request and return status and body, or fail with CODE_CONNECTION."""
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return int(response.status), bytes(response.read(limit))
        except urllib.error.HTTPError as err:
            try:
                return int(err.code), bytes(err.read(limit))
            finally:
                err.close()
        except (OSError, http.client.HTTPException) as err:
            reason = getattr(err, "reason", err)
            raise RelayError(0, CODE_CONNECTION, detail=str(reason)) from err

    def _request(self, request: urllib.request.Request) -> dict[str, Any]:
        status, body = self._raw(request, MAX_RESPONSE)
        if status // 100 != 2:
            raise _decode_error(status, body)
        try:
            obj = json.loads(body)
        except ValueError:
            obj = None
        if not isinstance(obj, dict):
            raise RelayError(status, "malformed_response", f"malformed response (HTTP {status})")
        return obj
