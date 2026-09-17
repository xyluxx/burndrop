"""The agent side of both flows.

:class:`Agent` creates one-time links for a human to submit a secret into
(:meth:`Agent.request_secret` and :meth:`Agent.fetch_secret`) and for a
human to receive one (:meth:`Agent.send_secret`). Values are returned to the
calling program as bytes. They are for the program only: never place a
value in a language model's context, a log, or a chat message. Use
:func:`run_with_secret` to hand a value to a subprocess and get back output
with the value and its encodings redacted.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import crypto
from ._time import format_rfc3339, parse_rfc3339
from .link import DropLink, LinkError, RevealLink, normalize_origin
from .password import new_salt, reveal_key_with_password
from .redact import Redactor
from .relay import (
    CODE_GONE,
    CODE_NOT_FOUND,
    STATE_CREATED,
    STATE_EXPIRED,
    STATE_FETCHED,
    STATE_REVOKED,
    STATE_UPLOADED,
    DeadlineExceeded,
    RelayClient,
    RelayError,
    Status,
)

__all__ = [
    "DEFAULT_RETENTION",
    "DEFAULT_STORAGE_LABEL",
    "DEFAULT_TTL",
    "MAX_FETCH_WAIT",
    "MAX_VALUE_BYTES",
    "STATUS_EXPIRED",
    "STATUS_GONE",
    "STATUS_RECEIVED",
    "STATUS_REJECTED",
    "STATUS_REVOKED",
    "STATUS_WAITING",
    "Agent",
    "AgentError",
    "Fetched",
    "Request",
    "RunError",
    "RunResult",
    "Sent",
    "check_envelope",
    "parse_retention",
    "run_with_secret",
    "validate_secret_name",
]

DEFAULT_TTL = 3600
"""Link lifetime in seconds when the caller does not choose one."""
DEFAULT_RETENTION = crypto.RETENTION_UNTIL_REVOKED
DEFAULT_STORAGE_LABEL = "the agent's process memory only"
"""What the human is told about storage unless the program says otherwise."""
DEFAULT_WAIT = 30
MAX_FETCH_WAIT = 300
"""Bound on one :meth:`Agent.fetch_secret` call, in seconds."""
MAX_VALUE_BYTES = 64 * 1024
"""Largest value that can be sent."""

STATUS_WAITING = "waiting"
STATUS_RECEIVED = "received"
STATUS_EXPIRED = "expired"
STATUS_REVOKED = "revoked"
STATUS_REJECTED = "rejected"
STATUS_GONE = "gone"

DEFAULT_RUN_TIMEOUT = 120.0
MAX_RUN_TIMEOUT = 3600.0
DEFAULT_MAX_OUTPUT = 32 * 1024
MAX_CAPTURED_BYTES = 1 << 20

_SECRET_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,255}")
_TIME_FORMAT = "%Y-%m-%d %H:%M UTC"


class AgentError(Exception):
    """The relay behaved in a way the flow cannot interpret."""


class RunError(Exception):
    """A command could not be started. The message is redacted."""


def validate_secret_name(name: str) -> None:
    """Check a secret reference name as the agent runtime does.

    Reference names are keys in external systems, so they are kept to a
    conservative character set: 1 to 100 characters of letters, digits, dot,
    underscore, or dash, starting with a letter or digit, without ``..``.
    """
    if not isinstance(name, str) or _SECRET_NAME_RE.fullmatch(name) is None:
        raise ValueError(
            f"{name!r} must be 1 to 100 characters of letters, digits, dot, underscore, "
            "or dash, starting with a letter or digit"
        )
    if ".." in name:
        raise ValueError(f"{name!r} must not contain a double dot")


def parse_retention(policy: str, now: datetime | None = None) -> datetime | None:
    """Validate a retention policy and return the expiry it implies (None for none)."""
    if policy in (crypto.RETENTION_SESSION, crypto.RETENTION_UNTIL_REVOKED):
        return None
    if policy.startswith(crypto.RETENTION_UNTIL_PREFIX):
        try:
            expires = parse_rfc3339(policy[len(crypto.RETENTION_UNTIL_PREFIX) :])
        except ValueError as err:
            raise ValueError(
                "retention date must be RFC 3339, for example until:2027-01-31T00:00:00Z"
            ) from err
        if expires <= (now or datetime.now(timezone.utc)):
            raise ValueError("retention date is in the past")
        return expires.astimezone(timezone.utc)
    raise ValueError(
        f"unknown retention policy {policy!r} "
        "(use session, until-revoked, or until:<RFC 3339 date>)"
    )


def _check_ttl(ttl: int) -> int:
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        raise ValueError("ttl must be a positive number of seconds")
    return ttl


def _when(value: datetime | None) -> str:
    if value is None:
        return "the relay's default expiry"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime(_TIME_FORMAT)


def _describe_retention(retention: str) -> str:
    if retention == crypto.RETENTION_SESSION:
        return "kept only until the agent process exits"
    if retention == crypto.RETENTION_UNTIL_REVOKED:
        return "kept until deleted"
    if retention.startswith(crypto.RETENTION_UNTIL_PREFIX):
        return "kept until " + retention[len(crypto.RETENTION_UNTIL_PREFIX) :]
    return retention


def _request_message(
    name: str,
    link: str,
    purpose: str,
    storage: str,
    retention: str,
    expires_at: datetime | None,
    fingerprint: str,
) -> str:
    """The disclosure text the model relays to the human.

    It contains everything the human must know: what is asked and why,
    where it will be stored and for how long, that the link opens once and
    expires, and the fingerprint to compare.
    """
    return (
        f"Please share {name} using this one-time secure link: {link}\n\n"
        f"What it is for: {purpose}\n"
        f"Where it will be stored: {storage} ({_describe_retention(retention)}).\n"
        f"The link works once and expires at {_when(expires_at)}. Before submitting, check "
        f"that the page shows fingerprint {fingerprint}. The secret is encrypted in your "
        "browser and only this agent can decrypt it; the relay never sees it. I will never "
        "see the value itself."
    )


def _send_message(
    name: str,
    link: str,
    expires_at: datetime | None,
    keeps_copy: bool,
    password_protected: bool = False,
) -> str:
    copy_note = "I keep my copy of it." if keeps_copy else "I have deleted my copy of it."
    password_note = (
        " The page asks for your reveal password before it shows the value."
        if password_protected
        else ""
    )
    return (
        f"Here is {name}: {link}\n\n"
        "The link reveals the value once, after you press the button on the page, and then "
        f"it is gone.{password_note} It expires at {_when(expires_at)}. {copy_note} Copy the "
        "value somewhere safe before closing the page."
    )


@dataclass
class Request:
    """An outstanding request: what to show the human plus what can open the drop.

    ``private_key`` is zeroed once the drop is decrypted, revoked, or found
    to be finished; ``fetch_token`` and ``upload_token`` are what a program
    needs if it must persist a request across processes. Treat the object as
    secret material and never log it.
    """

    request_id: str
    link: str
    fingerprint: str
    expires_at: datetime | None
    message: str
    name: str
    purpose: str
    retention: str
    storage: str
    public_key: bytes = field(repr=False)
    private_key: bytearray = field(repr=False)
    fetch_token: str = field(repr=False)
    upload_token: str = field(repr=False)

    def forget(self) -> None:
        """Zero the private key (best effort; Python may hold other copies)."""
        for i in range(len(self.private_key)):
            self.private_key[i] = 0


@dataclass(frozen=True)
class Fetched:
    """The outcome of :meth:`Agent.fetch_secret`.

    ``value`` is set only when ``status`` is :data:`STATUS_RECEIVED`. It is
    for the calling program and must not be placed in a language model's
    context.
    """

    status: str
    value: bytes | None = field(repr=False)
    name: str
    fingerprint: str
    request_id: str
    message: str
    expires_at: datetime | None = None


@dataclass(frozen=True)
class Sent:
    """The outcome of :meth:`Agent.send_secret`."""

    request_id: str
    link: str
    expires_at: datetime | None
    keeps_copy: bool
    message: str
    revoke_token: str = field(repr=False)
    password_protected: bool = False


@dataclass(frozen=True)
class RunResult:
    """The outcome of :func:`run_with_secret`; output is redacted and bounded."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    duration_ms: int


def check_envelope(env: crypto.Envelope, request: Request) -> str:
    """Verify a decrypted envelope against the request; empty means it matches.

    The page fills the envelope from the link it was given, so any
    difference means the link the human used was not the one this agent
    made.
    """
    if env.type != crypto.TYPE_DROP:
        return "the envelope is not a drop"
    if env.name != request.name:
        return "the secret name in the submission does not match the request"
    if env.fingerprint and env.fingerprint != request.fingerprint:
        return "the fingerprint shown to the human does not match this request"
    if env.retention != request.retention:
        return "the retention shown to the human does not match the request"
    if env.purpose != request.purpose:
        return "the purpose shown to the human does not match the request"
    if env.storage != request.storage:
        return "the storage description shown to the human does not match the request"
    return ""


class Agent:
    """Implements the flows against one relay.

    ``page_origin`` is where the drop page is served; it defaults to the
    relay origin. When they differ, links carry the relay origin in their
    ``r`` field.
    """

    def __init__(
        self,
        relay_origin: str,
        api_key: str | None = None,
        page_origin: str | None = None,
        *,
        client_name: str | None = None,
        relay: RelayClient | None = None,
    ) -> None:
        self.relay = relay or RelayClient(relay_origin, api_key, client_name=client_name)
        self.page_origin = normalize_origin(page_origin) if page_origin else self.relay.origin
        self.redactor = Redactor()

    def _relay_field(self) -> str:
        return self.relay.origin if self.relay.origin != self.page_origin else ""

    def request_secret(
        self,
        name: str,
        purpose: str,
        retention: str = DEFAULT_RETENTION,
        ttl: int = DEFAULT_TTL,
        storage_label: str | None = None,
    ) -> Request:
        """Create a drop slot and return the link and disclosures for the human.

        ``storage_label`` is what the human is told about where the value
        will be kept. Pass the truth: the default says the value stays in
        the agent's process memory.
        """
        validate_secret_name(name)
        crypto.validate_text("purpose", purpose)
        if not purpose.strip():
            raise ValueError("purpose is required so the human knows what the secret is for")
        parse_retention(retention)
        ttl = _check_ttl(ttl)
        storage = DEFAULT_STORAGE_LABEL if storage_label is None else storage_label
        crypto.validate_text("storage", storage)
        public_key, private_key = crypto.generate_keypair()
        created = self.relay.create_drop(crypto.commitment(public_key), ttl)
        fingerprint = crypto.fingerprint(public_key)
        link = DropLink(
            relay=self._relay_field(),
            id=created.id,
            upload_token=created.upload_token,
            recipient_key=public_key,
            name=name,
            purpose=purpose,
            storage=storage,
            retention=retention,
        )
        try:
            url = link.build(self.page_origin)
        except LinkError:
            self._quiet(lambda: self.relay.revoke_drop(created.id, created.upload_token))
            raise
        message = _request_message(
            name, url, purpose, storage, retention, created.expires_at, fingerprint
        )
        return Request(
            request_id=created.id,
            link=url,
            fingerprint=fingerprint,
            expires_at=created.expires_at,
            message=message,
            name=name,
            purpose=purpose,
            retention=retention,
            storage=storage,
            public_key=public_key,
            private_key=bytearray(private_key),
            fetch_token=created.fetch_token,
            upload_token=created.upload_token,
        )

    def fetch_secret(self, request: Request, wait_seconds: int = DEFAULT_WAIT) -> Fetched:
        """Wait for the human's upload, then download, decrypt, and verify it.

        Returns a :class:`Fetched` whose ``status`` says what happened. Only
        :data:`STATUS_RECEIVED` carries a value.
        """
        wait = DEFAULT_WAIT if wait_seconds == 0 else wait_seconds
        wait = min(max(wait, 0), MAX_FETCH_WAIT)
        status: Status | None
        try:
            status = self.relay.wait_for_upload(request.request_id, time.time() + wait)
        except DeadlineExceeded as timeout:
            status = timeout.last
        except RelayError as err:
            if err.code == CODE_NOT_FOUND:
                request.forget()
                return self._outcome(
                    request,
                    STATUS_EXPIRED,
                    "The request is no longer known to the relay; it expired. Ask again with "
                    "request_secret if you still need it.",
                )
            raise
        state = status.state if status is not None else ""
        if state in (STATE_CREATED, ""):
            return self._outcome(
                request,
                STATUS_WAITING,
                f"The human has not submitted {request.name} yet. The link is valid until "
                f"{_rfc3339(request.expires_at)}. Call fetch_secret again to keep waiting.",
            )
        if state == STATE_REVOKED:
            request.forget()
            return self._outcome(
                request,
                STATUS_REVOKED,
                "The request was revoked before the human submitted anything.",
            )
        if state == STATE_EXPIRED:
            request.forget()
            return self._outcome(
                request,
                STATUS_EXPIRED,
                "The request expired before the human submitted anything. Ask again with "
                "request_secret if you still need it.",
            )
        if state == STATE_FETCHED:
            request.forget()
            return self._outcome(
                request,
                STATUS_GONE,
                "The submission was already fetched. If it was not received by this agent, "
                "treat the secret as exposed and ask the human to rotate it.",
            )
        if state == STATE_UPLOADED:
            return self._fetch_uploaded(request)
        raise AgentError(f"unexpected relay state {state!r}")

    def _fetch_uploaded(self, request: Request) -> Fetched:
        try:
            ciphertext, _uploaded_at = self.relay.fetch(request.request_id, request.fetch_token)
        except RelayError as err:
            if err.code == CODE_GONE:
                request.forget()
                return self._outcome(
                    request,
                    STATUS_GONE,
                    "The submission was fetched by someone else before this agent could. Treat "
                    "the secret as exposed and ask the human to rotate it.",
                )
            raise
        try:
            env = crypto.open_envelope(request.public_key, bytes(request.private_key), ciphertext)
        except crypto.CryptoError:
            request.forget()
            return self._outcome(
                request,
                STATUS_REJECTED,
                "The submission could not be decrypted with this request's key. The relay or "
                "the page may have been tampered with. Ask the human to try again with a fresh "
                "link and to compare fingerprints.",
            )
        reason = check_envelope(env, request)
        if reason:
            request.forget()
            return self._outcome(
                request,
                STATUS_REJECTED,
                f"The submission was rejected: {reason}. Ask the human to try again with a "
                "fresh link.",
            )
        value = env.secret_bytes()
        request.forget()
        self.redactor.add(request.name, value)
        return Fetched(
            status=STATUS_RECEIVED,
            value=value,
            name=request.name,
            fingerprint=request.fingerprint,
            request_id=request.request_id,
            message=(
                f"Received {request.name} ({len(value)} bytes). The value was returned to the "
                "calling program and must not be placed in a language model's context."
            ),
            expires_at=request.expires_at,
        )

    @staticmethod
    def _outcome(request: Request, status: str, message: str) -> Fetched:
        return Fetched(
            status=status,
            value=None,
            name=request.name,
            fingerprint=request.fingerprint,
            request_id=request.request_id,
            message=message,
            expires_at=request.expires_at,
        )

    def send_secret(
        self,
        name: str,
        value: bytes,
        ttl: int = DEFAULT_TTL,
        keeps_copy: bool = True,
        password: str | None = None,
    ) -> Sent:
        """Encrypt a value for a human and return a one-time link.

        ``keeps_copy`` is disclosed to the human and authenticated into the
        ciphertext; pass False only if the program really deletes its copy.
        With ``password``, the link carries a salt and the page asks the human
        for that password before it shows the value (section 4.1).
        """
        validate_secret_name(name)
        ttl = _check_ttl(ttl)
        value = bytes(value)
        if len(value) > MAX_VALUE_BYTES:
            raise ValueError(f"value larger than {MAX_VALUE_BYTES} bytes")
        self.redactor.add(name, value)
        key = crypto.new_symmetric_key()
        enc_key = key
        salt = b""
        if password is not None:
            salt = new_salt()
            enc_key = reveal_key_with_password(key, password, salt)
        env = crypto.Envelope.reveal(name, value)
        ciphertext = crypto.encrypt_envelope(enc_key, env, crypto.reveal_aad(name, keeps_copy))
        created = self.relay.create_reveal(ciphertext, ttl)
        link = RevealLink(
            relay=self._relay_field(),
            id=created.id,
            reveal_token=created.reveal_token,
            key=key,
            name=name,
            keeps_copy=keeps_copy,
            salt=salt,
        )
        try:
            url = link.build(self.page_origin)
        except LinkError:
            self._quiet(lambda: self.relay.revoke_reveal(created.id, created.revoke_token))
            raise
        return Sent(
            request_id=created.id,
            link=url,
            expires_at=created.expires_at,
            keeps_copy=keeps_copy,
            message=_send_message(name, url, created.expires_at, keeps_copy, bool(salt)),
            revoke_token=created.revoke_token,
            password_protected=bool(salt),
        )

    def revoke(self, request: Request) -> str:
        """Cancel a pending request on the relay and forget its key.

        Returns the resulting state: ``revoked``, or the state the relay
        reported when the request had already finished.
        """
        request.forget()
        try:
            self.relay.revoke_drop(request.request_id, request.upload_token)
        except RelayError as err:
            if err.state:
                return err.state
            if err.code == CODE_NOT_FOUND:
                return STATE_EXPIRED
            raise
        return STATE_REVOKED

    def revoke_sent(self, sent: Sent) -> str:
        """Delete an unopened reveal from the relay. Returns the resulting state."""
        try:
            self.relay.revoke_reveal(sent.request_id, sent.revoke_token)
        except RelayError as err:
            if err.state:
                return err.state
            if err.code == CODE_NOT_FOUND:
                return STATE_EXPIRED
            raise
        return STATE_REVOKED

    def run_with_secret(
        self,
        command: Sequence[str],
        env: Mapping[str, bytes | str],
        *,
        cwd: str | os.PathLike[str] | None = None,
        stdin: bytes | str | None = None,
        timeout: float = DEFAULT_RUN_TIMEOUT,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT,
        discard_output: bool = False,
    ) -> RunResult:
        """:func:`run_with_secret` using this agent's redactor.

        Values received with :meth:`fetch_secret` or sent with
        :meth:`send_secret` are redacted from the output as well.
        """
        return run_with_secret(
            command,
            env,
            cwd=cwd,
            stdin=stdin,
            timeout=timeout,
            max_output_bytes=max_output_bytes,
            discard_output=discard_output,
            redactor=self.redactor,
        )

    @staticmethod
    def _quiet(action: object) -> None:
        try:
            if callable(action):
                action()
        except RelayError:
            pass


def _rfc3339(value: datetime | None) -> str:
    return format_rfc3339(value) if value is not None else "unknown"


def run_with_secret(
    command: Sequence[str],
    env: Mapping[str, bytes | str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    stdin: bytes | str | None = None,
    timeout: float = DEFAULT_RUN_TIMEOUT,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT,
    discard_output: bool = False,
    redactor: Redactor | None = None,
) -> RunResult:
    """Run a command with secrets injected as environment variables.

    ``env`` maps variable names to values. The command is started without a
    shell, inherits the current environment plus the injected variables,
    and its output is captured. Every injected value and its common
    encodings (base64, hex, URL and JSON escaping) are replaced with
    ``[redacted:<VARIABLE>]`` before the output is returned; the output is
    also bounded by ``max_output_bytes``. On Windows, values must be text.
    """
    command = [str(part) for part in command]
    if not command or not command[0].strip():
        raise ValueError("command must have at least the program name")
    if timeout <= 0:
        timeout = DEFAULT_RUN_TIMEOUT
    timeout = min(timeout, MAX_RUN_TIMEOUT)
    if redactor is None:
        redactor = Redactor()
    injected: dict[str, str] = {}
    for variable, value in env.items():
        if not isinstance(variable, str) or _ENV_NAME_RE.fullmatch(variable) is None:
            raise ValueError(f"{variable!r} is not a valid environment variable name")
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        redactor.add(variable, raw)
        injected[variable] = raw.decode("utf-8", "surrogateescape")
    child_env = _child_environment(injected)
    stdin_bytes = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
    start = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            env=child_env,
            cwd=cwd,
            input=stdin_bytes,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        exit_code = completed.returncode
        out_bytes: bytes = completed.stdout
        err_bytes: bytes = completed.stderr
    except subprocess.TimeoutExpired as expired:
        exit_code = -1
        timed_out = True
        out_bytes = _bytes(expired.stdout)
        err_bytes = _bytes(expired.stderr)
    except OSError as failure:
        raise RunError(f"could not start {command[0]}: {redactor.redact(str(failure))}") from None
    duration_ms = int((time.monotonic() - start) * 1000)
    truncated = False
    stdout = stderr = ""
    if not discard_output:
        stdout, cut_out = _clean(out_bytes, redactor, max_output_bytes)
        stderr, cut_err = _clean(err_bytes, redactor, max_output_bytes)
        truncated = cut_out or cut_err
    return RunResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        truncated=truncated,
        duration_ms=duration_ms,
    )


def _bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", "replace")
    return b""


def _child_environment(injected: Mapping[str, str]) -> dict[str, str]:
    child: dict[str, str] = {}
    if sys.platform == "win32":
        overridden = {name.upper() for name in injected}
        for key, value in os.environ.items():
            if key.upper() not in overridden:
                child[key] = value
    else:
        for key, value in os.environ.items():
            if key not in injected:
                child[key] = value
    child.update(injected)
    return child


def _clean(data: bytes, redactor: Redactor, max_output_bytes: int) -> tuple[str, bool]:
    data = redactor.redact_bytes(data[:MAX_CAPTURED_BYTES])
    text = data.decode("utf-8", "replace")
    if max_output_bytes > 0 and len(text) > max_output_bytes:
        return text[:max_output_bytes] + "\n[truncated]", True
    return text, False
