"""Replace known secret values, and their common encodings, in text.

The redactor is a safety net behind the rule that values are never put into
model-facing output on purpose. It learns values as the agent receives or
injects them and rewrites command output, error messages, and tool results
before they leave the process.
"""

from __future__ import annotations

import base64
import binascii
import threading
import urllib.parse

from ._json import json_string

__all__ = ["MIN_REDACT_LEN", "Redactor"]

MIN_REDACT_LEN = 6
"""Values shorter than this are never redacted, so they cannot mask ordinary text."""


def _forms(value: bytes) -> list[bytes]:
    """Return the value and its encodings, in the order the reference registers them.

    Standard and URL-safe base64 (with and without padding), hex, URL query
    escaping, URL path segment escaping, and JSON string escaping.
    """
    forms = [
        value,
        base64.b64encode(value),
        base64.b64encode(value).rstrip(b"="),
        base64.urlsafe_b64encode(value),
        base64.urlsafe_b64encode(value).rstrip(b"="),
        binascii.hexlify(value),
        urllib.parse.quote_plus(value, safe="").encode("ascii"),
        urllib.parse.quote(value, safe="$&+:=@").encode("ascii"),
    ]
    text = value.decode("utf-8", "surrogateescape")
    escaped = json_string(text, escape_html=True)[1:-1]
    forms.append(escaped.encode("utf-8", "surrogateescape"))
    trimmed = value.strip()
    if len(trimmed) != len(value) and trimmed:
        forms.append(trimmed)
    return forms


class Redactor:
    """Replaces registered values with ``[redacted:<name>]``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._forms: list[tuple[str, bytes]] = []

    def add(self, name: str, value: bytes) -> None:
        """Register a value under a name, together with its encoded forms."""
        value = bytes(value)
        if len(value) < MIN_REDACT_LEN:
            return
        with self._lock:
            seen = {form for _, form in self._forms}
            for form in _forms(value):
                if len(form) < MIN_REDACT_LEN or form in seen:
                    continue
                seen.add(form)
                self._forms.append((name, form))
            # Longest first so a longer encoding is replaced before a substring of it.
            self._forms.sort(key=lambda item: len(item[1]), reverse=True)

    def remove(self, name: str) -> None:
        """Forget every form registered under name."""
        with self._lock:
            self._forms = [item for item in self._forms if item[0] != name]

    def redact_bytes(self, data: bytes) -> bytes:
        """Return data with every known form replaced."""
        with self._lock:
            forms = list(self._forms)
        if not forms or not data:
            return bytes(data)
        out = bytes(data)
        for name, form in forms:
            if form in out:
                out = out.replace(form, b"[redacted:" + name.encode("utf-8") + b"]")
        return out

    def redact(self, text: str) -> str:
        """Return text with every known form replaced."""
        if not text:
            return text
        data = text.encode("utf-8", "surrogateescape")
        return self.redact_bytes(data).decode("utf-8", "replace")

    def __len__(self) -> int:
        """Return how many forms are registered; for tests and diagnostics."""
        with self._lock:
            return len(self._forms)
