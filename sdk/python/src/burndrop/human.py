"""The human side of both flows, for programs that stand in for the page.

:func:`submit` does what the drop page does when the human presses
"Encrypt and send": it seals the value to the key in the link, together
with the metadata the link displayed, and uploads it with the commitment
to that key so an honest relay rejects an altered link. :func:`open` does
what the reveal page does on "Reveal": it fetches the ciphertext (which
deletes it) and decrypts it with the display fields as additional data, so
an altered link fails to decrypt.
"""

from __future__ import annotations

from . import crypto
from .link import normalize_origin, parse_drop, parse_reveal
from .relay import RelayClient

__all__ = ["HumanError", "open", "submit"]


class HumanError(Exception):
    """A reveal could not be decrypted: the link was altered or the relay lied."""


def submit(
    link: str,
    value: bytes,
    *,
    relay: str | None = None,
    client_name: str | None = None,
) -> str:
    """Encrypt ``value`` for the agent behind a drop link and upload it.

    Returns the fingerprint of the key the value was encrypted to; compare
    it with the one the agent showed before calling, as the page asks the
    human to do. ``relay`` overrides the relay origin the link points at.
    """
    drop, page_origin = parse_drop(link)
    origin = normalize_origin(relay) if relay else drop.relay_origin(page_origin)
    value = bytes(value)
    if not value:
        raise ValueError("empty value")
    fingerprint = drop.fingerprint()
    envelope = crypto.Envelope.drop(
        drop.name, drop.purpose, drop.storage, drop.retention, fingerprint, value
    )
    sealed = crypto.seal_envelope(drop.recipient_key, envelope)
    client = RelayClient(origin, client_name=client_name)
    client.upload(drop.id, drop.upload_token, crypto.commitment(drop.recipient_key), sealed)
    return fingerprint


def open(
    link: str,
    *,
    relay: str | None = None,
    client_name: str | None = None,
) -> bytes:
    """Open a reveal link once and return the value.

    The relay deletes the ciphertext when it is handed out, so a second call
    fails with a ``gone`` relay error.
    """
    reveal, page_origin = parse_reveal(link)
    origin = normalize_origin(relay) if relay else reveal.relay_origin(page_origin)
    client = RelayClient(origin, client_name=client_name)
    ciphertext, _created_at = client.open(reveal.id, reveal.reveal_token)
    try:
        envelope = crypto.decrypt_envelope(reveal.key, ciphertext, reveal.aad())
    except crypto.CryptoError as err:
        raise HumanError(
            "the secret could not be decrypted: the link was altered or the relay returned "
            "the wrong data; the relay copy is gone, ask the agent to send it again"
        ) from err
    return envelope.secret_bytes()
