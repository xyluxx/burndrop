"""burndrop: one-time, end-to-end encrypted secret exchange between humans and AI agents.

The package implements the protocol natively (crypto plus relay client) so a
program can run without the Go binary:

* :mod:`burndrop.crypto`: sealed boxes, XChaCha20-Poly1305, padding, envelopes.
* :mod:`burndrop.link`: building and strict parsing of drop and reveal links.
* :mod:`burndrop.relay`: the relay API client.
* :mod:`burndrop.agent`: the agent flows and :func:`run_with_secret`.
* :mod:`burndrop.human`: the human side, for programs that stand in for the page.

Values are returned to the calling program as bytes and are for the program
only; never place one in a language model's context.
"""

from ._version import __version__
from .agent import Agent, Fetched, Request, RunResult, Sent, run_with_secret
from .crypto import Envelope
from .link import DropLink, LinkError, Parsed, RevealLink, parse
from .redact import Redactor
from .relay import DeadlineExceeded, RelayClient, RelayError

__all__ = [
    "Agent",
    "DeadlineExceeded",
    "DropLink",
    "Envelope",
    "Fetched",
    "LinkError",
    "Parsed",
    "Redactor",
    "RelayClient",
    "RelayError",
    "Request",
    "RevealLink",
    "RunResult",
    "Sent",
    "__version__",
    "parse",
    "run_with_secret",
]
