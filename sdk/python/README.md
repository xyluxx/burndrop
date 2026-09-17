# burndrop for Python

One-time, end-to-end encrypted secret exchange between humans and AI agents
through a zero-knowledge relay. This package implements the protocol
natively: libsodium sealed boxes and XChaCha20-Poly1305 through PyNaCl, the
link format, and the relay API client. A Python program can act as the agent,
or stand in for the human's page, without the Go binary.

The relay never sees a key or a value, links carry everything after `#` so no
server or log ever receives an identifier, and every drop or reveal can be
opened exactly once.

## Install

```sh
uv add burndrop
# or: pip install burndrop
```

Python 3.10 or newer. The only dependency is PyNaCl (pinned to 1.6.2); HTTP
uses the standard library.

## Ask a human for a secret

```python
from burndrop import Agent

agent = Agent("https://relay.example", api_key=os.environ["BURNDROP_AGENT_KEY"])
request = agent.request_secret(
    "openai-api-key", purpose="Call the OpenAI API from the billing script"
)
print(request.message)  # send this to the human: link, fingerprint, and the disclosures
fetched = agent.fetch_secret(request, wait_seconds=300)  # long polls until the human submits
api_key = fetched.value if fetched.status == "received" else None  # bytes, for the program only
```

`fetch_secret` returns a status of `waiting`, `received`, `expired`,
`revoked`, `rejected` (the envelope did not match the request: the link the
human used was altered), or `gone` (someone fetched it first; treat the
secret as exposed). Only `received` carries a value. `agent.revoke(request)`
cancels a pending request.

## Send a secret to a human

```python
sent = agent.send_secret("staging-db-url", b"postgres://app:...", ttl=1800, keeps_copy=False)
print(sent.message)  # the link opens once, expires, and says whether the agent keeps a copy
# password="..." makes the page ask for that password before it shows the value
status = agent.relay.wait_for_open(sent.request_id, time.time() + 600)
print(status.state)  # opened, expired, or revoked
```

## Use a value without showing it

```python
from burndrop import run_with_secret

result = run_with_secret(["python", "bill.py"], env={"OPENAI_API_KEY": fetched.value})
print(result.exit_code, result.stdout)  # the value and its encodings read [redacted:OPENAI_API_KEY]
```

`Agent.run_with_secret` does the same and also redacts every value the
agent received or sent earlier.

## The human side without a browser

```python
from burndrop import human

fingerprint = human.submit(drop_link, b"sk-live-...")  # what the drop page does
value = human.open(reveal_link)  # what the reveal page does; the relay copy is gone afterwards
# Links that carry a salt need the reveal password the human set.
value = human.open(protected_link, password="...")
```

`submit` seals the value to the key in the link together with the metadata
the link displays, and uploads it with the commitment (SHA-256 of that key)
so an honest relay rejects a link whose key was swapped. Compare the
returned fingerprint with the one the agent showed before calling. `open`
rebuilds the additional data from the display fields, so an altered link
fails to decrypt with `HumanError`.

## Security notes

What the SDK never does:

- It never puts a secret value in a link, a URL, a query string, a log
  line, an exception message, or a `repr`. Identifiers and tokens travel in
  request bodies, and links carry everything after `#`.
- It never talks to a relay over plain `http` except `localhost` and the
  loopback addresses.
- It never accepts an envelope whose name, fingerprint, retention, or type
  differs from the request it made, and never accepts a link with an
  unknown field, a wrong version, or a malformed value.

Values are bytes for the program only. `fetch_secret` and `human.open`
return the value to the calling code; the program decides where it goes.
Do not place a value in a language model's context, a chat message, a
prompt, or a tool result. Pass it to a subprocess with `run_with_secret`,
which injects it as an environment variable and replaces the raw value and
its common encodings (standard and URL-safe base64 with and without
padding, hex, URL query and path escaping, JSON string escaping) with
`[redacted:<VARIABLE>]` in the captured output. Redaction is a safety net,
not a substitute for keeping values out of model-facing output.

Memory: the private key of a pending request is kept in a `bytearray` and
zeroed once the drop is decrypted, revoked, or found to be finished.
Python cannot reliably erase every copy of a `bytes` object, so treat a
process that held a value as having held it until it exits.

Tell the human the truth about storage. `request_secret` says the value
stays in the agent's process memory unless you pass `storage_label`; if the
program writes the value somewhere, say where.

## API reference

| Module | Name | Purpose |
|---|---|---|
| `burndrop.agent` | `Agent(relay_origin, api_key=None, page_origin=None)` | The agent side against one relay. `page_origin` defaults to the relay origin; when they differ, links carry the relay in their `r` field. |
| | `Agent.request_secret(name, purpose, retention="until-revoked", ttl=3600, storage_label=None)` | Create a drop slot. Returns a `Request` with `request_id`, `link`, `fingerprint`, `expires_at`, `message`, and the key material needed to fetch or revoke. |
| | `Agent.fetch_secret(request, wait_seconds=30)` | Wait up to `wait_seconds` (at most 300) for the upload, then fetch, decrypt, and verify. Returns a `Fetched` with `status`, `value`, `name`, `fingerprint`, `request_id`, `message`. |
| | `Agent.send_secret(name, value, ttl=3600, keeps_copy=True, password=None)` | Encrypt a value for a human. With `password`, the link carries a salt and the page asks for that password (specification section 4.1). Returns a `Sent` with `request_id`, `link`, `expires_at`, `keeps_copy`, `password_protected`, `message`, `revoke_token`. |
| | `Agent.revoke(request)` and `Agent.revoke_sent(sent)` | Cancel on the relay; return the resulting state. |
| | `Agent.run_with_secret(command, env, ...)` | `run_with_secret` with the agent's redactor. |
| | `run_with_secret(command, env, *, cwd=None, stdin=None, timeout=120, max_output_bytes=32768, discard_output=False, redactor=None)` | Run a command with values injected as environment variables; returns a `RunResult` with `exit_code`, redacted and bounded `stdout` and `stderr`, `timed_out`, `truncated`, `duration_ms`. |
| | `validate_secret_name(name)`, `parse_retention(policy)`, `check_envelope(env, request)` | The validation rules the agent applies. |
| `burndrop.human` | `submit(link, value, *, relay=None)` | Seal and upload a value for a drop link; returns the fingerprint of the key it was encrypted to. |
| | `open(link, *, relay=None)` | Open a reveal link once and return the value. |
| `burndrop.relay` | `RelayClient(origin, api_key=None, *, client_name=None, timeout=45)` | The relay API. Every request is a JSON `POST` with the `X-Client` header; identifiers are never in URLs. |
| | `create_drop`, `upload`, `drop_status`, `wait_for_upload`, `fetch`, `revoke_drop` | The drop endpoints. `drop_status(id, wait_seconds, wait_while)` long polls for up to 30 seconds; `wait_for_upload(id, deadline)` repeats until the state changes or `deadline` (epoch seconds or a `datetime`) passes, then raises `DeadlineExceeded`. |
| | `create_reveal`, `open`, `reveal_status`, `wait_for_open`, `revoke_reveal` | The reveal endpoints. |
| | `info()`, `page_hash()` | The relay description; the SHA-256 of the served page. |
| | `RelayError` | `status`, `code`, `detail`, `state`, `at`. `status` 0 with code `connection_failed` means no HTTP response. |
| `burndrop.link` | `DropLink`, `RevealLink` | Frozen dataclasses with `build(page_origin)`, `validate()`, `relay_origin(page_origin)`; `DropLink.fingerprint()`, `RevealLink.aad()`. |
| | `parse(url)`, `parse_drop(url)`, `parse_reveal(url)` | Strict parsing: version must be `1`, fixed field lengths, no unknown or duplicate fields, `https` only except localhost. |
| | `normalize_origin(origin)` | Lowercase `scheme://host[:port]` with default ports removed. |
| `burndrop.crypto` | `generate_keypair()`, `seal`, `open_sealed` | X25519 keys and libsodium sealed boxes. |
| | `new_symmetric_key()`, `encrypt_aead(key, plaintext, aad, nonce=None)`, `decrypt_aead` | XChaCha20-Poly1305 (IETF); blobs are `nonce || ciphertext || tag`. |
| | `pad`, `unpad` | ISO/IEC 7816-4 padding to 256 bytes. |
| | `fingerprint`, `commitment`, `reveal_aad(name, keeps_copy)` | SHA-256 derived values from the specification. |
| | `Envelope` | Frozen dataclass with `encode()`, `Envelope.decode()`, `validate()`, `with_secret()`, `secret_bytes()`, and the `drop(...)` and `reveal(...)` constructors. |
| | `seal_envelope`, `open_envelope`, `encrypt_envelope`, `decrypt_envelope` | Encode, pad, and encrypt in one step, and back. |
| | `valid_token`, `hash_token`, `random_token`, `validate_name`, `validate_text`, `validate_retention` | Token and field rules. |
| `burndrop.redact` | `Redactor` | `add(name, value)`, `remove(name)`, `redact(text)`, `redact_bytes(data)`. Values shorter than 6 bytes are never redacted. |
| `burndrop.encoding` | `b64encode`, `b64decode` | base64url without padding, decoded strictly. |

Errors: `LinkError` (a `ValueError`) for links and origins, `EnvelopeError`
and the other `CryptoError` subclasses for cryptographic input,
`RelayError` for the relay, `DeadlineExceeded` (a `TimeoutError`) for
waits, `HumanError` for a reveal that does not decrypt, and `ValueError`
for bad arguments.

## Testing

```sh
cd sdk/python
uv sync
uv run ruff check
uv run mypy --strict src
uv run pytest -q
```

`tests/test_vectors.py` exercises every section of `spec/vectors.json`.
`tests/test_integration.py` builds the Go relay from this repository and
runs both flows against it, including the one-time property, revocation,
and tampered links; it is skipped when `go` is not installed. The relay
listens on `127.0.0.1:8080` when that port is free.

Coverage: `uv run pytest -q --cov=burndrop --cov-report=term-missing`.

## Cross-language interop

`spec/interop/python_gen.py` writes `spec/interop/python.json`, ciphertext
produced by this SDK for the Go and TypeScript implementations to open,
and `spec/interop/python_check.py` verifies every `*.json` in that
directory. Both run from `sdk/python` with `uv run python ...`. The schema
is documented in `spec/interop/README.md`.

## Differences from the Go implementation

The wire format, validation rules, and messages match the Go agent. Where
the two differ, it is because this SDK has no storage layer and returns
values to the program:

- `fetch_secret` reports success as `received` (Go: `stored`) and its
  message says the value was returned to the program.
- `send_secret` takes the value from the program; Go reads it from its
  storage backend and requires the `sendable` flag.
- `run_with_secret` takes values directly (`env` maps a variable name to a
  value) and labels redactions with the variable name. Go maps variables to
  stored secret names and also offers `capture_as`, `consume`, and the
  command allowlist.
- `storage_label` is free text for the link's `s` field and the message;
  the default is Go's description of its memory backend. Nothing is
  persisted: a program that must survive a restart keeps the `Request`
  fields itself.
- The `X-Client` value is `burndrop-python/<version>`.
- Long polls round the remaining time up to whole seconds; Go truncates,
  which can issue instant polls during the last second before a deadline.
- Envelope JSON keys are case-sensitive; Go's decoder matches field names
  case-insensitively.
- base64url decoding rejects newline characters, which Go's decoder skips.
- Percent-decoded link fields must be valid UTF-8; Go accepts invalid
  bytes in the name field and replaces them when it encodes the envelope.
- Origin hostnames are limited to letters, digits, `-._~%`, and IPv6
  brackets and colons; Go accepts a few more punctuation characters.
- RFC 3339 dates with year 0000 are rejected because `datetime` cannot
  represent them.
