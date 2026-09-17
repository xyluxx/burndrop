# Relay HTTP API

The burndrop relay is a zero-knowledge mailbox: it stores ciphertext, token hashes, state, and expiry, and nothing else. This page is the reference for its HTTP API as implemented in `internal/relay`. Every operation that names a drop is a `POST` with a JSON body, so no identifier, token, or key ever appears in a URL or an access log. The relay never sees plaintext: drops are sealed to a per-request X25519 key held by the agent, and reveals are encrypted under a key that travels only in the link fragment (see [crypto-spec.md](crypto-spec.md) and [design.md](design.md) section 6). The client side of this API is `internal/client` in Go; the drop page and the SDKs speak the same protocol.

## Conventions

- Base path: `/api/v1`. The current API version is reported by `GET /api/v1/info` as `"api":"v1"`.
- Every endpoint that names a drop is `POST` and takes `application/json`. `GET` and `HEAD` on those paths return `405 Method Not Allowed` with `Allow: OPTIONS, POST` and a plain text body, not JSON.
- `X-Client` is required on every `POST`. Any non-empty value works; the convention is `<name>/<version>` (the CLI sends `burndrop-cli/<version>`). The header exists so that a cross-origin browser call always triggers a CORS preflight and a plain HTML form cannot post to the API. Without it the relay answers `400 {"error":"missing_client_header","header":"X-Client"}`.
- `Content-Type` must be `application/json` (parameters after `;` are ignored). Anything else returns `415 {"error":"unsupported_media_type"}`.
- Bodies are decoded strictly: unknown fields, trailing data, and an empty body are rejected with `400 bad_request` and a `detail` such as `json: unknown field "foo"`, `trailing data`, `empty body`, `malformed JSON`, or `wrong type for field ttl_seconds`. The body is limited to `MAX_CIPHERTEXT_BYTES * 4 / 3 + 4096` bytes; a larger body returns `413 too_large`.
- Agent endpoints (`POST /api/v1/drops`, `POST /api/v1/drops/fetch`, `POST /api/v1/reveals`) require `Authorization: Bearer <agent key>`. The key must be 16 to 256 characters; the relay hashes it with SHA-256 and compares it in constant time against every entry in `BURNDROP_AGENT_KEYS`. A missing or unknown key returns `401 {"error":"unauthorized"}` with `WWW-Authenticate: Bearer realm="burndrop"`. When the relay runs with `BURNDROP_AGENT_AUTH=off` the header is optional; a valid key still identifies the caller for rate limiting; callers without one are recorded as `anonymous` and metered per client address.
- Page endpoints (`upload`, `open`, `status`, `revoke`) need no credential beyond the token in the body. Drop ids are unguessable, so `status` needs no token at all.
- Identifiers and tokens (`drop_id`, `upload_token`, `fetch_token`, `reveal_token`, `revoke_token`) are 22 characters of base64url without padding (16 random bytes). Commitments are 43 characters (a SHA-256 digest). Ciphertext is base64url without padding, decoded strictly. Requests with malformed values get `400 bad_request` with a `detail` such as `drop_id and upload_token must be 22 base64url characters`.
- Timestamps are RFC 3339 in UTC, for example `2026-09-17T12:10:15Z`. Optional timestamps are omitted from status bodies until they exist.
- Every response carries `X-Request-Id` (16 hex characters, also written to the relay log), `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, and a `Permissions-Policy` that denies every feature. `Strict-Transport-Security: max-age=31536000; includeSubDomains` is added when the request arrived over TLS or with `X-Forwarded-Proto: https`.
- `ttl_seconds` is never an error: `0` or absent means the relay default (`BURNDROP_DEFAULT_TTL`, 3600 seconds), anything below 60 becomes 60, anything above `BURNDROP_MAX_TTL` (86400 by default) is clamped. Clients read the effective expiry from `expires_at`.

### Error envelope

Errors are JSON objects with an `error` code and, depending on the code, extra fields:

```json
{"error":"gone","state":"fetched","at":"2026-09-17T12:12:03Z"}
```

| Field | Present on | Meaning |
|---|---|---|
| `error` | every error | The code from the table below |
| `detail` | `bad_request`, `commitment_mismatch` | A sentence that describes the structure of the problem; it never echoes a value |
| `state` | `gone`, `not_uploaded`, `already_uploaded` | The slot's current state |
| `at` | the same three codes | When that state was entered (`uploaded_at`, `fetched_at`, `opened_at`, `revoked_at`, or `expires_at` for `expired`) |
| `header` | `missing_client_header` | The missing header name, `X-Client` |
| `max_bytes` | `too_large` | The configured `MAX_CIPHERTEXT_BYTES` |

| Code | HTTP | When |
|---|---|---|
| `bad_request` | 400 | Malformed JSON, unknown field, wrong type, empty body, trailing data, malformed identifier or commitment, `wait_seconds` outside 0 to 30, ciphertext missing, not base64url, or shorter than the minimum |
| `missing_client_header` | 400 | `X-Client` absent on a `POST` |
| `unauthorized` | 401 | No bearer key or an unknown one on an agent endpoint |
| `bad_token` | 403 | The token in the body does not match the slot (live slots only; a terminal slot answers `gone`) |
| `origin_not_allowed` | 403 | The request carried an `Origin` header that is not in `BURNDROP_PAGE_ORIGINS`; nothing else is processed |
| `not_found` | 404 | Unknown `drop_id`, a drop id used on a reveal endpoint or the reverse, or a tombstone that has been swept |
| `not_uploaded` | 404 | `fetch` before the human uploaded; `state` is `created` |
| `already_uploaded` | 409 | `upload` on a slot that is already `uploaded` |
| `gone` | 410 | The slot is terminal: `fetched`, `opened`, `revoked`, or `expired` |
| `too_large` | 413 | Ciphertext or request body over `MAX_CIPHERTEXT_BYTES` |
| `unsupported_media_type` | 415 | `Content-Type` is not `application/json` |
| `commitment_mismatch` | 422 | The commitment sent with the upload differs from the one the agent registered; `detail` is `the public key in this link does not match the key the agent registered` |
| `rate_limited` | 429 | A token bucket is empty; see below. `Retry-After` is `1` (global) or `10` (per client or per key) |
| `internal_error` | 500 | Random source failure, an unexpected store error, or a panic |
| `store_full` | 503 | `MAX_LIVE_DROPS` or `MAX_TOTAL_BYTES` reached; `Retry-After: 30` |
| `too_many_waiters` | 503 | `MAX_WAITERS` long polls already in flight; `Retry-After: 5` |

Two responses are not JSON: the `405` for a wrong method, and the `503` text `The drop page is not built into this relay. Use the CLI or the browser extension, or rebuild the relay with the page.` when `/drop` is requested from a relay built without the page.

### Rate limits

Three token buckets, all configurable (see [self-hosting.md](self-hosting.md)):

| Bucket | Keyed by | Rate | Burst | Applies to |
|---|---|---|---|---|
| Global | the whole relay | `RATE_GLOBAL_PER_SEC`, default 500 per second | twice the rate | every request, including `/healthz` and the page |
| Page | client IP | `RATE_PAGE_PER_MIN`, default 60 per minute | `rate / 3 + 1`, so 21 | `upload`, `open`, `status`, `revoke` |
| Agent | agent key id | `RATE_AGENT_PER_MIN`, default 30 per minute | `rate / 3 + 1`, so 11 | `drops`, `drops/fetch`, `reveals` |

The client IP is the socket peer, unless the peer is inside `BURNDROP_TRUSTED_PROXIES`, in which case the rightmost `X-Forwarded-For` entry that is not itself a trusted proxy is used. Idle buckets are forgotten after ten minutes. There is no lockout after bad tokens (threat model T7): tokens have 128 bits of entropy, so the rate limit is the only brake needed.

### CORS

Only requests that carry an `Origin` header are affected; agents and curl never do. On `/api/` paths the origin must match (case-insensitively) one of `BURNDROP_PAGE_ORIGINS`, which defaults to `BURNDROP_PUBLIC_ORIGIN`, or be a browser extension origin: `chrome-extension://<id>` or `moz-extension://<id>` where `<id>` is 1 to 64 lowercase letters, digits, or dashes with nothing after it. Extension ids differ per browser and, in Firefox, per installation, so the bundled page of the browser extension could not be listed in advance; the origin list keeps foreign web pages out and is not an authentication boundary, since requests without an `Origin` header are served anyway. A match adds `Access-Control-Allow-Origin: <origin>`, `Access-Control-Allow-Methods: POST, GET, OPTIONS`, `Access-Control-Allow-Headers: Content-Type, X-Client, Authorization`, `Access-Control-Max-Age: 600`, and `Vary: Origin`; credentials are never allowed. Any other origin gets `403 origin_not_allowed` before the handler runs. `OPTIONS /api/v1/<anything>` answers `204` for allowed origins.

## Endpoints

### POST /api/v1/drops

Agent. Bearer key. Reserves a slot for a human to upload into.

| Request field | Type | Constraints |
|---|---|---|
| `ttl_seconds` | integer | Optional; clamped as described above |
| `commitment` | string | Required; base64url SHA-256 of the agent's per-request X25519 public key (43 characters) |

Response `201`:

```json
{"drop_id":"61jCwZl3_2GSkD6n7WvDQw","upload_token":"cTHdO2-SUOK9lEdeNN4oqQ","fetch_token":"-JpbUaTc8QRqqhqdszPSzw","expires_at":"2026-09-17T12:10:15Z"}
```

The agent puts `drop_id` and `upload_token` in the link and keeps `fetch_token` for itself. Errors: `400` (`detail`: `commitment must be the base64url SHA-256 of the recipient public key`), `401`, `429`, `503 store_full`, `500`.

### POST /api/v1/drops/upload

Page or `burndrop drop`. Upload token. Stores the sealed envelope and consumes the token.

| Request field | Type | Constraints |
|---|---|---|
| `drop_id` | string | 22 base64url characters |
| `upload_token` | string | 22 base64url characters |
| `commitment` | string | SHA-256 of the public key taken from the link; must equal the registered one |
| `ciphertext` | string | base64url sealed box; at least 304 bytes decoded (48 bytes of sealed-box overhead plus one 256-byte padding block), at most `MAX_CIPHERTEXT_BYTES` (65840 by default) |

Response `200 {"state":"uploaded"}`. Errors: `400`, `403 bad_token`, `404 not_found`, `409 already_uploaded`, `410 gone` (fetched, revoked, or expired), `413 too_large`, `422 commitment_mismatch`, `429`, `503 store_full` (the total byte cap). A replay with the correct token after a successful upload is reported as `already_uploaded` rather than `bad_token`.

### POST /api/v1/drops/status

Anyone who knows the id. No token.

| Request field | Type | Constraints |
|---|---|---|
| `drop_id` | string | 22 base64url characters |
| `wait_seconds` | integer | Optional; 0 to 30. Above 30 is `400 bad_request` (`wait_seconds must be between 0 and 30`) |
| `wait_while` | string | Optional; a state name. The relay only waits while the slot is in this state |

Response `200`:

```json
{"state":"uploaded","kind":"drop","created_at":"2026-09-17T12:00:15Z","expires_at":"2026-09-17T13:00:15Z","uploaded_at":"2026-09-17T12:03:40Z"}
```

`uploaded_at`, `fetched_at`, and `revoked_at` appear once set. A reveal id on this path answers `404 not_found`. Other errors: `400`, `429`, `503 too_many_waiters`.

### POST /api/v1/drops/fetch

Agent. Bearer key plus fetch token. Returns the ciphertext and deletes it in the same atomic step; the slot becomes a `fetched` tombstone.

| Request field | Type |
|---|---|
| `drop_id` | string |
| `fetch_token` | string |

Response `200 {"ciphertext":"<base64url>","uploaded_at":"2026-09-17T12:03:40Z"}`. Errors: `401`, `400`, `403 bad_token`, `404 not_found`, `404 not_uploaded` with `{"state":"created","at":"<created_at>"}` while the human has not uploaded, `410 gone` with `state` `fetched`, `revoked`, or `expired`, `429`. Only the first call with the right token succeeds; a second call answers `gone` with `state: fetched`, which is how an agent learns that someone else fetched first.

### POST /api/v1/drops/revoke

Page or agent. Either the upload token or the fetch token is accepted, so both sides can cancel.

| Request field | Type |
|---|---|
| `drop_id` | string |
| `token` | string |

Response `200 {"state":"revoked"}`. Errors: `400`, `403 bad_token`, `404 not_found`, `410 gone` when the slot is already terminal, `429`. Revoking an `uploaded` slot destroys the ciphertext.

### POST /api/v1/reveals

Agent. Bearer key. Stores an encrypted reveal for a human to open once.

| Request field | Type | Constraints |
|---|---|---|
| `ttl_seconds` | integer | Optional; clamped |
| `ciphertext` | string | base64url XChaCha20-Poly1305 blob; at least 296 bytes decoded (24-byte nonce, 16-byte tag, one padding block), at most `MAX_CIPHERTEXT_BYTES` |

Response `201`:

```json
{"drop_id":"3A6o-jeb0SGuZgLoI1kURg","reveal_token":"KsKizzOC53EcGn_CC12EWQ","revoke_token":"rhjBL5fSICJyvxzf1IqP7w","expires_at":"2026-09-17T13:02:00Z"}
```

Errors: `400`, `401`, `413 too_large`, `429`, `503 store_full`.

### POST /api/v1/reveals/open

Page or `burndrop open`. Reveal token. Returns the ciphertext and deletes it atomically; the slot becomes `opened`.

| Request field | Type |
|---|---|
| `drop_id` | string |
| `reveal_token` | string |

Response `200 {"ciphertext":"<base64url>","created_at":"2026-09-17T12:02:00Z"}`. Errors: `400`, `403 bad_token`, `404 not_found`, `410 gone` with `state` `opened` (and `at`, the time it was opened), `revoked`, or `expired`, `429`.

### POST /api/v1/reveals/status

Same request and response as `drops/status`, with `kind` `reveal` and `opened_at` instead of `fetched_at`. A drop id here answers `404 not_found`.

### POST /api/v1/reveals/revoke

Same as `drops/revoke`; `token` may be the reveal token or the revoke token. An unopened reveal is destroyed.

### GET /api/v1/info

No headers required. Describes the relay so clients can configure themselves:

```json
{"version":"v0.1.0","api":"v1","default_ttl_seconds":3600,"max_ttl_seconds":86400,"max_ciphertext_bytes":65840,"long_poll_max_seconds":30,"agent_auth":"required","page_served":true,"page_version":"v0.1.0","page_sha256":"<hex>"}
```

| Field | Meaning |
|---|---|
| `version` | Relay build version (`dev` for local builds) |
| `api` | Always `v1` |
| `default_ttl_seconds`, `max_ttl_seconds` | The configured TTL default and cap |
| `max_ciphertext_bytes` | The largest accepted ciphertext |
| `long_poll_max_seconds` | Always 30 |
| `agent_auth` | `required` or `off` |
| `page_served` | Whether this relay serves the drop page |
| `page_version`, `page_sha256` | Version and hex SHA-256 of the embedded page; empty strings when no page is built in |

### GET /healthz

Returns `200` with the text body `ok`. It does not touch the store. `burndrop-relay healthcheck` calls it for container probes.

### GET /, /drop, /reveal

Served when `BURNDROP_SERVE_PAGE=true` (the default). The response is the single-file page with `Content-Security-Policy` pinning the script and style hashes, `X-Frame-Options: DENY`, `X-Drop-Page-Version`, and `X-Drop-Page-SHA256` (the hex hash `burndrop verify-page` compares). `HEAD` returns the headers only. The link fragment after `#` is never sent to the relay.

## States

| Kind | State | Entered by | Next states |
|---|---|---|---|
| drop | `created` | `POST /drops` | `uploaded`, `revoked`, `expired` |
| drop | `uploaded` | `upload` | `fetched`, `revoked`, `expired` |
| drop | `fetched` | `fetch` | terminal |
| reveal | `created` | `POST /reveals` | `opened`, `revoked`, `expired` |
| reveal | `opened` | `open` | terminal |
| both | `revoked` | `revoke` | terminal |
| both | `expired` | the TTL passing | terminal |

Expiry is applied lazily on every access and by a sweeper that runs every 10 seconds, so a slot past its `expires_at` answers as `expired` even if the sweeper has not run yet. A terminal slot keeps a tombstone (id, kind, state, timestamps; no ciphertext, no token hashes) for 24 hours after its original `expires_at`, so both sides can render the distinct final state; after that it answers `not_found`.

## Long polling

`status` with `wait_seconds` above 0 holds the request until the state changes, the wait elapses, or the client disconnects, then returns the current status with `200`. It returns immediately when the slot is already terminal or when `wait_while` is set and does not equal the current state. Agents wait with `wait_while: "created"` to learn that an upload arrived; the page waits with `wait_while: "uploaded"` to show `Delivered`. With the memory store the wake-up is immediate; with the redis store the relay re-reads the slot every 200 milliseconds. At most `BURNDROP_MAX_WAITERS` (1000) polls may be in flight, after which the relay answers `503 too_many_waiters`. The HTTP server's write timeout is 45 seconds (30 plus 15), and the Go client uses the same 45-second request timeout; a reverse proxy in between must allow at least that.

The Go client's loop is the reference behavior: poll with `wait_seconds` 30 (or the remaining time, whichever is less) until a deadline; on a `5xx` or `rate_limited` answer back off `n` seconds after the `n`th consecutive failure and give up after five; return the first status whose state differs from the one waited on.

## Examples

Create a drop (the commitment is the base64url SHA-256 of a public key; the example value is a placeholder):

```bash
curl -s https://relay.example/api/v1/drops \
  -H 'Content-Type: application/json' -H 'X-Client: curl/1' \
  -H 'Authorization: Bearer <agent key>' \
  -d '{"ttl_seconds":1800,"commitment":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"}'
```

Wait up to 30 seconds for the upload:

```bash
curl -s https://relay.example/api/v1/drops/status \
  -H 'Content-Type: application/json' -H 'X-Client: curl/1' \
  -d '{"drop_id":"61jCwZl3_2GSkD6n7WvDQw","wait_seconds":30,"wait_while":"created"}'
```

Fetch and delete the ciphertext:

```bash
curl -s https://relay.example/api/v1/drops/fetch \
  -H 'Content-Type: application/json' -H 'X-Client: curl/1' \
  -H 'Authorization: Bearer <agent key>' \
  -d '{"drop_id":"61jCwZl3_2GSkD6n7WvDQw","fetch_token":"-JpbUaTc8QRqqhqdszPSzw"}'
```

Read the relay description:

```bash
curl -s https://relay.example/api/v1/info
```

The ciphertext formats, the envelope inside them, and the link fragment that carries the keys are specified in [crypto-spec.md](crypto-spec.md). Operating the relay is covered in [self-hosting.md](self-hosting.md); the CLI that drives this API is in [cli.md](cli.md).
