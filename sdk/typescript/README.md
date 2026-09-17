# burndrop (TypeScript SDK)

One-time, end-to-end encrypted secret exchange between humans and AI agents
through a zero-knowledge relay. This package implements the protocol natively
(libsodium crypto, link format, relay client, agent flows) so a Node program
can run without the Go binary.

- Human to agent: the agent asks for a secret and gets a one-time link. The
  human opens it, the browser seals the value to the agent's per-request
  X25519 key, and the relay only ever holds ciphertext it cannot read.
- Agent to human: the agent encrypts a value with XChaCha20-Poly1305 under a
  random key that travels only in the link fragment; the page opens it once.

The protocol, the cryptography, and the relay API are specified in
`docs/design.md` of the repository. The Go implementation is the reference;
this package matches it byte for byte where it matters (sealed boxes,
XChaCha20-Poly1305 blobs, padding, envelope JSON, link encoding) and is
checked against the shared vectors in `spec/vectors.json`.

## Install

```sh
npm install @burndrop/sdk
```

Requirements: Node 22.13 or newer (global `fetch`, WebCrypto, `AbortSignal.any`).
The only runtime dependency is `libsodium-wrappers-sumo` (pinned).

## Quick start

### Agent: ask a human for a secret

```ts
import { Agent } from "@burndrop/sdk";

const agent = new Agent({
  relay: "https://relay.example",
  apiKey: process.env.BURNDROP_API_KEY, // omit when the relay runs with agent auth off
});

const request = await agent.requestSecret("openai-api-key", "Call the OpenAI API from the billing script", {
  retention: "until-revoked",                 // what the human is promised
  storage: "the OS keychain on this machine", // where your program will keep it
  ttlSeconds: 1800,
});

// request.message contains the link, the fingerprint and every disclosure the
// human needs. Relay it verbatim (a model may see it: it contains no secret).
console.log(request.message);

// Wait for the human (up to 300 seconds per call; call again to keep waiting).
const result = await agent.fetchSecret(request, 120);
if (result.status === "received") {
  // result.value is a Uint8Array. It is for your program only.
  // Never place it in a language model's context; see Security notes.
  await agent.runWithSecret("node", ["bill.js"], { OPENAI_API_KEY: result.value });
} else {
  console.log(result.status, result.message); // waiting, expired, revoked, rejected, gone
}
```

### Agent: hand a secret to a human

```ts
const sent = await agent.sendSecret("staging-db-url", "postgres://app:s3cret@db.staging.example:5432/app", {
  ttlSeconds: 600,
  keepsCopy: false, // tell the human the truth about your own copy
  // password: "...", // the page then asks for this password before showing the value
});
console.log(sent.message); // link, "opens once", expiry, copy note

// Optional: learn when it was opened, or take it back.
const status = await agent.client.waitForOpen(sent.requestId, Date.now() + 60_000);
await agent.revoke(sent);
```

### Run a command with secrets, get redacted output back

```ts
import { runWithSecret } from "@burndrop/sdk";

const out = await runWithSecret("aws", ["sts", "get-caller-identity"], {
  AWS_ACCESS_KEY_ID: accessKey,      // Uint8Array or string
  AWS_SECRET_ACCESS_KEY: secretKey,
});
console.log(out.exitCode, out.stdout); // values appear as [redacted:AWS_SECRET_ACCESS_KEY]
```

Every injected value, plus its base64 (standard and url-safe, padded and not),
hex, URL-escaped, path-escaped, JSON-escaped, and trimmed forms, is replaced
in stdout and stderr. `Agent.runWithSecret` also redacts every value the agent
has received or sent.

### Human side without a browser

```ts
import { human } from "@burndrop/sdk";

// What the drop page does: check the link, seal the value to the key in the
// link, upload it with the key's commitment.
await human.submit(dropLink, "sk-live-...");

// What the reveal page does: open once, decrypt with the key in the link and
// the display fields as additional data.
const { value, name } = await human.open(revealLink);
// Links that carry a salt need the reveal password: human.open(link, { password: "..." })
```

### Relay client only

```ts
import { RelayClient } from "@burndrop/sdk";

const client = new RelayClient("https://relay.example", apiKey);
const info = await client.info();
const status = await client.dropStatus(dropId, 30, "created"); // long poll up to 30 s
```

### Crypto and links in the browser

`@burndrop/sdk/crypto` and `@burndrop/sdk/link` have no Node-only imports:

```ts
import { ready, seal, pad, encodeEnvelope, fingerprint } from "@burndrop/sdk/crypto";
import { parseLink } from "@burndrop/sdk/link";
```

## Security notes

- The value returned by `fetchSecret` (and by `human.open`) is for the calling
  program. Do not put it into a language model's context, a log, a tool result,
  or an error message. Use `runWithSecret` to give it to a subprocess and
  return only redacted output. `Agent.redact` and the `Redactor` class are a
  safety net for text that leaves the process; they are not a substitute for
  keeping values out of model-facing paths in the first place.
- Compare fingerprints. `requestSecret` returns the fingerprint of the
  per-request key; the page shows the fingerprint of the key in the link the
  human opened. The agent additionally rejects a submission whose envelope
  carries a different name, fingerprint, or retention than the request
  (`checkEnvelope`), and the relay rejects an upload whose key does not match
  the commitment registered at creation.
- Private keys and symmetric keys are zeroed after use (`zero`). This is best
  effort: JavaScript strings cannot be zeroed, and the runtime may hold other
  copies. Prefer `Uint8Array` values over strings for anything secret.
- Pending requests (private key, fetch token) live in the `Agent` instance's
  memory. If the process exits before `fetchSecret`, nobody can read the
  human's submission; it stays on the relay until it expires. Call `revoke`
  when you no longer want a link to work.
- `retention` and `storage` are statements to the human. The SDK does not
  enforce them; pass what your program actually does.
- `keepsCopy` on `sendSecret` is likewise a statement. Pass `false` only after
  you have deleted your copy.
- Always use `https://` relays. `http://` is accepted only for `localhost`,
  `127.0.0.1`, and `::1`, for local development.
- Keep the agent API key out of source and config files; read it from the
  environment or a keychain and pass it to the constructor.

## API

Everything is exported from `@burndrop/sdk`; the subpaths `@burndrop/sdk/crypto`,
`@burndrop/sdk/link`, `@burndrop/sdk/relay`, `@burndrop/sdk/agent`, and `@burndrop/sdk/human`
export the corresponding module only.

### Agent

| Member | Description |
|---|---|
| `new Agent(options)` | `relay` (origin) and optional `apiKey`, or a prepared `client`; `pageOrigin` (default: the relay), `clientName` (X-Client header), `fetch`, `timeoutMs`, `defaultTtlSeconds` (3600), `defaultRetention` (`until-revoked`), `defaultStorage`, `now`. |
| `requestSecret(name, purpose, options?)` | Creates a drop slot. Options: `retention`, `storage`, `ttlSeconds`, `signal`. Returns `{ requestId, link, fingerprint, expiresAt, storage, retention, name, purpose, message }`. |
| `fetchSecret(request, waitSeconds?, signal?)` | Waits up to `waitSeconds` (default 30, max 300) for the upload, then downloads, decrypts, and verifies. Returns `{ status, message, ... }` and, on `"received"`, `value` (Uint8Array), `format`, `sizeBytes`. Statuses: `waiting`, `received`, `expired`, `revoked`, `rejected`, `gone`. |
| `sendSecret(name, value, options?)` | Encrypts for a human. Options: `ttlSeconds`, `keepsCopy` (default true), `password` (the page then asks for it; specification section 4.1), `signal`. Returns `{ requestId, link, expiresAt, keepsCopy, passwordProtected, revokeToken, message }`. |
| `revoke(requestOrSendResult, signal?)` | Revokes a pending request (by id or result) or an unopened reveal (by `sendSecret` result). Returns the resulting relay state. |
| `pending()` | Outstanding requests without their keys. |
| `runWithSecret(command, args, secrets, options?)` | `runWithSecret` with the agent's redactor. |
| `redact(text)` | Replaces every value the agent has seen. |
| `client`, `pageOrigin`, `redactor` | The relay client, the page origin used in links, the redactor. |

Helpers: `checkEnvelope(envelope, request)`, `validateSecretName(name)`,
`validateRetentionPolicy(policy, now)`, `formatUtcMinute(date)`, `formatRfc3339(date)`.

### runWithSecret

`runWithSecret(command, args, secrets, options?)` spawns `command` with each
entry of `secrets` as an environment variable. Options: `cwd`, `stdin`,
`timeoutMs` (default 120000, max 3600000), `maxOutputBytes` (default 32768),
`redactor`, `discardOutput`, `baseEnv`. Returns
`{ exitCode, stdout, stderr, truncated, timedOut, durationMs }`.

`Redactor`: `add(name, value)`, `remove(name)`, `redact(text)`, `count`.

### human

| Function | Description |
|---|---|
| `submit(link, value, options?)` | Checks the drop link is still open, seals the value to its key with the fingerprint and display fields in the envelope, uploads with the key's commitment. Throws when the relay reports a commitment mismatch (altered link). Options: `relay` override, `clientName`, `fetch`, `timeoutMs`, `signal`. |
| `open(link, options?)` | Checks the reveal link is unopened, opens it (this deletes the relay copy), decrypts with the key and the display fields as additional data. A link with a salt needs `options.password`, which is derived before the relay is asked. Returns `{ name, value, format, keepsCopy, relay }`. |

Also exported as `submitDrop` and `openReveal` from the package root.

### RelayClient

`new RelayClient(origin, apiKey?, options?)` with `clientName`, `fetch`, `timeoutMs`.
Every call is a `POST` with JSON (identifiers only in bodies, never in URLs)
and the `X-Client` header; agent endpoints send `Authorization: Bearer`.

| Method | Relay endpoint |
|---|---|
| `createDrop(commitment, ttlSeconds?)` | `POST /api/v1/drops` |
| `upload(dropId, uploadToken, commitment, ciphertext)` | `POST /api/v1/drops/upload` |
| `dropStatus(dropId, waitSeconds?, waitWhile?)` | `POST /api/v1/drops/status` (long poll up to 30 s) |
| `waitForUpload(dropId, deadline)` | repeated long polls until the state leaves `created`; throws `DeadlineExceededError` (with `lastStatus`) |
| `fetch(dropId, fetchToken)` | `POST /api/v1/drops/fetch` (one time) |
| `revokeDrop(dropId, token)` | `POST /api/v1/drops/revoke` |
| `createReveal(ciphertext, ttlSeconds?)` | `POST /api/v1/reveals` |
| `open(dropId, revealToken)` | `POST /api/v1/reveals/open` (one time) |
| `revealStatus(dropId, waitSeconds?, waitWhile?)` | `POST /api/v1/reveals/status` |
| `waitForOpen(dropId, deadline)` | repeated long polls until the state leaves `created` |
| `revokeReveal(dropId, token)` | `POST /api/v1/reveals/revoke` |
| `info()` | `GET /api/v1/info` |

Errors: `RelayError` (`status`, `code`, `detail`, `state`, `at`) for error
responses, `RelayUnavailableError` for transport failures, timeouts, and
unreadable responses. Constants: `RelayCode`, `SlotState`, `MAX_WAIT_SECONDS`.

### crypto

| Function | Description |
|---|---|
| `ready()` | Resolves when libsodium is loaded (every function below awaits it itself). |
| `generateKeyPair()` | X25519 keypair `{ publicKey, privateKey }`. |
| `seal(publicKey, plaintext)` / `openSealed(publicKey, privateKey, sealed)` | libsodium sealed box. |
| `newSymmetricKey()` | 32 random bytes. |
| `encryptAead(key, plaintext, aad, { nonce? })` / `decryptAead(key, blob, aad)` | XChaCha20-Poly1305-IETF; blob is `nonce || ciphertext || tag`. |
| `pad(data, block?)` / `unpad(data, block?)` | ISO/IEC 7816-4 padding, block 256. |
| `sha256(data)`, `fingerprint(publicKey)`, `commitment(publicKey)` | WebCrypto SHA-256; `xxxx-xxxx-xxxx-xxxx` fingerprint; base64url commitment. |
| `sealEnvelope`, `openEnvelope`, `encryptEnvelope`, `decryptEnvelope` | Encode, pad, encrypt (and the reverse) with the size limits. |
| `encodeEnvelope(envelope)` / `decodeEnvelope(bytes)` / `validateEnvelope(envelope)` | Strict envelope JSON (unknown fields rejected, `v` must be 1, name and text rules, `text` or `base64` format, reveal envelopes carry no drop metadata). |
| `secretField(bytes)` / `secretBytes(envelope)` | Choose `text` or `base64`; get the raw bytes back. |
| `revealAad(name, keepsCopy)` | `"burndrop/reveal/v1\n" + name + "\n" + ("1" or "0")`. |
| `encodeBase64Url(bytes)` / `decodeBase64Url(text)` / `isBase64Url(text)` | base64url without padding; decoding rejects non-canonical input. |
| `constantTimeEqual(a, b)`, `zero(...buffers)`, `randomBytes(n)`, `publicKeyFromPrivate(privateKey)` | Helpers. |

Constants: `KEY_SIZE`, `NONCE_SIZE`, `TAG_SIZE`, `SEALED_OVERHEAD`,
`AEAD_OVERHEAD`, `PAD_BLOCK`, `MAX_PLAINTEXT`, `MAX_NAME_LEN`, `MAX_TEXT_LEN`.

### link

| Function | Description |
|---|---|
| `buildDropLink(drop, pageOrigin)` / `buildRevealLink(reveal, pageOrigin)` | Build `https://<page>/drop#v=1&i=...` and `.../reveal#v=1&i=...` (Go's `url.QueryEscape` encoding). |
| `parseLink(raw)` | Strict parse of either kind: `v` must be `1`, fixed token and key lengths, no unknown or duplicate fields, https only (http for localhost), default ports stripped. |
| `parseDropLink(raw)` / `parseRevealLink(raw)` | One kind, with the page origin. |
| `normalizeOrigin(origin)` | `scheme://host[:port]` in lowercase, or `LinkError`. |
| `relayOrigin(link, pageOrigin)` / `parsedRelayOrigin(parsed)` | The relay to talk to: the `r` field or the page origin. |
| `isValidToken(text)`, `queryEscape(text)`, `validateDropLink`, `validateRevealLink` | Helpers. |

Types: `DropLink`, `RevealLink`, `ParsedLink`, `Envelope`, `KeyPair`, `Status`,
`RelayInfo`, `RequestResult`, `FetchResult`, `SendResult`, `RunResult`.

Errors (all extend `BurndropError`): `EncodingError`, `CryptoError` (`code`:
`decrypt`, `padding`, `size`, `length`), `EnvelopeError`, `LinkError`,
`RelayError`, `RelayUnavailableError`, `DeadlineExceededError`,
`ValidationError`; `isRelayCode(err, code)`.

## Cross-language interop files

`spec/interop/README.md` defines the harness: each implementation writes a
`<language>.json` (version 1 schema with `drops` and `reveals` arrays, every
binary field base64url) with its own fresh keys, and each implementation's
checker opens every `*.json` in that directory, including its own. The
TypeScript pair is `spec/interop/typescript_gen.ts` and
`spec/interop/typescript_check.ts`, run with `tsx` (a dev dependency of this
package) against the SDK source. From `sdk/typescript` after `npm install`:

```sh
npm run interop:gen     # writes spec/interop/typescript.json (3 drops, 3 reveals)
npm run interop:check   # verifies every spec/interop/*.json; exit 1 on any failure
```

`npx tsx ../../spec/interop/typescript_check.ts <file>` checks one file. The
checker performs every check listed in that README: key derivation,
fingerprint and commitment, decryption, unpadding against `plaintext`,
strict envelope decoding against `envelope`, secret bytes, and, for reveals,
that a flipped `keeps_copy` no longer decrypts. Re-encoding an envelope
reproduces the producer's bytes for the Go and Python producers, which this
checker reports as a note when it does not.

## Development

```sh
npm install
npm run lint          # eslint with typescript-eslint (type-checked rules)
npm run typecheck     # tsc over src, tests, and the interop scripts
npm test              # vitest: vectors, unit tests, and the Go relay integration test
npm run test:coverage # same with V8 coverage
npm run build         # tsc to dist/ (ESM plus .d.ts)
```

The integration test builds `cmd/burndrop-relay` from the repository and
starts it on `127.0.0.1:8081` with `BURNDROP_AGENT_AUTH=off`; it is skipped
when no Go toolchain is found. `BURNDROP_TEST_PORT` changes the port and
`BURNDROP_SKIP_INTEGRATION=1` skips it.

## Differences from the Go implementation

The Go agent is an MCP server with a storage manager; this package is a
library for programs. Where the design document is silent the package follows
the Go code, with these deliberate exceptions:

1. No storage manager. `fetchSecret` returns the value to the caller with
   status `received` (Go stores it and reports `stored`). Pending requests are
   kept in memory only; Go persists them in the storage backend so they
   survive a restart. `runWithSecret` has no `capture_as`, `consume`, or
   `allowed_commands`; the program already holds the values.
2. Injected values are redacted as `[redacted:<ENV_VAR>]`; the Go agent uses
   the stored secret's name. Values received or sent through the `Agent` are
   redacted under their secret name, as in Go.
3. `storage` in `requestSecret` is a description string chosen by the caller
   (default "the agent's process memory only"); the Go agent derives it from
   the configured backend. Retention defaults to `until-revoked` as in Go.
4. Link and request lifetimes are given in seconds (`ttlSeconds`), not as Go
   duration strings.
5. Long polling rounds the remaining time up to whole seconds (Go rounds
   down), so a deadline is never spent in a burst of zero-second polls.
6. Origins are parsed by a small strict parser instead of `net/url`. It
   rejects a few malformed inputs that `net/url` tolerates: an empty port
   (`https://example.com:`), a second colon in the host, and an empty query
   string.
7. base64url decoding rejects embedded newlines; Go's decoder skips `\r` and
   `\n`. The relay never emits either.
8. `unpad` is implemented here with the Go rules (the input length must be a
   positive multiple of the block) instead of `sodium_unpad`, which accepts
   other lengths.
9. Envelope JSON is produced by a dedicated encoder that reproduces Go's
   `encoding/json` output byte for byte; a `v` that is not a JSON integer is
   rejected (Go rejects non-integers too, with its own message).
10. `createDrop` and `createReveal` treat a response without a valid
    `expires_at` as malformed (`RelayUnavailableError`); Go returns a zero time.
11. `runWithSecret` truncates output by UTF-16 units rather than bytes and
    reports a killed or timed-out child as exit code -1, as Go does for
    timeouts.

## License

Apache-2.0. See `LICENSE`.
