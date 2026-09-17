# Cryptography specification

This document is the normative description of every cryptographic operation
in burndrop, written so that a reviewer can check each implementation line
by line. Three implementations exist and must agree byte for byte:
`internal/crypto` (Go), `web/src/crypto.ts` (the drop page, also used by the
extension), and the SDKs under `sdk/`. `spec/vectors.json` is the shared
proof; every section below names the vector set that covers it.

Nothing here is novel. The primitives are libsodium's, used as documented,
with no custom construction.

## 1. Primitives

| Purpose | Primitive | Go | Browser and TypeScript | Python |
| --- | --- | --- | --- | --- |
| Human to agent | libsodium sealed box: X25519 ephemeral key agreement, XSalsa20-Poly1305, nonce = BLAKE2b-24(ephemeral pk, recipient pk) | `golang.org/x/crypto/nacl/box` `SealAnonymous`, `OpenAnonymous` | `crypto_box_seal`, `crypto_box_seal_open` | `nacl.public.SealedBox` |
| Agent to human | XChaCha20-Poly1305 (IETF): 256-bit key, 192-bit nonce, 128-bit tag, with additional data | `golang.org/x/crypto/chacha20poly1305` `NewX` | `crypto_aead_xchacha20poly1305_ietf_encrypt` and `_decrypt` | `nacl.bindings.crypto_aead_xchacha20poly1305_ietf_*` |
| Fingerprints, commitments, token hashes | SHA-256 | `crypto/sha256` | WebCrypto `digest` | `hashlib` |
| Randomness | Operating system CSPRNG | `crypto/rand` | `randombytes_buf` | `os.urandom` through PyNaCl |
| Padding | ISO/IEC 7816-4: append `0x80`, then `0x00` bytes to the next multiple of the block; block 256 bytes | own code | own code | own code |
| Encoding | base64url without padding, strict (RFC 4648 section 5, canonical trailing bits) | `base64.RawURLEncoding.Strict()` | own code | own code |

The relay uses only SHA-256 and the CSPRNG. No other primitive appears
anywhere in the project.

Vectors: `sealed_box`, `xchacha20poly1305`, `padding`, `fingerprint`.

## 2. Identifiers, tokens, keys

| Item | Bytes | Encoded | Notes |
| --- | --- | --- | --- |
| Drop id | 16 random | 22 characters | Chosen by the relay |
| Upload, fetch, reveal, revoke tokens | 16 random each | 22 characters | The relay stores `SHA-256(token)` and compares in constant time |
| Agent API key | 32 random | 43 characters | Bearer token; the relay stores `id:sha256:<base64url hash>` |
| X25519 keys | 32 | 43 characters | One recipient key pair per request |
| Reveal key | 32 random | 43 characters | One per reveal |
| Nonce | 24 random | inside the blob | Never reused: one key per reveal, one nonce per key |

Strict decoding: an encoded value is rejected if it contains padding, a
character outside the base64url alphabet, or non-zero trailing bits. A
token is valid only when it is exactly 22 characters that decode to 16
bytes. Vectors: `tokens` (includes the non-canonical and wrong-length cases).

## 3. Drop: human to agent

1. The agent generates an X25519 key pair `(pk, sk)` for this request only.
2. The agent computes `commitment = base64url(SHA-256(pk))` (43 characters) and creates a slot on the relay with it and a TTL. The relay returns the drop id, the upload token, and the fetch token.
3. The agent builds the drop link (section 6) carrying `pk`, the drop id, the upload token, and the display metadata: name, purpose, storage, retention.
4. The agent computes `fingerprint = hex(SHA-256(pk)[0:8])` formatted as `xxxx-xxxx-xxxx-xxxx` and gives it to the human next to the link, through the chat.
5. The page parses the fragment, removes it from the address bar with `history.replaceState` before any request, computes the fingerprint from `pk`, and shows it with the metadata. The human compares the two fingerprints.
6. On submit the page builds the drop envelope (section 5), pads it to a multiple of 256 bytes, and seals it: `ct = crypto_box_seal(padded, pk)`. `ct` is `ephemeral_pk (32) || XSalsa20-Poly1305 box (len + 16)`.
7. The page uploads `{drop_id, upload_token, commitment, ciphertext = base64url(ct)}` with `commitment` recomputed from `pk` in the link.
8. The relay checks the token hash, checks that the commitment equals the one registered at creation, stores the ciphertext, marks the slot `uploaded`, and consumes the upload token.
9. The agent long-polls the status, then fetches with the fetch token. The relay returns the ciphertext and deletes it in the same operation, leaving a tombstone in state `fetched`.
10. The agent opens the sealed box with `(pk, sk)`, unpads, decodes the envelope, and verifies that `type`, `name`, `purpose`, `storage`, `retention`, and `fingerprint` inside equal what it put in the link. It stores the value in the backend, zeroes `sk` and the value, and returns only the name and metadata to the model.

Why the commitment: substituting `pk` in the link (say, in the chat) is
detected by the fingerprint comparison, and even a human who skips that
comparison is protected because the relay refuses an upload whose
commitment does not match the key the agent registered. Defeating both
needs the chat channel and the relay to be compromised together.

Forward secrecy: after step 10 neither `sk` nor the ciphertext exists.
Compromising the agent later reveals nothing about the drop, and the relay
never had `sk`.

## 4. Reveal: agent to human

1. The agent reads the value from the storage backend.
2. The agent generates `key` (32 random bytes) and `nonce` (24 random bytes).
3. It builds the reveal envelope, pads it, and encrypts with additional data: `ct = xchacha20poly1305_ietf_encrypt(padded, aad, nonce, key)`, `blob = nonce || ct` (the tag is the last 16 bytes of `ct`).
4. It creates a reveal slot with `ciphertext = base64url(blob)` and a TTL. The relay assigns the drop id and returns it with the reveal token and the revoke token.
5. It builds the reveal link carrying the drop id, the reveal token, `key`, the name, and the keeps-a-copy flag.
6. The page parses the fragment, removes it from the address bar, shows the name and the flag, and waits for the click. Loading the page changes nothing on the relay.
7. On click the page posts `{drop_id, reveal_token}`. The relay returns the ciphertext and deletes it atomically, leaving a tombstone in state `opened` with the time.
8. The page rebuilds `aad` from the display fields in the link, decrypts, unpads, decodes the envelope, checks that `type` is `reveal` and `name` matches the link, and shows the value as inert text.

`aad` is the UTF-8 string:

```
"burndrop/reveal/v1" + "\n" + name + "\n" + ("1" if the agent keeps a copy else "0")
```

Altering the name or the flag in the link makes decryption fail. The drop
id is not part of `aad` because the relay assigns it after the ciphertext
exists; swapping ciphertexts between reveals is already impossible because
every reveal has its own random key. Vectors: `reveal_aad`,
`xchacha20poly1305`.

## 5. Envelope

The plaintext of both directions is one UTF-8 JSON document with the
fields in this order and no whitespace, then padded:

```
{"v":1,"type":"drop","name":"openai-api-key","purpose":"Call the API from the billing script","storage":"macOS Keychain","retention":"until-revoked","fingerprint":"7f4e-3996-5f9b-d725","format":"text","secret":"sk-live-..."}
{"v":1,"type":"reveal","name":"staging-db-url","format":"text","secret":"postgres://..."}
```

Encoding rules, identical in all implementations so that the same envelope
produces the same bytes:

- Field order: `v`, `type`, `name`, `purpose`, `storage`, `retention`, `fingerprint`, `format`, `secret`. Empty optional fields are omitted.
- No HTML escaping (`<`, `>`, `&` appear literally). `U+2028` and `U+2029` are written as ` ` and ` `. Control characters below `U+0020` are `\uXXXX` except `\n`, `\r`, `\t`, which use the short forms; `"` and `\` are escaped. This is Go's encoder with HTML escaping off; the TypeScript and Python encoders reproduce it.
- `format` is `text` (the secret is the UTF-8 string) or `base64` (the secret is base64url of the raw bytes). A value is stored as `text` when it is valid UTF-8 with no control character other than tab, newline, and carriage return; otherwise `base64`.

Validation, applied when encoding and when decoding (decoding also
rejects unknown fields, non-string fields, and trailing data):

| Field | Rule |
| --- | --- |
| `v` | the number `1` |
| `type` | `drop` or `reveal` |
| `name` | 1 to 100 characters (code points), no control characters, no leading or trailing whitespace |
| `purpose`, `storage` | at most 200 characters, no control characters except newline |
| `retention` | drop only: `session`, `until-revoked`, or `until:` followed by an RFC 3339 timestamp with a valid calendar date; must be empty for reveal |
| `fingerprint` | drop only: `^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$`; must be empty for reveal |
| `format` | `text` or `base64` |
| `secret` | valid base64url when `format` is `base64`; valid UTF-8 (no lone surrogates) when `text` |
| size | the encoded document is at most 65,536 bytes before padding |

Vectors: `envelope` (valid and invalid documents), and the `sealed_box`
vectors include the exact encoded bytes.

## 6. Link format

Everything after `#`. Fragments never leave the browser. Fields are
`key=value` pairs joined by `&`; values are percent-encoded (`+` decodes as
a space); binary values are base64url.

```
https://<page-host>/drop#v=1&i=<drop_id>&u=<upload_token>&k=<recipient_pk>&n=<name>&p=<purpose>&s=<storage>&t=<retention>[&r=<relay_origin>]
https://<page-host>/reveal#v=1&i=<drop_id>&o=<reveal_token>&k=<key>&n=<name>&c=<0|1>[&r=<relay_origin>]
```

Parsing rules (the Go, TypeScript, and Python parsers are equivalent and
share the test cases in `internal/link/link_test.go` and `web/test/link.test.ts`):

- The whole link is at most 8,192 characters, has no query string and no userinfo, and its path is `/drop` or `/reveal` (a trailing slash is ignored).
- `v` must be `1`. There is no fallback parsing for other versions.
- Unknown fields, duplicate fields, and malformed pairs are rejected. Required fields: `i`, `u`, `k`, `n`, `t` for drops; `i`, `o`, `k`, `n`, `c` for reveals.
- `k` must be 43 characters decoding to 32 bytes. `i`, `u`, `o` must be valid tokens (section 2).
- `n`, `p`, `s`, `t` follow the envelope rules of section 5. `c` is `0` or `1`.
- `r`, when present, is normalized: lowercase scheme and host, default ports removed, `https` only except `http` for `localhost`, `127.0.0.1`, and `[::1]`. The hosted page accepts `r` only when it equals the page's own origin; the browser extension and the CLI use it directly and default to the link's origin when it is absent.

A drop link is about 250 characters plus the metadata text.

## 7. Key and value lifecycle on the agent

- `sk` for a request is created by `request_secret` and stored, with the fetch token and the metadata, as a `pending` record in the configured storage backend, under the same protection as stored secrets and with a retention equal to the request's expiry. This is what lets `fetch_secret` work after the MCP server restarts and lets expired requests disappear on their own. `sk` is deleted and zeroed as soon as the drop is decrypted, revoked, or found expired.
- A reveal key exists only for the duration of `send_secret`; the link is the only place it lives afterwards.
- Values are held in memory only for the time needed to write them to the backend, or for the lifetime of the process under `session` retention.
- Zeroing is best effort in Go and JavaScript: buffers are overwritten, but the runtime may have made copies. This is stated rather than promised.

## 8. Test vectors

`spec/vectors.json` (version 1) contains:

| Section | Covers |
| --- | --- |
| `sealed_box` | recipient key pairs, sealed ciphertexts, the padded and unpadded plaintexts, four envelopes including unicode and binary |
| `xchacha20poly1305` | key, nonce, aad, padded plaintext, blob for two reveals |
| `padding` | eight boundary cases at block 256 |
| `fingerprint` | public keys with their fingerprint and commitment |
| `envelope` | six valid and six invalid documents |
| `reveal_aad` | name and flag to aad bytes |
| `tokens` | valid, non-canonical, wrong-length, wrong-alphabet, and empty tokens with their SHA-256 |

Every implementation loads the same file. `spec/interop/` adds files that
each language generates and every other language must open.

## 9. What is deliberately not done

No password-based encryption on drops: the key is random and strong, and a
password would add a weak factor and a phishing surface. No compression
before encryption. No key reuse across requests. No custom key derivation.
No signed tokens or JWTs: random tokens stored as hashes are simpler and
cannot be forged. No encryption at the relay: it has nothing to encrypt
with and nothing to protect that is not already ciphertext.
