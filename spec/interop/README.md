# Cross-language interop harness

`spec/vectors.json` proves that each implementation can consume fixed
inputs. This directory closes the loop in the other direction: every
implementation encrypts with its own code and every other implementation
must be able to open the result. The exchange is file based so it needs no
process orchestration: a generator writes `<language>.json`, a checker
reads every `*.json` in this directory.

```text
spec/interop/
  README.md          this file: the schema and the checks
  python_gen.py      writes python.json     (run: cd sdk/python && uv run python ../../spec/interop/python_gen.py)
  python_check.py    verifies every *.json  (run: cd sdk/python && uv run python ../../spec/interop/python_check.py)
  python.json        produced by the Python SDK
  typescript_gen.ts  writes typescript.json (run: cd sdk/typescript && npm run interop:gen)
  typescript_check.ts verifies every *.json (run: cd sdk/typescript && npm run interop:check)
  typescript.json    produced by the TypeScript SDK
  go.json            produced by the Go implementation (to be added)
```

Current state: the Python and TypeScript checkers each pass both
`python.json` and `typescript.json` (12 cases, and both encoders produce
byte-identical envelope JSON, so no re-encoding notes are printed).

A CI job runs every generator, then every checker. A checker exits with a
non-zero status when any file fails and prints one line per case.

## Schema (version 1)

All binary fields are base64url without padding, the encoding used
everywhere in burndrop. Envelope objects are the plain JSON objects
defined in the specification section 5.5. Secrets are placeholders, never
real credentials.

```json
{
  "version": 1,
  "producer": "python",
  "library": "burndrop-python 0.1.0, PyNaCl 1.6.2",
  "generated_at": "2026-09-17T05:00:00Z",
  "drops": [
    {
      "name": "drop text",
      "recipient_public_key": "<32 bytes>",
      "recipient_secret_key": "<32 bytes>",
      "fingerprint": "7f4e-3996-5f9b-d725",
      "commitment": "<32 bytes: SHA-256 of the public key>",
      "sealed": "<libsodium sealed box of the padded envelope>",
      "plaintext": "<the envelope JSON exactly as the producer encoded it, before padding>",
      "envelope": { "v": 1, "type": "drop", "name": "...", "purpose": "...", "storage": "...",
                    "retention": "...", "fingerprint": "...", "format": "text", "secret": "..." },
      "secret": "<the raw secret bytes>"
    }
  ],
  "reveals": [
    {
      "name": "reveal text",
      "key": "<32 bytes>",
      "nonce": "<24 bytes>",
      "display_name": "staging-db-url",
      "keeps_copy": true,
      "aad": "<reveal_aad(display_name, keeps_copy)>",
      "blob": "<nonce || XChaCha20-Poly1305 ciphertext || tag>",
      "plaintext": "<the envelope JSON exactly as the producer encoded it, before padding>",
      "envelope": { "v": 1, "type": "reveal", "name": "staging-db-url", "format": "text", "secret": "..." },
      "secret": "<the raw secret bytes>"
    }
  ]
}
```

Field rules:

- `version` is the integer 1. A checker refuses any other value.
- `producer` is `go`, `typescript`, or `python`. `library` and
  `generated_at` are free text for humans.
- `name` identifies the case in reports. Producers should include at least
  one text secret, one secret with characters that JSON must escape, and
  one binary secret (which forces `"format": "base64"`).
- `plaintext` is the exact byte string the producer padded and encrypted:
  the envelope JSON. It lets a checker verify padding and decoding
  separately from decryption. Consumers only need to parse it as JSON;
  producing byte-identical JSON is not required by the specification.
- `envelope` is the envelope as an object. Optional drop fields that are
  empty may be omitted. `secret` is the raw value the envelope carries,
  base64url encoded here so binary values survive the file.
- For drops, `fingerprint` and `commitment` are derived from
  `recipient_public_key`, and `envelope.fingerprint` must equal
  `fingerprint`. The secret key is included so checkers can open the box;
  it is generated for the file and has no other use.
- For reveals, `display_name` and `keeps_copy` are the link fields the
  additional data is built from; `aad` must equal
  `"burndrop/reveal/v1\n" + display_name + "\n" + ("1" or "0")`.
  `blob[0:24]` must equal `nonce`.

## What a checker verifies

For every file, every drop:

1. `recipient_public_key` equals the public key derived from
   `recipient_secret_key` (X25519 base point multiplication).
2. `fingerprint` and `commitment` equal the checker's own computation on
   the public key.
3. Opening `sealed` with the keypair succeeds; unpadding with block 256
   yields exactly `plaintext`.
4. Decoding `plaintext` with the checker's strict envelope parser succeeds
   and equals `envelope` field by field; its `type` is `drop` and its
   `fingerprint` equals `fingerprint`.
5. The decoded secret bytes equal `secret`.

For every reveal:

1. `aad` equals the checker's `reveal_aad(display_name, keeps_copy)`.
2. `blob[0:24]` equals `nonce`.
3. Decrypting `blob` with `key` and `aad` succeeds; unpadding yields
   exactly `plaintext`.
4. Decoding `plaintext` succeeds and equals `envelope`; its `type` is
   `reveal`; the secret bytes equal `secret`.
5. Decrypting with `keeps_copy` flipped in the additional data fails
   (proves the display fields are authenticated).

A checker may additionally report, without failing, whether re-encoding
the decoded envelope reproduces `plaintext` byte for byte. The Go and
Python implementations do; it is informational for TypeScript.

## A tolerated legacy layout

`python_check.py` also accepts a smaller single-case document, an early
draft layout: a `sealed` object (`public_key`, `private_key`, `ciphertext`,
`plaintext_envelope`) and an `aead` object (`key`, `aad` as text rather
than base64url, `ciphertext`, `plaintext_envelope`). It maps such a
document onto the checks above and skips the checks whose inputs it lacks.
New producers should use the schema above; nothing in this directory uses
the legacy layout any more.

## Adding an implementation

Write `<language>_gen` and `<language>_check` next to the existing scripts,
following the schema above, and wire both into the CI interop job. The
checker must read every `*.json` in this directory, including the file its
own generator wrote (a self check), and must not assume a fixed number of
cases.
