# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog, and the project uses Semantic Versioning.

## [Unreleased]

### Added

- Zero-knowledge relay (`burndrop-relay`) with a memory store and an optional
  Redis or Valkey store, POST-only API, atomic fetch and delete, long polling,
  hashed tokens, per-client rate limits, strict security headers, and a
  Content-Security-Policy that pins the embedded drop page.
- Cryptography: libsodium sealed boxes for human to agent, XChaCha20-Poly1305
  with authenticated display fields for agent to human, ISO/IEC 7816-4 padding,
  64-bit key fingerprints, public key commitments, and shared test vectors
  (`spec/vectors.json`) checked in Go, TypeScript, and Python.
- Agent runtime and CLI (`burndrop`): `init` with backend detection, MCP server
  with eight tools, `request`, `fetch`, `send`, `run` with redaction and
  `capture_as`, `list`, `delete`, `pending`, `revoke`, `audit`,
  `reveal-password`, `verify-page`, `doctor`, `instructions`, and the
  human-side `drop` and `open` commands.
- Optional reveal password: `burndrop reveal-password set` stores a password
  in the OS credential store and makes every reveal link ask for it before
  the page shows the value (Argon2id and BLAKE2b, crypto specification
  section 4.1). The `reveal_password` MCP tool turns the requirement on or
  off from the conversation; the password itself never passes through the
  chat. The page, the CLI, both SDKs, and the interop files support it.
- Delivery guidance: instruction rule 2 and a `delivery` field on every
  `request_secret` and `send_secret` result tell the model, on every call,
  to hand a link only to the human it works for, over whatever channel they
  already use, and never anywhere shared. `revoke_request` and
  `burndrop revoke` also cancel an unopened reveal link; the agent keeps
  the revoke token of every sent link until it expires.
- Twelve storage backends: OS keychain, age vault, `.env` file, memory,
  1Password, Bitwarden, HashiCorp Vault, Infisical, Doppler, AWS Secrets
  Manager, Google Secret Manager, and Azure Key Vault.
- Single-file drop page with masked input, fingerprint display, countdown,
  light and dark themes, and full keyboard and screen reader support; unit
  tests against the vectors and Playwright coverage of every state.
- Browser extension (Chrome and Firefox, Manifest V3) that replaces the hosted
  page with a bundled copy and verifies hosted pages against the release hash.
- Python and TypeScript SDKs implementing the protocol natively, with
  cross-language interop files.
- Deployment guides for Docker Compose with Caddy, Tailscale Funnel,
  Cloudflare Tunnel, and nip.io or sslip.io, plus a distroless container image.
- Agent instruction files for Claude Code, Cursor, and `AGENTS.md` consumers.
