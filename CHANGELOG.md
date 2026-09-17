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
  with seven tools, `request`, `fetch`, `send`, `run` with redaction and
  `capture_as`, `list`, `delete`, `pending`, `revoke`, `audit`, `verify-page`,
  `doctor`, `instructions`, and the human-side `drop` and `open` commands.
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
