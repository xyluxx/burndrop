# Security policy

burndrop exists to move secrets safely, so security reports get the fastest
attention this project can give.

## Reporting a vulnerability

Please do not open a public issue for anything that could be a vulnerability.

Use GitHub's private vulnerability reporting: open the repository's
**Security** tab and choose **Report a vulnerability**. Include what you
found, how to reproduce it, the version or commit, and what you think the
impact is. You will get an acknowledgement within 72 hours and a status
update at least every two weeks until the report is resolved.

If GitHub private reporting is unavailable to you, open a public issue that
says only "security report, please contact me" and a maintainer will reach
out through GitHub.

## What counts

Anything that lets a party other than the intended human and the intended
agent learn a secret, or lets someone alter what the human sees without the
agent noticing, is in scope. Examples:

- A way to obtain plaintext or keys on the relay, in logs, or in transit.
- A way to open a reveal or fetch a drop twice, or without the token.
- A way to make a link with a substituted key pass the fingerprint or
  commitment checks.
- A drop page that reads the fragment into a URL, a request, or storage.
- A secret value reaching the model through any MCP tool result.
- A storage backend writing a value somewhere readable by other users.
- A bypass of the Content-Security-Policy or the page hash verification.

Out of scope: denial of service through request volume (rate limits are
tunable and documented), findings that require a compromised agent host, and
reports about third party services (Tailscale, Cloudflare, secret managers)
themselves.

## Supported versions

The latest minor release receives fixes. Older releases should upgrade;
there is no data to migrate because nothing is persisted.

## How releases are protected

Releases are built by GitHub Actions from a tag, signed with Sigstore
(cosign, keyless), attested with GitHub artifact attestations, and shipped
with an SBOM and a checksums file. The drop page hash is published in every
release. See `docs/release-verification.md` for how to verify all of it.

## Design references

- `docs/threat-model.md`: assets, adversaries, mitigations, and what is
  deliberately not defended.
- `docs/crypto-spec.md`: every primitive, encoding, and byte order.
- `docs/architecture.md`: where trust lives.
