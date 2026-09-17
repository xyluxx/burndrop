# Prior art

What six existing tools do well, where each falls short for exchanging secrets with an AI agent, and what this project takes from them. Facts were checked on 2026-09-17 against the projects' repositories, documentation, and published audits; anything that could not be confirmed is marked unverified.

## Yopass

Go server plus a React SPA, Apache-2.0, about 3,100 stars, version 14.9.0 (August 2026). Ships as one binary or container but always needs Memcached or Redis. Since 14.0 a paid tier (OIDC, audit log, secret requests, webhooks) lives in the same repository behind a license key.

Crypto: the browser uses OpenPGP.js in symmetric mode (AES-256-GCM) with a 22-character random key (about 131 bits) carried in the URL fragment as `#/s/<id>/<key>`; a manual-key mode lets the key travel separately. No padding; TTL and the one-time flag are stored in clear.

One-time semantics: the burn happens on `GET /secret/{id}`. The server claims the secret with a delete and serves it only if the delete succeeded, so concurrent readers get one winner. After mail scanners burned links (issue 2154, 2024), the UI now calls a status endpoint first and shows a Reveal button. Scanners that also click the button still burn the secret (issue 3322, closed as by design in March 2026).

Programmatic: JSON API, bearer API tokens for machines (14.4), a CLI that creates and decrypts. The paid "Secret Requests" feature (14.2, June 2026) is the closest thing to our drop flow: the requester's browser generates an OpenPGP key pair, registers the public key, keeps the private key and a management token in localStorage, and shares a link with the fingerprint in the fragment; the responder's browser checks the fingerprint before encrypting. It is browser only (no CLI, no polling) and a fail-open bug in the fingerprint check shipped until 14.8.0.

Security record: no third-party audit found (unverified). A remote memory exhaustion fix in 14.7.0 (July 2026). No rate limiting; the SECURITY.md declares it out of scope.

Takeaways: fingerprint in the fragment and status-then-claim are the right ideas. For agents it falls short: requests are paid and browser bound, the private key sits in localStorage, the burn is a GET, there is no rate limiting, no requester authentication, and decrypted values land on stdout.

## PrivateBin

PHP pastebin forked from ZeroBin, zlib license, about 8,600 stars, version 2.0.6 (August 2026). Runs on any PHP host or the official container; storage is the filesystem by default, or SQL, S3, or Google Cloud Storage.

Crypto: WebCrypto with a random 32-byte key in the fragment (base58), PBKDF2-HMAC-SHA256 at 100,000 iterations over the key plus an optional password, AES-256-GCM, and zlib compression by default (the 2014 audit flagged the side channel). Cipher parameters are authenticated as additional data; expiry and the burn flag are in clear.

One-time semantics: the read is a GET with an `X-Requested-With` header; a burn-after-reading paste is read then deleted inside the request, with no visible compare-and-delete (concurrent behavior unverified). Since 1.7.0 (February 2024) burn links are marked `#-<key>` and require a confirmation click, prompted by chat previews and Safari prefetching.

Programmatic: a documented JSON API and more than a dozen third-party clients. Symmetric link model only; a program cannot publish a key and receive an encrypted reply.

Security record: a 2014 four-hour ZeroBin audit; six CVEs between 2022 and 2026, all in the HTML preview surface (SVG, filename, template, attachment XSS, and one LFI), none in the cipher path since 2018.

Takeaways: the best documented format and the cleanest burn UX (confirm before fetch). For agents: PHP stack, no asymmetric mode, destructive GET, create-side rate limiting only, and a large rendering surface that keeps producing XSS. Our reveal page renders values as inert text for exactly this reason.

## Bitwarden Send

A feature of Bitwarden (server C#/.NET under AGPL plus the Bitwarden license, clients TypeScript under GPL). Monthly releases. Self-hosting is a multi-container stack with MSSQL, or the single-container "Lite" edition; text Sends are free, file Sends need Premium.

Crypto: a 128-bit random seed expanded with HKDF-SHA256 to a 512-bit key for AES-256-CBC plus HMAC-SHA256; the key travels in the fragment. A password is authentication only (PBKDF2 hash verified by the server). Access is through a token from the identity service, then a POST to the access endpoint.

One-time semantics: not one-time by design; a "maximum access count" instead. The web client obtains the token and calls the access endpoint on page load, without a click, and the server increments the count with a read-modify-write that is not atomic. A text Send with count 1 is consumed by any renderer that loads the page; no official scanner guidance was found (unverified).

Programmatic: `bw send` and `bw receive <url>` in the CLI (receive needs no login), `bw serve` for a local REST API (no receive route). Symmetric only; no request mode.

Security record: annual third-party audits (Cure53 through 2025, an ETH Zurich cryptography review in 2025), SOC 2, ISO 27001; no Send-specific CVE found (unverified).

Takeaways: the most audited and the most scriptable receiver. For agents: an account is required to create, the stack is heavy, access is counted on page load with a racy counter, values print to stdout, and an agent cannot request a secret.

## age

A file encryption tool, format, and Go library by Filippo Valsorda. BSD-3-Clause, about 23,600 stars, version 1.3.2 (August 2026). Version 1.3.0 added post-quantum hybrid ML-KEM-768 recipients.

Format: a textual header with one stanza per recipient wrapping a random file key, authenticated with HMAC-SHA-256 under an HKDF-derived key; X25519 recipients use a fresh ephemeral key and HKDF-SHA-256, wrapping the file key with ChaCha20-Poly1305; scrypt recipients for passphrases; the payload is encrypted with STREAM over 64 KiB ChaCha20-Poly1305 chunks so truncation is detected. No signing, no compression.

Philosophy: small explicit keys, no configuration, composable. Implementations: Go (`filippo.io/age`), Rust (`rage`), TypeScript (`age-encryption` on npm, by the same author, using noble libraries and WebCrypto), Python bindings (`pyrage`). Plugins for YubiKey, Secure Enclave, and TPM speak a stdin/stdout protocol; since 1.3.0 native tag recipients let core age encrypt to those keys without the plugin.

Embedding: the Go library's `Recipient` and `Identity` interfaces let a vault implement an identity whose 32-byte seed lives in the OS keychain; multiple recipients allow an agent key plus a human recovery key. Files are write-once, so each update rewrites the vault.

Audits: no published report found, but about 25 commits in 1.3.2 credit Joe Doyle of Trail of Bits, so a review happened (unverified whether a report follows). A 2024 plugin-name flaw allowed arbitrary binary execution (GHSA-32gq-x56h-299c), fixed in 1.2.1.

Takeaways: this is the vault format for our `agevault` backend, embedded through the Go library with an identity held in the keychain, a passphrase, or a mounted file. age has no transport, no one-time semantics, and no relay, which is the gap this project fills.

## Mailvelope

An OpenPGP extension for webmail (Chrome and Firefox) on OpenPGP.js with an optional GnuPG backend. AGPL-3.0, about 1,800 stars, version 6.3.0 (June 2026), Manifest V3 since 6.0.0, about 100,000 Chrome users.

Isolation: the extension activates only on authorized domains; its editor, message view, and key dialogs are iframes served from the extension origin, so the webmail page can never read plaintext or keys. A user-chosen "security background" pattern drawn inside every dialog lets users spot page-drawn fakes (an inline variant was found spoofable in 2017; generated backgrounds were later made more distinct after an audit).

Trust model: standard OpenPGP fingerprints, verified out of band, plus the Mailvelope Key Server, which verifies email ownership before publishing a key. The client API exposes containers and booleans to the page, never plaintext or private keys.

Audits: ten since 2013 (Cure53 seven times, iSEC Partners, SEC Consult for the German BSI, and a 2025 Open Technology Fund audit that found a high clickjacking issue fixed in 6.1.0).

Takeaways: extension-owned UI for anything that shows a secret, an activation allowlist, and the lesson that audits of extension UI keep finding clickjacking and redressing bugs. For agents: PGP complexity, long-lived keys bound to email identities, no forward secrecy, no one-time messages, and no headless path.

## Meta Code Verify

MIT-licensed extension from Meta (about 180 stars), launched in March 2022 for WhatsApp Web with Cloudflare and later covering Facebook, Messenger, and Instagram web. Still maintained: 4.2.0 shipped in September 2026.

Mechanism: each release ships a manifest of SHA-256 hashes of every JavaScript and CSS file, and Meta publishes the root hash to Cloudflare. The extension hashes what the browser actually received, checks the leaves against the manifest, and compares the manifest's root with the value fetched independently from Cloudflare. Four statuses: Validated, Network Timed Out, Possible Risk Detected (another extension is interfering), Validation Failure (code differs from everyone else's).

Defends against code altered after release by a compromised server, insider, CDN, or a network attacker who defeated TLS. Does not defend against a compromised extension, store, or browser; relies on Cloudflare as a trusted witness with no public history; covers only listed resources; and gives consistency, not safety (malicious code shipped identically to everyone passes). The Chrome listing's 2.2 rating reflects years of false alarms from other extensions and CSP nonces.

Takeaways: publish a hash of every drop page release, let the extension and CLI compare what a host serves against the published value, make the manifest exhaustive (our page is one file, so one hash covers everything), separate "risk" from "failure", and show the verdict only in extension-owned UI.

## Comparison

| | Yopass | PrivateBin | Bitwarden Send | This project |
|---|---|---|---|---|
| Key transport | Fragment, or manual | Fragment, optional password | Fragment, password as auth | Fragment only; agent key per request |
| Encrypt to a program's public key | Paid, browser only | No | No | Yes, core flow, CLI and MCP |
| Burn request | GET, click to reveal | GET, click to confirm | POST on page load | POST on click; GET never mutates |
| Atomic single read | Yes | Unverified | No | Yes, under one lock or one Lua script |
| Identifiers in URL path | Yes | Yes | Yes | No, fragment and body only |
| Relay learns metadata | TTL, one-time flag, sizes | Expiry, burn flag, sizes | Names encrypted, counts | Coarse size class and timing only |
| Server dependencies | Memcached or Redis | None | MSSQL or SQLite | None (memory), Redis optional |
| Values kept out of the model | Not a goal | Not a goal | Not a goal | Yes, by construction |
| Rate limiting | None | Create only | Global | Per IP, per agent key, global |

## What this project takes from each

1. From Yopass: the fingerprint in the fragment and status-then-claim; then removes the paid wall, the browser-only request flow, and the destructive GET.
2. From PrivateBin: the confirm-before-fetch pattern for burn links, and the lesson to render nothing as HTML.
3. From Bitwarden Send: a scriptable receiver and the value of recurring audits; then fixes the racy counter with a real atomic single read.
4. From age: the vault format and the "small, no options" philosophy for the crypto module.
5. From Mailvelope: extension-owned UI for secrets and a per-host activation allowlist.
6. From Code Verify: published release hashes checked by code the user installed, never by the page itself.

## Sources

- https://github.com/jhaals/yopass and its releases, SECURITY.md, `pkg/server/server.go`, issues 2154 and 3322; https://yopass.se/docs/secret-requests/
- https://github.com/PrivateBin/PrivateBin, its CHANGELOG, the Encryption-format and API wiki pages, security advisories, issue 1237; https://privatebin.info/reports/zerobin-audit.html
- https://bitwarden.com/help/send-encryption/, https://bitwarden.com/help/send-lifespan/, https://bitwarden.com/help/send-cli/, https://bitwarden.com/help/is-bitwarden-audited/, https://github.com/bitwarden/server, https://github.com/bitwarden/clients
- https://github.com/FiloSottile/age and its releases, https://github.com/C2SP/C2SP/blob/main/age.md, https://github.com/C2SP/C2SP/blob/main/age-plugin.md, https://github.com/FiloSottile/typage, https://pypi.org/project/pyrage/
- https://github.com/mailvelope/mailvelope, https://github.com/mailvelope/mailvelope/wiki/Security, https://mailvelope.com/en/blog/security-audit_2025, https://github.com/mailvelope/keyserver
- https://github.com/facebookincubator/meta-code-verify, https://engineering.fb.com/2022/03/10/security/code-verify/, https://blog.cloudflare.com/cloudflare-verifies-code-whatsapp-web-serves-users/, https://arxiv.org/abs/2202.09795
