# Comparison with similar tools

burndrop borrows from tools that solved parts of the same problem and
differs from them on one point: it is built for a program, not a person, to
be one of the two ends. The research behind this page, with sources, is in
`research/prior-art.md`.

## One-time secret sharing services

Yopass, PrivateBin, and Bitwarden Send let a human share a secret with
another human through a link that carries the key in the fragment. They are
mature and well regarded, and burndrop's relay looks like theirs from the
outside. The differences are in what each end is.

| | Yopass | PrivateBin | Bitwarden Send | burndrop |
| --- | --- | --- | --- | --- |
| Key transport | Fragment, or typed by hand | Fragment, optional password | Fragment, password as access control | Fragment only; one recipient key per request |
| Encrypt to a program's public key | Paid tier, browser only | No | No | Core flow, from the CLI, the MCP server, or an SDK |
| Burn request | GET, then click to reveal | GET, click to confirm | POST on page load | POST on click; GET never changes state |
| Atomic single read | Yes | Not verified | No | Yes, one lock or one Lua script |
| Identifiers in the URL path | Yes | Yes | Yes | No; fragment and body only |
| What the server learns | TTL, one-time flag, sizes | Expiry, burn flag, sizes | Encrypted names, counts | Size rounded to 256 bytes, timing |
| Server dependencies | Memcached or Redis | None | Database | None (memory); Redis optional |
| Values kept away from the model | Not a goal | Not a goal | Not a goal | By construction: names and metadata only |
| Rate limiting | None built in | Create only | Global | Per client, per agent key, global |
| Verifiable page | No | No | No | Published hash, `verify-page`, extension |

What burndrop takes from each: the fragment-carried key and the
single-file page from Yopass, the click-to-reveal discipline from
PrivateBin, and the "server sees nothing useful" review culture of
Bitwarden Send.

## Secret managers and CLIs

1Password, Bitwarden, Vault, Infisical, Doppler, and the cloud secret
managers store secrets well. They do not solve the exchange problem: a
human still has to get a value into the agent's store, which usually means
pasting it into a chat or a terminal. burndrop is the exchange step, and it
stores the result in exactly these managers through their own CLIs, so an
organization keeps its existing key management.

## age

age showed that a small, opinionated tool with one file format and no
options can be trusted more than a flexible one. burndrop follows that
example: one construction per direction, no algorithm negotiation, no
passwords, a spec short enough to read in one sitting. The `agevault`
backend uses age itself for the encrypted file store.

## Mailvelope and Meta's Code Verify

Both address the question "is the page I am running the page that was
published?" Mailvelope moves the cryptography into an extension so the web
page cannot touch it; Code Verify compares a served page against a
published manifest. burndrop's extension does both: it replaces the hosted
page with a bundled copy for configured relays and hashes hosted pages
against the release manifest for the rest.

## MCP secret handling

Model Context Protocol clients expose tools, and a tool that returns a
secret puts it in the conversation, the context window, and the logs.
burndrop's tools never return a value: `request_secret` returns a link and
a fingerprint, `fetch_secret` returns a status, `run_with_secret` returns
redacted output, and `send_secret` returns a link. It also refuses to
collect secrets through elicitation, which the MCP specification forbids
for form-mode requests.

## When not to use burndrop

- Two humans sharing a password once: Yopass, PrivateBin, or Bitwarden Send do this with less to install.
- Long-lived secret distribution to services: a secret manager with workload identity.
- Agents whose tooling already has a workload identity to the secret manager: they do not need a human in the loop at all.
