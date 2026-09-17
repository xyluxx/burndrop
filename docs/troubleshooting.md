# Troubleshooting

Symptoms, their causes, and the fix, drawn from the messages the code produces. Start with `burndrop doctor` on the agent side: it prints one line per check and a `FAIL` line names the failing part with the same message you would see elsewhere. On the relay side, read the startup log line and `GET /api/v1/info`. Messages below are quoted exactly; placeholders such as `<path>` stand for the value in your output. The API codes are defined in [api.md](api.md), the CLI in [cli.md](cli.md), the variables in [self-hosting.md](self-hosting.md), and the backends in [storage-backends.md](storage-backends.md).

## Reading doctor output

```
ok    paths          /home/agent1/.config/burndrop/config.toml
ok    config         relay https://relay.example, storage keychain
FAIL  agent key      agent key not found in the keychain (keychain:burndrop/agent-key): storage: secret not found
ok    relay origin   https://relay.example
ok    relay          version v0.1.0, page served true, agent auth required
ok    page hash      <hex>
...
1 problem(s)
```

Checks run in order: `paths`, `config`, `config mode`, `agent key`, `relay origin`, `relay`, `page hash`, `state dir`, `backend open`, `backend probe`, `agent`, `purge expired`, `pending`, `secrets`, `audit log`. A failing `paths` or `config` stops the run (exit 1); everything else continues so one run shows every problem. `config mode` appears only when the config file is readable by other users on a non-Windows system: `<path> is readable by other users (mode 644); chmod 600 it`.

## Setup

| Symptom | Cause | Fix |
|---|---|---|
| `error: no configuration file; run the init command first` | No config at the platform path or at `BURNDROP_CONFIG` | Run `burndrop init -relay https://relay.example`, or point `BURNDROP_CONFIG` at the file |
| `error: the relay at https://relay.example did not answer: relay: Get "https://relay.example/api/v1/info": ...` | `init` could not reach `/api/v1/info`: wrong host, no TLS yet, a firewall, or the relay is down | Check `curl https://relay.example/api/v1/info` from the same machine; fix DNS, TLS, or the relay first |
| `error: relay: link: invalid link: http is only allowed for localhost` | The origin uses `http://` on a non-loopback host | Put TLS in front of the relay and use `https://`; `http://` is accepted only for `localhost`, `127.0.0.1`, and `::1` |
| `error: relay: link: invalid link: origin must be scheme://host[:port] only` | The origin carries a path, query, or fragment | Pass the bare origin, `https://relay.example` |
| `<config path>: unknown keys: run_with_secret.bogus` | A misspelled or unsupported key in `config.toml` | Remove it; only the keys listed in [storage-backends.md](storage-backends.md) are accepted |
| `agent_key must be keychain:<service>/<entry> or env:<VARIABLE>; never a plain value` | The key itself was written into the config | Remove it; rerun `init`, or set `agent_key = "env:BURNDROP_API_KEY"` |
| `only the dotenv backend is available; pass -allow-dotenv to accept a plain file, or -storage agevault` | No keychain, no vendor CLI, and `agevault` could not open | Prefer `-storage agevault` with `identity_file` set; use `-allow-dotenv` only when you accept a plain file |
| `no storage backend is available; install a credential store or use -storage agevault` | Even `dotenv` refused (for example, the state directory is inside a git repository and not ignored) | Use `-storage agevault`, or move `BURNDROP_STATE_DIR` outside the repository |

## MCP clients

| Symptom | Cause | Fix |
|---|---|---|
| The client reports that the server failed to start or is not connected | The client's PATH lacks `burndrop` (GUI clients often start with a minimal environment) | Replace `"command": "burndrop"` with the absolute path of the binary in the client configuration |
| The server exits at once; its stderr shows `error: no configuration file; run the init command first` | `init` was never run for the user account the client runs as, or `BURNDROP_CONFIG` differs | Run `burndrop init` as that user, or pass `BURNDROP_CONFIG` in the server entry's `env` map |
| The server exits with `error: agent key not found in the keychain ...` or `error: environment variable BURNDROP_API_KEY is empty` | The key source is not reachable from the client's process | See the next section; for `env:` keys add `BURNDROP_API_KEY` to the client's `env` map |
| No tools appear although the server started | The client connected to a different server entry, or the server line `burndrop <version>: MCP server on stdio, relay <origin>, storage <backend>` never appeared on stderr | Check the client's server log; the line is printed once at start |
| `send_secret` creates a link without asking the human | The client does not advertise the elicitation capability, or the server runs with `-no-confirm` | Rely on the client's tool approval for `send_secret` (the tool carries a destructive hint), or move to a client with elicitation |
| Every tool answers with a redacted error such as `relay: unauthorized [HTTP 401]` | The relay problem is real; the MCP layer only redacts and forwards | Fix the underlying error from the tables below; `burndrop doctor` shows the same failure |

## Agent key and authentication

| Symptom | Cause | Fix |
|---|---|---|
| `agent key not found in the keychain (keychain:burndrop/agent-key): storage: secret not found (run burndrop init, or set BURNDROP_API_KEY)` | `init` stored the key under another user account, the keychain was reset, or the key was never stored (`-agent-key-from env` was used but the variable is unset) | Rerun `burndrop init` and paste the key, or export `BURNDROP_API_KEY` |
| `environment variable BURNDROP_API_KEY is empty` | `agent_key = "env:BURNDROP_API_KEY"` but the MCP client did not pass the variable | Add an `env` map to the client's server entry, or launch the client from a shell that exports it |
| `keychain service "x" is not supported; use burndrop` | `agent_key` names a keychain service other than `burndrop` | Use `keychain:burndrop/<entry>` |
| `error: relay: unauthorized [HTTP 401]` | The relay does not know this key: wrong key, a key whose hash is not in `BURNDROP_AGENT_KEYS`, the relay restarted with a changed key list, or a key shorter than 16 characters | Compare with the operator's `keygen` output; keys are 43 characters. On the relay, `BURNDROP_AGENT_KEYS` must contain the `id:sha256:<hash>` entry and the relay must be restarted after changing it |
| `error: relay: rate_limited [HTTP 429]` on `request` or `fetch` | More than 30 slot creations or fetches per minute for this key (burst 11) | Space calls out, or ask the operator to raise `BURNDROP_RATE_AGENT_PER_MIN` |

## Requests and fetching

| Symptom | Cause | Fix |
|---|---|---|
| `waiting: The human has not submitted <name> yet. ...` then `error: still waiting; run fetch again` (exit 1) | Nothing uploaded within `-wait` seconds | Run `fetch` again; the link stays valid until the printed time |
| `error: no pending request with that id` | The request was revoked, fetched, or expired and its record purged; a different `BURNDROP_STATE_DIR`; `storage = "memory"` in a separate CLI process; or the agent's clock is ahead of the relay's so the record looked expired | `burndrop pending` lists what is known; request again. For CLI use, keep a persistent backend. Fix the clock (see below) |
| `error: more than one request is pending; pass request_id` | `fetch` without an id while several requests are outstanding | Pass the id from `burndrop pending` |
| `expired: The request expired before the human submitted anything. ...` or `The request is no longer known to the relay; it expired. ...` | The TTL passed, the relay restarted (memory store), or the relay swept the tombstone | Ask again with `request` |
| `revoked: The request was revoked before the human submitted anything.` | `revoke_request` or `burndrop revoke` ran, or another client revoked the slot with one of its tokens (the drop page never does) | Request again if still needed |
| `gone: The submission was already fetched. If it was not stored by this agent, treat the secret as exposed ...` | The fetch token was used before this agent could use it (a second process with the same pending record, or a compromised record) | Treat the secret as exposed: ask the human to rotate it, then request again |
| `rejected: The submission could not be decrypted with this request's key. ...` | The ciphertext was not sealed to this request's key: a tampered page, a swapped link, or a relay returning the wrong data | Revoke, request a fresh link, and have the human compare the fingerprint; run `burndrop verify-page` |
| `rejected: The submission was rejected: the secret name in the submission does not match the request. ...` (or `the fingerprint shown to the human does not match this request`, `the retention shown to the human does not match the request`, `the envelope is not a drop`) | The human used a link whose display fields differ from the ones this agent generated | Request a fresh link and send the message verbatim; the fields are authenticated so an edited link cannot pass |
| `the secret was received but could not be stored (...); ask the human to submit again after fixing storage` | The backend refused the write after the relay copy was deleted (locked vault, size limit, missing permission) | Fix the backend (see below) and request again |
| `the key in this link does not match the key the agent registered; the link was altered, do not use it` (`burndrop drop`) or the page's `The key in this link does not match the key the agent registered. The link was altered; do not use it.` | The relay answered `422 commitment_mismatch`: the public key in the link differs from the commitment the agent registered | Do not submit. Tell the agent, which should call `revoke_request` and generate a new link; compare fingerprints on the new one |
| `this link can no longer be used (state: uploaded)` | The link was already used once (upload done) | Nothing to do; the agent fetches it. A second value needs a new request |
| `this link has expired or was never created` | The relay answered `404 not_found` | Ask the agent for a new link |
| The page says `This link has expired` although the agent just created it | The browser's clock is ahead of the relay's; the page derives the countdown from the relay's `expires_at` and the local time | Fix the clock on the human's device, or use `burndrop drop LINK`, which does not compute a countdown |

## Sending and opening

| Symptom | Cause | Fix |
|---|---|---|
| `this secret was received from a human and is not marked sendable; only secrets created by the agent or marked sendable by the operator can be sent` | The secret came from a drop requested without `sendable`, or a pending record name was used | Request it again with `sendable: true`, or produce it with `capture_as`; there is no command that marks an existing secret sendable |
| `the human declined to send this secret` | The elicitation prompt was answered with no, cancel, or dismiss | Nothing to fix; the audit log shows `declined_by_human` |
| `this link was already used or revoked (state: opened)` (`burndrop open`) or the page's `This secret was already revealed` | The reveal was opened once already | If that was not you, tell the agent to rotate the secret and send it again |
| `the secret could not be decrypted: the link was altered or the relay returned the wrong data; the relay copy is gone, ask the agent to send it again` | The key or the display fields in the link were altered, so authentication failed after the relay deleted its copy | Ask the agent to send again; do not reuse the altered link |
| `cancelled; the secret is still on the relay until <time>` | `open` was answered with no | Open it before the printed time or let it expire |

## Storage backends

| Symptom | Cause | Fix |
|---|---|---|
| `credential store unavailable: ...` or `credential store could not read back a test entry` in the probe table | No usable keychain: on Linux no Secret Service daemon (GNOME Keyring, KWallet) on the session bus; on a headless host no session at all | Use `agevault` with `identity_file`, or start a keyring and unlock it |
| `storage: backend unavailable: ...` from the keychain | `go-keyring` reports an unsupported platform | Same as above |
| Many `burndrop` entries in the Windows Credential Manager, named `<name>#0`, `<name>#1`, and a header entry | Windows caps a credential blob at 2560 bytes, so records over 2000 bytes are chunked | Expected; delete through `burndrop delete NAME`, not by hand, so all chunks go |
| `storage: keychain entry "<name>" has a corrupt chunk header` or `is missing chunk N` | Chunks were deleted by hand or by another tool | Delete the remaining entries for that name and request the secret again |
| `storage: permission denied: <path>/.env is inside a git repository and is not ignored; add it to .gitignore first` | The `dotenv` file would be committed | Add the file to `.gitignore` (git is asked with `git check-ignore` when installed) or move `BURNDROP_STATE_DIR` |
| `the dotenv backend stores values in a plain file; pass -allow-dotenv to accept that` | `-storage dotenv` without the flag | Add `-allow-dotenv`, or choose a stronger backend |
| `storage: permission denied: the vault at <path> was encrypted with a different key` | The `vault.age` file was written under another identity: the keychain entry `vault-identity` was recreated, `identity_file` points at a new file, or the passphrase changed | Restore the original key, or delete `vault.age` and `index.json` and request the secrets again |
| `storage: <path> holds no AGE-SECRET-KEY line` | `identity_file` exists but is not an age identity | Point it at a file containing an `AGE-SECRET-KEY-...` line, or delete it so a new one is generated |
| `storage: the vault key in the keychain is not an age identity` | The `vault-identity` keychain entry was overwritten | Remove that entry and start over with a fresh vault, or set `identity_file` |
| `storage: vault is locked by another process (<path>.lock)` | Two writers at once, or a stale lock younger than a minute | Retry; a lock older than a minute is removed automatically |
| `agevault passphrase variable X is empty`, `bitwarden session variable X is empty`, `vault token variable X is empty` | The config names a variable the process does not have | Export it in the client's environment |
| `1Password CLI (op) is not installed; install it from https://developer.1password.com/docs/cli/get-started/ and run op signin` | `op` is not on PATH | Install it |
| `op is installed but not signed in (...); run op signin` | No session | `op signin`, or set `OP_SERVICE_ACCOUNT_TOKEN` |
| `Bitwarden CLI (bw) is not installed; install it with npm install -g @bitwarden/cli (https://bitwarden.com/help/cli/) and run bw login` | `bw` missing | Install it |
| `bw vault is locked for <email>; run bw unlock and export BW_SESSION` or `bw is not logged in; run bw login, then bw unlock and export BW_SESSION` | Locked or logged out vault; every call runs with `--nointeraction`, so nothing prompts | `bw login`, then `export BW_SESSION="$(bw unlock --raw)"` in the environment the agent runs in |
| `Doppler CLI (doppler) is not installed; ...`, `doppler is installed but not authenticated (...); run doppler login or set DOPPLER_TOKEN` | Missing CLI or token | Install; `doppler login` or `DOPPLER_TOKEN` |
| `Infisical CLI (infisical) is not installed; ...`, `infisical cannot read <scope> (...); run infisical login or set INFISICAL_TOKEN, and run infisical init or pass a project ID` | Missing CLI, login, or project scope | Install; log in; `infisical init` or set `project_id` |
| `vault address is not set (VAULT_ADDR)`, `vault address "x" must use https (plain http is allowed for localhost only)`, `no vault token: set VAULT_TOKEN or run vault login`, `Vault at <addr> is unreachable: ...`, `Vault at <addr> rejected the token: HTTP 403: ...` | Address, scheme, token, or policy problem | Set `address` or `VAULT_ADDR`, obtain a token with `vault login`, grant the KV policy in [backends/vault.md](backends/vault.md) |
| `aws CLI not found in PATH; install AWS CLI v2 (...)`, `aws CLI found but no usable credentials (run aws configure or aws sso login): ...` | Missing CLI or credentials | Install v2; `aws configure` or `aws sso login` |
| `gcloud not found in PATH; ...`, `gcloud found but no account is signed in; run gcloud auth login`, `gcloud has no default project; set GCP.Project or run gcloud config set project PROJECT_ID` | Missing CLI, login, or project | Install; `gcloud auth login`; set `project` |
| `az not found in PATH; ...`, `Azure.VaultName is not set`, `az found but not signed in (run az login): ...` | Missing CLI, `vault_name`, or login | Install; set `vault_name`; `az login` |
| `storage: permission denied: <cli> exited with code N: ...` on `Put`, `Get`, or `Delete` | The CLI printed `not signed in`, `unauthorized`, `access denied`, `permission denied`, `forbidden`, `vault is locked`, or `not logged in` | Sign in or unlock again in the agent's environment; check the IAM or policy notes on the backend's page |
| `storage: value too large` (`ErrTooLarge`) | The value exceeds 64 KiB, or the backend's own cap (Bitwarden 4 KiB, Doppler 36 KiB, Azure 18,432 bytes, AWS and GCP 48,384 bytes) | Store a smaller value or choose another backend |

## run_with_secret

| Symptom | Cause | Fix |
|---|---|---|
| `command is not in run_with_secret.allowed_commands: <name>` | The operator restricted programs in the config | Add the program's name to `allowed_commands`, or use one that is listed |
| `could not start <name>: exec: "<name>": executable file not found in %PATH%` (or `$PATH`) | The program is not on the agent's PATH | Give the full path in `command[0]` |
| `"X" is not a valid environment variable name` | `env` keys must match `[A-Za-z_][A-Za-z0-9_]*` | Rename the variable |
| `secret <name>: storage: secret not found` | The name is not stored, expired, or is a pending record | `list_secrets` shows what exists; fetch or request it first |
| `The command was stopped after 2m0s.` with `timed_out` true and exit code -1 (CLI exit 124) | The default 120-second timeout (or `timeout_seconds`) elapsed | Raise `timeout_seconds` (maximum 3600) |
| `The command ran but nothing matched capture_as.pattern; nothing was stored.` or `the command printed nothing` | The pattern has no match, or stdout was empty | Test the pattern; it needs exactly one capture group (`capture_as.pattern must have exactly one capture group`) |
| Output ends with `[truncated]` | Output exceeded `max_output_bytes` (32768) | Raise it in `[run_with_secret]`, or use `capture_as` or `discard_output` |
| A value appears in output despite redaction | Values under 6 bytes are not redacted; a value stored in an earlier process is unknown until it is used by this one; the program transformed the value (for example, split it) | Treat it as exposed per the instructions: rotate, `delete_secret`. Redaction is a safety net, not the boundary |

## Relay

| Symptom | Cause | Fix |
|---|---|---|
| `configuration error: BURNDROP_PUBLIC_ORIGIN is required, for example https://drop.example.com` (exit 2) | The one required variable is missing | Set it |
| `configuration error: BURNDROP_AGENT_KEYS is required when BURNDROP_AGENT_AUTH=required (generate one with: burndrop-relay keygen)` | No keys configured | Run `keygen` and set the entry, or set `BURNDROP_AGENT_AUTH=off` on a private network |
| `configuration error: BURNDROP_AGENT_KEYS: agent key entry "x" must look like id:sha256:<hash>` or `duplicate agent key id "agent1"` | A malformed or repeated entry | Paste the line printed by `keygen` unchanged; ids must be unique |
| `configuration error: BURNDROP_REDIS_URL is required when BURNDROP_STORE=redis`, `relay: invalid redis URL, want redis://host:port/db or rediss://host:port/db`, `relay: redis at host:6379 is unreachable: ...` | Redis settings | Set the URL; start Redis or Valkey first; the relay pings it once with a 5-second timeout at startup |
| `{"error":"missing_client_header","header":"X-Client"}` (400) | A client without the `X-Client` header, typically a hand-written script or a form post | Send `X-Client: <name>/<version>` on every `POST` |
| `{"error":"origin_not_allowed"}` (403) | A browser page from an origin not in `BURNDROP_PAGE_ORIGINS` called the API (browser extension origins are always admitted, so this is a web page, or a proxy that adds an `Origin` header) | Add the page origin to `BURNDROP_PAGE_ORIGINS`, serve the page from the relay, or stop the proxy from adding the header |
| `{"error":"rate_limited"}` (429) on the page, `Too many requests from this network right now. Wait a minute and try again.` | 60 page requests per minute per client IP (burst 21). Behind a proxy without `BURNDROP_TRUSTED_PROXIES`, every human shares the proxy's address and one bucket | Set `BURNDROP_TRUSTED_PROXIES` to the proxy's network; raise `BURNDROP_RATE_PAGE_PER_MIN` for large shared networks |
| `{"error":"store_full"}` (503, `Retry-After: 30`) | `BURNDROP_MAX_LIVE_DROPS` (10000) or `BURNDROP_MAX_TOTAL_BYTES` (256 MiB) reached; agents that create slots and never fetch them fill the store until the TTL passes | Wait for expiry (the sweeper runs every 10 seconds), lower `BURNDROP_MAX_TTL`, or raise the limits with more memory |
| `{"error":"too_many_waiters"}` (503, `Retry-After: 5`) | More than `BURNDROP_MAX_WAITERS` (1000) long polls in flight | Raise it, or add instances on the Redis store |
| `The drop page is not built into this relay. Use the CLI or the browser extension, or rebuild the relay with the page.` (503 on `/drop`) and the log line `drop page not built into this binary; /drop and /reveal will return 503` | The binary was built without `web/dist/page.html` and `page.meta.json` | Build the page (`node build.mjs` in `web/`) before `go build`, or use the container image, or host the page elsewhere with `BURNDROP_PAGE_ORIGINS` |
| `page verification failed; do not use this relay's page until the operator explains the difference` after `MISMATCH: the relay serves a page whose hash differs from what it reports` | The bytes served differ from the embedded page: a proxy or CDN rewrote the HTML (script injection, minification, "optimization") | Turn those features off at the edge; the CSP hash pins already block injected scripts |
| `MISMATCH: the served page is not the expected release page` | `-expect` does not match; a different release is deployed, or the page was replaced | Compare with the release notes; ask the operator which version runs |
| `note: the served page differs from the one embedded in this binary (different release or a modified relay)` | Only a version difference between your CLI and the relay | Informational; the served hash still matches what the relay reports |
| Long polls end after about 30 seconds with `502` or `504` from the proxy; agents log `relay: http_502 [HTTP 502]` and give up after five retries | The proxy's upstream timeout is shorter than the 30-second poll plus response time | Raise the proxy's read or response timeout above 45 seconds (60 is a safe value) |
| `fetch` reports `expired` although the link had time left | The relay restarted (memory store loses slots) | Request again; run two instances on Redis if restarts must be invisible |

## Checking a relay by hand

Three requests tell most of the story. Information about the relay, no headers needed:

```bash
curl -s https://relay.example/api/v1/info
```

A well-formed status request for an unknown id, which must answer `{"error":"not_found"}` with status 404 (a 403 `origin_not_allowed` here means a proxy added an `Origin` header; a 405 means the proxy changed the method or path):

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://relay.example/api/v1/drops/status \
  -H 'Content-Type: application/json' -H 'X-Client: curl/1' \
  -d '{"drop_id":"AAAAAAAAAAAAAAAAAAAAAA"}'
```

A long poll, which must take close to 30 seconds and return 200 rather than a proxy error:

```bash
time curl -s -o /dev/null -w '%{http_code}\n' https://relay.example/api/v1/drops/status \
  -H 'Content-Type: application/json' -H 'X-Client: curl/1' \
  -d '{"drop_id":"<an id from burndrop pending>","wait_seconds":30,"wait_while":"created"}'
```

Every response carries `X-Request-Id`; quote it to the operator, who can find the matching `request` line in the relay log without either side revealing an identifier.

## Clocks

The relay's clock decides expiry; the agent and the browser only display it. Skew shows up as: a pending request purged locally before the relay expires it (agent clock ahead), `no pending request with that id`; a record that lingers after the relay expired it (agent clock behind), reported as `expired` on the next fetch; the page showing `This link has expired` on load (browser clock ahead). `until:<date>` retention is checked against the agent's clock (`storage: invalid retention policy: date is in the past`). Keep every machine on NTP; there is no tolerance window in the code.
