# Self-hosting the relay

The relay is one static binary (`burndrop-relay`) with no database, no disk writes, and one required variable. It stores ciphertext, hashed tokens, states, and expiry times in memory (or in Redis/Valkey for more than one instance), serves the drop page from the same origin, and forgets everything on restart. Confidentiality never depends on it: keys travel in link fragments, which browsers never send to servers, so a compromised relay sees ciphertext, drop ids, hashed tokens, and client addresses, never plaintext or keys (see [threat-model.md](threat-model.md) T1). This page covers the deployment options, every `BURNDROP_*` variable, keys, sizing, reverse proxies, Redis, the split-origin layout, logging, health, upgrades, and a checklist. The API the relay exposes is in [api.md](api.md).

## Deployment options

Each option has a step-by-step README with its own trade-offs. All of them run the same image built from the repository `Dockerfile` (distroless, non-root, read-only root filesystem, page embedded).

| Option | For | TLS terminated by | Inbound ports | Guide |
|---|---|---|---|---|
| Docker Compose with Caddy | A server with your own domain (recommended) | Caddy on your host | 80, 443 | [deploy/compose/README.md](../deploy/compose/README.md) |
| Tailscale Funnel or Serve | Personal use with no public server | Tailscale | none | [deploy/tailscale/README.md](../deploy/tailscale/README.md) |
| Cloudflare Tunnel | Hosts behind NAT, no certificate management | Cloudflare edge | none | [deploy/cloudflare/README.md](../deploy/cloudflare/README.md) |
| nip.io or sslip.io | A quick trial with a public IP and no domain | Caddy on your host | 80, 443 | [deploy/nipio/README.md](../deploy/nipio/README.md) |

The overview and the reasoning per option are in [deploy/README.md](../deploy/README.md).

Without Docker, the binary alone is enough:

```bash
BURNDROP_PUBLIC_ORIGIN=https://drop.example.com \
BURNDROP_AGENT_KEYS='agent1:sha256:<hash from keygen>' \
burndrop-relay serve
```

It listens on `:8080` and expects something in front of it to terminate TLS, because `BURNDROP_PUBLIC_ORIGIN` must be `https://` (plain `http://` is accepted for `localhost`, `127.0.0.1`, and `::1` only, for local development). On start it logs one line with the effective settings:

```
level=INFO msg="relay started" version=v0.1.0 listen=:8080 public_origin=https://drop.example.com store=memory agent_auth=required page_served=true default_ttl=1h0m0s max_ttl=24h0m0s
```

### As a systemd service

The binary needs no files, so a minimal unit is enough. Keep the keys out of the unit file itself by putting them in an environment file readable only by root:

```ini
[Unit]
Description=burndrop relay
After=network-online.target

[Service]
EnvironmentFile=/etc/burndrop/relay.env
ExecStart=/usr/local/bin/burndrop-relay serve
Restart=on-failure
DynamicUser=yes
ProtectSystem=strict
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

`/etc/burndrop/relay.env` holds `BURNDROP_PUBLIC_ORIGIN`, `BURNDROP_AGENT_KEYS`, `BURNDROP_TRUSTED_PROXIES`, and any other variable from the table below. `systemctl stop` sends `SIGTERM`, which the relay handles as a graceful shutdown.

### The container image

The repository `Dockerfile` builds the page (Node), then the static Go binary with `-X main.version=<VERSION>`, and copies it into `gcr.io/distroless/static-debian12:nonroot`. The image has no shell, runs as `nonroot`, exposes port 8080, declares `HEALTHCHECK` with `/burndrop-relay healthcheck` every 30 seconds, and uses `ENTRYPOINT ["/burndrop-relay"]` with `CMD ["serve"]`, so `docker run <image> keygen -id agent1` runs the other subcommands.

```bash
docker build -t burndrop-relay --build-arg VERSION=v0.1.0 .
docker run --rm -p 127.0.0.1:8080:8080 --read-only \
  -e BURNDROP_PUBLIC_ORIGIN=https://drop.example.com \
  -e BURNDROP_AGENT_KEYS='agent1:sha256:<hash>' \
  -e BURNDROP_TRUSTED_PROXIES=172.17.0.0/16 \
  burndrop-relay
```

The Compose files in `deploy/` add `read_only`, `cap_drop: [ALL]`, and `no-new-privileges` for the same image.

## Variable reference

Every variable is prefixed `BURNDROP_`. Values are trimmed. Durations use Go syntax (`30m`, `1h`, `24h`). Booleans accept `true`, `false`, `1`, `0`. A parse error or a validation failure stops startup with `configuration error: BURNDROP_<NAME>: ...` and exit code 2.

| Variable | Default | Meaning | Validation |
|---|---|---|---|
| `LISTEN` | `:8080` | Bind address (`host:port`) | |
| `PUBLIC_ORIGIN` | none | The origin humans and agents use, `https://drop.example.com`. Used for links, as the default CORS origin, and in the startup log | Required. `scheme://host[:port]` only, no path, query, userinfo, or fragment; `https` except for localhost; a default port (`:443`, `:80`) is dropped; lower-cased |
| `PAGE_ORIGINS` | `PUBLIC_ORIGIN` | Comma-separated origins allowed by CORS on `/api/` paths, for a page hosted elsewhere. Browser extension origins (`chrome-extension://<id>`, `moz-extension://<id>`) are always admitted because their ids cannot be known in advance | Each entry normalized like `PUBLIC_ORIGIN` |
| `SERVE_PAGE` | `true` | Serve the embedded page at `/`, `/drop`, and `/reveal` | Boolean |
| `DEFAULT_TTL` | `1h` | Lifetime applied when a client sends `ttl_seconds` 0 or omits it | At least `60s`; at most `MAX_TTL` |
| `MAX_TTL` | `24h` | Hard cap; larger requests are clamped, not rejected | At least `60s`; at most `168h` (7 days) |
| `MAX_CIPHERTEXT_BYTES` | `65840` | Largest ciphertext accepted (64 KiB of envelope plus a 256-byte padding block plus 48 bytes of sealed-box overhead). Also bounds the request body (`* 4 / 3 + 4096`) | 1024 to 4194304 |
| `MAX_LIVE_DROPS` | `10000` | Live slots (not tombstones) across drops and reveals; beyond it creation answers `503 store_full` | At least 1 |
| `MAX_TOTAL_BYTES` | `268435456` (256 MiB) | Total ciphertext held; uploads and reveals beyond it answer `store_full` | At least `MAX_CIPHERTEXT_BYTES` |
| `MAX_WAITERS` | `1000` | Concurrent long polls; beyond it `status` answers `503 too_many_waiters` | At least 1 |
| `STORE` | `memory` | `memory` or `redis` | One of the two |
| `REDIS_URL` | none | `redis://host:port/db` or `rediss://host:port/db`, with credentials in the URL if needed | Required when `STORE=redis` |
| `AGENT_AUTH` | `required` | `required` (bearer key needed to create slots and fetch) or `off` | One of the two |
| `AGENT_KEYS` | none | Comma-separated `id:sha256:<base64url hash>` entries from `keygen` | Required when `AGENT_AUTH=required`; ids must be unique and non-empty; the hash must decode to 32 bytes |
| `RATE_PAGE_PER_MIN` | `60` | Per client IP, for `upload`, `open`, `status`, `revoke`; burst is `rate / 3 + 1` | Positive |
| `RATE_AGENT_PER_MIN` | `30` | Per agent key id, for `drops`, `fetch`, `reveals` | Positive |
| `RATE_GLOBAL_PER_SEC` | `500` | Whole-relay ceiling on every request; burst is twice the rate | Positive |
| `TRUSTED_PROXIES` | none | Comma-separated CIDRs (a bare address means `/32` or `/128`) whose `X-Forwarded-For` is honored | Each entry must parse |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` (case-insensitive) | One of the four |
| `LOG_FORMAT` | `text` | `text` or `json` (slog handlers) | One of the two |
| `LOG_CLIENT_IP` | `false` | Add `client_ip` to access log lines | Boolean |
| `SHUTDOWN_TIMEOUT` | `10s` | How long a graceful shutdown waits for in-flight requests | Duration |

Cross-field rules produce these messages: `TTLs must be at least 1m0s`, `BURNDROP_MAX_TTL cannot exceed 168h0m0s`, `BURNDROP_DEFAULT_TTL cannot exceed BURNDROP_MAX_TTL`, `BURNDROP_MAX_CIPHERTEXT_BYTES must be between 1024 and 4194304`, `capacity limits must be positive and consistent`, `BURNDROP_REDIS_URL is required when BURNDROP_STORE=redis`, `BURNDROP_AGENT_KEYS is required when BURNDROP_AGENT_AUTH=required (generate one with: burndrop-relay keygen)`, `rate limits must be positive`.

## Agent keys

Keys are per agent and only their SHA-256 hash is stored on the relay:

```bash
burndrop-relay keygen -id agent1
```

prints the key once (`Agent key for "agent1" (shown once, give it to the agent):`) and the line to add to the relay's environment, `BURNDROP_AGENT_KEYS=agent1:sha256:<hash>`. Give the key itself to whoever runs the agent; they pass it to `burndrop init` (stored in their OS keychain) or set `BURNDROP_API_KEY`. Repeat with another `-id` for each agent and join the entries with commas. The id names the key in rate limiting only; it never appears in logs. To rotate, generate a new key, add its entry alongside the old one, move the agent over, then remove the old entry and restart. In Compose, `docker compose run --rm relay keygen -id agent1` runs the same command inside the image.

`BURNDROP_AGENT_AUTH=off` is for private networks (a tailnet, a host-only relay). Anyone who can reach the relay can then create slots, and unauthenticated agents are metered per client address (30 per minute by default), as page requests are.

## Sizing and limits

- Memory: each live slot holds at most `MAX_CIPHERTEXT_BYTES` of ciphertext plus a few hundred bytes of state. The defaults (10000 slots, 256 MiB) fit in a small container; the Compose file gives Valkey `maxmemory 256mb` with `noeviction` for the same reason.
- Every expired or finished slot becomes a tombstone (no ciphertext, no token hashes) kept for 24 hours after its original expiry, so `MAX_LIVE_DROPS` counts live slots only.
- The sweeper runs every 10 seconds and expiry is also applied lazily on every access.
- HTTP server timeouts: 10 seconds to read headers, 30 seconds to read a request, 45 seconds to write a response (30 seconds of long poll plus 15), 120 seconds idle, 16 KiB of headers.
- Rate limits are per client IP for page endpoints, so many humans behind one NAT share 60 requests per minute; raise `RATE_PAGE_PER_MIN` if a large office uses one relay. A single agent gets 30 slot creations and fetches per minute per key.

## Behind a reverse proxy

The relay speaks plain HTTP and expects a proxy (Caddy, nginx, a cloud edge, Tailscale) to terminate TLS. Configure these points:

- `BURNDROP_TRUSTED_PROXIES`: the proxy's addresses or networks. Only then is `X-Forwarded-For` used, and only its rightmost entry that is not itself a trusted proxy, which is the one entry a client cannot forge. Without it every client looks like the proxy and shares one page rate-limit bucket. The Compose file sets Docker's private ranges; the Tailscale file sets `127.0.0.1/32,::1/128`.
- Forward `X-Forwarded-Proto: https` so the relay adds `Strict-Transport-Security`, or set HSTS at the proxy as the shipped Caddyfile does (`max-age=31536000; includeSubDomains; preload`). Setting it in both places is harmless.
- Timeouts: long polls hold a `status` request for up to 30 seconds and the relay writes the response within 45. Set the proxy's upstream read or response timeout above 45 seconds, otherwise polls end in `502` or `504` and agents retry with backoff.
- Compression: compress only the page (`GET` or `HEAD` on `/`, `/drop`, `/reveal`), never the API. API responses carry per-request tokens and stay uncompressed so their size reveals nothing; the shipped Caddyfile does exactly this with `encode @page zstd gzip`.
- Do not rewrite HTML (no script injection, no minification, no "optimization" features). The page's Content-Security-Policy pins its script and style hashes and `verify-page` checks the served bytes; any rewrite breaks both.
- Access logs at the proxy: paths carry no identifiers (everything is in the fragment or the body), but the relay already logs what an operator needs, so the shipped Caddyfile keeps proxy logging off.
- Keep the relay port unpublished so only the proxy can reach it.

## Multiple instances with Redis or Valkey

A single instance keeps everything in memory. To run more than one replica behind a load balancer, set `BURNDROP_STORE=redis` and `BURNDROP_REDIS_URL`. Every operation runs as one Lua script on the server (token check, state check, read-and-delete of ciphertext in one step), so "read exactly once" holds across replicas. Long polls re-read the slot every 200 milliseconds instead of waiting on a channel.

Requirements for the Redis or Valkey instance:

- No persistence: `save ""` and `appendonly no`. Never back it up. Drops must not touch a disk. The Compose `redis` profile starts Valkey with exactly these flags, `maxmemory 256mb`, and `maxmemory-policy noeviction` on a tmpfs.
- Reachable at startup: the relay pings it once with a 5-second timeout and refuses to start otherwise (`relay: redis at host:port is unreachable: ...`). A malformed URL fails with `relay: invalid redis URL, want redis://host:port/db or rediss://host:port/db` without echoing the URL.
- Use `rediss://` or a private network when the instance is not on the same host.

Keys live under the prefix `burndrop:`: one hash per slot (`slot:<id>`), two sorted sets for expiry and tombstone removal, and two counters (`live`, `bytes`). Every slot key also carries a `PEXPIRE` at expiry plus the 24-hour grace, so tombstones vanish even if no sweeper runs. The Redis client library's own logger is silenced so nothing bypasses the relay's log rules.

## Split origin: page on a static host

By default the relay serves the page and the API from one origin, and one variable sets everything. For operators who want a relay compromise not to imply a page compromise, host `web/dist/page.html` on any static host and:

1. Set `BURNDROP_PAGE_ORIGINS` to the static host's origin (comma-separated if several). Requests from that origin then pass CORS; every other origin is refused.
2. Optionally set `BURNDROP_SERVE_PAGE=false` so the relay no longer serves the page itself (`/drop` then answers `404`; `GET /api/v1/info` reports `page_served: false`).
3. Set the response headers on the static host yourself. The relay's CSP uses `connect-src 'self'`, which is only right when page and API share an origin; a page hosted elsewhere needs a policy whose `connect-src` names the relay origin, plus `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.
4. Tell agent operators to run `burndrop init -relay https://relay.example -page-origin https://drop.example.com`. Links then point at the page origin and carry the relay origin in their `r` field. `burndrop verify-page` only checks a page served by the relay itself (it reads `/drop` and `/api/v1/info` from one origin), so for a page on a static host publish the file's SHA-256 with your deployment notes and compare it with `sha256sum page.html` on the host, or with the hash in `web/dist/page.sha256` of the release.

## Logging

The relay logs through `log/slog` to stderr in `text` or `json` format at the configured level:

- Startup: `relay started` with `version`, `listen`, `public_origin`, `store`, `agent_auth`, `page_served`, `default_ttl`, `max_ttl`. Secrets never appear; `AGENT_KEYS` and `REDIS_URL` are not printed.
- One `request` line per request: `method`, `route` (the matched pattern such as `POST /api/v1/drops/fetch`, or `unmatched`), `status`, `duration_ms`, `request_id`, and `client_ip` only when `LOG_CLIENT_IP=true`.
- `store error` and `panic` lines with the request id and an error string; `sweep` at debug level with the count of touched slots; `shutting down`.
- Never: request or response bodies, drop ids, tokens, commitments, headers, query strings (there are none), URLs, or the page a client opened. The `X-Request-Id` response header lets a user report a failure without revealing anything.

## Health checks

- `GET /healthz` answers `200 ok` without touching the store; the global rate limit still applies.
- `burndrop-relay healthcheck` performs that request against the local listen port and exits 0 or 1; the image's `HEALTHCHECK` runs it every 30 seconds.
- `GET /api/v1/info` reports the version, TTLs, limits, auth mode, and the page hash; `burndrop doctor` and `burndrop verify-page` use it from the agent side.
- Compose starts Caddy only after the relay's health check passes.

## Upgrading

The relay is stateless on disk. Stop it, replace the binary or pull the image, start it. Slots held in memory are lost, so agents waiting on a request see `expired` and ask again; upgrade at a quiet moment or run two instances on Redis and restart them one at a time. `SIGINT` or `SIGTERM` starts a graceful shutdown that waits up to `BURNDROP_SHUTDOWN_TIMEOUT` for in-flight requests, which covers a long poll in progress. After an upgrade, check `GET /api/v1/info` for the new `version` and `page_version`, and run `burndrop verify-page -relay https://drop.example.com -expect <hash from the release notes>`; the page hash changes with every page release, and clients that embed the old page report the difference as a note, not a failure.

## Security checklist

- `BURNDROP_PUBLIC_ORIGIN` is `https://` and matches the certificate the proxy serves; agents refuse `http://` origins other than localhost.
- `BURNDROP_AGENT_AUTH=required` with one key per agent; keys generated by `keygen`, never invented; only hashes on the relay.
- `BURNDROP_TRUSTED_PROXIES` names exactly the proxies in front of the relay, and the relay port is not published.
- HSTS is set (at the proxy or through `X-Forwarded-Proto`); no HTML rewriting or injection features at the edge.
- Compression only for the page; API responses uncompressed.
- Redis or Valkey, if used, runs without persistence, without backups, on a private network or TLS.
- `BURNDROP_LOG_CLIENT_IP` stays `false` unless you need addresses for abuse handling, and proxy access logs are off or minimal.
- The container runs read-only, non-root, with all capabilities dropped, as the shipped Compose files do.
- Publish the page hash from `GET /api/v1/info` with your deployment notes so humans and agents can run `burndrop verify-page -expect <hash>`.
