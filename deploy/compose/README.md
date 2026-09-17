# Hosted relay on your own domain (Docker Compose and Caddy)

The recommended way to run burndrop: one small server, one domain, one
`A` record. Caddy terminates TLS with an automatic certificate and forwards
to the relay. Nothing is written to disk except Caddy's certificates.

What this deployment can and cannot see: the relay and Caddy see ciphertext,
drop ids, hashed tokens, and client IP addresses. They never see keys or
plaintext. Confidentiality does not depend on this server being honest; it
depends on the code at the two ends and the keys that travel in link
fragments, which browsers never send to servers.

## Requirements

- A host with Docker Engine 24 or later and the Compose plugin.
- Ports 80 and 443 reachable from the internet (443/udp for HTTP/3 is optional).
- A DNS `A` (and `AAAA` if you have IPv6) record for your domain pointing at the host.

## Steps

1. Get the files.

   ```bash
   git clone https://github.com/xyluxx/burndrop.git
   cd burndrop/deploy/compose
   cp .env.example .env
   ```

2. Set `DOMAIN` in `.env`.

3. Generate an agent key. Only its hash is stored on the relay; the key
   itself goes to the agent.

   ```bash
   docker compose run --rm relay keygen -id agent1
   ```

   Put the printed `agent1:sha256:...` line in `.env` as `AGENT_KEYS`. Give
   the key to the agent operator, who runs `burndrop init -relay https://<DOMAIN>`.
   Repeat with another id for each agent; join the entries with commas.

4. Start.

   ```bash
   docker compose up -d
   ```

   If the published image is not available yet, build it from source:
   `docker compose up -d --build`.

5. Verify.

   ```bash
   curl -s https://<DOMAIN>/api/v1/info
   burndrop verify-page -relay https://<DOMAIN>
   ```

   `verify-page` compares the hash of the page the relay serves with the
   hash the relay reports and the hash embedded in your CLI, and with a
   value from the release notes if you pass `-expect`.

## Operating

- Logs: `docker compose logs -f relay`. The relay logs in JSON without drop
  ids, tokens, URLs, or request bodies. Client addresses are logged only when
  `BURNDROP_LOG_CLIENT_IP=true`.
- Updates: `docker compose pull && docker compose up -d`. Drops in memory are
  lost on restart, so update at a quiet moment; agents retry status polls.
- Backups: none needed. Nothing is persisted on purpose.
- Limits: the defaults allow 1 hour TTL (24 hours maximum), 64 KiB ciphertext,
  and rate limits per client address. See `docs/self-hosting.md` for every
  variable.

## More than one relay instance

Start the `redis` profile so instances share drops through Valkey (in
memory, no persistence):

```bash
STORE=redis REDIS_URL=redis://valkey:6379/0 docker compose --profile redis up -d
```

## Hardening notes

- The relay container runs as a non-root user with a read-only root
  filesystem, all capabilities dropped, and no shell in the image (distroless).
- Caddy adds HSTS. The relay itself sends the Content-Security-Policy that
  pins the page's script and style hashes, `X-Frame-Options: DENY`, and
  `Referrer-Policy: no-referrer`.
- `BURNDROP_TRUSTED_PROXIES` lists the networks whose `X-Forwarded-For`
  header the relay believes. The default covers Docker's private ranges; the
  relay port is not published, so only Caddy can reach it.
- To serve the page from a different origin than the API (so that a relay
  compromise cannot also alter the page), host `web/dist/page.html` on any
  static host and set `BURNDROP_PAGE_ORIGINS` to that origin. Agents then
  pass `-page-origin` to `burndrop init`. `burndrop verify-page` checks
  the copy the relay serves, so in this layout verify the static host's copy
  with `sha256sum` against the hash in the release notes instead.
