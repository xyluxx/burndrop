# Relay behind a Cloudflare Tunnel

No inbound ports, no certificate to manage: `cloudflared` runs next to the
relay and keeps an outbound connection to Cloudflare, which terminates TLS at
its edge and forwards requests through the tunnel to `http://relay:8080`.
Good for a home server or any host behind NAT.

What Cloudflare sees: the edge decrypts TLS, so Cloudflare sees the same
things the relay sees: ciphertext, drop ids, hashed tokens, client addresses.
It never sees keys or plaintext, which live only in link fragments and in the
browsers and agents at the two ends.

## Steps

1. In the Cloudflare dashboard, Zero Trust, Networks, Tunnels: create a
   tunnel, choose the Docker connector, and copy the token.

2. Add a public hostname to the tunnel: your subdomain (for example
   `drop.example.com`), service type HTTP, URL `relay:8080`. Cloudflare
   creates the DNS record.

3. Configure and start.

   ```bash
   cd deploy/cloudflare
   cp .env.example .env            # DOMAIN, TUNNEL_TOKEN
   docker compose run --rm relay keygen -id agent1   # put the hash line in .env as AGENT_KEYS
   docker compose up -d
   ```

4. Verify: `burndrop verify-page -relay https://<DOMAIN>`.

## Settings worth turning on in Cloudflare

- SSL/TLS: Edge Certificates: enable HSTS and set the minimum TLS version to 1.2.
- Speed: leave Brotli compression on for the page; API responses are small
  and carry no reflected input, so compression is not a concern there.
- Caching: the relay sets `Cache-Control: no-store` on API responses and the
  page response includes its own hash headers; no page rules are needed.
- Do not enable Rocket Loader, email obfuscation, or any feature that rewrites
  HTML. They would change the page bytes and break the published hash (and the
  strict Content-Security-Policy would block the injected script).

## Trade-offs

- Cloudflare is a party that could observe metadata (who talks to the relay
  and when). It cannot read secrets.
- Tunnel connectors are an extra process to keep updated; pin the
  `cloudflared` image and update it with the relay.
