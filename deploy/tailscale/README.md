# Relay on Tailscale Funnel

For personal use with no public server: the relay listens on localhost, and
Tailscale exposes it at `https://<machine>.<tailnet>.ts.net`. Tailscale
issues the certificate and terminates TLS. Humans open drop links from any
browser, on or off your tailnet, because Funnel is public. If you only ever
open links from devices on your tailnet, use `tailscale serve` instead of
`tailscale funnel` and nothing is reachable from the internet at all.

What Tailscale sees: TLS is terminated by the `tailscaled` on your machine,
so Tailscale's relays (DERP) carry only encrypted TLS records. Your machine
sees ciphertext and client addresses, as any relay host does.

## Option A: Tailscale already runs on the host

1. In the Tailscale admin console, enable HTTPS certificates (DNS settings)
   and, for public access, Funnel (a `nodeAttrs` entry with `funnel` in the
   tailnet policy file).

2. Find your machine's name: `tailscale status` shows it; the public name is
   `https://<machine>.<tailnet>.ts.net`.

3. Start the relay bound to localhost with that name as the public origin.
   With Docker:

   ```bash
   cd deploy/tailscale
   cp .env.example .env    # set PUBLIC_ORIGIN and AGENT_KEYS
   docker compose run --rm relay keygen -id agent1
   docker compose up -d
   ```

   Without Docker, the same two variables work with the binary:
   `BURNDROP_PUBLIC_ORIGIN=... BURNDROP_AGENT_KEYS=... burndrop-relay serve`.

4. Expose it.

   ```bash
   tailscale funnel --bg 8080      # public; or "tailscale serve --bg 8080" for tailnet only
   tailscale funnel status
   ```

5. Verify with `burndrop verify-page -relay https://<machine>.<tailnet>.ts.net`.

The relay trusts `X-Forwarded-For` from `127.0.0.1` only, which is where the
local `tailscaled` proxies from.

## Option B: everything in Docker (Tailscale sidecar)

`docker-compose.sidecar.yml` runs the official Tailscale container next to
the relay with a serve configuration that enables Funnel. It needs an auth
key (`TS_AUTHKEY`, ideally a tagged, reusable key) and the same admin console
settings as above.

```bash
cp .env.example .env    # set TS_AUTHKEY, PUBLIC_ORIGIN, AGENT_KEYS
docker compose -f docker-compose.sidecar.yml up -d
docker compose -f docker-compose.sidecar.yml exec tailscale tailscale funnel status
```

`PUBLIC_ORIGIN` is `https://<hostname>.<tailnet>.ts.net` where `<hostname>`
is `TS_HOSTNAME` (default `burndrop`).

## Trade-offs

- Funnel serves only on ports 443, 8443, and 10000 and only under the
  `ts.net` name, which is fine here.
- Throughput through Funnel is modest. Drops are a few kilobytes, so it does
  not matter.
- The name is tied to your tailnet. Moving to your own domain later means
  re-running `burndrop init` with the new relay origin; there is no data to migrate.
