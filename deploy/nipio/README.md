# Quick trial with nip.io or sslip.io

`nip.io` and `sslip.io` are public wildcard DNS services: the name
`drop.203-0-113-10.nip.io` resolves to `203.0.113.10` with no DNS setup on
your side. Combined with Caddy's automatic certificates, a relay is reachable
over HTTPS a few minutes after you have a host with a public IP.

Use this to try burndrop. For anything longer than a trial, use your own
domain (`deploy/compose`) and understand the trade-offs below.

## Steps

```bash
cd deploy/nipio
cp .env.example .env     # DOMAIN=drop.<your-ip-with-hyphens>.nip.io
docker compose run --rm relay keygen -id agent1    # put the hash line in .env
docker compose up -d
burndrop verify-page -relay https://$DOMAIN
```

The Compose file includes `deploy/compose/docker-compose.yml`, so everything
in that README applies (Caddy on 80 and 443, the relay unpublished behind it).

## Trade-offs

- DNS for your relay is operated by a third party you have no agreement with.
  If the service is down or discontinued, your links stop resolving.
- Names are long and not memorable, and a lookalike is trivial: anyone can
  register the same pattern on another IP. Humans cannot tell
  `drop.203-0-113-10.nip.io` from `drop.203-0-113-11.nip.io`. Fingerprint
  comparison on the page still protects the secret itself, but phishing for a
  different secret becomes easier.
- Let's Encrypt rate limits are per registered domain, and every nip.io user
  shares the same one. Certificate issuance can fail during busy periods.
- The name embeds your IP address, so the relay moves when the IP changes and
  every agent has to run `burndrop init` again.

None of these weaken the encryption: a link's key never reaches the relay, and
the page verifies against the published hash regardless of the name it is
served under.
