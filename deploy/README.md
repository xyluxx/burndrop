# Deployment options

One folder per option, each with a step-by-step README. All of them run the
same relay image built from the `Dockerfile` at the repository root.

| Option | For | TLS terminated by | Inbound ports |
| --- | --- | --- | --- |
| [compose](compose/) | A server with a domain (recommended) | Caddy on your host | 80, 443 |
| [tailscale](tailscale/) | Personal use, no public server | Tailscale | none |
| [cloudflare](cloudflare/) | Hosts behind NAT, no certificate management | Cloudflare edge | none |
| [nipio](nipio/) | A quick trial with a public IP and no domain | Caddy on your host | 80, 443 |

Whatever you choose, secrets are safe: keys travel only in link fragments,
which browsers never send to servers, and the page and the agent verify each
other's keys through the fingerprint and the commitment. The deployment
choice affects availability, phishing resistance, and who can see ciphertext
and client addresses. Each README says exactly that for its option.

The full list of relay variables is in `docs/self-hosting.md`.
