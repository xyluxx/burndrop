# Documentation

Start with the [project README](../README.md) for the overview and the
five-minute quickstart. The documents here go deeper, roughly in the order a
new reader needs them.

## Using burndrop

| Document | What it covers |
| --- | --- |
| [Agent integration](agent-integration.md) | Connecting MCP clients, the eight tools and their results, the instruction files, and using the CLI or the SDKs without MCP |
| [CLI reference](cli.md) | Every `burndrop` command, flag, exit code, and output format |
| [Storage backends](storage-backends.md) | The twelve backends, how `init` chooses one, retention policies, and per-backend configuration |
| [Browser extension](browser-extension.md) | What the extension protects against, installing it, and building it from source |
| [Troubleshooting](troubleshooting.md) | Symptoms, causes, and fixes for the relay, the page, the agent, and the backends |

## Running a relay

| Document | What it covers |
| --- | --- |
| [Self-hosting](self-hosting.md) | Every environment variable, sizing, Redis or Valkey, proxies, logging, and upgrades |
| [Compose with Caddy](../deploy/compose/README.md) | The recommended deployment for a server with a domain |
| [Tailscale Funnel](../deploy/tailscale/README.md) | A relay on a tailnet with no public server |
| [Cloudflare Tunnel](../deploy/cloudflare/README.md) | A relay behind NAT |
| [nip.io or sslip.io](../deploy/nipio/README.md) | A quick trial on a public IP without DNS |
| [Relay API](api.md) | Endpoints, request and response bodies, error codes, headers, and rate limits |

## How it is built and why it is safe

| Document | What it covers |
| --- | --- |
| [Architecture](architecture.md) | The parts, the trust boundaries, both flows as sequence diagrams, and the repository layout |
| [Threat model](threat-model.md) | Assets, attackers, what each control defends against, and what remains out of scope |
| [Cryptography specification](crypto-spec.md) | Algorithms, encodings, envelope format, padding, fingerprints, commitments, and the shared test vectors |
| [Release verification](release-verification.md) | Checking signatures, attestations, SBOMs, the page hash, and the package provenance |
| [Comparison](comparison.md) | How burndrop relates to one-time secret sharing sites, password managers, and secret managers |
| [Design](design.md) | The original design document with the decisions taken and the reasoning behind them |

Research notes from before the first line of code live in
[research/](research/).
