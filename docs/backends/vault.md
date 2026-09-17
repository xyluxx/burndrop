# HashiCorp Vault (`vault`)

Records live in a KV version 2 secrets engine, reached over Vault's HTTP API with net/http. No Vault CLI or SDK is needed.

## Requirements

- Vault (Community, Enterprise or HCP) with a KV v2 engine at `Mount` (default `secret`).
- `Address` (or `VAULT_ADDR`); https is required unless the host is localhost. `Namespace` (or `VAULT_NAMESPACE`) for Enterprise and HCP.
- A token: `Token`, else `VAULT_TOKEN`, else `~/.vault-token` written by `vault login`. The token is read on every call, so a fresh `vault login` is picked up without a restart. burndrop performs no login itself; obtain a token first.
- A policy along these lines (the default policy already allows `auth/token/lookup-self`):

```hcl
path "secret/data/burndrop/*"     { capabilities = ["create", "update", "read"] }
path "secret/metadata/burndrop/*" { capabilities = ["read", "delete"] }
path "secret/metadata/burndrop"   { capabilities = ["list"] }
```

## What is stored where

- Path: `<Mount>/data/<Path>/<name>` (default `secret/data/burndrop/<name>`). burndrop names need no rewriting.
- Data: `{"record": "<the burndrop JSON record as a string>"}`, the record being `{"v":1,"meta":{...},"value":"<base64>"}`. On read the record's `meta.name` must equal the requested name; anything else is reported as not found.

## HTTP calls

Headers: `X-Vault-Token`, `X-Vault-Namespace` when set, `Content-Type: application/json` on writes. Timeout 10 seconds.

| Operation | Call |
|---|---|
| Probe | `GET /v1/auth/token/lookup-self` |
| Put | `POST /v1/<mount>/data/<path>/<name>` with `{"data":{"record":"..."}}` |
| Get | `GET /v1/<mount>/data/<path>/<name>` |
| Delete | `GET /v1/<mount>/metadata/<path>/<name>` then `DELETE /v1/<mount>/metadata/<path>/<name>` (metadata and all versions) |
| List | `LIST /v1/<mount>/metadata/<path>` then one `GET` of the data per key |

404 maps to not found, 403 to permission denied, 503 (sealed or down) to unavailable. The value travels only in the TLS request body.

## Limits

- Values up to 64 KiB (the burndrop maximum). Vault's default request limit is 32 MiB.
- Every Put writes a new version; KV v2 keeps `max_versions` (10 by default) and older versions stay readable until overwritten or destroyed. Delete removes the metadata and every version.

## Costs

None per operation. Self-hosted or HCP Vault pricing applies.

## Threat notes

- Anyone whose policy grants `read` on the data path reads the value. Vault's audit device logs every request with the token accessor and the path, and hashes request and response values.
- Plain http is refused except for localhost, so the token and the value never cross the network unencrypted. Certificate verification is on; give `HTTPClient` a transport with your private CA when needed.
- Delete is immediate: metadata and all versions are removed and the name is reusable at once. KV v2's own soft delete of single versions is not used.
- `~/.vault-token` and `VAULT_TOKEN` unlock everything the token's policies allow; protect them as you would the secrets.
