# Storage backends

A storage backend is where the agent keeps the secrets it receives. burndrop ships twelve, behind one interface (`internal/storage`): the OS credential store, an age-encrypted vault file, process memory, a `.env` file (opt-in, weakest), and eight external managers driven through their own CLIs or HTTP API. Values go from the relay client into the backend and from the backend into subprocess environments; they are never returned to the language model, never logged, and never written anywhere in plaintext except by the `dotenv` backend, which says so when you choose it. This page is the index and comparison; each external backend has its own page under `docs/backends/`.

## What a backend stores

Every secret is one record, stored as one item in the backend:

```json
{"v":1,"meta":{"name":"openai-api-key","backend":"keychain","retention":"until-revoked","created_at":"2026-09-17T12:03:51Z","source":"drop","sendable":false,"fingerprint":"978a-5944-726e-964c","size_bytes":51},"value":"<base64 of the bytes>"}
```

Values are bytes, at most 64 KiB (`MaxValueBytes`); the program uses them and the model never sees them. The metadata travels with the value so a value is never found without its context:

| Field | Meaning |
|---|---|
| `name` | The reference name: 1 to 100 characters of letters, digits, `.`, `_`, `-`, starting with a letter or digit, no `..` |
| `backend` | Which backend holds it |
| `retention` | `session`, `until-revoked`, or `until:<RFC 3339 date>` |
| `created_at`, `expires_at` | When it was stored and, for `until:` policies, when it is purged |
| `purpose` | The sentence shown to the human when it was requested |
| `source` | `drop` (received from a human), `capture` (output of `run_with_secret`), or `import` |
| `sendable` | Whether `send_secret` may hand it to a human |
| `fingerprint` | The request key fingerprint the human compared, for drops |
| `size_bytes` | Length of the value |
| `kind` | Empty for secrets; `pending` for the agent's own outstanding-request records, which listings hide |

Beside the backend, the agent keeps `index.json` in its state directory: names and metadata only, never values, mode 0600, written atomically. It exists because a keychain cannot be enumerated, so `list` works without touching values, and it is rebuilt entry by entry as secrets are stored and deleted. Backends that can enumerate (everything except `keychain`) still store the metadata inside each record, so the index can be rebuilt from them.

## Retention policies

| Policy | Where the value lives | When it is destroyed |
|---|---|---|
| `session` | Process memory of the process that fetched it (the MCP server or one CLI invocation), in the `memory` backend regardless of the configured one | When that process exits, on `delete_secret`, or on `run_with_secret` with `consume` |
| `until:<date>` | The configured backend, with `expires_at` in the metadata | On the first `list`, `get`, or `fetch` after the date, by `burndrop doctor` (`purge expired`), and by every `list_secrets` call |
| `until-revoked` | The configured backend | On `delete_secret`, `burndrop delete`, or `run_with_secret` with `consume` |

A `session` secret shadows a persistent one with the same name for the life of the process. Because a CLI process ends immediately, `session` retention is only useful inside a long-running process such as `burndrop mcp` or an SDK; `burndrop fetch -retention session` stores the value and then loses it when the command returns. The default is `until-revoked` (`default_retention` in the config).

## The twelve backends

| Name | Uses | Where the value lives | Platforms | Needs | Rank |
|---|---|---|---|---|---|
| `onepassword` | 1Password CLI 2 (`op`) | A Secure Note `burndrop/<name>` with a concealed `record` field, tag `burndrop` | Anywhere `op` runs | `op signin` or a service account token | 95 |
| `bitwarden` | Bitwarden CLI (`bw`) | A Secure Note `burndrop/<name>`; values up to 4 KiB | Anywhere `bw` runs | `bw login`, `bw unlock`, `BW_SESSION` | 94 |
| `infisical` | Infisical CLI | Secret `BURNDROP_<NAME>` in a project, environment, and path | Anywhere the CLI runs | `infisical login` or `INFISICAL_TOKEN`, `infisical init` or a project id | 86 |
| `doppler` | Doppler CLI | Secret `BURNDROP_<NAME>` in a project and config; values up to 36 KiB | Anywhere the CLI runs | `doppler login` or `DOPPLER_TOKEN`, `doppler setup` or project and config | 86 |
| `vault` | HashiCorp Vault KV v2 over HTTP (no CLI, no SDK) | `<mount>/data/<path>/<name>`, default `secret/data/burndrop/<name>` | Anywhere with network access | `VAULT_ADDR` (https unless localhost), a token from `VAULT_TOKEN` or `~/.vault-token` | 85 |
| `aws` | AWS CLI v2 | Secrets Manager secret `burndrop/<name>`; values up to 48,384 bytes | Anywhere `aws` runs | Credentials the CLI can find | 85 |
| `gcp` | Google Cloud CLI | Secret Manager secret `burndrop-<name>`, label `burndrop=1`; values up to 48,384 bytes | Anywhere `gcloud` runs | An active account and a project | 85 |
| `azure` | Azure CLI | Key Vault secret `burndrop-<name>`, tag `burndrop=1`; values up to 18,432 bytes | Anywhere `az` runs | `az login` and `vault_name` | 85 |
| `keychain` | `go-keyring` | macOS Keychain, Windows Credential Manager, or a Secret Service keyring (GNOME Keyring, KWallet) under service `burndrop` | Desktops with a credential store | An unlocked login session; on Linux a running Secret Service | 90 |
| `agevault` | age (X25519 plus ChaCha20-Poly1305) | One file `vault.age` in the state directory, mode 0600, rewritten atomically; the key in the keychain, an identity file, or a passphrase | Everywhere | Nothing beyond a place for the key | 80 |
| `memory` | Process memory | Nowhere on disk; gone at exit | Everywhere | Nothing | 10 |
| `dotenv` | A plain file | `<state dir>/.env`, mode 0600, `KEY="value"` lines with a metadata comment | Everywhere | `-allow-dotenv`, and the file must be git-ignored if inside a repository | 1 |

Ranks are the `Probe.Rank` values in the code; `init` uses them to order the table and pick a recommendation. External CLIs are used so the binary carries no vendor SDKs and reuses your existing login; Vault gets a native client because its HTTP API is small and it is common on hosts without the CLI. Values never appear on a command line: they travel on standard input, in a temporary file with mode 0600 (`aws`, `azure`, `infisical`), or in a TLS request body (`vault`).

## How `init` picks a backend

`burndrop init` builds one instance of every backend with default options, calls `Probe` on each, and prints the table. Probes never store a real value: the keychain writes and deletes a random test entry, the vendor backends run a `whoami`-style command (`op whoami`, `bw status`, `doppler me`, `infisical secrets folders get`, `aws sts get-caller-identity`, `gcloud auth list`, `az account show`, `GET /v1/auth/token/lookup-self`), `agevault` opens or creates the vault file, `dotenv` checks the git-ignore rule. Available backends are sorted by rank, highest first, then unavailable ones in the built-in order, and the first available one is recommended. Two guards apply:

- `dotenv` is never accepted, as recommendation or by `-storage dotenv`, without `-allow-dotenv`.
- When nothing is available the command fails with `no storage backend is available; install a credential store or use -storage agevault`.

A signed-in cloud or team CLI ranks below the OS keychain and the password managers, so a laptop with a working `aws` or `gcloud` login is still recommended `keychain`; pass `-storage aws` (or another name) to use that manager instead. On a headless Linux server without a Secret Service daemon, `keychain` is unavailable and `agevault` is the usual answer; `init` then generates an identity file next to the vault and records its path as `identity_file` (switch to `passphrase_env`, described below, if you prefer a passphrase).

## Configuration keys

The config file is TOML. `storage` names the backend and `[backends.<name>]` holds its options; only the table for the selected backend is read, and unknown keys anywhere are rejected (`config.toml: unknown keys: ...`). Every key is optional unless stated.

```toml
relay = "https://relay.example"
storage = "keychain"
agent_key = "keychain:burndrop/agent-key"   # or "env:BURNDROP_API_KEY"; never a plain value
default_ttl = "1h"
default_retention = "until-revoked"

[backends.keychain]
service = "burndrop"          # credential store service name; also used for the agevault key and the agent key
```

```toml
storage = "agevault"
[backends.agevault]
path = "/var/lib/burndrop/vault.age"     # default <state dir>/vault.age
identity_file = "/etc/burndrop/vault.key" # an age X25519 identity; created with mode 0600 if missing
passphrase_env = "BURNDROP_VAULT_PASSPHRASE" # or derive the key from a passphrase in this variable
```

```toml
storage = "dotenv"
[backends.dotenv]
path = "/home/agent1/.local/state/burndrop/.env"   # written by init; default <state dir>/.env
```

```toml
storage = "onepassword"
[backends.onepassword]
vault = "Agents"        # vault name or id; op's default vault when empty
account = "my-team"     # shorthand, sign-in address, or id when several accounts are signed in
```

```toml
storage = "bitwarden"
[backends.bitwarden]
session_env = "BW_SESSION"   # variable holding the "bw unlock --raw" key; empty lets bw read BW_SESSION itself
```

```toml
storage = "vault"
[backends.vault]
address = "https://vault.example:8200"  # VAULT_ADDR when empty; https unless localhost
mount = "secret"                        # KV v2 mount, default secret
path = "burndrop"                       # path under the mount, default burndrop
namespace = "team-a"                    # VAULT_NAMESPACE when empty (Enterprise, HCP)
token_env = "VAULT_TOKEN"               # else VAULT_TOKEN, then ~/.vault-token, read on every call
```

```toml
storage = "infisical"
[backends.infisical]
project_id = "<project id>"   # or run infisical init in the working directory
environment = "prod"          # --env
path = "/"                    # --path
```

```toml
storage = "doppler"
[backends.doppler]
project = "agents"   # --project; or run doppler setup in the working directory
config = "prd"       # --config
```

```toml
storage = "aws"
[backends.aws]
region = "eu-west-1"     # --region when set
profile = "agents"       # --profile when set
prefix = "burndrop/"     # secret name prefix, default burndrop/
```

```toml
storage = "gcp"
[backends.gcp]
project = "my-project"   # --project; else the gcloud default project
prefix = "burndrop-"     # secret id prefix, default burndrop-
```

```toml
storage = "azure"
[backends.azure]
vault_name = "agents-kv"   # required; the vault https://<vault_name>.vault.azure.net
prefix = "burndrop-"       # default burndrop-; letters, digits, dashes only
purge = true               # purge soft-deleted secrets at once so names can be reused
```

`memory` takes no options. When `session_env`, `token_env`, or `passphrase_env` names a variable that is empty, opening the backend fails with `bitwarden session variable X is empty`, `vault token variable X is empty`, or `agevault passphrase variable X is empty`.

## Notes per backend

**dotenv** is the weakest option and is documented as such: the file is readable by any process running as your user, and by anyone who obtains the file. `init` refuses it unless `-allow-dotenv` is given, and the backend refuses to write a file inside a git repository unless git ignores it (`storage: permission denied: <path> is inside a git repository and is not ignored; add it to .gitignore first`). Names become environment keys by upper-casing and replacing every other character with `_`, so `api-key` and `api_key` collide and the second is refused. Binary values are base64-encoded and marked as such in the metadata comment.

**agevault** holds every secret in one age-encrypted file and takes its key from the first configured source: `identity_file` (an `AGE-SECRET-KEY-...` line; created if the file does not exist), then `passphrase_env` (scrypt), then the keychain entry `vault-identity` under the keychain service (generated on first use). Reading a vault written under another key fails with `storage: permission denied: the vault at <path> was encrypted with a different key`. Writers take a `vault.age.lock` file; a lock older than a minute is treated as abandoned, and waiting more than 5 seconds fails with `storage: vault is locked by another process`. Back up the key with the file or the file is unreadable.

**keychain** files entries under the service name (`burndrop` unless `[backends.keychain] service` says otherwise). The Windows Credential Manager caps a blob at 2560 bytes, so records over 2000 bytes are split across numbered entries (`<name>#0`, `<name>#1`, ...) behind a header entry; large records therefore show as several credentials in the Windows UI. The store cannot be listed, so `list` relies on `index.json`. The same store keeps the relay agent key (`agent-key`) and the agevault key (`vault-identity`).

**memory** is the backend for `session` retention and the recommended choice for CI runners: nothing survives the job. Configured as the persistent backend, it means every CLI invocation starts empty; pending requests then do not survive between `burndrop request` and `burndrop fetch` either, so use it with `burndrop mcp` or an SDK process, not with one-shot CLI calls.

**External managers** map names conservatively: `onepassword` and `bitwarden` use item titles, `infisical` and `doppler` upper-case the name, `gcp` and `azure` rewrite names that contain characters the service rejects and add an 8-character hash suffix. Every read checks that the record's own `meta.name` equals the requested name and reports `not found` otherwise, so a foreign item under a burndrop name is never returned as a secret. Version histories are the operator's concern: 1Password, Infisical, Doppler, Vault, Secrets Manager, Secret Manager, and Key Vault all keep previous versions of an overwritten record until you prune them. Each page states the exact commands, permissions, limits, costs, and threat notes:

- [backends/onepassword.md](backends/onepassword.md)
- [backends/bitwarden.md](backends/bitwarden.md)
- [backends/infisical.md](backends/infisical.md)
- [backends/doppler.md](backends/doppler.md)
- [backends/vault.md](backends/vault.md)
- [backends/aws.md](backends/aws.md)
- [backends/gcp.md](backends/gcp.md)
- [backends/azure.md](backends/azure.md)

## Recommendations by environment

| Environment | Recommendation | Why |
|---|---|---|
| Personal laptop | `keychain`, or `onepassword` or `bitwarden` when you already use them | Protected by the OS or the password manager, unlocked with your login session |
| Headless server | `agevault` with `identity_file` on a root-owned path, or `vault` | No keychain daemon; encrypted at rest; key separated from data |
| Docker container | `memory`, or `agevault` with the identity mounted as a secret | Containers are ephemeral; never bake secrets into images |
| Kubernetes | `vault`, a cloud secret manager, or `agevault` with a mounted key | Central rotation and audit |
| CI runner | `memory` with `session` retention | Nothing should survive the job |

Adding a backend means implementing the six-method `Backend` interface (`Name`, `Probe`, `Put`, `Get`, `Delete`, `List`) and registering it with `agent.RegisterBackend`; the conformance suite in `internal/storage/suite_test.go` runs against a fake CLI runner so no real account is needed in tests.
