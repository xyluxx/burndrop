# Azure Key Vault (`azure`)

Records live in one Key Vault, one secret per burndrop name, driven through the az CLI.

## Requirements

- Azure CLI 2.x (`az version`) on PATH, signed in: `az login`, a service principal, or a managed identity. `az account show` must succeed.
- `VaultName`: the vault (`https://<VaultName>.vault.azure.net`). Required.
- Data plane rights on the vault: with RBAC the `Key Vault Secrets Officer` role (get, list, set, delete); with access policies the secret permissions `get`, `list`, `set`, `delete`. `Purge` also needs `purge` (`Key Vault Purge Operator`).

## What is stored where

- Secret name: `burndrop-<name>` (`Prefix` changes the first part), tagged `burndrop=1` and `file-encoding=utf-8` (the CLI adds the second). Key Vault names allow only letters, digits and dashes and compare case-insensitively, so a name that is not already lower-case letters, digits and dashes is lower-cased, has dots and underscores replaced by dashes, and gets an 8 character hash suffix (`prod.db_url` becomes `burndrop-prod-db-url-1f2e3d4c`, `API-KEY` becomes `burndrop-api-key-9a8b7c6d`).
- Secret value: the burndrop JSON record `{"v":1,"meta":{...},"value":"<base64>"}`. On read the record's `meta.name` must equal the requested name; anything else is reported as not found.

## Commands

Every call adds `--output json --only-show-errors`.

| Operation | Command |
|---|---|
| Probe | `az account show` |
| Put | `az keyvault secret set --vault-name <V> --name <n> --file <tmp> --encoding utf-8 --tags burndrop=1` |
| Get | `az keyvault secret show --vault-name <V> --name <n>` |
| Delete | `az keyvault secret delete --vault-name <V> --name <n>`, then with `Purge` `az keyvault secret purge --vault-name <V> --name <n>` (retried while the soft delete is still in progress) |
| List | `az keyvault secret list --vault-name <V> --query "[?tags.burndrop=='1']"` then one `secret show` per secret |

The record is written to a file with mode 0600 in the temporary directory, passed as `--file`, and removed as soon as the command returns. `--value` is never used, so the value is never an argument.

## Limits

- Secret values hold 25 KB. The record carries the base64 value plus metadata, so values up to 18,432 bytes are accepted; larger values, or a record that does not fit, return `ErrTooLarge`.
- Names up to 127 characters, so `Prefix` must stay short. 15 tags per secret.
- Every Put creates a version; older versions stay readable to anyone with `get` until you disable or delete them.

## Costs

At the time of writing: USD 0.03 per 10,000 secret operations on standard and premium vaults, no storage charge. List costs one show per secret.

## Threat notes

- Anyone with `get` on the vault reads every secret in it; Key Vault permissions are per vault, not per secret, so give burndrop its own vault. Diagnostic logs (`AuditEvent`) record each operation with the caller and the secret name, never the value.
- The value never appears on a command line. `--debug` is never used.
- Soft delete is on for every vault: Delete keeps the secret recoverable for 7 to 90 days and reserves the name. Without `Purge`, a Put of the same name during that time fails with a message that names the purge command; with `Purge` the secret is gone for good at once. Vaults with purge protection refuse the purge; Delete then reports the failure and the name stays reserved.
- The token cache under `~/.azure` unlocks everything; protect it as you would the secrets.
