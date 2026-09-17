# 1Password backend

Backend name `onepassword`, rank 95. Drives the 1Password CLI 2 (`op`).

## Requirements

- `op` 2.x on PATH (written against 2.39.0). Install: https://developer.1password.com/docs/cli/get-started/
- A signed-in account: `op signin`, the desktop app integration, or a service account token in `OP_SERVICE_ACCOUNT_TOKEN`. burndrop never signs in for you.
- Options: `Vault` (name or ID; op's default vault when empty) and `Account` (when several accounts are signed in).

## What is stored

One Secure Note item per secret:

- title `burndrop/<name>`, tag `burndrop`, category `SECURE_NOTE`
- one concealed field labelled `record` holding the burndrop JSON record `{"v":1,"meta":{...},"value":"<base64>"}`

The metadata (name, backend, retention, timestamps, purpose, source, fingerprint, size) lives inside the record, so the vault alone is enough to rebuild the local index.

## Commands

| Operation | Command |
|---|---|
| Probe | `op whoami --format json` |
| Put | `op item list --tags burndrop --format json` to find an existing item, then `op item edit <id>` or `op item create -` with the JSON template on stdin |
| Get | `op item get burndrop/<name> --fields label=record --format json --reveal` |
| Delete | `op item delete burndrop/<name>` |
| List | `op item list --tags burndrop --format json`, then one `op item get <id> --fields label=record --format json --reveal` per item; only metadata is returned |

`--vault <Vault>` and `--account <Account>` are appended when configured.

## How values travel

The record is embedded in an item JSON template written to the CLI's standard input. No value is ever placed in an argument or an environment variable. `op` output is parsed in memory and discarded.

## Limits

Values up to 64 KiB (the package maximum). 1Password caps an encrypted item at about 4 MB, far above the record size.

## Threat notes

- Anyone who can unlock the account or vault, or who holds the service account token, can read the items. Sharing the vault shares the secrets.
- `op item create` and `op item edit` print the resulting item, concealed field included, to stdout. The backend reads stdout into memory and never logs it.
- 1Password keeps item history. An overwritten record stays in the item's history, and a deleted item stays in Recently Deleted until 1Password purges it or you empty it.
- `op` writes diagnostics to stderr; the backend truncates them and never feeds them into a value. The CLI does not log field values.
- Names that differ only in letter case may look identical to `op`; the backend checks the record's own name on every read and reports "not found" on a mismatch. Duplicate titles are reported as an error until the duplicate is removed.
