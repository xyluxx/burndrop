# Google Cloud Secret Manager (`gcp`)

Records live in Secret Manager, one secret per burndrop name, driven through the gcloud CLI.

## Requirements

- Google Cloud CLI (`gcloud`) on PATH, signed in: `gcloud auth login`, a service account through `gcloud auth activate-service-account`, or workload identity. `gcloud auth list` must show an active account.
- A project: `Project` (passed as `--project`) or the gcloud default (`gcloud config set project`).
- The Secret Manager API enabled, and IAM on the project or the secrets: `secretmanager.secrets.create`, `secretmanager.versions.add`, `secretmanager.versions.access`, `secretmanager.secrets.get`, `secretmanager.secrets.delete`, `secretmanager.secrets.list`. `roles/secretmanager.admin` covers all of them; `roles/secretmanager.secretAccessor` alone is read only.

## What is stored where

- Secret ID: `burndrop-<name>` (`Prefix` changes the first part), label `burndrop=1`, automatic replication. Secret IDs allow letters, digits, underscore and dash, so a name with a dot has its dots replaced by dashes and gets an 8 character hash suffix (`prod.db_url` becomes `burndrop-prod-db_url-1f2e3d4c`). Names without dots are kept as they are.
- Payload of the latest version: the burndrop JSON record `{"v":1,"meta":{...},"value":"<base64>"}`. On read the record's `meta.name` must equal the requested name; anything else is reported as not found.

## Commands

| Operation | Command |
|---|---|
| Probe | `gcloud auth list --filter=status:ACTIVE --format=json`, then `gcloud config get-value project` when `Project` is unset |
| Put | `gcloud secrets create <id> --data-file=- --replication-policy=automatic --labels=burndrop=1`; on `ALREADY_EXISTS` `gcloud secrets versions add <id> --data-file=-` |
| Get | `gcloud secrets versions access latest --secret=<id>` |
| Delete | `gcloud secrets describe <id> --format=json` then `gcloud secrets delete <id> --quiet` |
| List | `gcloud secrets list --filter=labels.burndrop=1 --format=json` then one `versions access` per secret |

`--project=<Project>` is appended to every `secrets` command when set. The record goes to gcloud on standard input (`--data-file=-`); it is never an argument, an environment variable or a file.

## Limits

- Payload 64 KiB. The record carries the base64 value plus metadata, so values up to 48,384 bytes are accepted; larger values, or a record that does not fit, return `ErrTooLarge`.
- Secret IDs up to 255 characters. Write quota 600 per minute per project, access quota 90,000 per minute.
- Every Put adds a version; earlier versions stay enabled, readable and billed until you destroy them or delete the secret. burndrop never destroys versions on its own.

## Costs

At the time of writing: USD 0.06 per active secret version per replica location per month (six versions free) and USD 0.03 per 10,000 access operations. List costs one access per secret. Check the pricing page.

## Threat notes

- Anyone with `secretmanager.versions.access` on the secret or the project reads it. Admin activity is in Cloud Audit Logs by default; data access logs (each access) must be switched on. Logs carry the caller and the secret name, never the payload.
- The payload travels over a pipe to gcloud, so process listings and shell history stay clean. gcloud logs its invocations (not stdin) under its configuration directory.
- Delete is immediate and irreversible: all versions are destroyed and the name is reusable at once. There is no soft delete.
- The credentials under `~/.config/gcloud` unlock everything; protect them as you would the secrets.
