# Infisical backend

Backend name `infisical`, rank 92. Drives the Infisical CLI (`infisical`).

## Requirements

- `infisical` on PATH (written against v0.43.132). Install: https://infisical.com/docs/cli/overview
- Authentication: `infisical login` for a person, or a machine identity or service token in `INFISICAL_TOKEN`.
- Project scope: `infisical init` in the working directory (writes `.infisical.json`) or `InfisicalOptions.ProjectID` (`--projectId`). `Environment` (`--env`, for example `prod`) and `Path` (`--path`, default `/`) select where the keys live.

## What is stored

One secret per burndrop name, keyed `BURNDROP_<NAME>` where `<NAME>` is the name upper-cased with every other character replaced by an underscore (the same rule as `.env` keys). The value is the burndrop JSON record `{"v":1,"meta":{...},"value":"<base64>"}`; the record keeps the original name. `api-key` and `api_key` map to the same key, so the backend refuses to overwrite a record that belongs to another name (`ErrInvalidName`) and answers `ErrNotFound` when a read finds a record with a different name.

## Commands

Every call carries `--silent`, the configured `--env`, `--projectId` and `--path`, and `INFISICAL_DISABLE_UPDATE_CHECK=true` in its environment.

| Operation | Command |
|---|---|
| Probe | `infisical secrets folders get` (lists folder names only) |
| Put | `infisical secrets get KEY --plain --expand=false --include-imports=false` (collision check), then `infisical secrets set KEY=@<tempfile>` |
| Get | `infisical secrets get KEY --plain --expand=false --include-imports=false` |
| Delete | the same get, then `infisical secrets delete KEY` |
| List | `infisical export --format=json --expand=false --include-imports=false`, metadata decoded from each `BURNDROP_` record |

## How values travel

`infisical secrets set` only accepts `KEY=VALUE` arguments and has no stdin mode, but a value written as `@<path>` makes the CLI read the file. The backend writes the record to a file created with `os.CreateTemp` (mode 0600) in `os.TempDir()`, passes only its path on the command line, and removes the file as soon as the command returns. `--plain` prints the value on stdout, which the backend reads in memory. A missing key prints nothing and exits 0; the backend maps that to `ErrNotFound`.

## Limits

Values up to 64 KiB (the package maximum). Infisical documents no smaller cap on a secret value.

## Threat notes

- Anyone with read access to the project, environment and path (roles, machine identities, service tokens) can read the records; Infisical's audit log records the reads.
- The temporary file exists for the duration of one CLI call and is readable only by the current user (on Windows it inherits the per-user permissions of the temp directory). A crash between write and remove can leave it behind; the file name starts with `burndrop-`.
- `infisical secrets set` prints the key with a masked value; `secrets get --plain` prints the value, which the backend captures and never logs.
- `--expand=false` keeps the CLI from interpreting `${...}` inside a record; `--include-imports=false` keeps records of other environments out of reads.
- Infisical keeps secret versions, so an overwritten record stays readable in the version history until it is pruned.
