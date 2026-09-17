# Doppler backend

Backend name `doppler`, rank 92. Drives the Doppler CLI (`doppler`).

## Requirements

- `doppler` on PATH (written against 3.76.5). Install: https://docs.doppler.com/docs/install-cli
- Authentication: `doppler login` for a person, or a service token in `DOPPLER_TOKEN`.
- Project scope: `doppler setup` in the working directory, or `DopplerOptions.Project` and `Config` (`--project`, `--config`).

## What is stored

One secret per burndrop name, keyed `BURNDROP_<NAME>` where `<NAME>` is the name upper-cased with every other character replaced by an underscore (Doppler names allow only upper-case letters, digits and underscores). The value is the burndrop JSON record `{"v":1,"meta":{...},"value":"<base64>"}`; the record keeps the original name. `api-key` and `api_key` map to the same key, so the backend refuses to overwrite a record that belongs to another name (`ErrInvalidName`) and answers `ErrNotFound` when a read finds a record with a different name.

## Commands

Every call carries `--no-check-version`; commands under `doppler secrets` also carry the configured `--project` and `--config`.

| Operation | Command |
|---|---|
| Probe | `doppler me --json` |
| Put | `doppler secrets get KEY --json` (collision check), then `doppler secrets set KEY --no-interactive --silent` with the record on stdin |
| Get | `doppler secrets get KEY --json` (the `raw` value) |
| Delete | the same get, then `doppler secrets delete KEY --yes --silent` |
| List | `doppler secrets --only-names --json`, then one `doppler secrets get <BURNDROP_ keys...> --json` |

## How values travel

`doppler secrets set KEY` with data on standard input reads the value from stdin, the documented `echo "value" | doppler secrets set KEY` form. The CLI reads stdin line by line (64 KiB per line), so a record is always a single line. No value is placed in an argument or environment variable. `--silent` stops `set` and `delete` from printing the resulting secrets table.

## Limits

Values up to 36 KiB (`DopplerMaxValueBytes`). Doppler caps a secret value at 50 KiB (https://docs.doppler.com/docs/platform-limits); the backend also rejects any record over 50 KiB before calling the CLI. Secret names may be 200 characters, enough for the longest burndrop name.

## Threat notes

- Anyone with read access to the project and config (workplace members, service tokens) can read the records; Doppler's activity log records changes.
- `doppler secrets get --json` prints the value to stdout, which the backend parses in memory and never logs.
- Doppler keeps a version history of every config; an overwritten or deleted record stays in the history until Doppler's retention removes it.
- `--no-interactive` makes `set` fail rather than wait for a terminal if the pipe is ever missing.
- Raw values are stored as given; Doppler's `${...}` reference expansion only affects the `computed` view, which the backend never reads.
