# Bitwarden backend

Backend name `bitwarden`, rank 94. Drives the Bitwarden CLI (`bw`).

## Requirements

- `bw` on PATH (written against @bitwarden/cli 2026.8.0): `npm install -g @bitwarden/cli` or the release binary. Docs: https://bitwarden.com/help/cli/
- Logged in and unlocked: `bw login`, then `export BW_SESSION="$(bw unlock --raw)"`. The session key can also be given as `BitwardenOptions.Session`; it is passed to `bw` as `BW_SESSION`.
- Works with Bitwarden cloud, self-hosted Bitwarden and Vaultwarden (`bw config server <url>` before `bw login`).

## What is stored

One Secure Note per secret: name `burndrop/<name>`, type 2 with `secureNote.type` 0, and the notes field holding the burndrop JSON record `{"v":1,"meta":{...},"value":"<base64>"}`. New items get no folder, organization or collection; an overwritten item keeps the ones it has.

## Commands

Every call carries `--nointeraction`, so a locked vault fails instead of prompting for the master password.

| Operation | Command |
|---|---|
| Probe | `bw status` (the JSON `status` must be `unlocked`) |
| Put | `bw list items --search burndrop/<name>` to find the item, then `bw edit item <id>` or `bw create item` with the base64 JSON on stdin |
| Get | `bw list items --search burndrop/<name>`, filtered on the exact name |
| Delete | the same search, then `bw delete item <id> --permanent` for every exact match |
| List | `bw list items --search burndrop/`, metadata decoded from each record |

`--search` is a substring match, so results are always filtered on the exact item name in memory.

## How values travel

`bw create item` and `bw edit item` read the base64 encoded item JSON from standard input when the argument is omitted (the same bytes `bw encode` would print). No value is placed in an argument. The session key travels in the environment, which is how the CLI is designed to receive it.

## Limits

Values up to 4 KiB (`BitwardenMaxValueBytes`). The Bitwarden server rejects a note whose encrypted form exceeds 10,000 characters. The backend estimates that length before calling `bw` and returns `ErrTooLarge` early; it also maps the server's "exceeds the maximum encrypted value length" error to `ErrTooLarge`.

## Threat notes

- Anyone with the master password or a valid `BW_SESSION` can read the items; treat the session key as you would the vault.
- `bw` keeps an encrypted copy of the vault in its data directory and decrypts in memory only. `bw list`, `bw create` and `bw edit` print item JSON, notes included, to stdout; the backend parses it in memory and never logs it.
- Deletion is permanent (`--permanent`); nothing is left in the trash. The server may keep revision history under its own retention rules.
- The backend runs one `bw` process at a time per burndrop process because the CLI rewrites its local data file after every write.
- Other devices see new items after they sync; run `bw sync` on a machine that shares the account.
