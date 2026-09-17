# CLI reference

`burndrop` is the agent-side binary: it runs the MCP server, drives the request, fetch, send, and run flows from a shell, gives humans a terminal alternative to the drop page, and checks a deployment. `burndrop-relay` is the relay. This page lists every command, flag, output, and exit code of both, in the order of `burndrop help`. The flows themselves are explained in [agent-integration.md](agent-integration.md); the relay's variables are in [self-hosting.md](self-hosting.md).

## Global behavior

### Files and environment

| Item | Windows | macOS | Linux and others |
|---|---|---|---|
| Config file | `%APPDATA%\burndrop\config.toml` | `~/Library/Application Support/burndrop/config.toml` | `$XDG_CONFIG_HOME/burndrop/config.toml`, else `~/.config/burndrop/config.toml` |
| State directory | `%LOCALAPPDATA%\burndrop` | `~/Library/Application Support/burndrop` | `$XDG_STATE_HOME/burndrop`, else `~/.local/state/burndrop` |

`HOME` is honored first on every platform (`USERPROFILE` as a fallback on Windows). The state directory (created with mode 0700) holds `index.json` (names and metadata, never values), `vault.age` (the agevault backend), `audit.log`, and `.env` (the dotenv backend).

| Variable | Effect |
|---|---|
| `BURNDROP_CONFIG` | Path of the config file to use instead of the platform default |
| `BURNDROP_STATE_DIR` | Directory to use instead of the platform state directory |
| `BURNDROP_API_KEY` | The relay agent key. Used when `agent_key` in the config is `env:BURNDROP_API_KEY`, and tried first when `agent_key` is absent |

The agent key is resolved in this order: `agent_key = "env:<VAR>"` reads that variable; `agent_key = "keychain:burndrop/<entry>"` reads the OS credential store (only the service `burndrop` is supported by the CLI); with no `agent_key`, `BURNDROP_API_KEY` is tried, then `keychain:burndrop/agent-key`. Commands that talk to the relay as an agent (`mcp`, `request`, `fetch`, `send`, `run`, `revoke`) fail without a key: `error: agent key not found in the keychain (keychain:burndrop/agent-key): storage: secret not found (run burndrop init, or set BURNDROP_API_KEY)`. `list`, `delete`, `pending`, `audit`, and `doctor` work without one. The config file format is in [storage-backends.md](storage-backends.md) and [agent-integration.md](agent-integration.md).

### Flags, input, and confirmation

- Flags use Go syntax: `-name value`, `-name=value`, booleans as `-yes`. Flags may come after positional arguments (`burndrop drop LINK -yes`). Everything after `--` is positional; `run` stops parsing at the first positional so the child command keeps its own flags.
- `burndrop <command> -h` prints the usage line and flags to stderr and exits 0.
- Secret values (`drop`) come from `-file PATH`, otherwise from standard input when it is not a terminal (trailing newlines stripped, at most 64 KiB), otherwise from a hidden prompt `Secret value (not echoed): ` on stderr.
- Commands that ask `[y/N]` accept `y` or `yes`. When stdin is not a terminal they fail with `confirmation needed; pass -yes when not running interactively` unless `-yes` is given.
- `-json` prints the command's result as indented JSON on stdout. Links are written verbatim (the encoder does not escape `&`), so they can be copied out of the raw output.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (`fetch` exits 0 only when the status is not `waiting`) |
| 1 | An error, printed to stderr as `error: <message>` |
| 2 | Usage: no command, unknown command, missing required argument, or a bad flag |
| child code, 124 | `run` only: the child's exit code, or 124 when the timeout stopped it |

## Commands

### init

```
burndrop init -relay URL [-storage NAME] [-agent-key-from env|keychain|prompt] [-page-origin URL] [-allow-dotenv] [-yes]
```

| Flag | Meaning |
|---|---|
| `-relay URL` | Required. Relay origin, `https://relay.example` (`http://` only for localhost) |
| `-storage NAME` | Backend to use; default is the strongest available (see [storage-backends.md](storage-backends.md)) |
| `-agent-key-from` | `env` (read `BURNDROP_API_KEY` at run time), `keychain` or `prompt` (ask now with a hidden prompt and store it in the OS credential store). Default: keychain |
| `-page-origin URL` | Origin of the drop page when it is not served by the relay |
| `-allow-dotenv` | Permit the `dotenv` backend, which stores values in a plain file |
| `-yes` | Accept the recommendation without asking |

Prints `relay <origin>: version <v>, default link lifetime <n>s, agent auth <required|off>`, then `probing storage backends...` and a `BACKEND AVAILABLE NOTE` table, then `recommended: <name> (<reason>)` and `Use it? [y/N]` (skipped with `-yes` or `-storage`). Unless the relay reports `agent_auth` `off` or `-agent-key-from env` was given, it asks `Agent key from the relay operator (not echoed): ` and stores the key under the keychain service `burndrop`, entry `agent-key`, printing `agent key stored in the keychain`; with `env` it prints `the agent key will be read from BURNDROP_API_KEY at run time`. It ends with `wrote <config path>`, `storage: <name>`, and a `next:` hint. The written file (mode 0600) contains `relay`, `storage`, `default_ttl = "1h"`, `default_retention = "until-revoked"`, `agent_key`, `page_origin` when given, and `[backends.dotenv] path` when dotenv was chosen.

Errors (exit 1): `the relay at <origin> did not answer: ...`; `no storage backend is available; install a credential store or use -storage agevault`; `only the dotenv backend is available; pass -allow-dotenv to accept a plain file, or -storage agevault`; `the dotenv backend stores values in a plain file; pass -allow-dotenv to accept that`; `unknown storage backend "x"; choose one of keychain, agevault, memory, dotenv, onepassword, bitwarden, vault, infisical, doppler, aws, gcp, azure`; `cancelled; rerun with -storage NAME`; `an agent key is required because the relay requires agent auth; rerun with -agent-key-from env to supply it at run time`; `could not store the agent key in the keychain (...); rerun with -agent-key-from env`. Choosing an unavailable backend explicitly is allowed with a warning on stderr.

### mcp

```
burndrop mcp [-no-confirm]
```

Runs the MCP server on standard input and output until the client closes the pipe or the process is interrupted. `-no-confirm` disables the elicitation prompt before `send_secret`. On start it writes `burndrop <version>: MCP server on stdio, relay <origin>, storage <backend>` to stderr. Needs the agent key. See [agent-integration.md](agent-integration.md) for client configuration.

### request

```
burndrop request -name NAME -purpose TEXT [-retention POLICY] [-ttl DURATION] [-sendable] [-json]
```

| Flag | Meaning |
|---|---|
| `-name` | Required. 1 to 100 characters of letters, digits, dot, underscore, or dash, starting with a letter or digit, no `..` |
| `-purpose` | Required. One sentence for the human, at most 200 characters |
| `-retention` | `session`, `until-revoked`, or `until:<RFC 3339 date>`; default from the config (`until-revoked`) |
| `-ttl` | Link lifetime such as `30m` or `2h`; default from the config (`1h`); the relay clamps it to its maximum |
| `-sendable` | Allow the secret to be sent back to a human later with `send` |
| `-json` | Print `request_id`, `link`, `fingerprint`, `expires_at`, `storage`, `retention`, `message` |

Prints the ready-to-send message (link, purpose, storage, retention, expiry, fingerprint), a blank line, and `request id: <id>`. Exit 2 when `-name` or `-purpose` is missing; exit 1 on validation errors such as `ttl "abc" is not a positive duration such as 30m or 2h` or `storage: invalid retention policy: date is in the past`, and on relay errors such as `relay: unauthorized [HTTP 401]`.

### fetch

```
burndrop fetch [REQUEST_ID] [-wait SECONDS] [-json]
```

`REQUEST_ID` may be omitted when exactly one request is pending; otherwise `error: no pending request with that id` or `error: more than one request is pending; pass request_id`. `-wait` is the number of seconds to wait for the submission (default 30; `0` also means 30; values above 300 are clamped to 300). Prints `<status>: <message>`. With status `waiting` the command exits 1 with `error: still waiting; run fetch again`. Other statuses (`stored`, `expired`, `revoked`, `gone`, `rejected`) exit 0; see [agent-integration.md](agent-integration.md) for their meaning. `-json` prints `status`, `request_id`, `name`, `storage`, `retention`, `fingerprint`, `size_bytes`, `expires_at`, `message`.

### send

```
burndrop send NAME [-ttl DURATION] [-delete-after] [-yes] [-json]
```

Checks that `NAME` exists and is marked sendable before asking `Create a one-time link that reveals "NAME" to whoever opens it? [y/N]`, then creates the reveal and prints the message for the human. `-delete-after` deletes the agent's copy once the link exists (the message then says `I have deleted my copy of it.`). Errors: `this secret was received from a human and is not marked sendable; only secrets created by the agent or marked sendable by the operator can be sent`; `storage: secret not found`; `cancelled`. `-json` prints `request_id`, `link`, `expires_at`, `keeps_copy`, `message`.

### run

```
burndrop run [-env VAR=NAME ...] [-capture-as NAME] [-timeout SECONDS] [-cwd DIR] -- COMMAND [ARGS...]
```

| Flag | Meaning |
|---|---|
| `-env VAR=NAME` | Inject secret `NAME` as environment variable `VAR`; repeatable. `VAR` must match `[A-Za-z_][A-Za-z0-9_]*` |
| `-capture-as NAME` | Store the command's standard output as a new sendable secret instead of printing it |
| `-capture-pattern RE` | Regular expression with exactly one capture group applied to the output; default is the whole trimmed output |
| `-capture-retention` | Retention for the captured secret; default from the config |
| `-timeout SECONDS` | Stop the command after this long (default 120, maximum 3600) |
| `-cwd DIR` | Working directory |
| `-consume` | Delete the used secrets after the run |

The child inherits the environment with the injected variables overriding same-named ones. Its stdout goes to stdout and its stderr to stderr, both with every known secret value replaced by `[redacted:<name>]` and cut at `run_with_secret.max_output_bytes` (32768) with a `[truncated]` marker. With `-capture-as` nothing from stdout is printed; the result line (`Stored the command output as NAME (N bytes) in <backend>. ...`) and messages such as `The command was stopped after 1s.` go to stderr. Exit code: the child's, 124 on timeout, 1 when the command could not start (`could not start X: ...`), a secret is missing, or the program is not in `run_with_secret.allowed_commands`. Exit 2 when no command follows `--`.

### list

```
burndrop list [-json]
```

Prints `NAME STORAGE RETENTION CREATED EXPIRES SENDABLE SOURCE BYTES` for every stored secret, or `no stored secrets`. Expired entries are purged first. `-json` prints an array of metadata objects (`name`, `backend`, `retention`, `created_at`, `expires_at`, `purpose`, `source`, `sendable`, `fingerprint`, `size_bytes`). Pending requests are hidden; see `pending`. Values are never shown.

### delete

```
burndrop delete NAME
```

Prints `deleted NAME`. Error: `storage: secret not found`.

### pending

```
burndrop pending [-json]
```

Prints `REQUEST ID NAME FINGERPRINT RETENTION EXPIRES` for outstanding requests, oldest first, or `no pending requests`. `-json` adds `purpose`, `storage`, and `created_at`.

### revoke

```
burndrop revoke REQUEST_ID
```

Cancels the request on the relay and forgets it locally. Prints `request <id> is now <state>`: `revoked` normally, the relay's terminal state when it was already `fetched` or `expired`, or `expired` when the relay no longer knows the id. Error: `no pending request with that id`.

### audit

```
burndrop audit [-n COUNT] [-json]
```

Shows the last `COUNT` (default 50) audit events, oldest first, as `TIME EVENT NAME REQUEST RESULT DETAIL`, or `no audit events`. `-json` prints the raw events including their `fields`.

### drop

```
burndrop drop LINK [-file PATH] [-yes]
```

The human side of a request without a browser. Prints to stderr what the agent asked for (`name`, `purpose`, `stored in`, `kept`, `fingerprint`, `relay`) and `Compare the fingerprint with the one the agent showed you before continuing.`, checks that the slot is still `created`, asks `Submit a secret for this request? [y/N]`, reads the value, seals it exactly as the page does, uploads it, and prints `submitted NAME (N bytes, encrypted to fingerprint F); the link is now spent`. Errors: `this is not a valid drop link: ...`; `this link has expired or was never created`; `this link can no longer be used (state: uploaded|fetched|revoked|expired)`; `empty value`; `the key in this link does not match the key the agent registered; the link was altered, do not use it`.

### open

```
burndrop open LINK [-yes]
```

The human side of a reveal without a browser. Prints the name, whether the agent keeps a copy, and the relay to stderr, warns `Opening it deletes it from the relay; it can be shown only once.`, asks `Reveal it now? [y/N]`, then writes the value to stdout (with a trailing newline added if missing) and `(the relay copy is deleted; store the value somewhere safe)` to stderr. Errors: `this is not a valid reveal link: ...`; `this link has expired or was never created`; `this link was already used or revoked (state: opened|revoked|expired)`; `cancelled; the secret is still on the relay until <time>`; `the secret could not be decrypted: the link was altered or the relay returned the wrong data; the relay copy is gone, ask the agent to send it again`.

### verify-page

```
burndrop verify-page [-relay URL] [-expect SHA256]
```

Fetches `/drop` from the relay (`-relay`, default from the config) and prints `served page: <hex>`, `relay reports: <hex> (page version <v>)`, `this binary: <hex> (page version <v>)` or `this binary: no page embedded`, and `expected: <hex>` when `-expect` is given. A difference between the served hash and the one the relay reports, or between the served hash and `-expect`, prints a `MISMATCH:` line and exits 1 with `page verification failed; do not use this relay's page until the operator explains the difference`. A difference from the binary's own page is only a `note:`. Otherwise it prints `ok`. Without a config and without `-relay`: `pass -relay or run init first: ...`.

### doctor

```
burndrop doctor
```

Runs one check per line, `ok    <check>  <detail>` or `FAIL  <check>  <error>`: `paths`, `config`, `config mode` (only when the file is readable by other users, skipped on Windows), `agent key`, `relay origin`, `relay` (version, page served, agent auth), `page hash`, `state dir`, `backend open`, `backend probe`, `agent`, `purge expired`, `pending`, `secrets`, `audit log`. Ends with `all checks passed` (exit 0) or `<n> problem(s)` (exit 1). A failing `paths` or `config` check stops the run.

### instructions

```
burndrop instructions [-format text|claude|cursor|agents|mcp-json|vscode-mcp-json]
```

Prints the instruction text the MCP server sends to clients (`text`, the default), the same text under a `## Secrets: use burndrop` heading (`claude`, `agents`), a Cursor rule file with front matter (`cursor`), or the MCP client configuration `{"mcpServers":{"burndrop":{"command":"burndrop","args":["mcp"]}}}` (`mcp-json`). An unknown format exits 2.

### version

`burndrop version` (or `--version`) prints `burndrop <version>`. `burndrop help` prints the command index and exits 0; running with no arguments prints it and exits 2.

## burndrop-relay

```
burndrop-relay [serve|keygen|healthcheck|version|help]
```

Configuration comes only from `BURNDROP_*` variables ([self-hosting.md](self-hosting.md)). With no command, or when the first argument starts with `-`, `serve` is assumed.

| Command | Behavior | Exit codes |
|---|---|---|
| `serve` | Loads and validates the configuration, opens the store, embeds the page if built in, listens on `BURNDROP_LISTEN`, runs the expiry sweeper every 10 seconds, and shuts down gracefully on `SIGINT` or `SIGTERM` within `BURNDROP_SHUTDOWN_TIMEOUT`. Logs `relay started` with the effective settings | 2 on `configuration error: ...` or bad flags; 1 when the store cannot be opened or the listener fails; 0 after a clean shutdown |
| `keygen [-id ID]` | Generates a random agent key and prints it once (`Agent key for "agent1" (shown once, give it to the agent):`) followed by the entry to put in `BURNDROP_AGENT_KEYS` (`agent1:sha256:<hash>`). `-id` defaults to `agent1` and must not be empty or contain `:`, `,`, or whitespace | 0; 2 on a bad id or flag; 1 when the random source fails |
| `healthcheck` | Requests `http://127.0.0.1:<port>/healthz` with the port from `BURNDROP_LISTEN` (default `:8080`; `0.0.0.0` and `::` become `127.0.0.1`) with a 3-second timeout. Used by the container image's `HEALTHCHECK` because the image has no shell or curl | 0 when the relay answers 200; 1 otherwise; 2 when the listen address cannot be parsed |
| `version` | Prints `burndrop-relay <version>` | 0 |
| `help`, `-h`, `--help` | Prints the command list and the two required variables | 0; an unknown command prints the same to stderr and exits 2 |

Both binaries take their version from `-ldflags "-X main.version=v1.2.3"` at build time and report `dev` otherwise.
