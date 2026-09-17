# burndrop, for agents

This file is for an AI coding agent that has this repository open, either to
set burndrop up for its user or to change the code. An agent that only uses
burndrop from another project needs the rules printed by `burndrop
instructions` (step 5 below), not this file.

## What this is

burndrop lets a human hand a secret to an agent, or the agent hand one back,
through a one-time link instead of the chat. The value is encrypted in the
browser, passes through a relay that only ever sees ciphertext, and lands in
a storage backend on the agent's machine. The model sees names, statuses,
fingerprints, and links, never values. Read `README.md` first, then
`docs/agent-integration.md`.

## Setting it up for a user

1. Install the CLI: `go install github.com/xyluxx/burndrop/cmd/burndrop@latest`
   (or a release binary, or `npx burndrop`).
2. Get a relay. Either the user's operator gives you a relay origin and an
   agent key, or run one locally for a trial:

   ```bash
   git clone https://github.com/xyluxx/burndrop.git && cd burndrop
   make web build                  # builds the page and both binaries into bin/
   BURNDROP_PUBLIC_ORIGIN=http://localhost:8080 BURNDROP_AGENT_AUTH=off bin/burndrop-relay serve
   ```

   For a relay on a real domain follow `deploy/compose/README.md`.
3. Configure the agent: `burndrop init -relay <origin>`. Add `-yes` to accept
   the recommended storage backend, `-agent-key-from env` to read the key
   from `BURNDROP_API_KEY`. Then run `burndrop doctor`.
4. Connect the MCP server. Claude Code: `claude mcp add burndrop -- burndrop mcp`.
   Other clients merge `agent-instructions/mcp/mcp.json` (VS Code takes
   `agent-instructions/mcp/vscode-mcp.json`).
5. Install the rules where the model reads them:
   `burndrop instructions -format claude >> CLAUDE.md`,
   `-format agents >> AGENTS.md`, or
   `-format cursor > .cursor/rules/burndrop.mdc`.
6. From then on, never ask the user to paste a secret into the chat. Call
   `request_secret` with a name, a one-sentence purpose, and a ttl that
   matches when the user will act, and relay its message verbatim.

## Working on the code

- Layout: `cmd/` (the `burndrop` CLI and `burndrop-relay`), `internal/`
  (relay, crypto, link, agent runtime, storage backends, MCP server), `web/`
  (the drop and reveal page), `extension/`, `sdk/python`, `sdk/typescript`,
  `spec/` (shared vectors and the interop exchange), `deploy/`, `docs/`.
- Before a commit: `gofmt -l cmd internal web` prints nothing,
  `go vet ./...` and `go test ./...` pass. For the page:
  `cd web && npm run typecheck && npx vitest run && node build.mjs --version dev`,
  then `node e2e/build-relay.mjs && npx playwright test` with Go on the PATH.
- Regenerate `agent-instructions/` with `make instructions` whenever
  `internal/mcpserver/instructions.go` changes; CI diffs the files.
- Rules CI enforces, in full in `CONTRIBUTING.md`: no em dash character
  anywhere, no AI attribution in commits or files, conventional commit
  messages, no secrets or personal data, actions pinned by commit SHA, Go
  statement coverage at or above 80 percent.
- Anything in `internal/crypto`, `web/src/crypto.ts`, or the SDK crypto
  modules must keep `spec/vectors.json` passing in Go, TypeScript, and
  Python.
- Values never reach the model. No tool result, log line, audit entry, or
  error may contain a secret; every string that leaves the agent passes
  through the redactor. Keep it that way.
