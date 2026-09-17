# burndrop

One-time, end-to-end encrypted secret exchange between humans and AI
agents through a zero-knowledge relay. This npm package installs the
`burndrop` command line tool and MCP server (a single Go binary, selected
for your platform at install time) so that MCP clients can run it with
`npx`:

```json
{
  "mcpServers": {
    "burndrop": {
      "command": "npx",
      "args": ["-y", "burndrop", "mcp"]
    }
  }
}
```

First run `npx burndrop init -relay https://drop.example.com` once to pick
a storage backend and store the agent key.

Documentation, source, and release verification:
https://github.com/xyluxx/burndrop

Supported platforms: Linux, macOS, and Windows on x64 and arm64. On other
platforms the command prints where to get a build.
