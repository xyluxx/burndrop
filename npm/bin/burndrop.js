#!/usr/bin/env node
// Runs the burndrop binary from the platform package that npm installed
// through optionalDependencies. Arguments, stdio, and the exit code pass
// straight through, so `npx burndrop mcp` behaves exactly like the binary.
"use strict";
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const os = process.platform;
const cpu = process.arch;
const name = `@burndrop/cli-${os}-${cpu}`;
const exe = os === "win32" ? "burndrop.exe" : "burndrop";

let binary;
try {
  binary = path.join(path.dirname(require.resolve(`${name}/package.json`)), "bin", exe);
} catch {
  process.stderr.write(
    `burndrop: no prebuilt binary for ${os} ${cpu} (${name}).\n` +
      "Install from the GitHub release page or build from source: go install github.com/xyluxx/burndrop/cmd/burndrop@latest\n",
  );
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit", windowsHide: true });
if (result.error) {
  process.stderr.write(`burndrop: could not start ${binary}: ${result.error.message}\n`);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
