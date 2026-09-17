// Starts the relay built by build-relay.mjs with a configuration suited to
// tests: memory store, no agent auth, generous rate limits, short TTLs.
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const web = dirname(dirname(fileURLToPath(import.meta.url)));
const exe = process.platform === "win32" ? ".exe" : "";
const port = process.env.BURNDROP_E2E_PORT || "8931";

const child = spawn(join(web, "build", `burndrop-relay${exe}`), ["serve"], {
  stdio: "inherit",
  env: {
    ...process.env,
    BURNDROP_LISTEN: `127.0.0.1:${port}`,
    BURNDROP_PUBLIC_ORIGIN: `http://localhost:${port}`,
    BURNDROP_AGENT_AUTH: "off",
    BURNDROP_RATE_PAGE_PER_MIN: "100000",
    BURNDROP_RATE_AGENT_PER_MIN: "100000",
    BURNDROP_RATE_GLOBAL_PER_SEC: "100000",
    BURNDROP_LOG_LEVEL: "warn",
  },
});
child.on("exit", (code, signal) => {
  process.exit(code ?? (signal ? 1 : 0));
});
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => child.kill());
}
