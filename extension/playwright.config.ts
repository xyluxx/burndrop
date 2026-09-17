import { defineConfig } from "@playwright/test";

// The suite loads the test build of the extension (dist/chrome-test) into a
// persistent Chromium context and runs the real relay, the same binary the
// web suite builds with web/e2e/build-relay.mjs, on its own port so both
// suites can run at once.
export const PORT = Number(process.env["BURNDROP_EXTENSION_E2E_PORT"] ?? 8941);
const origin = `http://localhost:${PORT}`;

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  workers: 1,
  retries: 0,
  reporter: process.env["CI"] ? [["github"], ["list"]] : [["list"]],
  webServer: {
    command: "node ../web/e2e/relay.mjs",
    url: `${origin}/healthz`,
    env: { BURNDROP_E2E_PORT: String(PORT) },
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
