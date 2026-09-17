import { defineConfig, devices } from "@playwright/test";

// The end-to-end suite runs the real relay binary (built with the page
// embedded by e2e/build-relay.mjs) and drives the page in a browser.
export const PORT = Number(process.env["BURNDROP_E2E_PORT"] ?? 8931);
const origin = `http://localhost:${PORT}`;
const allBrowsers = process.env["BURNDROP_E2E_ALL_BROWSERS"] === "1";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  workers: 4,
  retries: 0,
  reporter: process.env["CI"] ? [["github"], ["list"]] : [["list"]],
  use: {
    baseURL: origin,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "node e2e/relay.mjs",
    url: `${origin}/healthz`,
    env: { BURNDROP_E2E_PORT: String(PORT) },
    reuseExistingServer: false,
    timeout: 30_000,
  },
  projects: [
    { name: "desktop-light", use: { ...devices["Desktop Chrome"], colorScheme: "light" } },
    { name: "desktop-dark", use: { ...devices["Desktop Chrome"], colorScheme: "dark" } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
    ...(allBrowsers
      ? [
          { name: "firefox", use: { ...devices["Desktop Firefox"] } },
          { name: "webkit", use: { ...devices["Desktop Safari"] } },
        ]
      : []),
  ],
});
