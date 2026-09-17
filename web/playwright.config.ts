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
    { name: "desktop-light", testIgnore: /screenshots\.spec\.ts/, use: { ...devices["Desktop Chrome"], colorScheme: "light" } },
    { name: "desktop-dark", testIgnore: /screenshots\.spec\.ts/, use: { ...devices["Desktop Chrome"], colorScheme: "dark" } },
    { name: "mobile", testIgnore: /screenshots\.spec\.ts/, use: { ...devices["Pixel 7"] } },
    ...(allBrowsers
      ? [
          { name: "firefox", testIgnore: /screenshots\.spec\.ts/, use: { ...devices["Desktop Firefox"] } },
          { name: "webkit", testIgnore: /screenshots\.spec\.ts/, use: { ...devices["Desktop Safari"] } },
        ]
      : []),
    // README material, produced on demand: BURNDROP_SCREENSHOTS=1 npx playwright test --project=screenshots
    ...(process.env["BURNDROP_SCREENSHOTS"] === "1"
      ? [{ name: "screenshots", testMatch: /screenshots\.spec\.ts/, use: { ...devices["Desktop Chrome"], viewport: { width: 1200, height: 720 }, deviceScaleFactor: 2, video: { mode: "on" as const, size: { width: 1200, height: 720 } } } }]
      : []),
  ],
});
