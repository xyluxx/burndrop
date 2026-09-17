// Captures the screenshots and the demo recording used by the README from
// the real page against the real relay, so they never drift from the
// product. Runs only in the "screenshots" project:
//
//   BURNDROP_SCREENSHOTS=1 npx playwright test --project=screenshots
//
// Output: docs/screenshots/*.png and docs/screenshots/demo.webm (the
// Makefile turns the recording into demo.gif with ffmpeg).
import { expect, test, type Page } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createDrop, createReveal, fetchDrop } from "./helpers.js";

const out = join(dirname(dirname(dirname(fileURLToPath(import.meta.url)))), "docs", "screenshots");
mkdirSync(out, { recursive: true });

const main = (page: Page) => page.locator("#main");

async function settled(page: Page): Promise<void> {
  await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished)));
}

async function visit(page: Page, url: string): Promise<void> {
  await page.goto("about:blank");
  await page.goto(url);
}

async function shot(page: Page, name: string): Promise<void> {
  await settled(page);
  await page.screenshot({ path: join(out, `${name}.png`), fullPage: false });
}

for (const theme of ["light", "dark"] as const) {
  test(`drop states (${theme})`, async ({ page, baseURL }) => {
    await page.emulateMedia({ colorScheme: theme });
    const drop = await createDrop(baseURL!, { name: "openai-api-key", purpose: "Call the OpenAI API from the billing script", storage: "macOS Keychain", retention: "until-revoked" });
    await visit(page, drop.link);
    await expect(main(page)).toHaveAttribute("data-state", "waiting");
    await page.locator("#secret").fill("sk-live-0123456789abcdef0123456789abcdef");
    await shot(page, `drop-waiting-${theme}`);
    await page.locator("#send").click();
    await expect(main(page)).toHaveAttribute("data-state", "sent");
    await shot(page, `drop-sent-${theme}`);
    await fetchDrop(baseURL!, drop.id, drop.fetchToken);
    await expect(main(page)).toHaveAttribute("data-state", "delivered", { timeout: 20_000 });
    await shot(page, `drop-delivered-${theme}`);
  });

  test(`reveal states (${theme})`, async ({ page, baseURL }) => {
    await page.emulateMedia({ colorScheme: theme });
    const reveal = await createReveal(baseURL!, "staging-db-url", false, "postgres://app:s3cret@db.staging.example:5432/app");
    await visit(page, reveal.link);
    await expect(main(page)).toHaveAttribute("data-state", "ready");
    await shot(page, `reveal-ready-${theme}`);
    await page.locator("#reveal").click();
    await expect(main(page)).toHaveAttribute("data-state", "revealed");
    await shot(page, `reveal-revealed-${theme}`);
    await visit(page, reveal.link);
    await expect(main(page)).toHaveAttribute("data-state", "opened");
    await shot(page, `reveal-opened-${theme}`);
  });
}

test("error state", async ({ page, baseURL }) => {
  await page.emulateMedia({ colorScheme: "light" });
  await visit(page, `${baseURL}/drop#v=1&i=short`);
  await expect(main(page)).toHaveAttribute("data-state", "error");
  await shot(page, "drop-error-light");
});

test.describe("demo recording", () => {
  test("human drops a secret and the agent receives it", async ({ page, baseURL }) => {
    await page.emulateMedia({ colorScheme: "light" });
    const drop = await createDrop(baseURL!, { name: "openai-api-key", purpose: "Call the OpenAI API from the billing script", storage: "macOS Keychain", retention: "until-revoked" });
    await visit(page, drop.link);
    await expect(main(page)).toHaveAttribute("data-state", "waiting");
    await page.waitForTimeout(1500);
    await page.locator("#secret").pressSequentially("sk-live-0123456789abcdef", { delay: 45 });
    await page.waitForTimeout(800);
    await page.locator("#send").click();
    await expect(main(page)).toHaveAttribute("data-state", "sent");
    await page.waitForTimeout(1500);
    await fetchDrop(baseURL!, drop.id, drop.fetchToken);
    await expect(main(page)).toHaveAttribute("data-state", "delivered", { timeout: 20_000 });
    await page.waitForTimeout(2000);
    const video = page.video();
    await page.close();
    await video?.saveAs(join(out, "demo.webm"));
  });
});
