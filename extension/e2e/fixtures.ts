// Launches Chromium with the test build of the extension. Extensions only
// load into a persistent context, and the "chromium" channel is the build
// that runs them in headless mode.
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, expect, test as base, type BrowserContext, type Page, type Worker } from "@playwright/test";
import { PORT } from "../playwright.config.js";

export const RELAY = `http://localhost:${PORT}`;
const DIST = join(dirname(dirname(fileURLToPath(import.meta.url))), "dist", "chrome-test");

export interface Extension {
  context: BrowserContext;
  id: string;
  base: string;
  worker: Worker;
}

export async function launchExtension(userDataDir = ""): Promise<Extension> {
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: "chromium",
    args: [`--disable-extensions-except=${DIST}`, `--load-extension=${DIST}`],
  });
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker"));
  const id = new URL(worker.url()).host;
  return { context, id, base: `chrome-extension://${id}`, worker };
}

export const test = base.extend<{ page: Page }, { extension: Extension }>({
  extension: [
    async ({}, use) => {
      const extension = await launchExtension();
      await use(extension);
      await extension.context.close();
    },
    { scope: "worker" },
  ],
  page: async ({ extension }, use) => {
    const page = await extension.context.newPage();
    await use(page);
    await page.close();
  },
});

/** registeredIds lists the content script registrations the background holds. */
export function registeredIds(extension: Extension): Promise<string[]> {
  return extension.worker.evaluate(async () => (await chrome.scripting.getRegisteredContentScripts()).map((s) => s.id));
}

export function storedOrigins(extension: Extension): Promise<string[]> {
  return extension.worker.evaluate(async () => ((await chrome.storage.local.get("origins"))["origins"] ?? []) as string[]);
}

/** addOrigin adds a relay through the options page, the way a person would. */
export async function addOrigin(extension: Extension, page: Page, origin: string): Promise<void> {
  await page.goto(`${extension.base}/options.html`);
  await page.locator("#origin").fill(origin);
  await page.locator("#add").click();
  await expect(page.locator("#add-status")).toContainText(`${origin} is now protected`);
}

export async function ensureOrigin(extension: Extension, page: Page, origin: string): Promise<void> {
  if (!(await storedOrigins(extension)).includes(origin)) {
    await addOrigin(extension, page, origin);
  }
}

/**
 * openLink navigates to a hosted link and waits for the extension to move
 * the tab. It returns every URL the main frame passed through, so a test
 * can check the fragment survived the hand-over.
 */
export async function openLink(page: Page, link: string): Promise<string[]> {
  const navigated: string[] = [];
  page.on("framenavigated", (frame) => {
    if (frame === page.mainFrame()) {
      navigated.push(frame.url());
    }
  });
  await page.goto(link, { waitUntil: "commit" });
  await page.waitForURL((url) => url.protocol === "chrome-extension:");
  return navigated;
}
