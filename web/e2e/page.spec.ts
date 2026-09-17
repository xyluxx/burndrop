import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";
import { api, c, createDrop, createReveal, dropState, fetchDrop, randomToken, revealState, uploadAsPage } from "./helpers.js";
import { buildDropLink, buildRevealLink } from "../src/link.js";

/** watch collects page errors, console errors, and API request URLs. */
function watch(page: Page): { errors: string[]; requests: string[] } {
  const errors: string[] = [];
  const requests: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => {
    if (m.type() === "error") errors.push(m.text());
  });
  page.on("request", (r) => {
    if (r.url().includes("/api/")) requests.push(`${r.method()} ${r.url()}`);
  });
  return { errors, requests };
}

const main = (page: Page) => page.locator("#main");

/** settled waits for the card fade-in so axe measures final colors. */
async function settled(page: Page): Promise<void> {
  await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished)));
}

/** visit always performs a full navigation, even when only the fragment differs from the current URL. */
async function visit(page: Page, url: string) {
  await page.goto("about:blank");
  return page.goto(url);
}

test.describe("drop page", () => {
  test("encrypts a secret that only the agent can open, then reports delivery", async ({ page, baseURL }) => {
    const base = baseURL!;
    const drop = await createDrop(base, { name: "openai-api-key", purpose: "Call the API from the billing script", storage: "macOS Keychain", retention: "until-revoked" });
    const seen = watch(page);
    const response = await visit(page, drop.link);
    expect(response?.headers()["content-security-policy"]).toMatch(/script-src 'sha256-[^']+' 'wasm-unsafe-eval'/);
    expect(response?.headers()["content-security-policy"]).toContain("default-src 'none'");

    await expect(main(page)).toHaveAttribute("data-state", "waiting");
    // The fragment is gone from the address bar before the first request.
    expect(page.url()).toBe(`${base}/drop`);
    expect(await page.evaluate(() => location.hash)).toBe("");
    for (const r of seen.requests) {
      expect(r).not.toContain("#");
      expect(r.startsWith("POST ")).toBe(true);
    }
    await expect(page.locator("#ctx-name")).toHaveText("openai-api-key");
    await expect(page.locator("#ctx-purpose")).toHaveText("Call the API from the billing script");
    await expect(page.locator("#ctx-storage")).toHaveText("macOS Keychain");
    await expect(page.locator("#ctx-retention")).toHaveText("until the agent deletes it");
    await expect(page.locator("#ctx-fingerprint")).toHaveText(drop.fingerprint);
    await expect(page.locator("#ctx-expires")).toContainText("in ");

    const secret = "sk-live-0123456789abcdef";
    await page.locator("#secret").fill(secret);
    await expect(page.locator("#secret")).toHaveClass(/masked/);
    await page.locator("#toggle-mask").click();
    await expect(page.locator("#secret")).not.toHaveClass(/masked/);
    await page.locator("#toggle-mask").click();
    await page.locator("#send").click();
    await expect(main(page)).toHaveAttribute("data-state", "sent");
    await expect(page.locator("#drop-form")).toBeHidden();
    await expect(page.locator("#secret")).toHaveValue("");

    // Agent side: fetch, open, compare, and watch the page notice delivery.
    expect(await dropState(base, drop.id)).toBe("uploaded");
    const envelope = c.openEnvelope(drop.kp.publicKey, drop.kp.privateKey, await fetchDrop(base, drop.id, drop.fetchToken));
    expect(envelope).toEqual({
      v: 1,
      type: "drop",
      name: "openai-api-key",
      purpose: "Call the API from the billing script",
      storage: "macOS Keychain",
      retention: "until-revoked",
      fingerprint: drop.fingerprint,
      format: "text",
      secret,
    });
    await expect(main(page)).toHaveAttribute("data-state", "delivered", { timeout: 20_000 });
    expect((await api(base, "/api/v1/drops/fetch", { drop_id: drop.id, fetch_token: drop.fetchToken })).status).toBe(410);
    expect(seen.errors).toEqual([]);
  });

  test("works with the keyboard alone", async ({ page, baseURL }) => {
    const drop = await createDrop(baseURL!, { name: "db-password" });
    await visit(page, drop.link);
    await expect(main(page)).toHaveAttribute("data-state", "waiting");
    await page.keyboard.press("Tab"); // skip link
    await page.keyboard.press("Tab"); // the secret field
    await expect(page.locator("#secret")).toBeFocused();
    await page.keyboard.type("hunter2");
    await page.keyboard.press("Tab"); // show or hide
    await page.keyboard.press("Tab"); // send
    await expect(page.locator("#send")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(main(page)).toHaveAttribute("data-state", "sent");
    const env = c.openEnvelope(drop.kp.publicKey, drop.kp.privateKey, await fetchDrop(baseURL!, drop.id, drop.fetchToken));
    expect(env.secret).toBe("hunter2");
  });

  test("stores binary and multi-line values faithfully", async ({ page, baseURL }) => {
    const drop = await createDrop(baseURL!, { name: "ssh-key" });
    await visit(page, drop.link);
    const value = "-----BEGIN KEY-----\nline one\nline two\n-----END KEY-----\n";
    await page.locator("#secret").fill(value);
    await page.locator("#send").click();
    await expect(main(page)).toHaveAttribute("data-state", "sent");
    const env = c.openEnvelope(drop.kp.publicKey, drop.kp.privateKey, await fetchDrop(baseURL!, drop.id, drop.fetchToken));
    expect(env.format).toBe("text");
    expect(env.secret).toBe(value);
  });

  test("refuses an empty secret and one over the size limit", async ({ page, baseURL }) => {
    const drop = await createDrop(baseURL!, { name: "x" });
    await visit(page, drop.link);
    await page.locator("#secret").fill("   ");
    await page.locator("#send").click();
    await expect(page.locator("#status")).toHaveText(/Paste the secret first/);
    await expect(main(page)).toHaveAttribute("data-state", "waiting");
    await page.locator("#secret").fill("a".repeat(61 * 1024));
    await page.locator("#send").click();
    await expect(page.locator("#status")).toHaveText(/too large/);
    await expect(main(page)).toHaveAttribute("data-state", "waiting");
    expect(await dropState(baseURL!, drop.id)).toBe("created");
  });

  test("rejects a link whose key was swapped", async ({ page, baseURL }) => {
    const drop = await createDrop(baseURL!, { name: "x" });
    const other = c.generateKeyPair();
    const altered = buildDropLink(baseURL!, { relay: null, id: drop.id, uploadToken: drop.uploadToken, recipientKey: other.publicKey, name: "x", purpose: "", storage: "", retention: "session" });
    await visit(page, altered);
    await expect(main(page)).toHaveAttribute("data-state", "waiting");
    await page.locator("#secret").fill("value");
    await page.locator("#send").click();
    await expect(page.locator("#status")).toHaveText(/does not match/);
    await expect(main(page)).toHaveAttribute("data-state", "waiting");
    expect(await dropState(baseURL!, drop.id)).toBe("created");
  });

  test("shows the right closed states", async ({ page, baseURL }) => {
    const base = baseURL!;
    const unknown = buildDropLink(base, { relay: null, id: randomToken(), uploadToken: randomToken(), recipientKey: c.generateKeyPair().publicKey, name: "gone", purpose: "", storage: "", retention: "session" });
    await visit(page, unknown);
    await expect(main(page)).toHaveAttribute("data-state", "expired");
    await expect(page.locator("#drop-form")).toBeHidden();

    const revoked = await createDrop(base, { name: "cancelled" });
    expect((await api(base, "/api/v1/drops/revoke", { drop_id: revoked.id, token: revoked.fetchToken })).status).toBe(200);
    await visit(page, revoked.link);
    await expect(main(page)).toHaveAttribute("data-state", "revoked");

    const uploaded = await createDrop(base, { name: "already-sent" });
    await uploadAsPage(base, uploaded, "value");
    await visit(page, uploaded.link);
    await expect(main(page)).toHaveAttribute("data-state", "sent");
    await expect(page.locator("#drop-form")).toBeHidden();
    await fetchDrop(base, uploaded.id, uploaded.fetchToken);
    await expect(main(page)).toHaveAttribute("data-state", "delivered", { timeout: 20_000 });
    await visit(page, uploaded.link);
    await expect(main(page)).toHaveAttribute("data-state", "delivered");
  });

  test("a malformed link never touches the API", async ({ page, baseURL }) => {
    const seen = watch(page);
    await visit(page, `${baseURL}/drop#v=1&i=short`);
    await expect(main(page)).toHaveAttribute("data-state", "error");
    await expect(page.locator("#state-text")).toContainText("incomplete or was altered");
    await expect(page.locator("#context")).toBeHidden();
    expect(seen.requests).toEqual([]);
    await visit(page, `${baseURL}/drop`);
    await expect(main(page)).toHaveAttribute("data-state", "error");
    expect(seen.requests).toEqual([]);
  });

  test("refuses a link that points at another relay", async ({ page, baseURL }) => {
    const seen = watch(page);
    const drop = await createDrop(baseURL!, { name: "x" });
    const foreign = buildDropLink(baseURL!, { relay: "https://relay.example", id: drop.id, uploadToken: drop.uploadToken, recipientKey: drop.kp.publicKey, name: "x", purpose: "", storage: "", retention: "session" });
    await visit(page, foreign);
    await expect(main(page)).toHaveAttribute("data-state", "error");
    await expect(page.locator("#state-text")).toContainText("different relay");
    expect(seen.requests).toEqual([]);
  });

  test("remembers the theme and has no accessibility violations in either", async ({ page, baseURL }) => {
    const drop = await createDrop(baseURL!, { name: "x", purpose: "p", storage: "s" });
    await visit(page, drop.link);
    await expect(main(page)).toHaveAttribute("data-state", "waiting");
    await settled(page);
    const light = await new AxeBuilder({ page }).analyze();
    expect(light.violations).toEqual([]);
    const wasDark = await page.evaluate(() => document.documentElement.classList.contains("dark"));
    await page.locator("#theme").click();
    expect(await page.evaluate(() => document.documentElement.classList.contains("dark"))).toBe(!wasDark);
    await settled(page);
    const toggled = await new AxeBuilder({ page }).analyze();
    expect(toggled.violations).toEqual([]);
    await page.reload();
    await expect(main(page)).toHaveAttribute("data-state", "error"); // no fragment after a reload
    expect(await page.evaluate(() => document.documentElement.classList.contains("dark"))).toBe(!wasDark);
    expect(await page.evaluate(() => localStorage.getItem("burndrop-theme"))).toBe(wasDark ? "light" : "dark");
  });

  test("fits the viewport without horizontal scrolling", async ({ page, baseURL }) => {
    const drop = await createDrop(baseURL!, { name: "a-rather-long-secret-name-that-should-still-wrap-inside-the-card", purpose: "p".repeat(200), storage: "s".repeat(100) });
    await visit(page, drop.link);
    await expect(main(page)).toHaveAttribute("data-state", "waiting");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });
});

test.describe("reveal page", () => {
  test("reveals once, and only after a click", async ({ page, baseURL, context, browserName }) => {
    const base = baseURL!;
    const reveal = await createReveal(base, "staging-db-url", true, "postgres://app:s3cret@db.internal:5432/app");
    const seen = watch(page);
    await visit(page, reveal.link);
    await expect(main(page)).toHaveAttribute("data-state", "ready");
    expect(page.url()).toBe(`${base}/reveal`);
    await expect(page.locator("#ctx-name")).toHaveText("staging-db-url");
    await expect(page.locator("#ctx-copy")).toHaveText("yes");
    await expect(page.locator("#ctx-opens")).toHaveText("once");
    // Loading the page must not burn the secret.
    expect(await revealState(base, reveal.id)).toBe("created");
    await page.waitForTimeout(500);
    expect(await revealState(base, reveal.id)).toBe("created");

    await page.locator("#reveal").click();
    await expect(main(page)).toHaveAttribute("data-state", "revealed");
    await expect(page.locator("#value")).toHaveValue(reveal.secret);
    await expect(page.locator("#value")).toHaveClass(/masked/);
    await page.locator("#toggle-value").click();
    await expect(page.locator("#value")).not.toHaveClass(/masked/);
    await expect(page.locator("#toggle-value")).toHaveText("Hide");
    expect(await revealState(base, reveal.id)).toBe("opened");
    expect((await api(base, "/api/v1/reveals/open", { drop_id: reveal.id, reveal_token: reveal.revealToken })).status).toBe(410);

    if (browserName === "chromium") {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      await page.locator("#copy").click();
      await expect(page.locator("#copy-status")).toContainText("Copied");
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(reveal.secret);
      await page.locator("#clear-clipboard").click();
      await expect(page.locator("#copy-status")).toContainText("cleared");
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("");
    }
    await settled(page);
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations).toEqual([]);
    expect(seen.errors).toEqual([]);

    // Opening the link again says when it was revealed.
    await visit(page, reveal.link);
    await expect(main(page)).toHaveAttribute("data-state", "opened");
    await expect(page.locator("#state-text")).toContainText("It was opened");
    await expect(page.locator("#reveal-panel")).toBeHidden();
  });

  test("a link with a changed name cannot decrypt the secret", async ({ page, baseURL }) => {
    const base = baseURL!;
    const reveal = await createReveal(base, "db", false, "value");
    const altered = buildRevealLink(base, { relay: null, id: reveal.id, revealToken: reveal.revealToken, key: reveal.key, name: "db-prod", keepsCopy: false });
    await visit(page, altered);
    await expect(main(page)).toHaveAttribute("data-state", "ready");
    await expect(page.locator("#ctx-copy")).toHaveText("no");
    await page.locator("#reveal").click();
    await expect(main(page)).toHaveAttribute("data-state", "error");
    await expect(page.locator("#state-text")).toContainText("could not be decrypted");
    await expect(page.locator("#value-panel")).toBeHidden();
  });

  test("shows expired and revoked links", async ({ page, baseURL }) => {
    const base = baseURL!;
    await visit(page, buildRevealLink(base, { relay: null, id: randomToken(), revealToken: randomToken(), key: c.newSymmetricKey(), name: "gone", keepsCopy: false }));
    await expect(main(page)).toHaveAttribute("data-state", "expired");
    const revoked = await createReveal(base, "withdrawn", false, "v");
    expect((await api(base, "/api/v1/reveals/revoke", { drop_id: revoked.id, token: revoked.revokeToken })).status).toBe(200);
    await visit(page, revoked.link);
    await expect(main(page)).toHaveAttribute("data-state", "revoked");
    await expect(page.locator("#reveal-panel")).toBeHidden();
  });

  test("keyboard: tab to the button and press Enter", async ({ page, baseURL }) => {
    const reveal = await createReveal(baseURL!, "token", true, "abc");
    await visit(page, reveal.link);
    await expect(main(page)).toHaveAttribute("data-state", "ready");
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    await expect(page.locator("#reveal")).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(main(page)).toHaveAttribute("data-state", "revealed");
    await expect(page.locator("#value")).toBeFocused();
  });
});
