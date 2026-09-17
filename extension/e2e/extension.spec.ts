import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import AxeBuilder from "@axe-core/playwright";
import { expect, type Page } from "@playwright/test";
import { c, createDrop, createReveal, dropState, fetchDrop, randomToken, revealState } from "../../web/e2e/helpers.js";
import { buildDropLink } from "../../web/src/link.js";
import { addOrigin, ensureOrigin, launchExtension, openLink, registeredIds, RELAY, storedOrigins, test } from "./fixtures.js";

const bundled = JSON.parse(readFileSync(join(dirname(dirname(fileURLToPath(import.meta.url))), "dist", "chrome-test", "page.meta.json"), "utf8")) as { version: string; sha256: string };
const main = (page: Page) => page.locator("#main");
const options = (page: Page, base: string) => page.goto(`${base}/options.html`);

/** watchApi records who made each relay API call: the Origin header, method, and path. */
function watchApi(page: Page): () => Promise<string[]> {
  const pending: Promise<string>[] = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/")) {
      const describe = `${r.method()} ${new URL(r.url()).pathname}`;
      pending.push(r.allHeaders().then((h) => `${h["origin"] ?? "(no origin)"} ${describe}`, () => `(headers unavailable) ${describe}`));
    }
  });
  return () => Promise.all(pending);
}

interface LocalServer {
  origin: string;
  hits: string[];
  close: () => Promise<void>;
}

/** startServer runs a throwaway HTTP server on 127.0.0.1 that logs every request it gets. */
async function startServer(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<LocalServer> {
  const hits: string[] = [];
  const server = createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    hits,
    // Chromium keeps a speculative connection to a navigated origin open
    // without sending a request; server.close alone would wait for it.
    close: () =>
      new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
        server.closeAllConnections();
      }),
  };
}

function html(body: string): (req: IncomingMessage, res: ServerResponse) => void {
  return (req, res) => {
    if (req.url === "/drop") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(body);
    } else {
      res.writeHead(404);
      res.end();
    }
  };
}

test.describe("options page", () => {
  test("adds a relay origin and registers its content script", async ({ page, extension }) => {
    await options(page, extension.base);
    await expect(page.locator("#bundled")).toHaveText(`bundled page ${bundled.version}, sha256 ${bundled.sha256}`);
    await expect(page.locator("#empty")).toBeVisible();
    const refused: Array<[string, string]> = [
      ["relay.example", "not a URL"],
      ["http://relay.example", "http is only allowed for localhost"],
      [`${RELAY}/drop`, "without a path"],
    ];
    for (const [input, complaint] of refused) {
      await page.locator("#origin").fill(input);
      await page.locator("#add").click();
      await expect(page.locator("#add-status")).toContainText(complaint);
    }
    expect(await storedOrigins(extension)).toEqual([]);

    await page.locator("#origin").fill(RELAY);
    await page.locator("#add").click();
    await expect(page.locator("#add-status")).toContainText(`${RELAY} is now protected`);
    await expect(page.locator("#origins")).toContainText(RELAY);
    await expect(page.locator("#empty")).toBeHidden();
    expect(await storedOrigins(extension)).toEqual([RELAY]);
    const scripts = await extension.worker.evaluate(() => chrome.scripting.getRegisteredContentScripts());
    expect(scripts).toEqual([
      expect.objectContaining({
        id: `relay:${RELAY}`,
        js: ["content.js"],
        matches: [`${RELAY}/drop*`, `${RELAY}/reveal*`],
        runAt: "document_start",
        persistAcrossSessions: true,
      }),
    ]);

    await page.locator("#origin").fill(RELAY);
    await page.locator("#add").click();
    await expect(page.locator("#add-status")).toContainText("already protected");
    expect(await storedOrigins(extension)).toEqual([RELAY]);
  });

  test("removes an origin together with its registration", async ({ page, extension }) => {
    await ensureOrigin(extension, page, RELAY);
    await options(page, extension.base);
    await page.getByRole("button", { name: `Remove ${RELAY}` }).click();
    await expect(page.locator("#add-status")).toContainText(`${RELAY} removed`);
    await expect(page.locator("#empty")).toBeVisible();
    expect(await storedOrigins(extension)).toEqual([]);
    expect(await registeredIds(extension)).toEqual([]);
  });

  test("has no accessibility violations in either theme", async ({ page, extension }) => {
    await ensureOrigin(extension, page, RELAY);
    await options(page, extension.base);
    await expect(page.locator("#origins")).toContainText(RELAY);
    for (const colorScheme of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme });
      // Let the theme's colour transitions finish so axe measures final colours.
      await page.evaluate(() => Promise.all(document.getAnimations().map((a) => a.finished)));
      const results = await new AxeBuilder({ page }).analyze();
      expect(results.violations, colorScheme).toEqual([]);
    }
  });
});

test.describe("links", () => {
  test("a drop link opens in the bundled page with its fragment intact, and the secret reaches the agent", async ({ page, extension }) => {
    await ensureOrigin(extension, page, RELAY);
    const drop = await createDrop(RELAY, { name: "openai-api-key", purpose: "Call the API from the billing script", storage: "macOS Keychain", retention: "until-revoked" });
    const fragment = drop.link.slice(drop.link.indexOf("#") + 1);
    const apiCalls = watchApi(page);
    const navigated = await openLink(page, drop.link);
    await expect(main(page)).toHaveAttribute("data-state", "waiting");

    // The tab went to the bundled page with the whole fragment, which the
    // page then removed before its first request.
    const pageUrl = `${extension.base}/page.html?mode=drop&origin=${encodeURIComponent(RELAY)}`;
    expect(navigated).toContain(`${pageUrl}#${fragment}`);
    expect(page.url()).toBe(pageUrl);
    expect(await page.evaluate(() => location.hash)).toBe("");
    await expect(page.locator("#ctx-name")).toHaveText("openai-api-key");
    await expect(page.locator("#ctx-purpose")).toHaveText("Call the API from the billing script");
    await expect(page.locator("#ctx-fingerprint")).toHaveText(drop.fingerprint);

    const secret = "sk-live-0123456789abcdef";
    await page.locator("#secret").fill(secret);
    await page.locator("#send").click();
    await expect(main(page)).toHaveAttribute("data-state", "sent");
    expect(await dropState(RELAY, drop.id)).toBe("uploaded");
    const envelope = c.openEnvelope(drop.kp.publicKey, drop.kp.privateKey, await fetchDrop(RELAY, drop.id, drop.fetchToken));
    expect(envelope.name).toBe("openai-api-key");
    expect(envelope.secret).toBe(secret);
    await expect(main(page)).toHaveAttribute("data-state", "delivered", { timeout: 20_000 });

    // Every API call came from the extension's origin, none from the relay's page.
    const calls = await apiCalls();
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) {
      expect(call.startsWith(`${extension.base} POST /api/v1/drops/`)).toBe(true);
    }
  });

  test("a reveal link opens in the bundled page and reveals once, after a click", async ({ page, extension }) => {
    await ensureOrigin(extension, page, RELAY);
    const reveal = await createReveal(RELAY, "staging-db-url", true, "postgres://app:s3cret@db.example:5432/app");
    await openLink(page, reveal.link);
    await expect(main(page)).toHaveAttribute("data-state", "ready");
    expect(page.url()).toBe(`${extension.base}/page.html?mode=reveal&origin=${encodeURIComponent(RELAY)}`);
    await expect(page.locator("#ctx-name")).toHaveText("staging-db-url");
    await expect(page.locator("#ctx-copy")).toHaveText("yes");
    expect(await revealState(RELAY, reveal.id)).toBe("created");
    await page.locator("#reveal").click();
    await expect(main(page)).toHaveAttribute("data-state", "revealed");
    await expect(page.locator("#value")).toHaveValue(reveal.secret);
    expect(await revealState(RELAY, reveal.id)).toBe("opened");
  });

  test("a link without a fragment still moves to the bundled page, which reports the problem", async ({ page, extension }) => {
    await ensureOrigin(extension, page, RELAY);
    await openLink(page, `${RELAY}/drop`);
    await expect(main(page)).toHaveAttribute("data-state", "error");
    await expect(page.locator("#state-text")).toContainText("incomplete or was altered");
  });

  test("the page a protected relay serves never runs", async ({ page, extension }) => {
    // A page that reports back the moment any of its scripts execute.
    const bait = await startServer(
      html(
        '<!doctype html><html><head><meta charset="utf-8"><script>var a = new XMLHttpRequest(); a.open("POST", "/ran?at=head", false); a.send();</script><title>bait</title></head>' +
          '<body><main id="main" data-state="hosted"></main><script>var b = new XMLHttpRequest(); b.open("POST", "/ran?at=body", false); b.send();</script></body></html>',
      ),
    );
    try {
      await ensureOrigin(extension, page, bait.origin);
      await c.ready();
      const link = buildDropLink(bait.origin, { relay: null, id: randomToken(), uploadToken: randomToken(), recipientKey: c.generateKeyPair().publicKey, name: "bait", purpose: "", storage: "", retention: "session" });
      await openLink(page, link);
      // The bundled page asks the bait server for the drop's status, gets a 404, and treats the drop as gone.
      await expect(main(page)).toHaveAttribute("data-state", "expired");
      expect(bait.hits).toContain("GET /drop");
      expect(bait.hits.filter((hit) => hit.includes("/ran"))).toEqual([]);
    } finally {
      await bait.close();
    }
    await options(page, extension.base);
    await page.getByRole("button", { name: `Remove ${bait.origin}` }).click();
    await expect(page.locator("#add-status")).toContainText(`${bait.origin} removed`);
  });
});

test.describe("verify mode", () => {
  test("reports verified, mismatch with both hashes, and could not fetch", async ({ page, extension }) => {
    await options(page, extension.base);
    const result = page.locator("#verify-result");
    await page.locator("#verify-origin").fill(RELAY);
    await page.locator("#verify").click();
    await expect(result).toContainText(`Verified: ${RELAY} serves the bundled page (version ${bundled.version}).`);
    await expect(result).toContainText(`${bundled.sha256} (version ${bundled.version}), which agrees with what it served`);

    // An impostor that serves its own page while claiming the genuine hash.
    const impostorPage = "<!doctype html><title>not the page</title>";
    const impostor = await startServer((req, res) => {
      if (req.url === "/api/v1/info") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ page_sha256: bundled.sha256, page_version: bundled.version }));
      } else {
        html(impostorPage)(req, res);
      }
    });
    try {
      await page.locator("#verify-origin").fill(impostor.origin);
      await page.locator("#verify").click();
      await expect(result).toContainText(`Mismatch: the page ${impostor.origin} serves is not the bundled page.`);
      await expect(result).toContainText(createHash("sha256").update(impostorPage).digest("hex"));
      await expect(result).toContainText(bundled.sha256);
      await expect(result).toContainText("which does not agree with what it served");
    } finally {
      await impostor.close();
    }

    // Nothing listens on that port any more.
    await page.locator("#verify-origin").fill(impostor.origin);
    await page.locator("#verify").click();
    await expect(result).toContainText(`Could not fetch ${impostor.origin}/drop: the relay did not answer.`);
    await expect(result).toContainText("none (no answer from /api/v1/info)");
    expect(await storedOrigins(extension)).not.toContain(impostor.origin);
  });
});

test.describe("startup", () => {
  test("rebuilds registrations from storage when the browser starts again", async () => {
    const profile = mkdtempSync(join(tmpdir(), "burndrop-extension-"));
    try {
      const first = await launchExtension(profile);
      try {
        await addOrigin(first, await first.context.newPage(), RELAY);
        await first.worker.evaluate(() => chrome.scripting.unregisterContentScripts());
        expect(await registeredIds(first)).toEqual([]);
      } finally {
        await first.context.close();
      }
      const second = await launchExtension(profile);
      try {
        await expect.poll(() => registeredIds(second)).toEqual([`relay:${RELAY}`]);
        expect(await storedOrigins(second)).toEqual([RELAY]);
      } finally {
        await second.context.close();
      }
    } finally {
      rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 250 });
    }
  });
});
