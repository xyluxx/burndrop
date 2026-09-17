import { describe, expect, it } from "vitest";

import { Agent, BurndropError, RelayError, ValidationError, buildDropLink, buildRevealLink, encodeBase64Url, human, parseDropLink, parseRevealLink } from "../src/index.js";
import { FakeRelay, randomToken, text } from "./helpers.js";

function setup(): { fake: FakeRelay; agent: Agent } {
  const fake = new FakeRelay();
  return { fake, agent: new Agent({ relay: fake.origin, fetch: fake.fetch }) };
}

describe("human.submit", () => {
  it("refuses links the relay does not know, empty values, and spent links", async () => {
    const { fake, agent } = setup();
    const unknown = buildDropLink(
      { id: randomToken(), uploadToken: randomToken(), recipientKey: new Uint8Array(32).fill(1), name: "n", purpose: "", storage: "", retention: "session" },
      fake.origin,
    );
    await expect(human.submit(unknown, "value", { fetch: fake.fetch })).rejects.toThrow(/expired or was never created/);
    const req = await agent.requestSecret("n", "p");
    await expect(human.submit(req.link, "", { fetch: fake.fetch })).rejects.toBeInstanceOf(ValidationError);
    await expect(human.submit(req.link, new Uint8Array(0), { fetch: fake.fetch })).rejects.toBeInstanceOf(ValidationError);
    await human.submit(req.link, "value", { fetch: fake.fetch });
    await expect(human.submit(req.link, "value", { fetch: fake.fetch })).rejects.toThrow(/no longer be used \(state: uploaded\)/);
    await expect(human.submit("https://drop.example/drop", "value", { fetch: fake.fetch })).rejects.toThrow(/no fragment/);
  });

  it("detects a link whose key was swapped through the relay commitment", async () => {
    const { fake, agent } = setup();
    const req = await agent.requestSecret("n", "p");
    const { drop, pageOrigin } = parseDropLink(req.link);
    const swapped = buildDropLink({ ...drop, recipientKey: new Uint8Array(32).fill(0x42) }, pageOrigin);
    const err = await human.submit(swapped, "value", { fetch: fake.fetch }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BurndropError);
    expect((err as BurndropError).message).toContain("does not match the key the agent registered");
    expect((err as BurndropError).cause).toBeInstanceOf(RelayError);
    expect(fake.state(req.requestId)).toBe("created");
    // The honest link still works afterwards.
    const ok = await human.submit(req.link, "value", { fetch: fake.fetch });
    expect(ok.name).toBe("n");
    expect(ok.relay).toBe(fake.origin);
  });

  it("propagates other relay errors and honors a relay override", async () => {
    const { fake, agent } = setup();
    const req = await agent.requestSecret("n", "p");
    fake.failures.push([503, { error: "store_full" }]);
    await expect(human.submit(req.link, "value", { fetch: fake.fetch })).rejects.toMatchObject({ status: 503 });
    fake.failures.push([200, { state: "created", kind: "drop" }]);
    fake.failures.push([403, { error: "bad_token" }]);
    await expect(human.submit(req.link, "value", { fetch: fake.fetch })).rejects.toMatchObject({ code: "bad_token" });
    const { drop } = parseDropLink(req.link);
    const elsewhere = buildDropLink(drop, "https://page.example");
    const out = await human.submit(elsewhere, "value", { fetch: fake.fetch, relay: fake.origin, clientName: "test/1" });
    expect(out.relay).toBe(fake.origin);
    expect(fake.requests.at(-1)?.headers["x-client"]).toBe("test/1");
  });
});

describe("human.open", () => {
  it("refuses unknown links and fails closed on altered display fields", async () => {
    const { fake, agent } = setup();
    const unknown = buildRevealLink({ id: randomToken(), revealToken: randomToken(), key: new Uint8Array(32).fill(1), name: "n", keepsCopy: true }, fake.origin);
    await expect(human.open(unknown, { fetch: fake.fetch })).rejects.toThrow(/expired or was never created/);
    const sent = await agent.sendSecret("n", "the-secret-value");
    const altered = sent.link.replace("&c=1", "&c=0");
    expect(parseRevealLink(altered).reveal.keepsCopy).toBe(false);
    const err = await human.open(altered, { fetch: fake.fetch }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BurndropError);
    expect((err as BurndropError).message).toContain("the link was altered");
    // The relay copy is gone: the honest link cannot be opened any more.
    expect(fake.state(sent.requestId)).toBe("opened");
    await expect(human.open(sent.link, { fetch: fake.fetch })).rejects.toThrow(/already used or revoked/);
  });

  it("fails closed on an altered name or key and propagates relay errors", async () => {
    const { fake, agent } = setup();
    const renamed = await agent.sendSecret("n", "the-secret-value");
    const { reveal, pageOrigin } = parseRevealLink(renamed.link);
    await expect(human.open(buildRevealLink({ ...reveal, name: "other" }, pageOrigin), { fetch: fake.fetch })).rejects.toThrow(/could not be decrypted/);
    const rekeyed = await agent.sendSecret("n", "the-secret-value");
    const parsed = parseRevealLink(rekeyed.link).reveal;
    const badKey = rekeyed.link.replace("k=" + encodeBase64Url(parsed.key), "k=" + encodeBase64Url(new Uint8Array(32).fill(3)));
    await expect(human.open(badKey, { fetch: fake.fetch })).rejects.toThrow(/could not be decrypted/);
    const failing = await agent.sendSecret("n", "the-secret-value");
    fake.failures.push([200, { state: "created", kind: "reveal" }]);
    fake.failures.push([403, { error: "bad_token" }]);
    await expect(human.open(failing.link, { fetch: fake.fetch })).rejects.toMatchObject({ code: "bad_token" });
    fake.failures.push([500, { error: "internal_error" }]);
    await expect(human.open(failing.link, { fetch: fake.fetch })).rejects.toMatchObject({ status: 500 });
    const fine = await human.open(failing.link, { fetch: fake.fetch });
    expect(text(fine.value)).toBe("the-secret-value");
  });
});
