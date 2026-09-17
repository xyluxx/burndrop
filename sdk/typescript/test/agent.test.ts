import { describe, expect, it } from "vitest";

import {
  Agent,
  DEFAULT_RETENTION,
  DEFAULT_STORAGE,
  RelayClient,
  ValidationError,
  checkEnvelope,
  commitment,
  fingerprint,
  formatRfc3339,
  formatUtcMinute,
  human,
  parseDropLink,
  parseRevealLink,
  seal,
  sealEnvelope,
  validateRetentionPolicy,
  validateSecretName,
  type Envelope,
} from "../src/index.js";
import { FakeRelay, bytesEqual, text, utf8 } from "./helpers.js";

function setup(options: { pageOrigin?: string } = {}): { fake: FakeRelay; agent: Agent } {
  const fake = new FakeRelay();
  const agent = new Agent({ relay: fake.origin, fetch: fake.fetch, ...options });
  return { fake, agent };
}

describe("Agent construction and validation", () => {
  it("requires a relay or a client and validates defaults", () => {
    expect(() => new Agent({})).toThrow(ValidationError);
    expect(() => new Agent({ relay: "http://relay.example" })).toThrow(/only allowed for localhost/);
    expect(() => new Agent({ relay: "https://relay.example", defaultRetention: "forever" })).toThrow(ValidationError);
    expect(() => new Agent({ relay: "https://relay.example", defaultTtlSeconds: 0 })).toThrow(ValidationError);
    expect(() => new Agent({ relay: "https://relay.example", defaultStorage: "a".repeat(201) })).toThrow(/storage/);
    const client = new RelayClient("https://relay.example", "k");
    const a = new Agent({ client, pageOrigin: "https://Drop.Example/" });
    expect(a.client).toBe(client);
    expect(a.pageOrigin).toBe("https://drop.example");
    expect(new Agent({ relay: "https://relay.example" }).pageOrigin).toBe("https://relay.example");
  });

  it("validates names, retention, and formats dates like Go", () => {
    validateSecretName("openai-api-key");
    validateSecretName("A.b_c-1");
    for (const bad of ["", "bad name", "-lead", ".lead", "a..b", "a/b", "a".repeat(101), "clé"]) {
      expect(() => validateSecretName(bad), bad).toThrow(ValidationError);
    }
    const now = new Date("2026-09-17T00:00:00Z");
    validateRetentionPolicy("session", now);
    validateRetentionPolicy("until-revoked", now);
    validateRetentionPolicy("until:2027-01-31T00:00:00Z", now);
    expect(() => validateRetentionPolicy("until:2026-01-31T00:00:00Z", now)).toThrow(/in the past/);
    expect(() => validateRetentionPolicy("until:2027-01-31", now)).toThrow(/RFC 3339/);
    expect(() => validateRetentionPolicy("forever", now)).toThrow(ValidationError);
    expect(formatUtcMinute(new Date("2026-09-17T05:04:59Z"))).toBe("2026-09-17 05:04 UTC");
    expect(formatRfc3339(new Date("2026-09-17T05:04:59.250Z"))).toBe("2026-09-17T05:04:59Z");
  });

  it("checks envelopes exactly like the Go agent", () => {
    const rec = { name: "n", fingerprint: "0000-0000-0000-0000", retention: "session" };
    const env: Envelope = { v: 1, type: "drop", name: "n", retention: "session", fingerprint: "0000-0000-0000-0000", format: "text", secret: "s" };
    expect(checkEnvelope(env, rec)).toBe("");
    expect(checkEnvelope({ ...env, fingerprint: undefined }, rec)).toBe("");
    expect(checkEnvelope({ ...env, type: "reveal" }, rec)).toMatch(/not a drop/);
    expect(checkEnvelope({ ...env, name: "other" }, rec)).toMatch(/name/);
    expect(checkEnvelope({ ...env, fingerprint: "1111-1111-1111-1111" }, rec)).toMatch(/fingerprint/);
    expect(checkEnvelope({ ...env, retention: "until-revoked" }, rec)).toMatch(/retention/);
  });
});

describe("requestSecret", () => {
  it("rejects bad input before touching the relay", async () => {
    const { fake, agent } = setup();
    await expect(agent.requestSecret("bad name", "x")).rejects.toBeInstanceOf(ValidationError);
    await expect(agent.requestSecret("k", "  ")).rejects.toThrow(/purpose is required/);
    await expect(agent.requestSecret("k", "p", { retention: "forever" })).rejects.toBeInstanceOf(ValidationError);
    await expect(agent.requestSecret("k", "p", { ttlSeconds: -1 })).rejects.toBeInstanceOf(ValidationError);
    await expect(agent.requestSecret("k", "p", { storage: "a\tb" })).rejects.toThrow(/storage/);
    await expect(agent.requestSecret("k", "a".repeat(201))).rejects.toThrow(/purpose longer/);
    expect(fake.requests.length).toBe(0);
  });

  it("creates a slot with the commitment and returns a link, fingerprint, and disclosures", async () => {
    const { fake, agent } = setup();
    const before = Date.now();
    const out = await agent.requestSecret("openai-api-key", "Call the OpenAI API for the nightly report", { ttlSeconds: 1800 });
    expect(out.requestId).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(out.link.startsWith(fake.origin + "/drop#")).toBe(true);
    expect(out.storage).toBe(DEFAULT_STORAGE);
    expect(out.retention).toBe(DEFAULT_RETENTION);
    expect(out.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 1800 * 1000 - 1000);
    expect(out.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 1800 * 1000 + 1000);
    const { drop, pageOrigin } = parseDropLink(out.link);
    expect(pageOrigin).toBe(fake.origin);
    expect(drop.relay).toBeUndefined();
    expect(drop.name).toBe("openai-api-key");
    expect(drop.purpose).toBe("Call the OpenAI API for the nightly report");
    expect(drop.storage).toBe(DEFAULT_STORAGE);
    expect(drop.retention).toBe(DEFAULT_RETENTION);
    expect(await fingerprint(drop.recipientKey)).toBe(out.fingerprint);
    // The relay holds the commitment of the key in the link.
    expect(fake.slots.get(out.requestId)?.commitment).toBe(await commitment(drop.recipientKey));
    expect(fake.requests[0].body).toEqual({ ttl_seconds: 1800, commitment: await commitment(drop.recipientKey) });
    // The message discloses everything the human must know.
    expect(out.message).toContain(out.link);
    expect(out.message).toContain(out.fingerprint);
    expect(out.message).toContain("works once");
    expect(out.message).toContain("expires at " + formatUtcMinute(out.expiresAt));
    expect(out.message).toContain("What it is for: Call the OpenAI API for the nightly report");
    expect(out.message).toContain("Where it will be stored: " + DEFAULT_STORAGE + " (kept until deleted).");
    expect(out.message).toContain("I will never see the value itself");
    const pending = agent.pending();
    expect(pending.length).toBe(1);
    expect(pending[0].requestId).toBe(out.requestId);
    expect(pending[0].fingerprint).toBe(out.fingerprint);
    expect(Object.keys(pending[0])).not.toContain("privateKey");
  });

  it("puts the relay origin in the link when the page lives elsewhere", async () => {
    const { fake, agent } = setup({ pageOrigin: "https://drop.example" });
    const r = await agent.requestSecret("n", "p", { retention: "session", storage: "a .env file" });
    const { drop, pageOrigin } = parseDropLink(r.link);
    expect(pageOrigin).toBe("https://drop.example");
    expect(drop.relay).toBe(fake.origin);
    expect(r.message).toContain("(kept only until the agent process exits)");
    const s = await agent.sendSecret("s", "sendable-value");
    const { reveal, pageOrigin: revealPage } = parseRevealLink(s.link);
    expect(revealPage).toBe("https://drop.example");
    expect(reveal.relay).toBe(fake.origin);
  });

  it("describes until dates", async () => {
    const { agent } = setup();
    const r = await agent.requestSecret("n", "p", { retention: "until:2030-01-02T03:04:05Z" });
    expect(r.message).toContain("(kept until 2030-01-02T03:04:05Z)");
  });
});

describe("fetchSecret", () => {
  it("waits, then receives the value, forgets the key, and learns the redaction", async () => {
    const { fake, agent } = setup();
    const req = await agent.requestSecret("openai-api-key", "Call the OpenAI API");
    const waiting = await agent.fetchSecret(req.requestId, 1);
    expect(waiting.status).toBe("waiting");
    expect(waiting.value).toBeUndefined();
    expect(waiting.message).toContain("has not submitted openai-api-key yet");
    expect(waiting.message).toContain(formatRfc3339(req.expiresAt));
    expect(agent.pending().length).toBe(1);

    const submitted = await human.submit(req.link, "sk-live-secret-value-123", { fetch: fake.fetch });
    expect(submitted.fingerprint).toBe(req.fingerprint);
    expect(submitted.sizeBytes).toBe("sk-live-secret-value-123".length);
    expect(fake.state(req.requestId)).toBe("uploaded");

    const got = await agent.fetchSecret(req, 1);
    expect(got.status).toBe("received");
    expect(got.format).toBe("text");
    expect(got.sizeBytes).toBe(24);
    expect(got.value).toBeDefined();
    expect(text(got.value ?? new Uint8Array())).toBe("sk-live-secret-value-123");
    expect(got.message).not.toContain("sk-live");
    expect(got.fingerprint).toBe(req.fingerprint);
    expect(fake.state(req.requestId)).toBe("fetched");
    expect(agent.pending().length).toBe(0);
    expect(agent.redact("token=sk-live-secret-value-123")).toBe("token=[redacted:openai-api-key]");
    await expect(agent.fetchSecret(req.requestId)).rejects.toThrow(/no pending request/);
    await expect(agent.fetchSecret("not-a-token")).rejects.toThrow(/malformed request id/);
  });

  it("receives binary values as base64", async () => {
    const { fake, agent } = setup();
    const req = await agent.requestSecret("client-cert", "TLS client certificate");
    const value = new Uint8Array([0, 1, 2, 3, 0xff, 0xfe]);
    await human.submit(req.link, value, { fetch: fake.fetch });
    const got = await agent.fetchSecret(req);
    expect(got.status).toBe("received");
    expect(got.format).toBe("base64");
    expect(bytesEqual(got.value ?? new Uint8Array(), value)).toBe(true);
  });

  it("reports revoked, expired, unknown, and already fetched requests", async () => {
    const { fake, agent } = setup();
    const revoked = await agent.requestSecret("a", "p");
    await new RelayClient(fake.origin, "", { fetch: fake.fetch }).revokeDrop(revoked.requestId, fake.slots.get(revoked.requestId)?.tokenA ?? "");
    const r = await agent.fetchSecret(revoked.requestId, 1);
    expect(r.status).toBe("revoked");
    expect(agent.pending().length).toBe(0);

    const expired = await agent.requestSecret("b", "p");
    fake.expire(expired.requestId);
    const e = await agent.fetchSecret(expired.requestId, 1);
    expect(e.status).toBe("expired");
    expect(e.message).toContain("expired before the human submitted");

    const unknown = await agent.requestSecret("c", "p");
    fake.delete(unknown.requestId);
    const u = await agent.fetchSecret(unknown.requestId, 1);
    expect(u.status).toBe("expired");
    expect(u.message).toContain("no longer known to the relay");

    const stolen = await agent.requestSecret("d", "p");
    await human.submit(stolen.link, "value-that-was-taken", { fetch: fake.fetch });
    const slot = fake.slots.get(stolen.requestId);
    await new RelayClient(fake.origin, "", { fetch: fake.fetch }).fetch(stolen.requestId, slot?.tokenB ?? "");
    const g = await agent.fetchSecret(stolen.requestId, 1);
    expect(g.status).toBe("gone");
    expect(g.message).toContain("treat the secret as exposed");
    expect(agent.pending().length).toBe(0);
  });

  it("reports a race where the ciphertext is fetched between status and fetch", async () => {
    const { fake, agent } = setup();
    const req = await agent.requestSecret("d", "p");
    await human.submit(req.link, "value-that-was-taken", { fetch: fake.fetch });
    // The status says uploaded, then the fetch finds the tombstone.
    fake.failures.push([200, { state: "uploaded", kind: "drop" }]);
    fake.failures.push([410, { error: "gone", state: "fetched" }]);
    const g = await agent.fetchSecret(req.requestId, 1);
    expect(g.status).toBe("gone");
    expect(g.message).toContain("fetched by someone else");
  });

  it("rejects submissions whose envelope does not match the request", async () => {
    const { fake, agent } = setup();
    const client = new RelayClient(fake.origin, "", { fetch: fake.fetch });
    async function tampered(env: (drop: Envelope) => Envelope | Uint8Array): Promise<{ status: string; message: string }> {
      const req = await agent.requestSecret("openai-api-key", "purpose");
      const { drop } = parseDropLink(req.link);
      const honest: Envelope = {
        v: 1,
        type: "drop",
        name: drop.name,
        purpose: drop.purpose,
        storage: drop.storage,
        retention: drop.retention,
        fingerprint: await fingerprint(drop.recipientKey),
        format: "text",
        secret: "value-value",
      };
      const payload = env(honest);
      const sealed = payload instanceof Uint8Array ? payload : await sealEnvelope(drop.recipientKey, payload);
      await client.upload(drop.id, drop.uploadToken, await commitment(drop.recipientKey), sealed);
      const out = await agent.fetchSecret(req.requestId, 1);
      expect(agent.pending().find((p) => p.requestId === req.requestId)).toBeUndefined();
      return out;
    }
    const fp = await tampered((e) => ({ ...e, fingerprint: "0000-0000-0000-0000" }));
    expect(fp.status).toBe("rejected");
    expect(fp.message).toContain("fingerprint shown to the human does not match");
    const name = await tampered((e) => ({ ...e, name: "other-name" }));
    expect(name.status).toBe("rejected");
    expect(name.message).toContain("secret name in the submission does not match");
    const retention = await tampered((e) => ({ ...e, retention: "session" }));
    expect(retention.message).toContain("retention shown to the human does not match");
    const kind = await tampered((e) => ({ v: 1, type: "reveal", name: e.name, format: "text", secret: "value-value" }));
    expect(kind.message).toContain("not a drop");
    const garbage = await tampered(() => {
      const junk = new Uint8Array(400);
      globalThis.crypto.getRandomValues(junk);
      return junk;
    });
    expect(garbage.status).toBe("rejected");
    expect(garbage.message).toContain("could not be decrypted");
  });

  it("accepts a sealed box with the right key but unpadded content as rejected, not as a crash", async () => {
    const { fake, agent } = setup();
    const req = await agent.requestSecret("n", "p");
    const { drop } = parseDropLink(req.link);
    const client = new RelayClient(fake.origin, "", { fetch: fake.fetch });
    const sealed = await seal(drop.recipientKey, new Uint8Array(300));
    await client.upload(drop.id, drop.uploadToken, await commitment(drop.recipientKey), sealed);
    const out = await agent.fetchSecret(req.requestId, 1);
    expect(out.status).toBe("rejected");
  });

  it("propagates unexpected relay errors", async () => {
    const { fake, agent } = setup();
    const req = await agent.requestSecret("n", "p");
    fake.failures.push([500, { error: "internal_error" }]);
    fake.failures.push([500, { error: "internal_error" }]);
    fake.failures.push([500, { error: "internal_error" }]);
    fake.failures.push([500, { error: "internal_error" }]);
    fake.failures.push([500, { error: "internal_error" }]);
    fake.failures.push([500, { error: "internal_error" }]);
    fake.failures.push([403, { error: "bad_token" }]);
    fake.failures.push([400, { error: "bad_request" }]);
    // The first status call fails with a client error that is not not_found.
    fake.failures.length = 0;
    fake.failures.push([403, { error: "bad_token" }]);
    await expect(agent.fetchSecret(req.requestId, 1)).rejects.toMatchObject({ code: "bad_token" });
    expect(agent.pending().length).toBe(1);
  });
});

describe("sendSecret", () => {
  it("encrypts for the human with the display fields authenticated", async () => {
    const { fake, agent } = setup();
    await expect(agent.sendSecret("bad name", "v")).rejects.toBeInstanceOf(ValidationError);
    await expect(agent.sendSecret("n", "v", { ttlSeconds: 0 })).rejects.toBeInstanceOf(ValidationError);
    const out = await agent.sendSecret("staging-db-url", "postgres://app:s3cret@db.staging.example:5432/app", { ttlSeconds: 600 });
    expect(out.link.startsWith(fake.origin + "/reveal#")).toBe(true);
    expect(out.keepsCopy).toBe(true);
    expect(out.revokeToken).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(out.message).toContain(out.link);
    expect(out.message).toContain("reveals the value once");
    expect(out.message).toContain("I keep my copy of it.");
    expect(out.message).toContain("expires at " + formatUtcMinute(out.expiresAt));
    expect(out.message).not.toContain("s3cret");
    expect(fake.requests.at(-1)?.body).toMatchObject({ ttl_seconds: 600 });
    const { reveal } = parseRevealLink(out.link);
    expect(reveal.name).toBe("staging-db-url");
    expect(reveal.keepsCopy).toBe(true);
    const opened = await human.open(out.link, { fetch: fake.fetch });
    expect(text(opened.value)).toBe("postgres://app:s3cret@db.staging.example:5432/app");
    expect(opened.format).toBe("text");
    expect(opened.keepsCopy).toBe(true);
    expect(opened.name).toBe("staging-db-url");
    expect(fake.state(out.requestId)).toBe("opened");
    await expect(human.open(out.link, { fetch: fake.fetch })).rejects.toThrow(/already used or revoked \(state: opened\)/);
    expect(agent.redact("s3cret is postgres://app:s3cret@db.staging.example:5432/app")).toBe("s3cret is [redacted:staging-db-url]");
  });

  it("tells the human when the copy was deleted and handles binary values", async () => {
    const { fake, agent } = setup();
    const value = new Uint8Array([7, 0, 9, 200]);
    const out = await agent.sendSecret("blob", value, { keepsCopy: false });
    expect(out.message).toContain("I have deleted my copy of it.");
    expect(parseRevealLink(out.link).reveal.keepsCopy).toBe(false);
    const opened = await human.open(out.link, { fetch: fake.fetch });
    expect(opened.format).toBe("base64");
    expect(bytesEqual(opened.value, value)).toBe(true);
    expect(opened.keepsCopy).toBe(false);
  });
});

describe("revoke", () => {
  it("revokes pending requests and unopened reveals", async () => {
    const { fake, agent } = setup();
    const req = await agent.requestSecret("n", "p");
    expect(await agent.revoke(req)).toBe("revoked");
    expect(fake.state(req.requestId)).toBe("revoked");
    expect(agent.pending().length).toBe(0);
    await expect(agent.revoke(req.requestId)).rejects.toThrow(/no pending request/);
    await expect(human.submit(req.link, "value", { fetch: fake.fetch })).rejects.toThrow(/no longer be used \(state: revoked\)/);

    const sent = await agent.sendSecret("s", "sendable-value");
    expect(await agent.revoke(sent)).toBe("revoked");
    expect(fake.state(sent.requestId)).toBe("revoked");
    await expect(human.open(sent.link, { fetch: fake.fetch })).rejects.toThrow(/already used or revoked \(state: revoked\)/);
    // Revoking again reports the state the slot is already in.
    expect(await agent.revoke(sent)).toBe("revoked");
  });

  it("maps relay outcomes to states", async () => {
    const { fake, agent } = setup();
    const fetched = await agent.requestSecret("a", "p");
    await human.submit(fetched.link, "value-value", { fetch: fake.fetch });
    await new RelayClient(fake.origin, "", { fetch: fake.fetch }).fetch(fetched.requestId, fake.slots.get(fetched.requestId)?.tokenB ?? "");
    expect(await agent.revoke(fetched.requestId)).toBe("fetched");
    const gone = await agent.requestSecret("b", "p");
    fake.delete(gone.requestId);
    expect(await agent.revoke(gone.requestId)).toBe("expired");
    const failing = await agent.requestSecret("c", "p");
    fake.failures.push([500, { error: "internal_error" }]);
    await expect(agent.revoke(failing.requestId)).rejects.toMatchObject({ status: 500 });
    expect(agent.pending().length).toBe(1);
  });
});

describe("runWithSecret through the agent", () => {
  it("redacts values the agent has seen and the injected ones", async () => {
    const { fake, agent } = setup();
    const req = await agent.requestSecret("api-key", "p");
    await human.submit(req.link, "received-secret-value", { fetch: fake.fetch });
    const got = await agent.fetchSecret(req.requestId);
    const value = got.value ?? new Uint8Array();
    const out = await agent.runWithSecret(process.execPath, ["-e", 'console.log(process.env.API_KEY + " " + process.env.OTHER)'], {
      API_KEY: value,
      OTHER: utf8("another-secret-value"),
    });
    expect(out.exitCode).toBe(0);
    expect(out.stdout.trim()).toBe("[redacted:api-key] [redacted:OTHER]");
    expect(agent.redact("another-secret-value")).toBe("[redacted:OTHER]");
  });
});
