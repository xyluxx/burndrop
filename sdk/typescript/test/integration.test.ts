/**
 * End-to-end test against the real Go relay. It builds cmd/burndrop-relay
 * from the repository, starts it on 127.0.0.1:8081 (BURNDROP_TEST_PORT
 * overrides the port) with agent authentication off, and runs both flows.
 * Skipped when the Go toolchain is not available.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  Agent,
  BurndropError,
  DeadlineExceededError,
  RelayClient,
  RelayError,
  buildDropLink,
  commitment,
  fingerprint,
  human,
  parseDropLink,
  sealEnvelope,
  type Envelope,
} from "../src/index.js";
import { bytesEqual, text } from "./helpers.js";

const repoRoot = fileURLToPath(new URL("../../../", import.meta.url));
const port = Number(process.env.BURNDROP_TEST_PORT ?? "8081");
const origin = "http://127.0.0.1:" + String(port);

function findGo(): string | undefined {
  const candidates = ["go", "C:\\Program Files\\Go\\bin\\go.exe", "/usr/local/go/bin/go", join(process.env.HOME ?? "", "go", "bin", "go")];
  for (const candidate of candidates) {
    try {
      if (spawnSync(candidate, ["version"], { stdio: "ignore" }).status === 0) {
        return candidate;
      }
    } catch {
      // try the next one
    }
  }
  return undefined;
}

const goBin = process.env.BURNDROP_SKIP_INTEGRATION === undefined ? findGo() : undefined;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

describe.skipIf(goBin === undefined)("integration with the Go relay", () => {
  let relay: ChildProcess | undefined;
  let dir = "";
  let relayLog = "";

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "burndrop-ts-"));
    const exe = join(dir, process.platform === "win32" ? "burndrop-relay.exe" : "burndrop-relay");
    const build = spawnSync(goBin ?? "go", ["build", "-o", exe, "./cmd/burndrop-relay"], { cwd: repoRoot, encoding: "utf8" });
    if (build.status !== 0) {
      throw new Error("go build failed: " + build.stderr);
    }
    relay = spawn(exe, ["serve"], {
      env: {
        ...process.env,
        BURNDROP_PUBLIC_ORIGIN: origin,
        BURNDROP_AGENT_AUTH: "off",
        BURNDROP_LISTEN: "127.0.0.1:" + String(port),
        BURNDROP_RATE_PAGE_PER_MIN: "6000",
        BURNDROP_RATE_AGENT_PER_MIN: "6000",
        BURNDROP_LOG_LEVEL: "warn",
      },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    relay.stdout?.on("data", (chunk: Buffer) => {
      relayLog += chunk.toString();
    });
    relay.stderr?.on("data", (chunk: Buffer) => {
      relayLog += chunk.toString();
    });
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      try {
        const res = await fetch(origin + "/healthz");
        if (res.ok) {
          return;
        }
      } catch {
        // not up yet
      }
      if (relay.exitCode !== null) {
        break;
      }
      await sleep(100);
    }
    throw new Error("relay did not start on " + origin + ": " + relayLog);
  }, 180_000);

  afterAll(async () => {
    if (relay?.exitCode === null) {
      const exited = new Promise<void>((resolve) => relay?.once("exit", () => resolve()));
      relay.kill();
      await Promise.race([exited, sleep(5000)]);
    }
    if (dir !== "") {
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    }
  });

  function newAgent(): Agent {
    return new Agent({ relay: origin, clientName: "burndrop-ts-test/1" });
  }

  it("describes itself", async () => {
    const info = await new RelayClient(origin).info();
    expect(info.api).toBe("v1");
    expect(info.agentAuth).toBe("off");
    expect(info.longPollMaxSeconds).toBe(30);
    expect(info.maxCiphertextBytes).toBeGreaterThan(64 * 1024);
  });

  it("runs the drop flow once and only once", async () => {
    const agent = newAgent();
    const req = await agent.requestSecret("openai-api-key", "Call the OpenAI API for the nightly report", { ttlSeconds: 1800 });
    const minutes = (req.expiresAt.getTime() - Date.now()) / 60_000;
    expect(minutes).toBeGreaterThan(25);
    expect(minutes).toBeLessThan(31);
    expect(req.link.startsWith(origin + "/drop#")).toBe(true);

    const waiting = await agent.fetchSecret(req.requestId, 1);
    expect(waiting.status).toBe("waiting");

    // A long poll returns as soon as the human submits.
    const started = Date.now();
    const poll = agent.client.waitForUpload(req.requestId, Date.now() + 15_000);
    await sleep(300);
    const submitted = await human.submit(req.link, "sk-live-secret-value-123");
    expect(submitted.fingerprint).toBe(req.fingerprint);
    const status = await poll;
    expect(status.state).toBe("uploaded");
    expect(status.uploadedAt).toBeDefined();
    expect(Date.now() - started).toBeLessThan(10_000);

    const got = await agent.fetchSecret(req.requestId);
    expect(got.status).toBe("received");
    expect(text(got.value ?? new Uint8Array())).toBe("sk-live-secret-value-123");
    expect(got.format).toBe("text");
    expect(agent.pending().length).toBe(0);

    // The relay deleted the ciphertext: a second fetch is gone.
    const st = await agent.client.dropStatus(req.requestId);
    expect(st.state).toBe("fetched");
    expect(st.fetchedAt).toBeDefined();
    const again = await agent.client.fetch(req.requestId, "AAAAAAAAAAAAAAAAAAAAAA").catch((e: unknown) => e);
    expect(again).toBeInstanceOf(RelayError);
    expect((again as RelayError).status).toBe(410);
    expect((again as RelayError).code).toBe("gone");
    expect((again as RelayError).state).toBe("fetched");
    await expect(human.submit(req.link, "second try")).rejects.toThrow(/no longer be used \(state: fetched\)/);
    expect(agent.redact("sk-live-secret-value-123")).toBe("[redacted:openai-api-key]");
  });

  it("runs the reveal flow once and only once", async () => {
    const agent = newAgent();
    const sent = await agent.sendSecret("staging-db-url", "postgres://app:s3cret@db.staging.example:5432/app", { ttlSeconds: 600, keepsCopy: false });
    expect(sent.message).toContain("I have deleted my copy of it.");
    const notYet = await agent.client.waitForOpen(sent.requestId, Date.now() + 1000).catch((e: unknown) => e);
    expect(notYet).toBeInstanceOf(DeadlineExceededError);
    const poll = agent.client.waitForOpen(sent.requestId, Date.now() + 15_000);
    await sleep(200);
    const opened = await human.open(sent.link);
    expect(text(opened.value)).toBe("postgres://app:s3cret@db.staging.example:5432/app");
    expect(opened.keepsCopy).toBe(false);
    const status = await poll;
    expect(status.state).toBe("opened");
    expect(status.openedAt).toBeDefined();
    await expect(human.open(sent.link)).rejects.toThrow(/already used or revoked \(state: opened\)/);
    const again = await agent.client.open(sent.requestId, "AAAAAAAAAAAAAAAAAAAAAA").catch((e: unknown) => e);
    expect((again as RelayError).status).toBe(410);
    expect((again as RelayError).state).toBe("opened");
  });

  it("revokes requests and reveals", async () => {
    const agent = newAgent();
    const req = await agent.requestSecret("token", "purpose");
    expect(await agent.revoke(req)).toBe("revoked");
    expect((await agent.client.dropStatus(req.requestId)).state).toBe("revoked");
    await expect(human.submit(req.link, "value")).rejects.toThrow(/\(state: revoked\)/);
    await expect(agent.revoke(req)).rejects.toThrow(/no pending request/);

    const sent = await agent.sendSecret("token", "value-to-revoke");
    expect(await agent.revoke(sent)).toBe("revoked");
    await expect(human.open(sent.link)).rejects.toThrow(/\(state: revoked\)/);
    expect(await agent.revoke(sent)).toBe("revoked");

    // A revoke from the human side (with the upload token) is reported to the agent.
    const other = await agent.requestSecret("token2", "purpose");
    const { drop } = parseDropLink(other.link);
    await agent.client.revokeDrop(drop.id, drop.uploadToken);
    const outcome = await agent.fetchSecret(other.requestId, 1);
    expect(outcome.status).toBe("revoked");
  });

  it("rejects tampered links", async () => {
    const agent = newAgent();
    // A swapped key is caught by the relay's commitment check.
    const req = await agent.requestSecret("api-key", "purpose");
    const { drop, pageOrigin } = parseDropLink(req.link);
    const swapped = buildDropLink({ ...drop, recipientKey: new Uint8Array(32).fill(0x42) }, pageOrigin);
    const err = await human.submit(swapped, "value").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BurndropError);
    expect((err as BurndropError).message).toContain("does not match the key the agent registered");
    expect((err as BurndropError).cause).toMatchObject({ status: 422, code: "commitment_mismatch" });

    // A page that shows the wrong fingerprint but seals to the right key is
    // caught by the agent's envelope check.
    const env: Envelope = {
      v: 1,
      type: "drop",
      name: drop.name,
      purpose: drop.purpose,
      storage: drop.storage,
      retention: drop.retention,
      fingerprint: "0000-0000-0000-0000",
      format: "text",
      secret: "value-value",
    };
    expect(await fingerprint(drop.recipientKey)).not.toBe(env.fingerprint);
    await agent.client.upload(drop.id, drop.uploadToken, await commitment(drop.recipientKey), await sealEnvelope(drop.recipientKey, env));
    const outcome = await agent.fetchSecret(req.requestId, 1);
    expect(outcome.status).toBe("rejected");
    expect(outcome.message).toContain("fingerprint shown to the human does not match");
    expect(outcome.value).toBeUndefined();
    expect(agent.pending().length).toBe(0);

    // An altered reveal link fails to decrypt and the relay copy is gone.
    const sent = await agent.sendSecret("db-url", "the-secret-value");
    await expect(human.open(sent.link.replace("&c=1", "&c=0"))).rejects.toThrow(/the link was altered/);
    await expect(human.open(sent.link)).rejects.toThrow(/already used or revoked/);
  });

  it("carries binary values in both directions", async () => {
    const agent = newAgent();
    const value = new Uint8Array(1000);
    globalThis.crypto.getRandomValues(value);
    value[0] = 0;
    const req = await agent.requestSecret("blob", "binary test");
    await human.submit(req.link, value);
    const got = await agent.fetchSecret(req.requestId);
    expect(got.status).toBe("received");
    expect(got.format).toBe("base64");
    expect(bytesEqual(got.value ?? new Uint8Array(), value)).toBe(true);
    const sent = await agent.sendSecret("blob", value);
    const opened = await human.open(sent.link);
    expect(opened.format).toBe("base64");
    expect(bytesEqual(opened.value, value)).toBe(true);
  });

  it("holds a long poll for the requested time", async () => {
    const agent = newAgent();
    const req = await agent.requestSecret("slow", "purpose");
    const started = Date.now();
    const st = await agent.client.dropStatus(req.requestId, 2, "created");
    expect(st.state).toBe("created");
    expect(Date.now() - started).toBeGreaterThanOrEqual(1500);
    expect(await agent.revoke(req)).toBe("revoked");
  });
});
